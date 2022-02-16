use std::path::Path;

use framehop::x86_64::*;
use framehop::Unwinder;

mod common;

#[test]
fn test_plt_cfa_expr() {
    let mut cache = CacheX86_64::<_>::new();
    let mut unwinder = UnwinderX86_64::new();
    common::add_object(
        &mut unwinder,
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/linux/x86_64/fp/nightly-firefox-bin"),
        0x1000000,
    );

    // Test some functions from the .plt section. All PLT stubs are covered by one
    // large CFI rule which uses the following DWARF expression to compute the CFA:
    // CFA=reg7 + 8 + (((reg16 & 0xf) >= 0xb) << 3)
    // or, in other words:
    //  - Check the last hex digit of the current instruction address.
    //  - If it's >= b then we've pushed an 8-byte value to the stack, otherwise we
    //    haven't pushed anything.
    //
    //         j_ceil:        // ceil
    // c0d0         jmp        qword [ceil@GOT]
    //          sub_c0d6:
    // c0d6         push       0xa
    // c0db         jmp        0xc020
    //         j_sprintf:        // sprintf
    // c0e0         jmp        qword [sprintf@GOT]
    //         sub_c0e6:
    // c0e6         push       0xb
    // c0eb         jmp        0xc020

    // return address 0x123456 is at stack location 0x30.
    let stack = [1, 2, 3, 4, 5, 0xa, 0x123456, 6, 7, 8, 9];
    let mut read_mem = |addr| stack.get((addr / 8) as usize).cloned().ok_or(());

    for (sp, rel_pc) in [
        (0x28, 0xc0db),
        (0x30, 0xc0e0),
        (0x30, 0xc0e6),
        (0x28, 0xc0eb),
    ]
    .iter()
    {
        let mut regs = UnwindRegsX86_64::new(0x1000000 + rel_pc, *sp, 0x345);
        let res = unwinder.unwind_first(0x1000000 + rel_pc, &mut regs, &mut cache, &mut read_mem);
        assert_eq!(res, Ok(Some(0x123456)));
        assert_eq!(regs.sp(), 0x38);
        assert_eq!(regs.bp(), 0x345);
    }
}

#[test]
fn test_pthread_cfa_expr() {
    let mut cache = CacheX86_64::<_>::new();
    let mut unwinder = UnwinderX86_64::new();
    common::add_object(
        &mut unwinder,
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/linux/x86_64/nofp/libpthread-2.19.so"),
        0x7f54b14fc000,
    );

    // ...
    // _L_lock_4767:
    // 9423  lea  rdi, qword [stack_cache_lock]
    // 942a  sub  rsp, 0x80
    // 9431  call  __lll_lock_wait_private
    // 9436  add  rsp, 0x80
    // 943d  jmp  loc_8c2c
    // _L_unlock_4791:
    // ...
    //
    // with DWARF CFI:
    //
    // 0x9423: CFA=reg7-128: reg16=DW_OP_breg16 +19 // 0x9423 + 19 == 0x9436
    // 0x942a: CFA=reg7-128: reg16=DW_OP_breg16 +12 // 0x942a + 12 == 0x9436
    // 0x9431: CFA=reg7: reg16=DW_OP_breg16 +5 // 0x9431 + 5 == 0x9436
    // 0x9435: CFA=reg7+128: reg16=DW_OP_breg16 +6, DW_OP_const4s -45616, DW_OP_minus, DW_OP_const4s -47680, DW_OP_plus
    // 0x943d: CFA=reg7-128: reg16=DW_OP_breg16 -7 // 0x943d - 7 == 0x9436
    //
    // This is some super weird stuff. So basically, all addresses other than the add instruction "unwind" by jumping
    // to the add instruction. And then from there, you unwind by adding and subtracting some literals to rip.
    // CFA=reg7+128: reg16=rip + 6 - -45616 + -47680 (== 0x8c2c)
    //
    // Yes, indeed, 0x8c2c seems like the right target address:
    //
    // pthread_create@@GLIBC_2.2.5:
    // 8430  push  rbp
    // ...
    // 8c1e  lock cmpxchg dword [stack_cache_lock], esi
    // 8c26  jne  _L_lock_4767                    ; <-- _L_lock_4767 is function we just unwound from
    // 8c2c  mov  rdx, qword [__stack_user]       ; <-- this is the return address we unwound to
    // 8c33  lea  rax, qword [r15+0x2c0]
    // ...
    //
    let mut stack = vec![0u64; 0x200 / 8];
    stack[0x120 / 8] = 0x1234;
    stack[0x128 / 8] = 0xbe7042;
    let mut read_mem = |addr| stack.get((addr / 8) as usize).cloned().ok_or(());
    let mut regs = UnwindRegsX86_64::new(0x7f54b14fc000 + 0x9431, 0x10, 0x120);

    let res = unwinder.unwind_first(
        0x7f54b14fc000 + 0x9431,
        &mut regs,
        &mut cache,
        &mut read_mem,
    );
    assert_eq!(res, Ok(Some(0x7f54b14fc000 + 0x9436)));
    assert_eq!(regs.sp(), 0x10);
    assert_eq!(regs.bp(), 0x120);

    let res = unwinder.unwind_next(
        0x7f54b14fc000 + 0x9436,
        &mut regs,
        &mut cache,
        &mut read_mem,
    );
    assert_eq!(res, Ok(Some(0x7f54b14fc000 + 0x8c2c)));
    assert_eq!(regs.sp(), 0x90);
    assert_eq!(regs.bp(), 0x120);

    // 0x88e8: CFA=reg7+8: reg3=[CFA-56], reg6=[CFA-16], reg12=[CFA-48], reg13=[CFA-40], reg14=[CFA-32], reg15=[CFA-24], reg16=[CFA-8]
    // This is a frame pointer unwind!
    let res = unwinder.unwind_next(
        0x7f54b14fc000 + 0x8c2c,
        &mut regs,
        &mut cache,
        &mut read_mem,
    );
    assert_eq!(res, Ok(Some(0xbe7042)));
    assert_eq!(regs.sp(), 0x130);
    assert_eq!(regs.bp(), 0x1234);
}
