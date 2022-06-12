use std::path::Path;

use framehop::aarch64::*;
use framehop::x86_64::*;
use framehop::FrameAddress;
use framehop::Unwinder;

use super::common;

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
    let mut read_stack = |addr| stack.get((addr / 8) as usize).cloned().ok_or(());

    for (sp, rel_pc) in [
        (0x28, 0xc0db),
        (0x30, 0xc0e0),
        (0x30, 0xc0e6),
        (0x28, 0xc0eb),
    ]
    .iter()
    {
        let mut regs = UnwindRegsX86_64::new(0x1000000 + rel_pc, *sp, 0x345);
        let res = unwinder.unwind_frame(
            FrameAddress::from_instruction_pointer(0x1000000 + rel_pc),
            &mut regs,
            &mut cache,
            &mut read_stack,
        );
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
    let mut read_stack = |addr| stack.get((addr / 8) as usize).cloned().ok_or(());
    let mut regs = UnwindRegsX86_64::new(0x7f54b14fc000 + 0x9431, 0x10, 0x120);

    let res = unwinder.unwind_frame(
        FrameAddress::from_instruction_pointer(0x7f54b14fc000 + 0x9431),
        &mut regs,
        &mut cache,
        &mut read_stack,
    );
    assert_eq!(res, Ok(Some(0x7f54b14fc000 + 0x9436)));
    assert_eq!(regs.sp(), 0x10);
    assert_eq!(regs.bp(), 0x120);

    let res = unwinder.unwind_frame(
        FrameAddress::from_return_address(0x7f54b14fc000 + 0x9436).unwrap(),
        &mut regs,
        &mut cache,
        &mut read_stack,
    );
    assert_eq!(res, Ok(Some(0x7f54b14fc000 + 0x8c2c)));
    assert_eq!(regs.sp(), 0x90);
    assert_eq!(regs.bp(), 0x120);

    // 0x88e8: CFA=reg7+8: reg3=[CFA-56], reg6=[CFA-16], reg12=[CFA-48], reg13=[CFA-40], reg14=[CFA-32], reg15=[CFA-24], reg16=[CFA-8]
    // This is a frame pointer unwind!
    let res = unwinder.unwind_frame(
        FrameAddress::from_return_address(0x7f54b14fc000 + 0x8c2c).unwrap(),
        &mut regs,
        &mut cache,
        &mut read_stack,
    );
    assert_eq!(res, Ok(Some(0xbe7042)));
    assert_eq!(regs.sp(), 0x130);
    assert_eq!(regs.bp(), 0x1234);
}

#[test]
fn test_no_eh_frame_hdr() {
    let mut cache = CacheAarch64::<_>::new();
    let mut unwinder = UnwinderAarch64::new();
    common::add_object(
        &mut unwinder,
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/linux/aarch64/vdso.so"),
        0x0,
    );
    let mut stack = [
        /* 0x0: */ 0, /* 0x8: */ 1, /* 0x10: */ 2, /* 0x18: */ 3,
        /* 0x20: */ 40000, // stored fp
        /* 0x28: */ 50000, // stored lr
        /* 0x30: */ 6, /* 0x38: */ 7, /* 0x40: */ 80000, // stored fp
        /* 0x48: */ 90000, // stored lr
        /* 0x50: */ 10, /* 0x58: */ 11, /* 0x60: */ 12, /* 0x68: */ 13,
        /* 0x70: */ 0x0, // sentinel fp
        /* 0x78: */ 0x0, // sentinel lr
    ];
    let mut regs = UnwindRegsAarch64::new(0x1234, 0x50, 0x70);
    let res = unwinder.unwind_frame(
        FrameAddress::from_instruction_pointer(0x5a8),
        &mut regs,
        &mut cache,
        &mut |addr| stack.get((addr / 8) as usize).cloned().ok_or(()),
    );
    assert_eq!(res, Ok(Some(0x1234)));
    assert_eq!(regs.sp(), 0x50);
    assert_eq!(regs.fp(), 0x70);
    assert_eq!(regs.lr(), 0x1234);

    let mut regs = UnwindRegsAarch64::new(0x1234, 0x40, 0x70);
    stack[8] = regs.fp();
    stack[9] = regs.lr();
    let res = unwinder.unwind_frame(
        FrameAddress::from_instruction_pointer(0x5ac),
        &mut regs,
        &mut cache,
        &mut |addr| stack.get((addr / 8) as usize).cloned().ok_or(()),
    );
    assert_eq!(res, Ok(Some(0x1234)));
    assert_eq!(regs.sp(), 0x50);
    assert_eq!(regs.fp(), 0x70);
    assert_eq!(regs.lr(), 0x1234);

    let mut regs = UnwindRegsAarch64::new(0x1234, 0x40, 0x40);
    let res = unwinder.unwind_frame(
        FrameAddress::from_instruction_pointer(0x5b0),
        &mut regs,
        &mut cache,
        &mut |addr| stack.get((addr / 8) as usize).cloned().ok_or(()),
    );
    assert_eq!(res, Ok(Some(0x1234)));
    assert_eq!(regs.sp(), 0x50);
    assert_eq!(regs.fp(), 0x70);
    assert_eq!(regs.lr(), 0x1234);

    let mut regs = UnwindRegsAarch64::new(0x5b4, 0x40, 0x40);
    let res = unwinder.unwind_frame(
        FrameAddress::from_instruction_pointer(0x3c0),
        &mut regs,
        &mut cache,
        &mut |addr| stack.get((addr / 8) as usize).cloned().ok_or(()),
    );
    assert_eq!(res, Ok(Some(0x5b4)));
    assert_eq!(regs.sp(), 0x40);
    assert_eq!(regs.fp(), 0x40);
    assert_eq!(regs.lr(), 0x5b4);

    let mut regs = UnwindRegsAarch64::new(0x5b4, 0x40, 0x40);
    let res = unwinder.unwind_frame(
        FrameAddress::from_instruction_pointer(0x3c0),
        &mut regs,
        &mut cache,
        &mut |addr| stack.get((addr / 8) as usize).cloned().ok_or(()),
    );
    assert_eq!(res, Ok(Some(0x5b4)));
    assert_eq!(regs.sp(), 0x40);
    assert_eq!(regs.fp(), 0x40);
    assert_eq!(regs.lr(), 0x5b4);

    let mut regs = UnwindRegsAarch64::new(0x5b4, 0x40, 0x40);
    let res = unwinder.unwind_frame(
        FrameAddress::from_instruction_pointer(0x3ec),
        &mut regs,
        &mut cache,
        &mut |addr| stack.get((addr / 8) as usize).cloned().ok_or(()),
    );
    assert_eq!(res, Ok(Some(0x5b4)));
    assert_eq!(regs.sp(), 0x40);
    assert_eq!(regs.fp(), 0x40);
    assert_eq!(regs.lr(), 0x5b4);
    let res = unwinder.unwind_frame(
        FrameAddress::from_instruction_pointer(0x5b4),
        &mut regs,
        &mut cache,
        &mut |addr| stack.get((addr / 8) as usize).cloned().ok_or(()),
    );
    assert_eq!(res, Ok(Some(0x1234)));
    assert_eq!(regs.sp(), 0x50);
    assert_eq!(regs.fp(), 0x70);
    assert_eq!(regs.lr(), 0x1234);

    let mut regs = UnwindRegsAarch64::new(0x1234, 0x50, 0x70);
    let res = unwinder.unwind_frame(
        FrameAddress::from_instruction_pointer(0x5b8),
        &mut regs,
        &mut cache,
        &mut |addr| stack.get((addr / 8) as usize).cloned().ok_or(()),
    );
    assert_eq!(res, Ok(Some(0x1234)));
    assert_eq!(regs.sp(), 0x50);
    assert_eq!(regs.fp(), 0x70);
    assert_eq!(regs.lr(), 0x1234);
}

#[test]
fn test_epilogue_bp_already_popped() {
    let mut cache = CacheX86_64::<_>::new();
    let mut unwinder = UnwinderX86_64::new();
    common::add_object(
        &mut unwinder,
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/linux/x86_64/nofp/rustup"),
        0x0,
    );

    // ...
    // 583a11  add  rsp, 0x128
    // 583a18  pop  rbx
    // 583a19  pop  r14
    // 583a1b  pop  r15
    // 583a1d  pop  rbp
    // 583a1e  ret               ; <-- profiler sampled here, bp already popped
    // 583a1f  xorps xmm0, xmm0
    // ...
    //
    // DWARF CFI:
    // ...
    // 0x583a18: CFA=RSP+40: RBX=[CFA-40], RBP=[CFA-16], R14=[CFA-32], R15=[CFA-24], RIP=[CFA-8]
    // 0x583a19: CFA=RSP+32: RBX=[CFA-40], RBP=[CFA-16], R14=[CFA-32], R15=[CFA-24], RIP=[CFA-8]
    // 0x583a1b: CFA=RSP+24: RBX=[CFA-40], RBP=[CFA-16], R14=[CFA-32], R15=[CFA-24], RIP=[CFA-8]
    // 0x583a1d: CFA=RSP+16: RBX=[CFA-40], RBP=[CFA-16], R14=[CFA-32], R15=[CFA-24], RIP=[CFA-8]
    // 0x583a1e: CFA=RSP+8: RBX=[CFA-40], RBP=[CFA-16], R14=[CFA-32], R15=[CFA-24], RIP=[CFA-8]
    // 0x583a1f: CFA=RSP+336: RBX=[CFA-40], RBP=[CFA-16], R14=[CFA-32], R15=[CFA-24], RIP=[CFA-8]
    // ...
    //
    // Note the "CFA=RSP+8: RBX=[CFA-40], RBP=[CFA-16]" - the dwarf cfi is referring to registers
    // that are stored on the stack at locations beyond the current stack pointer value.
    //
    // We don't need to read those registers; we've already popped them so they're already in
    // the "pre-unwind" register values.

    // sp = 0x330
    // return address 0x123456 is at stack location 0x330.
    let mut read_stack = |addr| {
        if addr < 0x330 {
            return Err(());
        }
        if addr == 0x330 {
            return Ok(0x123456);
        };
        Ok(addr - 0x330)
    };

    // The correct value for bp is already in the bp register, we're just
    // past the instruction that popped the value.
    let mut regs = UnwindRegsX86_64::new(0x583a1e, 0x330, 0x348);
    let res = unwinder.unwind_frame(
        FrameAddress::from_instruction_pointer(0x583a1e),
        &mut regs,
        &mut cache,
        &mut read_stack,
    );
    assert_eq!(res, Ok(Some(0x123456)));
    assert_eq!(regs.sp(), 0x338);
    assert_eq!(regs.bp(), 0x348);
}

#[test]
fn test_libc_syscall_no_fde() {
    let mut cache = CacheX86_64::<_>::new();
    let mut unwinder = UnwinderX86_64::new();
    common::add_object(
        &mut unwinder,
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/linux/x86_64/nofp/libc.so.6"),
        0x0,
    );

    // sub_129720:
    // 129720  endbr64                      ; End of unwind block (FDE at 0x206a24), Begin of unwind block (FDE at 0x206a6c)
    // 129724  mov        eax, 0xffffffea
    // 129729  test       rdi, rdi
    // 12972c  je         loc_12975a
    // 12972e  test       rdx, rdx
    // 129731  je         loc_12975a
    // 129733  mov        r8, rcx
    // 129736  mov        eax, 0x1b3
    // 12973b  syscall                      ; End of unwind block (FDE at 0x206a6c)
    // 12973d  test       rax, rax    ; <-- profiler sampled here
    // 129740  jl         loc_12975a
    // 129742  je         loc_129745
    // 129744  ret
    // 129745  xor        ebp, ebp
    // ...

    // There is no FDE covering the sampled instruction.

    // sp = 0x330
    // return address 0x123456 is at stack location 0x330.
    let mut read_stack = |addr| {
        if addr < 0x330 {
            return Err(());
        }
        if addr == 0x330 {
            return Ok(0x123456);
        };
        Ok(addr - 0x330)
    };

    // The correct value for bp is already in the bp register, we're just
    // past the instruction that popped the value.
    let mut regs = UnwindRegsX86_64::new(0x12973d, 0x330, 0x348);
    let res = unwinder.unwind_frame(
        FrameAddress::from_instruction_pointer(0x12973d),
        &mut regs,
        &mut cache,
        &mut read_stack,
    );
    assert_eq!(res, Ok(Some(0x123456)));
    assert_eq!(regs.sp(), 0x338);
    assert_eq!(regs.bp(), 0x348);
}
