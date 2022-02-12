use std::path::Path;

use framehop::*;

mod common;

#[test]
fn test_plt_cfa_expr() {
    let mut cache = CacheX86_64::default();
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
    let mut read_mem = |addr| match stack.get((addr / 8) as usize) {
        Some(val) => Ok(*val),
        None => Err(()),
    };

    for (sp, rel_pc) in [
        (0x28, 0xc0db),
        (0x30, 0xc0e0),
        (0x30, 0xc0e6),
        (0x28, 0xc0eb),
    ]
    .iter()
    {
        let mut regs = UnwindRegsX86_64::new(*sp, 0x345);
        let res = unwinder.unwind_first(0x1000000 + rel_pc, &mut regs, &mut cache, &mut read_mem);
        assert_eq!(res, Ok(0x123456));
        assert_eq!(regs.sp(), 0x38);
        assert_eq!(regs.bp(), 0x345);
    }
}

#[test]
fn test_pthread_cfa_expr() {
    let mut cache = CacheX86_64::default();
    let mut unwinder = UnwinderX86_64::new();
    common::add_object(
        &mut unwinder,
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/linux/x86_64/nofp/libpthread-2.19.so"),
        0x7f54b14fc000,
    );
    let mut stack = vec![0u64; 0x100];
    stack[(0x10 + 0x80) / 8] = 0xbe7042;
    let mut read_mem = |addr| match stack.get((addr / 8) as usize) {
        Some(val) => Ok(*val),
        None => Err(()),
    };
    let mut regs = UnwindRegsX86_64::new(0x10, 0x1234);
    // ...
    // _L_lock_4767:
    // 0000000000009423         lea        rdi, qword [stack_cache_lock]               ; End of unwind block (FDE at 0x1436c), Begin of unwind block (FDE at 0x143b4), argument #1 for method __lll_lock_wait_private, stack_cache_lock, CODE XREF=pthread_create@@GLIBC_2.2.5+2038
    // 000000000000942a         sub        rsp, 0x80
    // 0000000000009431         call       __lll_lock_wait_private                     ; __lll_lock_wait_private
    // 0000000000009436         add        rsp, 0x80
    // 000000000000943d         jmp        loc_8c2c
    // _L_unlock_4791:
    // ...
    let res = unwinder.unwind_first(
        0x7f54b14fc000 + 0x9431,
        &mut regs,
        &mut cache,
        &mut read_mem,
    );
    assert_eq!(res, Ok(0xbe7042));
    assert_eq!(regs.sp(), 0x98);
    assert_eq!(regs.bp(), 0x1234);
}
