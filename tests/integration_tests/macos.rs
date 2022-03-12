use std::path::Path;

use fallible_iterator::FallibleIterator;
use framehop::aarch64::*;
use framehop::x86_64::*;
use framehop::FrameAddress;
use framehop::Unwinder;

use super::common;

#[test]
fn test_basic() {
    let mut cache = CacheAarch64::<_>::new();
    let mut unwinder = UnwinderAarch64::new();
    common::add_object(
        &mut unwinder,
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/macos/arm64/fp/query-api"),
        0x1003fc000,
    );
    let stack = [
        /* 0x0: */ 1,
        /* 0x8: */ 2,
        /* 0x10: */ 3,
        /* 0x18: */ 4,
        /* 0x20: */ 0x40, // stored fp
        /* 0x28: */ 0x1003fc000 + 0x100dc4, // stored lr
        /* 0x30: */ 5,
        /* 0x38: */ 6,
        /* 0x40: */ 0x70, // stored fp
        /* 0x48: */ 0x1003fc000 + 0x12ca28, // stored lr
        /* 0x50: */ 7,
        /* 0x58: */ 8,
        /* 0x60: */ 9,
        /* 0x68: */ 10,
        /* 0x70: */ 0x0, // sentinel fp
        /* 0x78: */ 0x0, // sentinel lr
    ];
    let mut read_mem = |addr| stack.get((addr / 8) as usize).cloned().ok_or(());
    let mut regs = UnwindRegsAarch64::new(0x1003fc000 + 0xe4830, 0x10, 0x20);
    // There's a frameless function at e0d2c.
    let res = unwinder.unwind_frame(
        FrameAddress::from_instruction_pointer(0x1003fc000 + 0x1292c0),
        &mut regs,
        &mut cache,
        &mut read_mem,
    );
    assert_eq!(res, Ok(Some(0x1003fc000 + 0xe4830)));
    assert_eq!(regs.sp(), 0x10);
    let res = unwinder.unwind_frame(
        FrameAddress::from_return_address(0x1003fc000 + 0xe4830).unwrap(),
        &mut regs,
        &mut cache,
        &mut read_mem,
    );
    assert_eq!(res, Ok(Some(0x1003fc000 + 0x100dc4)));
    assert_eq!(regs.sp(), 0x30);
    assert_eq!(regs.fp(), 0x40);
    let res = unwinder.unwind_frame(
        FrameAddress::from_return_address(0x1003fc000 + 0x100dc4).unwrap(),
        &mut regs,
        &mut cache,
        &mut read_mem,
    );
    assert_eq!(res, Ok(Some(0x1003fc000 + 0x12ca28)));
    assert_eq!(regs.sp(), 0x50);
    assert_eq!(regs.fp(), 0x70);
    let res = unwinder.unwind_frame(
        FrameAddress::from_return_address(0x1003fc000 + 0x100dc4).unwrap(),
        &mut regs,
        &mut cache,
        &mut read_mem,
    );
    assert_eq!(res, Ok(None));
}

#[test]
fn test_basic_iterator() {
    let mut cache = CacheAarch64::<_>::new();
    let mut unwinder = UnwinderAarch64::new();
    common::add_object(
        &mut unwinder,
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/macos/arm64/fp/query-api"),
        0x1003fc000,
    );
    let stack = [
        /* 0x0: */ 1,
        /* 0x8: */ 2,
        /* 0x10: */ 3,
        /* 0x18: */ 4,
        /* 0x20: */ 0x40, // stored fp
        /* 0x28: */ 0x1003fc000 + 0x100dc4, // stored lr
        /* 0x30: */ 5,
        /* 0x38: */ 6,
        /* 0x40: */ 0x70, // stored fp
        /* 0x48: */ 0x1003fc000 + 0x12ca28, // stored lr
        /* 0x50: */ 7,
        /* 0x58: */ 8,
        /* 0x60: */ 9,
        /* 0x68: */ 10,
        /* 0x70: */ 0x0, // sentinel fp
        /* 0x78: */ 0x0, // sentinel lr
    ];
    let mut read_mem = |addr| stack.get((addr / 8) as usize).cloned().ok_or(());
    let frames = unwinder
        .iter_frames(
            0x1003fc000 + 0x1292c0,
            UnwindRegsAarch64::new(0x1003fc000 + 0xe4830, 0x10, 0x20),
            &mut cache,
            &mut read_mem,
        )
        .collect();
    assert_eq!(
        frames,
        Ok(vec![
            FrameAddress::from_instruction_pointer(0x1003fc000 + 0x1292c0),
            FrameAddress::from_return_address(0x1003fc000 + 0xe4830).unwrap(),
            FrameAddress::from_return_address(0x1003fc000 + 0x100dc4).unwrap(),
            FrameAddress::from_return_address(0x1003fc000 + 0x12ca28).unwrap()
        ])
    );
}

#[test]
fn test_epilogue() {
    // This test checks that we don't blindly trust the "use framepointer" __unwind_info
    // opcode. The __unwind_info does not call out function prologues or epilogues; the
    // opcode covers the entire function.
    // When the instruction pointer is in a prologue or epilogue, we need to manually look
    // at the assembly and figure out how to unwind from the current frame.
    // Only the first frame can be inside a prologue / epilogue; return addresses are always
    // inside the function body.
    //
    // In this test, we step through the epilogue of a function which uses frame pointers.
    // At some point, fp and lr have been restored but sp has not been adjust yet.
    // At that point, using fp for unwinding would skip the immediate caller.
    // Instead, we need to detect that lr already has the correct return address, and that
    // fp already has the value it should have in the caller. And we need to detect by how
    // much we still need to adjust the stack pointer.

    let mut cache = CacheAarch64::<_>::new();
    let mut unwinder = UnwinderAarch64::new();
    common::add_object(
        &mut unwinder,
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/macos/arm64/fp/query-api"),
        0x1003fc000,
    );
    let stack = [
        /* 0x0: */ 1,
        /* 0x8: */ 2,
        /* 0x10: */ 3,
        /* 0x18: */ 4,
        /* 0x20: */ 5,
        /* 0x28: */ 6,
        /* 0x30: */ 7,
        /* 0x38: */ 8,
        /* 0x40: */ 0x70, // stored fp (already restored)
        /* 0x48: */ 0x1003fc000 + 0xe4830, // stored lr (already restored)
        /* 0x50: */ 7,
        /* 0x58: */ 8,
        /* 0x60: */ 9,
        /* 0x68: */ 10,
        /* 0x70: */ 0x0, // sentinel fp
        /* 0x78: */ 0x0, // sentinel lr
    ];
    //
    // 00000001000e0d08         stp        x11, x8, [x19, #0x8]
    // 00000001000e0d0c         stp        x10, x13, [x19, #0x18]
    // 00000001000e0d10         strh       w20, [x19, #0x28]
    // 00000001000e0d14         str        x14, [x19]
    // 00000001000e0d18         ldp        fp, lr, [sp, #0x40]
    // 00000001000e0d1c         ldp        x20, x19, [sp, #0x30]
    // 00000001000e0d20         ldp        x22, x21, [sp, #0x20]
    // 00000001000e0d24         add        sp, sp, #0x50
    // 00000001000e0d28         ret
    let mut read_mem = |addr| stack.get((addr / 8) as usize).cloned().ok_or(());
    let mut do_check = |pc, mut regs| {
        let res = unwinder.unwind_frame(
            FrameAddress::from_instruction_pointer(pc),
            &mut regs,
            &mut cache,
            &mut read_mem,
        );
        // The result after unwinding should always be the same.
        assert_eq!(res, Ok(Some(0x1003fc000 + 0xe4830)));
        assert_eq!(regs.sp(), 0x50);
        assert_eq!(regs.fp(), 0x70);
    };
    // Start in the function body and then step towards the end of the function.
    // At every address, the unwinding post state should be the same.
    let mut pc = 0x1003fc000 + 0xe0d08;
    do_check(pc, UnwindRegsAarch64::new(0x1003fc000 + 0x8765, 0x0, 0x40));
    pc += 4; // step over 00000001000e0d08  stp  x11, x8, [x19, #0x8]
    do_check(pc, UnwindRegsAarch64::new(0x1003fc000 + 0x8765, 0x0, 0x40));
    pc += 4; // step over 00000001000e0d0c  stp  x10, x13, [x19, #0x18]
    do_check(pc, UnwindRegsAarch64::new(0x1003fc000 + 0x8765, 0x0, 0x40));
    pc += 4; // step over 00000001000e0d10  strh  w20, [x19, #0x28]
    do_check(pc, UnwindRegsAarch64::new(0x1003fc000 + 0x8765, 0x0, 0x40));
    pc += 4; // step over 00000001000e0d14  str  x14, [x19]
    do_check(pc, UnwindRegsAarch64::new(0x1003fc000 + 0x8765, 0x0, 0x40));
    pc += 4; // step over 00000001000e0d18  ldp  fp, lr, [sp, #0x40]
             // We just restored fp and lr. We are now firmly inside the epilogue.
    do_check(pc, UnwindRegsAarch64::new(0x1003fc000 + 0xe4830, 0x0, 0x70));
    pc += 4; // step over 00000001000e0d1c  ldp  x20, x19, [sp, #0x30]
    do_check(pc, UnwindRegsAarch64::new(0x1003fc000 + 0xe4830, 0x0, 0x70));
    pc += 4; // step over 00000001000e0d20  ldp  x22, x21, [sp, #0x20]
    do_check(pc, UnwindRegsAarch64::new(0x1003fc000 + 0xe4830, 0x0, 0x70));
    pc += 4; // step over 00000001000e0d24  add  sp, sp, #0x50
             // We've adjusted the stack pointer.
    do_check(
        pc,
        UnwindRegsAarch64::new(0x1003fc000 + 0xe4830, 0x50, 0x70),
    );
    pc += 4; // step over 00000001000e0d28  ret
    do_check(
        pc,
        UnwindRegsAarch64::new(0x1003fc000 + 0xe4830, 0x50, 0x70),
    );
}

#[test]
fn test_prologue_nofp() {
    let mut cache = CacheAarch64::<_>::new();
    let mut unwinder = UnwinderAarch64::new();
    common::add_object(
        &mut unwinder,
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/macos/arm64/nofp/rustup"),
        0,
    );
    let mut s = [
        /* 0x0: */ 1, /* 0x8: */ 2, /* 0x10: */ 3, /* 0x18: */ 4,
        /* 0x20: */ 5, /* 0x28: */ 6, /* 0x30: */ 7, /* 0x38: */ 8,
        /* 0x40: */ 9, /* 0x48: */ 10, /* 0x50: */ 11, /* 0x58: */ 12,
        /* 0x60: */ 13, /* 0x68: */ 14, /* 0x70: */ 15, /* 0x78: */ 16,
        /* 0x80: */ 17, /* 0x88: */ 18, /* 0x90: */ 19, /* 0x98: */ 20,
        /* 0xa0: */ 21, /* 0xa8: */ 22, /* 0xb0: */ 23, /* 0xb8: */ 24,
        /* 0xc0: */ 25, /* 0xc8: */ 26, /* 0xd0: */ 27, /* 0xd8: */ 28,
        /* 0xe0: */ 0x10028, /* 0xe8: */ 0x10027, /* 0xf0: */ 0x10026,
        /* 0xf8: */ 0x10025, /* 0x100: */ 0x10024, /* 0x108: */ 0x10023,
        /* 0x110: */ 0x10022, /* 0x118: */ 0x10021, /* 0x120: */ 0x10020,
        /* 0x128: */ 0x10019, /* 0x130: */ 0x10029, /* 0x138: */ 0x10030,
        /* 0x140: */ 1, /* 0x148: */ 2, /* 0x150: */ 3, /* 0x158: */ 4,
        /* 0x160: */ 5, /* 0x168: */ 6, /* 0x170: */ 7, /* 0x178: */ 8,
        /* 0x180: */ 9, /* 0x188: */ 10, /* 0x190: */ 11, /* 0x198: */ 12,
        /* 0x1a0: */ 13, /* 0x1a8: */ 14, /* 0x1b0: */ 0x1e0, // parent fp
        /* 0x1b8: */ 0x9876, // parent lr
        /* 0x1c0: */ 7, /* 0x1c8: */ 8, /* 0x1d0: */ 9, /* 0x1d8: */ 10,
        /* 0x1e0: */ 0x0, // sentinel fp
        /* 0x1e8: */ 0x0, // sentinel lr
    ];
    //
    // __ZN4toml6tokens9Tokenizer11read_string17hae8557cf3c6de096E:        // toml::tokens::Tokenizer::read_string::hae8557cf3c6de096
    // 000000010039e690         sub        sp, sp, #0x120                              ; End of unwind block (FDE at 0x10055d32c), Begin of unwind block (FDE at 0x10057ab54), CODE XREF=sub_100397004+788
    // 000000010039e694         stp        x28, x27, [sp, #0xc0]
    // 000000010039e698         stp        x26, x25, [sp, #0xd0]
    // 000000010039e69c         stp        x24, x23, [sp, #0xe0]
    // 000000010039e6a0         stp        x22, x21, [sp, #0xf0]
    // 000000010039e6a4         stp        x20, x19, [sp, #0x100]
    // 000000010039e6a8         stp        fp, lr, [sp, #0x110]
    // 000000010039e6ac         mov        x27, x5
    // 000000010039e6b0         str        x4, [sp, #0x120 + var_E8]
    // 000000010039e6b4         str        x3, [sp, #0x120 + var_108]

    // The __eh_frame info has the following to say about this function:
    //
    //   0x10039e690: CFA=reg31
    //   0x10039e6ac: CFA=reg31+288: reg19=[CFA-24], reg20=[CFA-32], reg21=[CFA-40], reg22=[CFA-48], reg23=[CFA-56], reg24=[CFA-64], reg25=[CFA-72], reg26=[CFA-80], reg27=[CFA-88], reg28=[CFA-96], reg29=[CFA-16], reg30=[CFA-8]
    //
    // This is incomplete; from 39e694 to 39e6ac it is missing the stack pointer adjustment by 0x120.
    // Our prologue analysis needs to fix this up.

    let mut do_check = |pc, mut regs, stack: &[u64]| {
        let res = unwinder.unwind_frame(
            FrameAddress::from_instruction_pointer(pc),
            &mut regs,
            &mut cache,
            &mut |addr| stack.get((addr / 8) as usize).cloned().ok_or(()),
        );
        // The result after unwinding should always be the same.
        assert_eq!(res, Ok(Some(0xe4830)));
        assert_eq!(regs.sp(), 0x140);
        assert_eq!(regs.fp(), 0x1e0);
    };
    // Start at the function start and then step towards the function body.
    // At every address, the unwinding post state should be the same.
    let mut pc = 0x39e690;
    do_check(pc, UnwindRegsAarch64::new(0xe4830, 0x140, 0x1e0), &s);
    pc += 4; // step over 000000010039e690 sub  sp, sp, #0x120
    do_check(pc, UnwindRegsAarch64::new(0xe4830, 0x20, 0x1e0), &s);
    pc += 4; // step over 000000010039e694 stp  x28, x27, [sp, #0xc0]
    do_check(pc, UnwindRegsAarch64::new(0xe4830, 0x20, 0x1e0), &s);
    pc += 4; // step over 000000010039e698 stp  x26, x25, [sp, #0xd0]
    do_check(pc, UnwindRegsAarch64::new(0xe4830, 0x20, 0x1e0), &s);
    pc += 4; // step over 000000010039e69c stp  x24, x23, [sp, #0xe0]
    do_check(pc, UnwindRegsAarch64::new(0xe4830, 0x20, 0x1e0), &s);
    pc += 4; // step over 000000010039e6a0 stp  x22, x21, [sp, #0xf0]
    do_check(pc, UnwindRegsAarch64::new(0xe4830, 0x20, 0x1e0), &s);
    pc += 4; // step over 000000010039e6a4 stp  x20, x19, [sp, #0x100]
    do_check(pc, UnwindRegsAarch64::new(0xe4830, 0x20, 0x1e0), &s);
    pc += 4; // step over 000000010039e6a8 stp  fp, lr, [sp, #0x110]
    s[0x130 / 8] = 0x1e0;
    s[0x138 / 8] = 0xe4830;
    do_check(pc, UnwindRegsAarch64::new(0xe4830, 0x20, 0x1e0), &s);
    pc += 4; // step over 000000010039e6ac mov  x27, x5
    do_check(pc, UnwindRegsAarch64::new(0xe4830, 0x20, 0x1e0), &s);
    pc += 4; // step over 000000010039e6b0 str  x4, [sp, #0x120 + var_E8]
    do_check(pc, UnwindRegsAarch64::new(0xe4830, 0x20, 0x1e0), &s);
    pc += 4; // step over 000000010039e6b4 str  x3, [sp, #0x120 + var_108]
    do_check(pc, UnwindRegsAarch64::new(0xe4830, 0x20, 0x1e0), &s);
}

fn make_stack(size_in_bytes: usize) -> Vec<u64> {
    let ptr_count = size_in_bytes / 8;
    (0..ptr_count).map(|i| 0xf000 + i as u64 * 8).collect()
}

// This test checks that we can detect prologues even if we don't know
// at which address the function starts.
//
// We need to do prologue analysis for a function which starts at cb130.
// However, there is no entry in the __unwind_info at cb130. Instead, we have one entry
// which spans all the way from ca858 to cb580:
//   0x000ca858: CFA=reg29+16: reg29=[CFA-16], reg30=[CFA-8], reg19=[CFA-32], reg20=[CFA-40]
//   0x000cb580: CFA=reg31
// This is because __unwind_info collapsed consecutive functions with the same unwind info
// into one entry.
//
// 00000001000ca708 t __ZN5alloc7raw_vec11finish_grow17hf3aa5d5c8bbce1e0E
// 00000001000ca858 t __ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$16reserve_for_push17h001c5c98cb44bce3E
// 00000001000ca918 t __ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$16reserve_for_push17h09cdb89db29ebbaeE
// 00000001000ca9bc t __ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$16reserve_for_push17h0a0847e6c710a012E
// 00000001000caa7c t __ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$16reserve_for_push17h0dd5923e580e54d2E
// 00000001000cab20 t __ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$16reserve_for_push17h0ee4b9c21168dc65E
// 00000001000cabe0 t __ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$16reserve_for_push17h12b63212fac3395bE
// 00000001000cac84 t __ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$16reserve_for_push17h22085d3419271d76E
// 00000001000cad28 t __ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$16reserve_for_push17h35e704022e6cbb3eE
// 00000001000cadcc t __ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$16reserve_for_push17h3bd4045812016c5fE
// 00000001000cae8c t __ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$16reserve_for_push17h52624263b5943b13E
// 00000001000caf14 t __ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$16reserve_for_push17h6ecd6fa80dd63df9E
// 00000001000cafd0 t __ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$16reserve_for_push17h7742b849959e0fbbE
// 00000001000cb070 t __ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$16reserve_for_push17h83aed742a9080921E
// 00000001000cb130 t __ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$16reserve_for_push17h873f2ca1234a16a6E
// 00000001000cb1f8 t __ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$16reserve_for_push17h899ea1b95c67f66fE
// 00000001000cb2b8 t __ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$16reserve_for_push17haa095bd6eeb2e7f9E
// 00000001000cb35c t __ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$16reserve_for_push17hb89c849137330384E
// 00000001000cb41c t __ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$16reserve_for_push17hf1654d15d708534fE
// 00000001000cb4dc t __ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$16reserve_for_push17hf6c61180373a7270E
// 00000001000cb580 t __ZN77_$LT$alloc..raw_vec..RawVec$LT$T$C$A$GT$$u20$as$u20$core..ops..drop..Drop$GT$4drop17h0eed06c0f045ac6cE
//
// So we can't use the unwind info entry's address as the function start address.
// Instead, we need to detect the beginning of the prologue based on which
// instructions we encounter.
#[test]
fn test_prologue_fp() {
    let mut cache = CacheAarch64::<_>::new();
    let mut unwinder = UnwinderAarch64::new();
    common::add_object(
        &mut unwinder,
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/macos/arm64/fp/query-api"),
        0,
    );
    // ...
    // 00000001000cb128  ldr  x0, [sp, #0x330 + var_320]
    // 00000001000cb12c  bl  __ZN5alloc5alloc18handle_alloc_error17h8501b3266a472769E
    //
    // __ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$16reserve_for_push17h873f2ca1234a16a6E:
    // 00000001000cb130  sub  sp, sp, #0x40
    // 00000001000cb134  stp  x20, x19, [sp, #0x20]
    // 00000001000cb138  stp  fp, lr, [sp, #0x30]
    // 00000001000cb13c  add  fp, sp, #0x30
    // 00000001000cb140  adds  x8, x1, #0x1

    let mut do_check = |pc, mut regs, stack: &[u64]| {
        let res = unwinder.unwind_frame(
            FrameAddress::from_instruction_pointer(pc),
            &mut regs,
            &mut cache,
            &mut |addr| stack.get((addr / 8) as usize).cloned().ok_or(()),
        );
        // The result after unwinding should always be the same.
        assert_eq!(res, Ok(Some(0x10030)));
        assert_eq!(regs.sp(), 0x140);
        assert_eq!(regs.fp(), 0x10029);
    };
    // Start at the function start and then step towards the function body.
    // At every address, the unwinding post state should be the same.
    let mut s = make_stack(0x140);
    let mut pc = 0xcb130;
    do_check(pc, UnwindRegsAarch64::new(0x10030, 0x140, 0x10029), &s);
    pc += 4; // step over 00000001000cb130  sub  sp, sp, #0x40
    do_check(pc, UnwindRegsAarch64::new(0x10030, 0x100, 0x10029), &s);
    pc += 4; // step over 00000001000cb134  stp  x20, x19, [sp, #0x20]
    do_check(pc, UnwindRegsAarch64::new(0x10030, 0x100, 0x10029), &s);
    pc += 4; // step over 00000001000cb138  stp  fp, lr, [sp, #0x30]
    s[0x130 / 8] = 0x10029;
    s[0x138 / 8] = 0x10030;
    do_check(pc, UnwindRegsAarch64::new(0x10030, 0x100, 0x10029), &s);
    pc += 4; // step over 00000001000cb13c  add  fp, sp, #0x30
    do_check(pc, UnwindRegsAarch64::new(0x10030, 0x100, 0x130), &s);
    pc += 4; // step over 00000001000cb140  adds  x8, x1, #0x1
    do_check(pc, UnwindRegsAarch64::new(0x10030, 0x100, 0x130), &s);
}

#[test]
fn test_prologue_fp_2() {
    let mut cache = CacheAarch64::<_>::new();
    let mut unwinder = UnwinderAarch64::new();
    common::add_object(
        &mut unwinder,
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/macos/arm64/fp/query-api"),
        0,
    );
    let stack = make_stack(0x100);
    // __ZN4core3ptr68drop_in_place$LT$profiler_get_symbols..shared..CandidatePathInfo$GT$17hd2d591af2d08cebdE:        // core::ptr::drop_in_place$LT$profiler_get_symbols..shared..CandidatePathInfo$GT$::hd2d591af2d08cebd
    // 00000001000c98c8         stp        x20, x19, [sp, #-0x20]!
    // 00000001000c98cc         stp        fp, lr, [sp, #0x10]
    // 00000001000c98d0         add        fp, sp, #0x10
    // 00000001000c98d4         mov        x19, x0
    let mut regs = UnwindRegsAarch64::new(0x10030, 0x60, 0x10029);
    let res = unwinder.unwind_frame(
        FrameAddress::from_instruction_pointer(0xc98cc),
        &mut regs,
        &mut cache,
        &mut |addr| stack.get((addr / 8) as usize).cloned().ok_or(()),
    );
    assert_eq!(res, Ok(Some(0x10030)));
    assert_eq!(regs.sp(), 0x80);
    assert_eq!(regs.fp(), 0x10029);
}

#[test]
fn test_prologue_epilogue_x86_64_fp() {
    let mut cache = CacheX86_64::<_>::new();
    let mut unwinder = UnwinderX86_64::new();
    common::add_object(
        &mut unwinder,
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/macos/x86_64/fp/query-api"),
        0,
    );
    // ...
    // 6e63d  mov  rdi, qword [rbp+var_28]
    // 6e641  call  __ZN5alloc5alloc18handle_alloc_error17hb4f515095d9ee4afE
    // 6e646  nop  word [cs:rax+rax]
    //
    // __ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$16reserve_for_push17h20f84d285b129f0dE:
    // 6e650  push  rbp
    // 6e651  mov  rbp, rsp
    // 6e654  push  r15
    // 6e656  push  r14
    // 6e658  push  rbx
    // 6e659  sub  rsp, 0x18
    // 6e65d  inc  rsi
    // 6e660  je  loc_10006e6e7
    // 6e666  mov  r14, rdi
    // 6e669  mov  rcx, qword [rdi+8]
    // ...
    // 6e6c8  mov  rax, qword [rbp+var_28]
    // 6e6cc  mov  qword [r14], rax
    // 6e6cf  mov  qword [r14+8], r15
    // 6e6d3  add  rsp, 0x18
    // 6e6d7  pop  rbx
    // 6e6d8  pop  r14
    // 6e6da  pop  r15
    // 6e6dc  pop  rbp
    // 6e6dd  ret
    // 6e6de  mov  rsi, qword [rbp+var_20]
    // 6e6e2  test  rsi, rsi
    // ...

    let mut do_check = |pc, mut regs, stack: &[u64]| {
        let res = unwinder.unwind_frame(
            FrameAddress::from_instruction_pointer(pc),
            &mut regs,
            &mut cache,
            &mut |addr| stack.get((addr / 8) as usize).cloned().ok_or(()),
        );
        // The result after unwinding should always be the same.
        assert_eq!(res, Ok(Some(0x12345)));
        assert_eq!(regs.sp(), 0x140);
        assert_eq!(regs.bp(), 0x160);
    };
    // Start at the function start and then step towards the function body.
    // At every address, the unwinding post state should be the same.
    let mut s = make_stack(0x160);
    s[0x138 / 8] = 0x12345; // put return address on the stack
    let mut pc = 0x6e650;
    do_check(pc, UnwindRegsX86_64::new(pc, 0x138, 0x160), &s);
    pc = 0x6e651; // step over 6e650  push  rbp
    s[0x130 / 8] = 0x160;
    do_check(pc, UnwindRegsX86_64::new(pc, 0x130, 0x160), &s);
    pc = 0x6e654; // step over 6e651  mov  rbp, rsp
    do_check(pc, UnwindRegsX86_64::new(pc, 0x130, 0x130), &s);
    pc = 0x6e656; // step over 6e654  push  r15
    do_check(pc, UnwindRegsX86_64::new(pc, 0x128, 0x130), &s);
    pc = 0x6e658; // step over 6e656  push  r14
    do_check(pc, UnwindRegsX86_64::new(pc, 0x120, 0x130), &s);
    pc = 0x6e659; // step over 6e658  push  rbx
    do_check(pc, UnwindRegsX86_64::new(pc, 0x118, 0x130), &s);
    pc = 0x6e65d; // step over 6e659  sub  rsp, 0x18
    do_check(pc, UnwindRegsX86_64::new(pc, 0x100, 0x130), &s);
    pc = 0x6e660; // step over 6e65d  inc  rsi
    do_check(pc, UnwindRegsX86_64::new(pc, 0x100, 0x130), &s);
    pc = 0x6e666; // step over 6e660  je  loc_10006e6e7
    do_check(pc, UnwindRegsX86_64::new(pc, 0x100, 0x130), &s);
    pc = 0x6e669; // step over 6e666  mov  r14, rdi
    do_check(pc, UnwindRegsX86_64::new(pc, 0x100, 0x130), &s);

    // We are now firmly inside the body of the function.

    // Skip ahead, close to an epilogue.
    pc = 0x6e6c8;
    do_check(pc, UnwindRegsX86_64::new(pc, 0x100, 0x130), &s);
    pc = 0x6e6cc; // step over 6e6c8  mov  rax, qword [rbp+var_28]
    do_check(pc, UnwindRegsX86_64::new(pc, 0x100, 0x130), &s);
    pc = 0x6e6cf; // step over 6e6cc  mov  qword [r14], rax
    do_check(pc, UnwindRegsX86_64::new(pc, 0x100, 0x130), &s);
    pc = 0x6e6d3; // step over 6e6cf  mov  qword [r14+8], r15
    do_check(pc, UnwindRegsX86_64::new(pc, 0x100, 0x130), &s);
    pc = 0x6e6d7; // step over 6e6d3  add  rsp, 0x18
    do_check(pc, UnwindRegsX86_64::new(pc, 0x118, 0x130), &s);
    pc = 0x6e6d8; // step over 6e6d7  pop  rbx
    do_check(pc, UnwindRegsX86_64::new(pc, 0x120, 0x130), &s);
    pc = 0x6e6da; // step over 6e6d8  pop  r14
    do_check(pc, UnwindRegsX86_64::new(pc, 0x128, 0x130), &s);
    pc = 0x6e6dc; // step over 6e6da  pop  r15
    do_check(pc, UnwindRegsX86_64::new(pc, 0x130, 0x130), &s);
    pc = 0x6e6dd; // step over 6e6dc  pop  rbp
    do_check(pc, UnwindRegsX86_64::new(pc, 0x138, 0x160), &s);
    pc = 0x6e6de; // step over 6e6dd  ret

    // Now we are in a different basic block, back in the body of the function.
    do_check(pc, UnwindRegsX86_64::new(pc, 0x100, 0x130), &s);
    pc = 0x6e6e2; // step over 6e6de  mov  rsi, qword [rbp+var_20]
    do_check(pc, UnwindRegsX86_64::new(pc, 0x100, 0x130), &s);
}

#[test]
fn test_prologue_epilogue_tail_call_x86_64_nofp() {
    let mut cache = CacheX86_64::<_>::new();
    let mut unwinder = UnwinderX86_64::new();
    common::add_object(
        &mut unwinder,
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/macos/x86_64/nofp/libmozglue.dylib"),
        0,
    );

    // sub_1a20:
    // 1a20  push  r14
    // 1a22  push  rbx
    // 1a23  push  rax
    // 1a24  mov  rbx, rsi
    // 1a27  mov  r14, rdi
    // 1a2a  mov  rdi, rsi
    // 1a2d  call  _malloc_usable_size
    // 1a32  test  rax, rax
    // 1a35  je  loc_1a46
    // 1a37  mov  rdi, rbx
    // 1a3a  add  rsp, 0x8
    // 1a3e  pop  rbx
    // 1a3f  pop  r14
    // 1a41  jmp  _free
    // 1a46  mov  rdi, r14
    // 1a49  mov  rsi, rbx
    // 1a4c  add  rsp, 0x8
    // 1a50  pop  rbx
    // 1a51  pop  r14
    // 1a53  jmp  sub_2af90+16
    // 1a58  align  32

    let mut do_check = |pc, mut regs, stack: &[u64]| {
        let res = unwinder.unwind_frame(
            FrameAddress::from_instruction_pointer(pc),
            &mut regs,
            &mut cache,
            &mut |addr| stack.get((addr / 8) as usize).cloned().ok_or(()),
        );
        // The result after unwinding should always be the same.
        assert_eq!(res, Ok(Some(0x12345)));
        assert_eq!(regs.sp(), 0x100);
        assert_eq!(regs.bp(), 0x120);
    };
    // Start at the function start and then step towards the function body.
    // At every address, the unwinding post state should be the same.
    let mut s = make_stack(0x160);
    s[0xf8 / 8] = 0x12345; // put return address on the stack
    let mut pc = 0x1a20;
    do_check(pc, UnwindRegsX86_64::new(pc, 0xf8, 0x120), &s);
    pc = 0x1a22; // step over 1a20  push  r14
    do_check(pc, UnwindRegsX86_64::new(pc, 0xf0, 0x120), &s);
    pc = 0x1a23; // step over 1a22  push  rbx
    do_check(pc, UnwindRegsX86_64::new(pc, 0xe8, 0x120), &s);
    pc = 0x1a24; // step over 1a23  push  rax
    do_check(pc, UnwindRegsX86_64::new(pc, 0xe0, 0x120), &s);
    pc = 0x1a27; // step over 1a24  mov  rbx, rsi
    do_check(pc, UnwindRegsX86_64::new(pc, 0xe0, 0x120), &s);
    pc = 0x1a2a; // step over 1a27  mov  r14, rdi
    do_check(pc, UnwindRegsX86_64::new(pc, 0xe0, 0x120), &s);
    pc = 0x1a2d; // step over 1a2a  mov  rdi, rsi
    do_check(pc, UnwindRegsX86_64::new(pc, 0xe0, 0x120), &s);
    pc = 0x1a32; // step over 1a2d  call  _malloc_usable_size
    do_check(pc, UnwindRegsX86_64::new(pc, 0xe0, 0x120), &s);
    pc = 0x1a35; // step over 1a32  test  rax, rax
    do_check(pc, UnwindRegsX86_64::new(pc, 0xe0, 0x120), &s);
    pc = 0x1a37; // step over 1a35  je  loc_1a46
    do_check(pc, UnwindRegsX86_64::new(pc, 0xe0, 0x120), &s);
    pc = 0x1a3a; // step over 1a37  mov  rdi, rbx
    do_check(pc, UnwindRegsX86_64::new(pc, 0xe0, 0x120), &s);
    pc = 0x1a3e; // step over 1a3a  add  rsp, 0x8
    do_check(pc, UnwindRegsX86_64::new(pc, 0xe8, 0x120), &s);
    pc = 0x1a3f; // step over 1a3e  pop  rbx
    do_check(pc, UnwindRegsX86_64::new(pc, 0xf0, 0x120), &s);
    pc = 0x1a41; // step over 1a3f  pop  r14
    do_check(pc, UnwindRegsX86_64::new(pc, 0xf8, 0x120), &s);
    pc = 0x1a46; // step over 1a41  jmp  _free
    do_check(pc, UnwindRegsX86_64::new(pc, 0xe0, 0x120), &s);
    pc = 0x1a49; // step over 1a46  mov  rdi, r14
    do_check(pc, UnwindRegsX86_64::new(pc, 0xe0, 0x120), &s);
    pc = 0x1a4c; // step over 1a49  mov  rsi, rbx
    do_check(pc, UnwindRegsX86_64::new(pc, 0xe0, 0x120), &s);
    pc = 0x1a50; // step over 1a4c  add  rsp, 0x8
    do_check(pc, UnwindRegsX86_64::new(pc, 0xe8, 0x120), &s);
    pc = 0x1a51; // step over 1a50  pop  rbx
    do_check(pc, UnwindRegsX86_64::new(pc, 0xf0, 0x120), &s);
    pc = 0x1a53; // step over 1a51  pop  r14
    do_check(pc, UnwindRegsX86_64::new(pc, 0xf8, 0x120), &s);
    // 1a53  jmp  sub_2af90+16
}

#[test]
fn test_prologue_epilogue_rbp_x86_64_nofp() {
    let mut cache = CacheX86_64::<_>::new();
    let mut unwinder = UnwinderX86_64::new();
    common::add_object(
        &mut unwinder,
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/macos/x86_64/nofp/libmozglue.dylib"),
        0,
    );

    // sub_e030:
    // e030  push  rbp
    // e031  push  r15
    // e033  push  r14
    // e035  push  rbx
    // e036  sub  rsp, 0x18
    // e03a  mov  rax, qword [___stack_chk_guard_76060]
    // e041  mov  rax, qword [rax]
    // e044  mov  qword [rsp+0x38+var_28], rax
    // e049  mov  eax, dword [dword_772d0]
    // e04f  mov  bl, 0x1
    // e051  test  eax, eax
    // e053  je  loc_e078
    // e055  mov  rax, qword [___stack_chk_guard_76060]
    // e05c  mov  rax, qword [rax]
    // e05f  cmp  rax, qword [rsp+0x38+var_28]
    // e064  jne  loc_e073
    // e066  mov  eax, ebx
    // e068  add  rsp, 0x18
    // e06c  pop  rbx
    // e06d  pop  r14
    // e06f  pop  r15
    // e071  pop  rbp
    // e072  ret
    // e073  call  imp___stubs____stack_chk_fail
    // e078  lea  rdi, qword [byte_772b0+8]
    // ...

    let mut do_check = |pc, mut regs, stack: &[u64]| {
        let res = unwinder.unwind_frame(
            FrameAddress::from_instruction_pointer(pc),
            &mut regs,
            &mut cache,
            &mut |addr| stack.get((addr / 8) as usize).cloned().ok_or(()),
        );
        // The result after unwinding should always be the same.
        assert_eq!(res, Ok(Some(0x12345)));
        assert_eq!(regs.sp(), 0x100);
        assert_eq!(regs.bp(), 0x120);
    };

    // Start at the function start and then step towards the function body.
    // At every address, the unwinding post state should be the same.
    let mut s = make_stack(0x160);
    s[0xf8 / 8] = 0x12345; // put return address on the stack
    let mut pc = 0x1a20;
    do_check(pc, UnwindRegsX86_64::new(pc, 0xf8, 0x120), &s);
    pc = 0xe031; // step over e030  push  rbp
    s[0xf0 / 8] = 0x120;
    do_check(pc, UnwindRegsX86_64::new(pc, 0xf0, 0x120), &s);
    pc = 0xe033; // step over e031  push  r15
    do_check(pc, UnwindRegsX86_64::new(pc, 0xe8, 0x120), &s);
    pc = 0xe035; // step over e033  push  r14
    do_check(pc, UnwindRegsX86_64::new(pc, 0xe0, 0x120), &s);
    pc = 0xe036; // step over e035  push  rbx
    do_check(pc, UnwindRegsX86_64::new(pc, 0xd8, 0x120), &s);
    pc = 0xe03a; // step over e036  sub  rsp, 0x18
    do_check(pc, UnwindRegsX86_64::new(pc, 0xc0, 0x120), &s);
    pc = 0xe041; // step over e03a  mov  rax, qword [___stack_chk_guard_76060]
    do_check(pc, UnwindRegsX86_64::new(pc, 0xc0, 0x120), &s);
    pc = 0xe044; // step over e041  mov  rax, qword [rax]
    do_check(pc, UnwindRegsX86_64::new(pc, 0xc0, 0x120), &s);
    pc = 0xe049; // step over e044  mov  qword [rsp+0x38+var_28], rax
    do_check(pc, UnwindRegsX86_64::new(pc, 0xc0, 0x120), &s);
    pc = 0xe04f; // step over e049  mov  eax, dword [dword_772d0]
    do_check(pc, UnwindRegsX86_64::new(pc, 0xc0, 0x120), &s);
    pc = 0xe051; // step over e04f  mov  bl, 0x1
    do_check(pc, UnwindRegsX86_64::new(pc, 0xc0, 0x120), &s);
    pc = 0xe053; // step over e051  test  eax, eax
    do_check(pc, UnwindRegsX86_64::new(pc, 0xc0, 0x120), &s);
    pc = 0xe055; // step over e053  je  loc_e078

    // 0xe055 is also a jump target from somewhere inside the rest of the function.
    // The rbp register may have been modified. Use a different value to test that
    // we are restoring it properly.
    do_check(pc, UnwindRegsX86_64::new(pc, 0xc0, 0x999), &s);
    pc = 0xe05c; // step over e055  mov  rax, qword [___stack_chk_guard_76060]
    do_check(pc, UnwindRegsX86_64::new(pc, 0xc0, 0x999), &s);
    pc = 0xe05f; // step over e05c  mov  rax, qword [rax]
    do_check(pc, UnwindRegsX86_64::new(pc, 0xc0, 0x999), &s);
    pc = 0xe064; // step over e05f  cmp  rax, qword [rsp+0x38+var_28]
    do_check(pc, UnwindRegsX86_64::new(pc, 0xc0, 0x999), &s);
    pc = 0xe066; // step over e064  jne  loc_e073
    do_check(pc, UnwindRegsX86_64::new(pc, 0xc0, 0x999), &s);
    pc = 0xe068; // step over e066  mov  eax, ebx
    do_check(pc, UnwindRegsX86_64::new(pc, 0xc0, 0x999), &s);
    pc = 0xe06c; // step over e068  add  rsp, 0x18
    do_check(pc, UnwindRegsX86_64::new(pc, 0xd8, 0x999), &s);
    pc = 0xe06d; // step over e06c  pop  rbx
    do_check(pc, UnwindRegsX86_64::new(pc, 0xe0, 0x999), &s);
    pc = 0xe06f; // step over e06d  pop  r14
    do_check(pc, UnwindRegsX86_64::new(pc, 0xe8, 0x999), &s);
    pc = 0xe071; // step over e06f  pop  r15
    do_check(pc, UnwindRegsX86_64::new(pc, 0xf0, 0x999), &s);
    pc = 0xe072; // step over e071  pop  rbp
                 // Bp has been restored.
    do_check(pc, UnwindRegsX86_64::new(pc, 0xf8, 0x120), &s);
    pc = 0xe073; // step over e072  ret

    // We are now in a different basic block, which is part of the body
    // of the function.
    do_check(pc, UnwindRegsX86_64::new(pc, 0xc0, 0x999), &s);
    pc = 0xe078; // step over e073  call  imp___stubs____stack_chk_fail
    do_check(pc, UnwindRegsX86_64::new(pc, 0xc0, 0x999), &s);
    // e078  lea  rdi, qword [byte_772b0+8]
}
