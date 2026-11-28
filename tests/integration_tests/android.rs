use std::path::Path;

use framehop::aarch64::*;
use framehop::{ExplicitModuleSectionInfo, FrameAddress, Module, Unwinder};
use gimli::write::{
    Address, CallFrameInstruction, CommonInformationEntry, DebugFrame, EndianVec, Expression,
    FrameDescriptionEntry, FrameTable,
};
use gimli::{AArch64, Encoding, Format, LittleEndian, Register};

const MODULE_BASE: u64 = 0x10000;

/// ART's tag for the dex pc of interpreter frames.
const DEX1: u32 = u32::from_le_bytes(*b"DEX1");

/// The dex pc of the frame which the last step unwound, as samply finds it.
macro_rules! last_dex_pc {
    ($iter:expr) => {
        $iter
            .last_val_expression_values()
            .find(|v| v.tag == Some(DEX1))
            .map(|v| v.value)
    };
}

/// `DW_OP_const4u "DEX1"; DW_OP_drop; DW_OP_bregx <reg> <offset>`
fn dex_marker_bregx(reg: u8, offset: i8) -> Expression {
    let mut bytes = vec![0x0c, b'D', b'E', b'X', b'1', 0x13, 0x92, reg];
    bytes.push(offset as u8 & 0x7f);
    Expression::raw(bytes)
}

/// `DW_OP_const4u "DEX1"; DW_OP_drop; DW_OP_breg<reg> <offset>`
fn dex_marker_breg(reg: u8, offset: i8) -> Expression {
    let bytes = vec![
        0x0c,
        b'D',
        b'E',
        b'X',
        b'1',
        0x13,
        0x70 + reg,
        offset as u8 & 0x7f,
    ];
    Expression::raw(bytes)
}

/// A function: start svma, length, and (offset, instruction) pairs.
type Func = (u64, u32, Vec<(u32, CallFrameInstruction)>);

fn frame_table(funcs: Vec<Func>) -> FrameTable {
    let encoding = Encoding {
        format: Format::Dwarf32,
        version: 1,
        address_size: 8,
    };
    let mut table = FrameTable::default();
    let mut cie = CommonInformationEntry::new(encoding, 4, -8, AArch64::X30);
    cie.add_instruction(CallFrameInstruction::Cfa(AArch64::SP, 0));
    let cie_id = table.add_cie(cie);
    for (start, len, instructions) in funcs {
        let mut fde = FrameDescriptionEntry::new(Address::Constant(start), len);
        for (offset, instruction) in instructions {
            fde.add_instruction(offset, instruction);
        }
        table.add_fde(cie_id, fde);
    }
    table
}

fn debug_frame_bytes(funcs: Vec<Func>) -> Vec<u8> {
    let mut debug_frame = DebugFrame(EndianVec::new(LittleEndian));
    frame_table(funcs)
        .write_debug_frame(&mut debug_frame)
        .unwrap();
    debug_frame.0.into_vec()
}

fn reg(n: u16) -> Register {
    Register(n)
}

/// "inner": a regular function which saves fp, lr, x22 and x19.
fn func_inner() -> Func {
    use CallFrameInstruction::*;
    (
        0x1000,
        0x100,
        vec![
            (4, CfaOffset(32)),
            (4, Offset(AArch64::X29, -32)),
            (4, Offset(AArch64::X30, -24)),
            (4, Offset(reg(22), -16)),
            (4, Offset(reg(19), -8)),
        ],
    )
}

/// "nterp": CFA = *(x25 - 8) + 0x40, saves fp, lr, x22, x25, and has a DEX1 marker
/// referring to x22 (bregx form).
fn func_nterp() -> Func {
    use CallFrameInstruction::*;
    (
        0x2000,
        0x100,
        vec![
            (
                4,
                CfaExpression(gimli::write::Expression::raw(vec![
                    0x92, 25, 0x78, // DW_OP_bregx x25 -8
                    0x06, // DW_OP_deref
                    0x23, 0x40, // DW_OP_plus_uconst 0x40
                ])),
            ),
            (4, Offset(AArch64::X29, -16)),
            (4, Offset(AArch64::X30, -8)),
            (4, Offset(reg(22), -24)),
            (4, Offset(reg(25), -32)),
            (8, ValExpression(reg(0), dex_marker_bregx(22, 0))),
        ],
    )
}

/// "switch": like ExecuteSwitchImplAsm. CFA = sp + 16, saves x19 and lr, DEX1 marker
/// referring to x19 (short breg form).
fn func_switch() -> Func {
    use CallFrameInstruction::*;
    (
        0x3000,
        0x100,
        vec![
            (4, CfaOffset(16)),
            (4, Offset(reg(19), -16)),
            (4, Offset(AArch64::X30, -8)),
            (8, ValExpression(reg(0), dex_marker_breg(19, 0))),
        ],
    )
}

/// "generic": CFA = x23 + 0x20, which is not cacheable. Saves fp, lr, x22, and
/// has a DEX1 marker referring to x22 + 2.
fn func_generic() -> Func {
    use CallFrameInstruction::*;
    (
        0x4000,
        0x100,
        vec![
            (4, Cfa(reg(23), 0x20)),
            (4, Offset(AArch64::X29, -16)),
            (4, Offset(AArch64::X30, -8)),
            (4, Offset(reg(22), -24)),
            (4, ValExpression(reg(0), dex_marker_bregx(22, 2))),
        ],
    )
}

fn all_funcs() -> Vec<Func> {
    vec![func_inner(), func_nterp(), func_switch(), func_generic()]
}

fn add_module(
    unwinder: &mut UnwinderAarch64<Vec<u8>>,
    eh_frame: Option<Vec<u8>>,
    debug_frame: Option<Vec<u8>>,
) {
    unwinder.add_module(Module::new(
        "synthetic".to_string(),
        MODULE_BASE..MODULE_BASE + 0x10000,
        MODULE_BASE,
        ExplicitModuleSectionInfo {
            base_svma: 0,
            text_svma: Some(0x1000..0x5000),
            eh_frame_svma: eh_frame.as_ref().map(|d| 0x8000..0x8000 + d.len() as u64),
            eh_frame,
            debug_frame,
            ..Default::default()
        },
    ));
}

fn stack_reader(stack: &[(u64, u64)]) -> impl FnMut(u64) -> Result<u64, ()> + '_ {
    move |addr| {
        stack
            .iter()
            .find(|(a, _)| *a == addr)
            .map(|(_, v)| *v)
            .ok_or(())
    }
}

/// Stack for: inner (pc 0x1010, first frame) <- nterp (0x2010) <- switch (0x3010) <- end.
fn inner_nterp_switch_stack() -> Vec<(u64, u64)> {
    vec![
        // inner frame, sp = 0x100, CFA = 0x120
        (0x100, 0x5555),               // caller fp
        (0x108, MODULE_BASE + 0x2010), // return address into nterp
        (0x110, 0xdec0de),             // saved x22 (nterp's dex pc)
        (0x118, 0x1919),               // saved x19
        (0x1f8, 0x180),                // *(x25 - 8), x25 = 0x200
        // nterp frame, CFA = 0x180 + 0x40 = 0x1c0
        (0x1a0, 0x2525),               // saved x25
        (0x1a8, 0x2222),               // saved x22
        (0x1b0, 0x6666),               // caller fp
        (0x1b8, MODULE_BASE + 0x3010), // return address into switch
        // switch frame, CFA = 0x1d0
        (0x1c0, 0x1900), // saved x19
        (0x1c8, 0),      // return address: end of stack
    ]
}

fn sampled_regs(with_callee_saved: bool) -> UnwindRegsAarch64 {
    let mut regs = UnwindRegsAarch64::new(0xffff, 0x100, 0x4444);
    if with_callee_saved {
        let mut values = [0xbad; 10];
        values[25 - 19] = 0x200;
        regs.set_callee_saved_from_sample(values);
    }
    regs
}

struct Frame {
    address: FrameAddress,
    dex_pc_of_previous: Option<u64>,
    x19: Option<u64>,
    x22: Option<u64>,
    x25: Option<u64>,
}

fn unwind(
    unwinder: &UnwinderAarch64<Vec<u8>>,
    cache: &mut CacheAarch64,
    pc: u64,
    regs: UnwindRegsAarch64,
    stack: &[(u64, u64)],
) -> (Vec<Frame>, Result<(), framehop::Error>) {
    let mut read_stack = stack_reader(stack);
    let mut iter = unwinder.iter_frames(pc, regs, cache, &mut read_stack);
    let mut frames = Vec::new();
    let result = loop {
        match iter.next() {
            Ok(Some(address)) => frames.push(Frame {
                address,
                dex_pc_of_previous: last_dex_pc!(iter),
                x19: iter.regs().callee_saved(19),
                x22: iter.regs().callee_saved(22),
                x25: iter.regs().callee_saved(25),
            }),
            Ok(None) => break Ok(()),
            Err(e) => break Err(e),
        }
    };
    (frames, result)
}

fn check_inner_nterp_switch(frames: &[Frame], result: Result<(), framehop::Error>) {
    assert_eq!(result, Ok(()));
    assert_eq!(frames.len(), 3);
    assert_eq!(
        frames[0].address,
        FrameAddress::from_instruction_pointer(MODULE_BASE + 0x1010)
    );
    assert_eq!(frames[0].dex_pc_of_previous, None);
    assert_eq!(frames[0].x22, Some(0xbad));

    // Stepped out of "inner": x22 and x19 were restored from inner's save slots,
    // x25 is unchanged.
    assert_eq!(
        frames[1].address,
        FrameAddress::from_return_address(MODULE_BASE + 0x2010).unwrap()
    );
    assert_eq!(frames[1].dex_pc_of_previous, None);
    assert_eq!(frames[1].x19, Some(0x1919));
    assert_eq!(frames[1].x22, Some(0xdec0de));
    assert_eq!(frames[1].x25, Some(0x200));

    // Stepped out of "nterp": its dex pc is its x22 value.
    assert_eq!(
        frames[2].address,
        FrameAddress::from_return_address(MODULE_BASE + 0x3010).unwrap()
    );
    assert_eq!(frames[2].dex_pc_of_previous, Some(0xdec0de));
    assert_eq!(frames[2].x19, Some(0x1919));
    assert_eq!(frames[2].x22, Some(0x2222));
    assert_eq!(frames[2].x25, Some(0x2525));
}

#[test]
fn test_callee_saved_and_dex_pc_cache_miss_and_hit() {
    let mut unwinder = UnwinderAarch64::new();
    add_module(&mut unwinder, None, Some(debug_frame_bytes(all_funcs())));
    let mut cache = CacheAarch64::new();
    let stack = inner_nterp_switch_stack();

    let (frames, result) = unwind(
        &unwinder,
        &mut cache,
        MODULE_BASE + 0x1010,
        sampled_regs(true),
        &stack,
    );
    check_inner_nterp_switch(&frames, result);
    assert_eq!(cache.stats().hits(), 0);
    assert_eq!(cache.stats().misses(), 3);

    let (frames, result) = unwind(
        &unwinder,
        &mut cache,
        MODULE_BASE + 0x1010,
        sampled_regs(true),
        &stack,
    );
    check_inner_nterp_switch(&frames, result);
    assert_eq!(cache.stats().hits(), 3);
}

#[test]
fn test_switch_interpreter_dex_pc_at_end_of_stack() {
    let mut unwinder = UnwinderAarch64::new();
    add_module(&mut unwinder, None, Some(debug_frame_bytes(all_funcs())));
    let mut cache = CacheAarch64::new();
    let stack = inner_nterp_switch_stack();
    let mut read_stack = stack_reader(&stack);
    let mut iter = unwinder.iter_frames(
        MODULE_BASE + 0x1010,
        sampled_regs(true),
        &mut cache,
        &mut read_stack,
    );
    for _ in 0..3 {
        iter.next().unwrap().unwrap();
    }
    // The switch frame's return address is 0, so the stack ends here. The dex pc
    // of the switch frame (x19) is still reported.
    assert_eq!(iter.next(), Ok(None));
    assert_eq!(last_dex_pc!(iter), Some(0x1919));
}

#[test]
fn test_unsampled_callee_saved() {
    let mut unwinder = UnwinderAarch64::new();
    add_module(&mut unwinder, None, Some(debug_frame_bytes(all_funcs())));
    let mut cache = CacheAarch64::new();
    let stack = inner_nterp_switch_stack();

    // Without sampled values, the CFI of "inner" restores x22 and x19 but not x25,
    // so the nterp CFA cannot be computed.
    let (frames, result) = unwind(
        &unwinder,
        &mut cache,
        MODULE_BASE + 0x1010,
        sampled_regs(false),
        &stack,
    );
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].x22, None);
    assert_eq!(
        (frames[1].x19, frames[1].x22, frames[1].x25),
        (Some(0x1919), Some(0xdec0de), None)
    );
    assert_eq!(result, Err(framehop::Error::RegisterValueUnknown));

    // The cached rules don't depend on which registers were known.
    let (frames, result) = unwind(
        &unwinder,
        &mut cache,
        MODULE_BASE + 0x1010,
        sampled_regs(true),
        &stack,
    );
    check_inner_nterp_switch(&frames, result);
}

#[test]
fn test_unknown_after_frame_pointer_fallback() {
    let mut unwinder = UnwinderAarch64::new();
    add_module(&mut unwinder, None, Some(debug_frame_bytes(all_funcs())));

    // Frame 0 is outside any module, so it's unwound with the frame pointer.
    // The switch frame's x19 is then unknown, and so is its dex pc.
    let stack = vec![
        (0x300, 0x400),                // caller fp
        (0x308, MODULE_BASE + 0x3010), // return address into switch
        (0x310, 0x1900),               // saved x19 of switch's caller
        (0x318, 0),
    ];
    for _ in 0..2 {
        let mut cache = CacheAarch64::new();
        let mut regs = UnwindRegsAarch64::new(0xffff, 0x200, 0x300);
        regs.set_callee_saved_from_sample([0x1234; 10]);
        let mut read_stack = stack_reader(&stack);
        let mut iter = unwinder.iter_frames(0x9999_0000, regs, &mut cache, &mut read_stack);
        iter.next().unwrap().unwrap();
        assert_eq!(iter.regs().callee_saved(19), Some(0x1234));
        assert_eq!(
            iter.next(),
            Ok(Some(
                FrameAddress::from_return_address(MODULE_BASE + 0x3010).unwrap()
            ))
        );
        assert_eq!(iter.regs().callee_saved(19), None);
        assert_eq!(iter.regs().callee_saved(28), None);
        assert_eq!(iter.next(), Ok(None));
        assert_eq!(last_dex_pc!(iter), None);
    }
}

#[test]
fn test_generic_path() {
    let mut unwinder = UnwinderAarch64::new();
    add_module(&mut unwinder, None, Some(debug_frame_bytes(all_funcs())));
    let mut cache = CacheAarch64::new();

    // "generic" is the first frame, CFA = x23 + 0x20 = 0x220.
    let stack = vec![
        (0x208, 0x2222),               // saved x22
        (0x210, 0x7777),               // caller fp
        (0x218, MODULE_BASE + 0x3010), // return address into switch
        (0x220, 0x1900),               // switch: saved x19
        (0x228, 0),                    // switch: end of stack
    ];
    for _ in 0..2 {
        let mut regs = UnwindRegsAarch64::new(0xffff, 0x200, 0x4444);
        let mut values = [0x1234; 10];
        values[22 - 19] = 0xd000;
        values[23 - 19] = 0x200;
        regs.set_callee_saved_from_sample(values);
        let mut read_stack = stack_reader(&stack);
        let mut iter =
            unwinder.iter_frames(MODULE_BASE + 0x4010, regs, &mut cache, &mut read_stack);
        iter.next().unwrap().unwrap();
        assert_eq!(
            iter.next(),
            Ok(Some(
                FrameAddress::from_return_address(MODULE_BASE + 0x3010).unwrap()
            ))
        );
        assert_eq!(last_dex_pc!(iter), Some(0xd002));
        assert_eq!(iter.regs().sp(), 0x220);
        assert_eq!(iter.regs().fp(), 0x7777);
        assert_eq!(iter.regs().callee_saved(22), Some(0x2222));
        assert_eq!(iter.regs().callee_saved(23), Some(0x200));
        assert_eq!(iter.next(), Ok(None));
        assert_eq!(last_dex_pc!(iter), Some(0x1234));
    }
    // The "generic" rule is not cacheable; the switch rule is.
    assert_eq!((cache.stats().hits(), cache.stats().misses()), (1, 3));
}

#[test]
fn test_generic_path_unknown_register() {
    // "generic" has CFA = x23 + 0x20. Without x23, the walk ends there and nothing
    // is cached, so a later walk which knows x23 still unwinds the frame.
    let mut unwinder = UnwinderAarch64::new();
    add_module(&mut unwinder, None, Some(debug_frame_bytes(all_funcs())));
    let mut cache = CacheAarch64::new();
    let stack = [(0x210, 0x7777), (0x218, MODULE_BASE + 0x3010)];

    let regs = UnwindRegsAarch64::new(0xffff, 0x200, 0x4444);
    let mut read_stack = stack_reader(&stack);
    let mut iter = unwinder.iter_frames(MODULE_BASE + 0x4010, regs, &mut cache, &mut read_stack);
    iter.next().unwrap().unwrap();
    assert_eq!(iter.next(), Err(framehop::Error::RegisterValueUnknown));

    let mut regs = UnwindRegsAarch64::new(0xffff, 0x200, 0x4444);
    regs.set_callee_saved(23, Some(0x200));
    let mut read_stack = stack_reader(&stack);
    let mut iter = unwinder.iter_frames(MODULE_BASE + 0x4010, regs, &mut cache, &mut read_stack);
    iter.next().unwrap().unwrap();
    assert_eq!(
        iter.next(),
        Ok(Some(
            FrameAddress::from_return_address(MODULE_BASE + 0x3010).unwrap()
        ))
    );
}

#[test]
fn test_generic_path_failure_is_cached() {
    // CFA = x5 + 16 can never be computed, because framehop doesn't track x5. This
    // doesn't depend on the walk, so the frame-pointer fallback rule is cached.
    use CallFrameInstruction::*;
    let func = (0x4800, 0x100, vec![(0, Cfa(reg(5), 16))]);
    let mut unwinder = UnwinderAarch64::new();
    add_module(&mut unwinder, None, Some(debug_frame_bytes(vec![func])));
    let mut cache = CacheAarch64::new();
    let stack = [(0x300, 0), (0x308, 0x9999_0000)];
    for _ in 0..2 {
        let regs = UnwindRegsAarch64::new(0xffff, 0x200, 0x300);
        let mut read_stack = stack_reader(&stack);
        let mut iter =
            unwinder.iter_frames(MODULE_BASE + 0x4810, regs, &mut cache, &mut read_stack);
        iter.next().unwrap().unwrap();
        assert_eq!(
            iter.next(),
            Ok(Some(
                FrameAddress::from_return_address(0x9999_0000).unwrap()
            ))
        );
    }
    assert_eq!((cache.stats().hits(), cache.stats().misses()), (1, 1));
}

/// Returns an unwinder with an excerpt of the unwind information of libart.so from
/// a Pixel 6 (ART mainline module), loaded at `base`. The excerpt has the CIE and
/// four FDEs of the original `.eh_frame` section, placed at its original address
/// 0xd3d00, and a matching `.eh_frame_hdr` at its original address 0xb32b0. The
/// pc-relative FDE fields were adjusted for the FDEs' new offsets. The excerpt was
/// made with `fixtures/android/aarch64/make-libart-excerpt.py`.
///
/// The FDEs are for:
///
/// - `ExecuteSwitchImplAsm` (0x41e980..0x41e994), which saves x19 and lr, sets x19
///   to the dex instructions and calls `ExecuteSwitchImplCpp` at 0x41e988.
/// - `ExecuteSwitchImplCpp<false>` (0x73ecec..0x74d8a8).
/// - `ExecuteNterpImpl` (0x74e040..0x764d5c).
/// - An nterp helper at 0x765550 which saves x21 - x30 and calls into the runtime:
///
/// ```text
/// 765550: adrp x16, ...
/// 765554: ldr  x16, [x16, #0x438]
/// 765558: ldr  x16, [x16, #0x8]
/// 76555c: sub  sp, sp, #0x60
/// 765560: stp  x21, x22, [sp, #0x10]
/// 765564: stp  x23, x24, [sp, #0x20]
/// 765568: stp  x25, x26, [sp, #0x30]
/// 76556c: stp  x27, x28, [sp, #0x40]
/// 765570: stp  x29, x30, [sp, #0x50]
/// 765574: stp  x16, x20, [sp]
/// 765578: mov  x16, sp
/// 76557c: str  x16, [x19, #0xb0]
/// 765580: bl   0x41ea34
/// ```
///
/// nterp calls this helper with `bl 0x765550` at 0x74e77c.
fn libart_excerpt_unwinder(base: u64) -> UnwinderAarch64<Vec<u8>> {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/android/aarch64");
    let eh_frame = std::fs::read(fixtures.join("libart-excerpt.eh_frame")).unwrap();
    let eh_frame_hdr = std::fs::read(fixtures.join("libart-excerpt.eh_frame_hdr")).unwrap();
    let mut unwinder = UnwinderAarch64::new();
    unwinder.add_module(Module::new(
        "libart.so".to_string(),
        base..base + 0xe10000,
        base,
        ExplicitModuleSectionInfo {
            base_svma: 0,
            text_svma: Some(0x200000..0xa9fbf8),
            eh_frame_svma: Some(0xd3d00..0xd3d00 + eh_frame.len() as u64),
            eh_frame: Some(eh_frame),
            eh_frame_hdr_svma: Some(0xb32b0..0xb32b0 + eh_frame_hdr.len() as u64),
            eh_frame_hdr: Some(eh_frame_hdr),
            ..Default::default()
        },
    ));
    unwinder
}

#[test]
fn test_libart_nterp() {
    let base = 0x7a_0000_0000;
    check_libart_nterp(&libart_excerpt_unwinder(base), base);
}

#[test]
fn test_libart_switch_interpreter_asm() {
    let base = 0x7a_0000_0000;
    let unwinder = libart_excerpt_unwinder(base);

    // In ExecuteSwitchImplAsm, after the call to ExecuteSwitchImplCpp.
    let stack = vec![(0x1000, 0x1919), (0x1008, 0x6f_0000_1234)];
    let mut cache = CacheAarch64::new();
    let mut regs = UnwindRegsAarch64::new(0xffff, 0x1000, 0x9999);
    regs.set_callee_saved_from_sample([0x7b_0000_0000; 10]);
    let mut read_stack = stack_reader(&stack);
    let mut iter = unwinder.iter_frames(base + 0x41e98c, regs, &mut cache, &mut read_stack);
    iter.next().unwrap().unwrap();
    assert_eq!(
        iter.next(),
        Ok(Some(
            FrameAddress::from_return_address(0x6f_0000_1234).unwrap()
        ))
    );
    assert_eq!(last_dex_pc!(iter), Some(0x7b_0000_0000));
    assert_eq!(iter.regs().callee_saved(19), Some(0x1919));
}

#[test]
fn test_libart_switch_interpreter() {
    let base = 0x7a_0000_0000;
    let unwinder = libart_excerpt_unwinder(base);

    // Frame 0: ExecuteSwitchImplCpp<false> (0x73ecec) in its body, where
    // CFA = x29 + 96, x19 at CFA - 8, x30 at CFA - 88, x29 at CFA - 96.
    // Frame 1: ExecuteSwitchImplAsm, return address 0x41e98c, CFA = sp + 16,
    // x19 at CFA - 16, x30 at CFA - 8, dex pc in x19.
    let stack = vec![
        (0x1f00, 0),               // somewhere below the frame record
        (0x2000, 0x3000),          // x29 of the Asm frame
        (0x2008, base + 0x41e98c), // x30: return address into Asm
        (0x2058, 0x7b_dead_0000),  // x19 of the Asm frame: the dex insns
        (0x2060, 0x1919),          // x19 of Asm's caller
        (0x2068, 0x6f_0000_1234),  // x30: Asm's return address
    ];
    let mut cache = CacheAarch64::new();
    for round in 0..2 {
        let mut regs = UnwindRegsAarch64::new(0xffff, 0x1f00, 0x2000);
        regs.set_callee_saved_from_sample([0xbad; 10]);
        let mut read_stack = stack_reader(&stack);
        let mut iter = unwinder.iter_frames(base + 0x73f000, regs, &mut cache, &mut read_stack);
        iter.next().unwrap().unwrap();
        assert_eq!(
            iter.next(),
            Ok(Some(
                FrameAddress::from_return_address(base + 0x41e98c).unwrap()
            )),
            "round {round}"
        );
        assert_eq!(iter.regs().sp(), 0x2060, "round {round}");
        assert_eq!(
            iter.regs().callee_saved(19),
            Some(0x7b_dead_0000),
            "round {round}"
        );
        assert_eq!(
            iter.next(),
            Ok(Some(
                FrameAddress::from_return_address(0x6f_0000_1234).unwrap()
            )),
            "round {round}"
        );
        assert_eq!(last_dex_pc!(iter), Some(0x7b_dead_0000), "round {round}");
    }
}

fn check_libart_nterp(unwinder: &UnwinderAarch64<Vec<u8>>, base: u64) {
    // Frame 0: the helper at 0x765580 (about to call the runtime). sp = 0x1000,
    // CFA = 0x1060. The helper hasn't modified x22 or x25 yet, but we pretend that
    // the sampled registers were clobbered to check that the saved values are used.
    // Frame 1: nterp, return address 0x74e780. Its CFA is *(x25 - 8) + 0xa0, with
    // x25 = 0x2000 (restored from the helper's frame) and *(0x1ff8) = 0x1100, so
    // CFA = 0x11a0. Its dex pc is x22 = 0x7b_1234_5678 (restored from the
    // helper's frame).
    let caller_of_nterp = 0x6f_0000_1234;
    let stack = vec![
        (0x1000, 0x1616),          // x16
        (0x1008, 0x2020),          // x20
        (0x1010, 0x2121),          // x21
        (0x1018, 0x7b_1234_5678),  // x22: nterp's xPC
        (0x1020, 0x2323),          // x23
        (0x1028, 0x2424),          // x24
        (0x1030, 0x2000),          // x25: nterp's xREFS
        (0x1038, 0x2626),          // x26
        (0x1040, 0x2727),          // x27
        (0x1048, 0x2828),          // x28
        (0x1050, 0x2929),          // x29
        (0x1058, base + 0x74e780), // x30: return address into nterp
        (0x1ff8, 0x1100),          // *(xREFS - 8): nterp's sp
        // nterp frame: CFA = 0x11a0, saves x19 - x30 at CFA - 96 .. CFA - 8.
        (0x11a0 - 96, 0x1919),         // x19
        (0x11a0 - 72, 0x2222_0000),    // x22 of nterp's caller
        (0x11a0 - 48, 0x2525_0000),    // x25 of nterp's caller
        (0x11a0 - 16, 0x2929_0000),    // x29 of nterp's caller
        (0x11a0 - 8, caller_of_nterp), // x30: return address
    ];

    let mut cache = CacheAarch64::new();
    for round in 0..2 {
        let mut regs = UnwindRegsAarch64::new(0xffff, 0x1000, 0x9999);
        regs.set_callee_saved_from_sample([0xbad; 10]);
        let mut read_stack = stack_reader(&stack);
        let mut iter = unwinder.iter_frames(base + 0x765580, regs, &mut cache, &mut read_stack);
        assert_eq!(
            iter.next(),
            Ok(Some(FrameAddress::from_instruction_pointer(
                base + 0x765580
            )))
        );
        assert_eq!(
            iter.next(),
            Ok(Some(
                FrameAddress::from_return_address(base + 0x74e780).unwrap()
            ))
        );
        assert_eq!(last_dex_pc!(iter), None);
        assert_eq!(iter.regs().sp(), 0x1060);
        assert_eq!(iter.regs().callee_saved(22), Some(0x7b_1234_5678));
        assert_eq!(iter.regs().callee_saved(25), Some(0x2000));
        // x19 isn't saved by the helper, so it keeps its sampled value.
        assert_eq!(iter.regs().callee_saved(19), Some(0xbad));

        assert_eq!(
            iter.next(),
            Ok(Some(
                FrameAddress::from_return_address(caller_of_nterp).unwrap()
            ))
        );
        assert_eq!(last_dex_pc!(iter), Some(0x7b_1234_5678));
        assert_eq!(iter.regs().sp(), 0x11a0);
        assert_eq!(iter.regs().fp(), 0x2929_0000);
        assert_eq!(iter.regs().callee_saved(19), Some(0x1919));
        assert_eq!(iter.regs().callee_saved(22), Some(0x2222_0000));
        assert_eq!(iter.regs().callee_saved(25), Some(0x2525_0000));

        let stats = cache.stats();
        if round == 0 {
            assert_eq!((stats.hits(), stats.misses()), (0, 2));
        } else {
            assert_eq!((stats.hits(), stats.misses()), (2, 2));
        }
    }
}

#[test]
fn test_val_expression_values() {
    // CFA = sp + 16, lr at CFA - 8. x5 = x29 + 8 (no tag), x0 = x19 - 4 (tag 0xabcd).
    use CallFrameInstruction::*;
    let untagged = gimli::write::Expression::raw(vec![0x70 + 29, 8]);
    let tagged = gimli::write::Expression::raw(vec![0x0c, 0xcd, 0xab, 0, 0, 0x13, 0x70 + 19, 0x7c]);
    let func = (
        0x4800,
        0x100,
        vec![
            (0, CfaOffset(16)),
            (0, Offset(AArch64::X30, -8)),
            (0, ValExpression(reg(5), untagged)),
            (0, ValExpression(reg(0), tagged)),
        ],
    );
    let mut unwinder = UnwinderAarch64::new();
    add_module(&mut unwinder, None, Some(debug_frame_bytes(vec![func])));
    let mut cache = CacheAarch64::new();
    let stack = [(0x108, 0)];
    for _ in 0..2 {
        let mut regs = UnwindRegsAarch64::new(0xffff, 0x100, 0x3000);
        regs.set_callee_saved(19, Some(0x1904));
        let mut read_stack = stack_reader(&stack);
        let mut iter =
            unwinder.iter_frames(MODULE_BASE + 0x4810, regs, &mut cache, &mut read_stack);
        iter.next().unwrap().unwrap();
        assert_eq!(iter.next(), Ok(None));
        let values: Vec<_> = iter.last_val_expression_values().collect();
        assert_eq!(
            values,
            [
                ValExpressionValue {
                    register: 5,
                    tag: None,
                    value: 0x3008,
                },
                ValExpressionValue {
                    register: 0,
                    tag: Some(0xabcd),
                    value: 0x1900,
                },
            ]
        );
    }
    assert_eq!((cache.stats().hits(), cache.stats().misses()), (1, 1));
}
