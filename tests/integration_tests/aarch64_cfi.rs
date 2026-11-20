use framehop::aarch64::*;
use framehop::{ExplicitModuleSectionInfo, FrameAddress, Module, Unwinder};
use gimli::write::{
    Address, CallFrameInstruction, CommonInformationEntry, EhFrame, EndianVec,
    FrameDescriptionEntry, FrameTable,
};
use gimli::{AArch64, Encoding, Format, LittleEndian};

const MODULE_BASE: u64 = 0x10000;

/// A function with return address signing, as compiled for Android: its FDE
/// starts with `DW_CFA_AARCH64_negate_ra_state` (for `paciasp`).
fn pac_signed_eh_frame() -> Vec<u8> {
    let encoding = Encoding {
        format: Format::Dwarf32,
        version: 1,
        address_size: 8,
    };
    let mut table = FrameTable::default();
    let mut cie = CommonInformationEntry::new(encoding, 4, -8, AArch64::X30);
    cie.add_instruction(CallFrameInstruction::Cfa(AArch64::SP, 0));
    let cie_id = table.add_cie(cie);
    let mut fde = FrameDescriptionEntry::new(Address::Constant(0x1000), 0x100);
    fde.add_instruction(0, CallFrameInstruction::NegateRaState);
    fde.add_instruction(4, CallFrameInstruction::CfaOffset(16));
    fde.add_instruction(8, CallFrameInstruction::Offset(AArch64::X30, -8));
    fde.add_instruction(8, CallFrameInstruction::Offset(AArch64::X29, -16));
    table.add_fde(cie_id, fde);
    let mut eh_frame = EhFrame(EndianVec::new(LittleEndian));
    table.write_eh_frame(&mut eh_frame).unwrap();
    eh_frame.0.into_vec()
}

#[test]
fn test_negate_ra_state() {
    let eh_frame = pac_signed_eh_frame();
    let mut unwinder = UnwinderAarch64::new();
    unwinder.add_module(Module::new(
        "synthetic".to_string(),
        MODULE_BASE..MODULE_BASE + 0x10000,
        MODULE_BASE,
        ExplicitModuleSectionInfo {
            base_svma: 0,
            text_svma: Some(0x1000..0x2000),
            eh_frame_svma: Some(0x8000..0x8000 + eh_frame.len() as u64),
            eh_frame: Some(eh_frame),
            ..Default::default()
        },
    ));

    let stack = [(0x100, 0x5555), (0x108, 0x6f_0000_1234)];
    let mut read_stack = |addr| {
        stack
            .iter()
            .find(|(a, _)| *a == addr)
            .map(|(_, v)| *v)
            .ok_or(())
    };
    let mut cache = CacheAarch64::new();
    // Without the CFI, framehop would treat the function as a leaf and
    // return lr.
    let regs = UnwindRegsAarch64::new(0xffff, 0x100, 0x4444);
    let mut iter = unwinder.iter_frames(MODULE_BASE + 0x1010, regs, &mut cache, &mut read_stack);
    assert_eq!(
        iter.next(),
        Ok(Some(FrameAddress::from_instruction_pointer(
            MODULE_BASE + 0x1010
        )))
    );
    assert_eq!(
        iter.next(),
        Ok(Some(
            FrameAddress::from_return_address(0x6f_0000_1234).unwrap()
        ))
    );
}
