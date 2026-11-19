use gimli::{
    CfaRule, Encoding, EvaluationStorage, Reader, ReaderOffset, Register, RegisterRule,
    UnwindContextStorage, UnwindSection, UnwindTableRow, X86_64,
};

use super::{
    arch::ArchX86_64,
    unwind_rule::UnwindRuleX86_64,
    unwindregs::{Reg, UnwindRegsX86_64},
};
use crate::dwarf::{
    eval_cfa_rule, eval_register_rule, ConversionError, DwarfUnwindRegs, DwarfUnwinderError,
    DwarfUnwinding,
};
use crate::unwind_result::UnwindResult;
use crate::unwind_rule::UnwindRule;

impl DwarfUnwindRegs for UnwindRegsX86_64 {
    fn get(&self, register: Register) -> Option<u64> {
        match register {
            X86_64::RA => Some(self.ip()),
            X86_64::RAX => self.get_if_set(Reg::RAX),
            X86_64::RDX => self.get_if_set(Reg::RDX),
            X86_64::RCX => self.get_if_set(Reg::RCX),
            X86_64::RBX => self.get_if_set(Reg::RBX),
            X86_64::RSI => self.get_if_set(Reg::RSI),
            X86_64::RDI => self.get_if_set(Reg::RDI),
            // RSP/RBP are always populated by `UnwindRegsX86_64::new`.
            X86_64::RSP => Some(self.sp()),
            X86_64::RBP => Some(self.bp()),
            X86_64::R8 => self.get_if_set(Reg::R8),
            X86_64::R9 => self.get_if_set(Reg::R9),
            X86_64::R10 => self.get_if_set(Reg::R10),
            X86_64::R11 => self.get_if_set(Reg::R11),
            X86_64::R12 => self.get_if_set(Reg::R12),
            X86_64::R13 => self.get_if_set(Reg::R13),
            X86_64::R14 => self.get_if_set(Reg::R14),
            X86_64::R15 => self.get_if_set(Reg::R15),
            _ => None,
        }
    }
}

impl DwarfUnwinding for ArchX86_64 {
    fn unwind_frame<F, R, UCS, ES>(
        section: &impl UnwindSection<R>,
        unwind_info: &UnwindTableRow<R::Offset, UCS>,
        encoding: Encoding,
        regs: &mut Self::UnwindRegs,
        is_first_frame: bool,
        is_signal_frame: bool,
        signal_aware: bool,
        read_stack: &mut F,
    ) -> Result<UnwindResult<Self::UnwindRule>, DwarfUnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
        R: Reader,
        UCS: UnwindContextStorage<R::Offset>,
        ES: EvaluationStorage<R>,
    {
        if is_signal_frame {
            let result = unwind_signal_frame::<F, R, UCS, ES>(
                section,
                unwind_info,
                encoding,
                regs,
                is_first_frame || signal_aware,
                read_stack,
            );
            // Whether a signal frame can be unwound depends on the stack and on the caller,
            // so a failure must not be cached for its address.
            return Ok(result.unwrap_or(UnwindResult::ExecRuleUncached(
                UnwindRuleX86_64::fallback_rule(),
            )));
        }

        let cfa_rule = unwind_info.cfa();
        let bp_rule = unwind_info.register(X86_64::RBP);
        let ra_rule = unwind_info.register(X86_64::RA);

        match translate_into_unwind_rule(cfa_rule, bp_rule.as_ref(), ra_rule.as_ref()) {
            Ok(unwind_rule) => return Ok(UnwindResult::ExecRule(unwind_rule)),
            Err(_err) => {
                // Could not translate into a cacheable unwind rule. Fall back to the generic path.
                // eprintln!("Unwind rule translation failed: {:?}", err);
            }
        }

        let cfa = eval_cfa_rule::<R, F, _, ES>(section, cfa_rule, encoding, regs, read_stack)
            .ok_or(DwarfUnwinderError::CouldNotRecoverCfa)?;

        let ip = regs.ip();
        let bp = regs.bp();
        let sp = regs.sp();

        let new_bp = eval_register_rule::<R, F, _, ES>(
            section, bp_rule, cfa, encoding, bp, regs, read_stack,
        )
        .unwrap_or(bp);

        let return_address = match eval_register_rule::<R, F, _, ES>(
            section, ra_rule, cfa, encoding, ip, regs, read_stack,
        ) {
            Some(ra) => ra,
            None => {
                read_stack(cfa - 8).map_err(|_| DwarfUnwinderError::CouldNotRecoverReturnAddress)?
            }
        };

        if cfa == sp && return_address == ip {
            return Err(DwarfUnwinderError::DidNotAdvance);
        }
        if !is_first_frame && cfa < regs.sp() {
            return Err(DwarfUnwinderError::StackPointerMovedBackwards);
        }

        regs.clear_unrestored_caller_registers();
        regs.set_ip(return_address);
        regs.set_bp(new_bp);
        regs.set_sp(cfa);

        Ok(UnwindResult::Uncacheable(return_address))
    }

    fn rule_if_uncovered_by_fde() -> Self::UnwindRule {
        UnwindRuleX86_64::JustReturnIfFirstFrameOtherwiseFp
    }
}

/// The registers that a signal frame restores besides RIP, RSP and RBP.
const SIGNAL_FRAME_REGISTERS: [(Register, Reg); 14] = [
    (X86_64::RAX, Reg::RAX),
    (X86_64::RDX, Reg::RDX),
    (X86_64::RCX, Reg::RCX),
    (X86_64::RBX, Reg::RBX),
    (X86_64::RSI, Reg::RSI),
    (X86_64::RDI, Reg::RDI),
    (X86_64::R8, Reg::R8),
    (X86_64::R9, Reg::R9),
    (X86_64::R10, Reg::R10),
    (X86_64::R11, Reg::R11),
    (X86_64::R12, Reg::R12),
    (X86_64::R13, Reg::R13),
    (X86_64::R14, Reg::R14),
    (X86_64::R15, Reg::R15),
];

/// Unwinds a signal frame, whose unwind info says where the registers of the interrupted
/// code were saved. Every rule is evaluated with the registers of the signal frame.
///
/// The interrupted code may run on another stack, so its stack pointer can be lower than
/// the signal frame's. That is an error unless `sp_may_decrease`.
fn unwind_signal_frame<F, R, UCS, ES>(
    section: &impl UnwindSection<R>,
    unwind_info: &UnwindTableRow<R::Offset, UCS>,
    encoding: Encoding,
    regs: &mut UnwindRegsX86_64,
    sp_may_decrease: bool,
    read_stack: &mut F,
) -> Result<UnwindResult<UnwindRuleX86_64>, DwarfUnwinderError>
where
    F: FnMut(u64) -> Result<u64, ()>,
    R: Reader,
    UCS: UnwindContextStorage<R::Offset>,
    ES: EvaluationStorage<R>,
{
    let ra_rule = unwind_info.register(X86_64::RA);
    if matches!(ra_rule, None | Some(RegisterRule::Undefined)) {
        return Ok(UnwindResult::ExecRule(UnwindRuleX86_64::EndOfStack));
    }

    let old = *regs;
    let cfa = eval_cfa_rule::<R, F, _, ES>(section, unwind_info.cfa(), encoding, &old, read_stack)
        .ok_or(DwarfUnwinderError::CouldNotRecoverCfa)?;
    let mut eval = |rule, same_value: Option<u64>| match rule {
        None => None,
        Some(RegisterRule::SameValue) => same_value,
        rule => {
            eval_register_rule::<R, F, _, ES>(section, rule, cfa, encoding, 0, &old, read_stack)
        }
    };

    let ip =
        eval(ra_rule, Some(old.ip())).ok_or(DwarfUnwinderError::CouldNotRecoverReturnAddress)?;
    // Without a rule, the stack pointer is the CFA.
    let sp = match unwind_info.register(X86_64::RSP) {
        None => cfa,
        rule => eval(rule, Some(old.sp())).ok_or(DwarfUnwinderError::CouldNotRecoverCfa)?,
    };
    // As in an ordinary frame, the frame pointer is kept if it cannot be recovered.
    let bp = eval(unwind_info.register(X86_64::RBP), Some(old.bp())).unwrap_or(old.bp());
    if sp == old.sp() && ip == old.ip() {
        return Err(DwarfUnwinderError::DidNotAdvance);
    }
    if !sp_may_decrease && sp < old.sp() {
        return Err(DwarfUnwinderError::StackPointerMovedBackwards);
    }

    let mut new = UnwindRegsX86_64::new(ip, sp, bp);
    for (register, reg) in SIGNAL_FRAME_REGISTERS {
        if let Some(value) = eval(unwind_info.register(register), old.get_if_set(reg)) {
            new.set(reg, value);
        }
    }
    *regs = new;

    Ok(UnwindResult::Interrupted(ip))
}

fn register_rule_to_cfa_offset<RO: ReaderOffset>(
    rule: Option<&RegisterRule<RO>>,
) -> Result<Option<i64>, ConversionError> {
    match rule {
        None | Some(RegisterRule::Undefined) | Some(RegisterRule::SameValue) => Ok(None),
        Some(RegisterRule::Offset(offset)) => Ok(Some(*offset)),
        _ => Err(ConversionError::RegisterNotStoredRelativeToCfa),
    }
}

fn translate_into_unwind_rule<RO: ReaderOffset>(
    cfa_rule: &CfaRule<RO>,
    bp_rule: Option<&RegisterRule<RO>>,
    ra_rule: Option<&RegisterRule<RO>>,
) -> Result<UnwindRuleX86_64, ConversionError> {
    match ra_rule {
        None | Some(RegisterRule::Undefined) => {
            // No return address. This means that we've reached the end of the stack.
            return Ok(UnwindRuleX86_64::EndOfStack);
        }
        Some(RegisterRule::Offset(offset)) if *offset == -8 => {
            // This is normal case. Return address is [CFA-8].
        }
        Some(RegisterRule::Offset(_)) => {
            // Unsupported, will have to use the slow path.
            return Err(ConversionError::ReturnAddressRuleWithUnexpectedOffset);
        }
        _ => {
            // Unsupported, will have to use the slow path.
            return Err(ConversionError::ReturnAddressRuleWasWeird);
        }
    }

    match cfa_rule {
        CfaRule::RegisterAndOffset { register, offset } => match *register {
            X86_64::RSP => {
                let sp_offset_by_8 =
                    u16::try_from(offset / 8).map_err(|_| ConversionError::SpOffsetDoesNotFit)?;
                let fp_cfa_offset = register_rule_to_cfa_offset(bp_rule)?;
                match fp_cfa_offset {
                    None => Ok(UnwindRuleX86_64::OffsetSp { sp_offset_by_8 }),
                    Some(bp_cfa_offset) => {
                        let bp_storage_offset_from_sp_by_8 =
                            i16::try_from((offset + bp_cfa_offset) / 8)
                                .map_err(|_| ConversionError::FpStorageOffsetDoesNotFit)?;
                        Ok(UnwindRuleX86_64::OffsetSpAndRestoreBp {
                            sp_offset_by_8,
                            bp_storage_offset_from_sp_by_8,
                        })
                    }
                }
            }
            X86_64::RBP => {
                let bp_cfa_offset = register_rule_to_cfa_offset(bp_rule)?
                    .ok_or(ConversionError::FramePointerRuleDoesNotRestoreBp)?;
                if *offset == 16 && bp_cfa_offset == -16 {
                    Ok(UnwindRuleX86_64::UseFramePointer)
                } else {
                    // TODO: Maybe handle this case. This case has been observed in _ffi_call_unix64,
                    // which has the following unwind table:
                    //
                    // 00000060 00000024 0000001c FDE cie=00000048 pc=000de548...000de6a6
                    //   0xde548: CFA=reg7+8: reg16=[CFA-8]
                    //   0xde562: CFA=reg6+32: reg6=[CFA-16], reg16=[CFA-8]
                    //   0xde5ad: CFA=reg7+8: reg16=[CFA-8]
                    //   0xde668: CFA=reg7+8: reg6=[CFA-16], reg16=[CFA-8]
                    Err(ConversionError::FramePointerRuleHasStrangeBpOffset)
                }
            }
            _ => Err(ConversionError::CfaIsOffsetFromUnknownRegister),
        },
        CfaRule::Expression(_) => Err(ConversionError::CfaIsExpression),
    }
}

#[cfg(test)]
mod test {
    use alloc::{vec, vec::Vec};

    use gimli::{BaseAddresses, EhFrame, EndianSlice, LittleEndian, StoreOnHeap, UnwindContext};

    use super::*;

    /// An `.eh_frame` section with one signal frame, like the one of FreeBSD's signal
    /// trampoline: the CFA is the trampoline's stack pointer, and the interrupted stack
    /// pointer has a rule of its own.
    fn signal_frame_section() -> Vec<u8> {
        let cie = [
            0, 0, 0, 0, // CIE id
            1, // version
            b'z', b'R', b'S', 0,    // augmentation; S marks signal frames
            1,    // code alignment factor
            0x78, // data alignment factor: -8
            16,   // return address register
            1,    // augmentation data length
            0x04, // R: addresses are DW_EH_PE_udata8
        ];
        let instructions = [
            0x0c, 7, 0, // 0x1000: DW_CFA_def_cfa: RSP+0
            0x11, 16, 0x7e, // DW_CFA_offset_extended_sf: RIP at [CFA+16]
            0x11, 7, 0x7d, // RSP at [CFA+24]
            0x11, 6, 0x7c, // RBP at [CFA+32]
            0x11, 9, 0x7b, // R9 at [CFA+40]
            0x41, // DW_CFA_advance_loc: 1
            0x07, 16,   // 0x1001: DW_CFA_undefined: RIP
            0x41, // DW_CFA_advance_loc: 1
            0x08, 16, // 0x1002: DW_CFA_same_value: RIP
        ];
        let mut section = vec![];
        section.extend((cie.len() as u32).to_le_bytes());
        section.extend(cie);
        let cie_pointer = section.len() as u32 + 4;
        section.extend((4 + 8 + 8 + 1 + instructions.len() as u32).to_le_bytes());
        section.extend(cie_pointer.to_le_bytes());
        section.extend(0x1000u64.to_le_bytes()); // start address
        section.extend(3u64.to_le_bytes()); // length
        section.push(0); // augmentation data length
        section.extend(instructions);
        section
    }

    fn unwind_with(
        address: u64,
        regs: &mut UnwindRegsX86_64,
        stack: &[u64],
        sp_may_decrease: bool,
    ) -> Result<UnwindResult<UnwindRuleX86_64>, DwarfUnwinderError> {
        let section = signal_frame_section();
        let section = EhFrame::new(&section, LittleEndian);
        let bases = BaseAddresses::default();
        let fde = section
            .fde_for_address(&bases, address, EhFrame::cie_from_offset)
            .unwrap();
        let mut context = UnwindContext::new();
        let row = fde
            .unwind_info_for_address(&section, &bases, &mut context, address)
            .unwrap();
        let mut read_stack = |address: u64| stack.get((address / 8) as usize).copied().ok_or(());
        assert!(fde.is_signal_trampoline());
        unwind_signal_frame::<_, EndianSlice<LittleEndian>, StoreOnHeap, StoreOnHeap>(
            &section,
            row,
            fde.cie().encoding(),
            regs,
            sp_may_decrease,
            &mut read_stack,
        )
    }

    fn unwind(
        address: u64,
        regs: &mut UnwindRegsX86_64,
        stack: &[u64],
    ) -> Result<UnwindResult<UnwindRuleX86_64>, DwarfUnwinderError> {
        unwind_with(address, regs, stack, true)
    }

    #[test]
    fn signal_frame_restores_the_interrupted_registers() {
        // The trampoline's stack pointer is 0x20.
        let mut stack = [0u64; 16];
        stack[0x30 / 8] = 0x123456; // RIP
        stack[0x38 / 8] = 0x8; // RSP, lower than the trampoline's
        stack[0x40 / 8] = 0x4567; // RBP
        stack[0x48 / 8] = 0x89ab; // R9

        let mut regs = UnwindRegsX86_64::new(0x1000, 0x20, 0x9999);
        regs.set(Reg::R10, 0x1111);
        let res = unwind(0x1000, &mut regs, &stack);
        assert!(matches!(res, Ok(UnwindResult::Interrupted(0x123456))));
        let mut expected = UnwindRegsX86_64::new(0x123456, 0x8, 0x4567);
        expected.set(Reg::R9, 0x89ab);
        assert_eq!(regs, expected);

        // A caller that cannot deal with a lower stack pointer gets an error.
        let old = UnwindRegsX86_64::new(0x1000, 0x20, 0x9999);
        let mut regs = old;
        let res = unwind_with(0x1000, &mut regs, &stack, false);
        assert_eq!(
            res.unwrap_err(),
            DwarfUnwinderError::StackPointerMovedBackwards
        );
        assert_eq!(regs, old);
        stack[0x38 / 8] = 0x28;
        let res = unwind_with(0x1000, &mut regs, &stack, false);
        assert!(matches!(res, Ok(UnwindResult::Interrupted(0x123456))));
        assert_eq!(regs.sp(), 0x28);
    }

    #[test]
    fn signal_frame_without_a_return_address_ends_the_stack() {
        let regs = UnwindRegsX86_64::new(0x1001, 0x20, 0x9999);
        let mut unwound = regs;
        let res = unwind(0x1001, &mut unwound, &[0; 16]);
        assert!(matches!(
            res,
            Ok(UnwindResult::ExecRule(UnwindRuleX86_64::EndOfStack))
        ));
        assert_eq!(unwound, regs);
    }

    #[test]
    fn signal_frame_with_the_same_return_address_needs_another_stack_pointer() {
        let mut stack = [0u64; 16];
        stack[0x38 / 8] = 0x8; // RSP
        let mut regs = UnwindRegsX86_64::new(0x1002, 0x20, 0x9999);
        let res = unwind(0x1002, &mut regs, &stack);
        assert!(matches!(res, Ok(UnwindResult::Interrupted(0x1002))));
        let mut expected = UnwindRegsX86_64::new(0x1002, 0x8, 0);
        expected.set(Reg::R9, 0);
        assert_eq!(regs, expected);

        stack[0x38 / 8] = 0x20;
        let mut regs = UnwindRegsX86_64::new(0x1002, 0x20, 0x9999);
        let res = unwind(0x1002, &mut regs, &stack);
        assert_eq!(res.unwrap_err(), DwarfUnwinderError::DidNotAdvance);
    }

    #[test]
    fn signal_frame_with_an_unreadable_register() {
        // The stack ends before the slot of RBP, which is then kept.
        let regs = UnwindRegsX86_64::new(0x1000, 0x20, 0x9999);
        let mut unwound = regs;
        let res = unwind(0x1000, &mut unwound, &[1; 8]);
        assert!(matches!(res, Ok(UnwindResult::Interrupted(1))));
        assert_eq!(unwound, UnwindRegsX86_64::new(1, 1, 0x9999));

        // The stack ends before the slot of RSP.
        let mut unwound = regs;
        let res = unwind(0x1000, &mut unwound, &[1; 7]);
        assert_eq!(res.unwrap_err(), DwarfUnwinderError::CouldNotRecoverCfa);
        assert_eq!(unwound, regs);

        // The stack ends before the slot of RIP.
        let res = unwind(0x1000, &mut unwound, &[1; 6]);
        assert_eq!(
            res.unwrap_err(),
            DwarfUnwinderError::CouldNotRecoverReturnAddress
        );
        assert_eq!(unwound, regs);
    }
}
