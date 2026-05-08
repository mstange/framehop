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
        read_stack: &mut F,
    ) -> Result<UnwindResult<Self::UnwindRule>, DwarfUnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
        R: Reader,
        UCS: UnwindContextStorage<R::Offset>,
        ES: EvaluationStorage<R>,
    {
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
