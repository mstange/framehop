use gimli::{
    CfaRule, Encoding, Reader, Register, RegisterRule, UnwindContextStorage, UnwindTableRow, X86_64,
};

use crate::{
    arch::ArchX86_64, rules::UnwindRuleX86_64, unwind_result::UnwindResult,
    unwindregs::UnwindRegsX86_64,
};

use super::{
    eval_cfa_rule, eval_register_rule, ConversionError, DwarfUnwindRegs, DwarfUnwinderError,
    DwarfUnwinding,
};

impl DwarfUnwindRegs for UnwindRegsX86_64 {
    fn get(&self, register: Register) -> Option<u64> {
        match register {
            X86_64::RA => Some(self.ip()),
            X86_64::RSP => Some(self.sp()),
            X86_64::RBP => Some(self.bp()),
            _ => None,
        }
    }
}

impl DwarfUnwinding for ArchX86_64 {
    fn unwind_first<F, R, S>(
        unwind_info: &UnwindTableRow<R, S>,
        encoding: Encoding,
        regs: &mut Self::UnwindRegs,
        pc: u64,
        read_mem: &mut F,
    ) -> Result<UnwindResult<Self::UnwindRule>, DwarfUnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
        R: Reader,
        S: UnwindContextStorage<R>,
    {
        let cfa_rule = unwind_info.cfa();
        let bp_rule = unwind_info.register(X86_64::RBP);
        let ra_rule = unwind_info.register(X86_64::RA);

        match translate_into_unwind_rule(cfa_rule, &bp_rule, &ra_rule) {
            Ok(unwind_rule) => return Ok(UnwindResult::ExecRule(unwind_rule)),
            Err(_err) => {
                // eprintln!("Unwind rule translation failed: {:?}", err);
            }
        }

        // println!("cfa rule: {:?}, regs: {:?}", cfa_rule, regs);
        let cfa = match eval_cfa_rule(cfa_rule, encoding, regs) {
            Some(cfa) => cfa,
            None => {
                // eprintln!("Could not recover CFA.");
                return Err(DwarfUnwinderError::CouldNotRecoverCfa);
            }
        };

        // eprintln!("cfa: {:x}", cfa);

        let bp = regs.bp();
        let bp = eval_register_rule(bp_rule, cfa, encoding, bp, regs, read_mem).unwrap_or(bp);

        let return_address = match eval_register_rule(ra_rule, cfa, encoding, pc, regs, read_mem) {
            Some(ra) => ra,
            None => {
                read_mem(cfa - 8).map_err(|_| DwarfUnwinderError::CouldNotRecoverReturnAddress)?
            }
        };

        if cfa == regs.sp() && return_address == regs.ip() {
            return Err(DwarfUnwinderError::DidNotAdvance);
        }

        regs.set_ip(return_address);
        regs.set_bp(bp);
        regs.set_sp(cfa);

        Ok(UnwindResult::Uncacheable(return_address))
    }

    fn unwind_next<F, R, S>(
        unwind_info: &UnwindTableRow<R, S>,
        encoding: Encoding,
        regs: &mut Self::UnwindRegs,
        read_mem: &mut F,
    ) -> Result<UnwindResult<Self::UnwindRule>, DwarfUnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
        R: Reader,
        S: UnwindContextStorage<R>,
    {
        let cfa_rule = unwind_info.cfa();
        let bp_rule = unwind_info.register(X86_64::RBP);
        let ra_rule = unwind_info.register(X86_64::RA);

        match translate_into_unwind_rule(cfa_rule, &bp_rule, &ra_rule) {
            Ok(unwind_rule) => return Ok(UnwindResult::ExecRule(unwind_rule)),
            Err(_err) => {
                // eprintln!("Unwind rule translation failed: {:?}", err);
            }
        }

        // println!("cfa rule: {:?}, regs: {:?}", cfa_rule, regs);
        let cfa = eval_cfa_rule(cfa_rule, encoding, regs)
            .ok_or(DwarfUnwinderError::CouldNotRecoverCfa)?;
        if cfa <= regs.sp() {
            return Err(DwarfUnwinderError::StackPointerMovedBackwards);
        }

        // eprintln!("cfa: {:x}", cfa);
        // println!("rules: fp {:?}, lr {:?}", bp_rule, lr_rule);
        let bp = eval_register_rule(bp_rule, cfa, encoding, regs.bp(), regs, read_mem)
            .ok_or(DwarfUnwinderError::CouldNotRecoverFramePointer)?;

        let return_address =
            match eval_register_rule(ra_rule, cfa, encoding, regs.ip(), regs, read_mem) {
                Some(ra) => ra,
                None => read_mem(cfa - 8)
                    .map_err(|_| DwarfUnwinderError::CouldNotRecoverReturnAddress)?,
            };

        regs.set_ip(return_address);
        regs.set_bp(bp);
        regs.set_sp(cfa);

        Ok(UnwindResult::Uncacheable(return_address))
    }
}

fn register_rule_to_cfa_offset<R: gimli::Reader>(
    rule: &RegisterRule<R>,
) -> Result<Option<i64>, ConversionError> {
    match *rule {
        RegisterRule::Undefined | RegisterRule::SameValue => Ok(None),
        RegisterRule::Offset(offset) => Ok(Some(offset)),
        _ => Err(ConversionError::RegisterNotStoredRelativeToCfa),
    }
}

fn translate_into_unwind_rule<R: gimli::Reader>(
    cfa_rule: &CfaRule<R>,
    bp_rule: &RegisterRule<R>,
    ra_rule: &RegisterRule<R>,
) -> Result<UnwindRuleX86_64, ConversionError> {
    match ra_rule {
        RegisterRule::Undefined => {
            // This is normal. Return address is [CFA-8].
        }
        RegisterRule::Offset(offset) => {
            if *offset == -8 {
                // Weirdly explicit, but also ok.
            } else {
                // Not ok.
                return Err(ConversionError::ReturnAddressRuleWithUnexpectedOffset);
            }
        }
        _ => {
            // Somebody's being extra. Go down the slow path.
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
                            i8::try_from((offset + bp_cfa_offset) / 8)
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
                    Err(ConversionError::FramePointerRuleHasStrangeBpOffset)
                }
            }
            _ => Err(ConversionError::CfaIsOffsetFromUnknownRegister),
        },
        CfaRule::Expression(_) => Err(ConversionError::CfaIsExpression),
    }
}
