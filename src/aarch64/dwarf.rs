use gimli::{
    AArch64, CfaRule, Encoding, EvaluationStorage, Reader, Register, RegisterRule,
    UnwindContextStorage, UnwindTableRow,
};

use super::{arch::ArchAarch64, unwind_rule::UnwindRuleAarch64, unwindregs::UnwindRegsAarch64};

use crate::unwind_result::UnwindResult;
use crate::FrameAddress;

use crate::dwarf::{
    eval_cfa_rule, eval_register_rule, ConversionError, DwarfUnwindRegs, DwarfUnwinderError,
    DwarfUnwinding,
};

impl DwarfUnwindRegs for UnwindRegsAarch64 {
    fn get(&self, register: Register) -> Option<u64> {
        match register {
            AArch64::SP => Some(self.sp()),
            AArch64::X29 => Some(self.fp()),
            AArch64::X30 => Some(self.lr()),
            _ => None,
        }
    }
}

impl DwarfUnwinding for ArchAarch64 {
    fn unwind_frame<F, R, S>(
        unwind_info: &UnwindTableRow<R, S>,
        encoding: Encoding,
        regs: &mut Self::UnwindRegs,
        address: FrameAddress,
        read_stack: &mut F,
    ) -> Result<UnwindResult<Self::UnwindRule>, DwarfUnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
        R: Reader,
        S: UnwindContextStorage<R> + EvaluationStorage<R>,
    {
        let cfa_rule = unwind_info.cfa();
        let fp_rule = unwind_info.register(AArch64::X29);
        let lr_rule = unwind_info.register(AArch64::X30);

        match translate_into_unwind_rule(cfa_rule, &fp_rule, &lr_rule) {
            Ok(unwind_rule) => return Ok(UnwindResult::ExecRule(unwind_rule)),
            Err(err) => {
                eprintln!("Unwind rule translation failed: {:?}", err);
            }
        }

        let cfa = eval_cfa_rule::<R, _, S>(cfa_rule, encoding, regs)
            .ok_or(DwarfUnwinderError::CouldNotRecoverCfa)?;

        let lr = regs.lr();
        let fp = regs.fp();
        let sp = regs.sp();

        let (fp, lr) = if address.is_return_address() {
            if cfa <= sp {
                return Err(DwarfUnwinderError::StackPointerMovedBackwards);
            }
            let fp = eval_register_rule::<R, F, _, S>(
                fp_rule,
                cfa,
                encoding,
                regs.fp(),
                regs,
                read_stack,
            )
            .ok_or(DwarfUnwinderError::CouldNotRecoverFramePointer)?;
            let lr = eval_register_rule::<R, F, _, S>(
                lr_rule,
                cfa,
                encoding,
                regs.lr(),
                regs,
                read_stack,
            )
            .ok_or(DwarfUnwinderError::CouldNotRecoverReturnAddress)?;
            (fp, lr)
        } else {
            // For the first frame, be more lenient when encountering errors.
            // TODO: Find evidence of what this gives us. I think on macOS the prologue often has Unknown register rules
            // and we only encounter prologues for the first frame.
            let fp = eval_register_rule::<R, F, _, S>(fp_rule, cfa, encoding, fp, regs, read_stack)
                .unwrap_or(fp);
            let lr = eval_register_rule::<R, F, _, S>(lr_rule, cfa, encoding, lr, regs, read_stack)
                .unwrap_or(lr);
            if cfa == sp && lr == address.address() {
                return Err(DwarfUnwinderError::DidNotAdvance);
            }
            (fp, lr)
        };

        regs.set_fp(fp);
        regs.set_sp(cfa);
        regs.set_lr(lr);

        Ok(UnwindResult::Uncacheable(lr))
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
    fp_rule: &RegisterRule<R>,
    lr_rule: &RegisterRule<R>,
) -> Result<UnwindRuleAarch64, ConversionError> {
    match cfa_rule {
        CfaRule::RegisterAndOffset { register, offset } => match *register {
            AArch64::SP => {
                let sp_offset_by_16 =
                    u16::try_from(offset / 16).map_err(|_| ConversionError::SpOffsetDoesNotFit)?;
                let lr_cfa_offset = register_rule_to_cfa_offset(lr_rule)?;
                let fp_cfa_offset = register_rule_to_cfa_offset(fp_rule)?;
                match (lr_cfa_offset, fp_cfa_offset) {
                    (None, Some(_)) => Err(ConversionError::RestoringFpButNotLr),
                    (None, None) => Ok(UnwindRuleAarch64::OffsetSp { sp_offset_by_16 }),
                    (Some(lr_cfa_offset), None) => {
                        let lr_storage_offset_from_sp_by_8 =
                            i16::try_from((offset + lr_cfa_offset) / 8)
                                .map_err(|_| ConversionError::LrStorageOffsetDoesNotFit)?;
                        Ok(UnwindRuleAarch64::OffsetSpAndRestoreLr {
                            sp_offset_by_16,
                            lr_storage_offset_from_sp_by_8,
                        })
                    }
                    (Some(lr_cfa_offset), Some(fp_cfa_offset)) => {
                        let lr_storage_offset_from_sp_by_8 =
                            i16::try_from((offset + lr_cfa_offset) / 8)
                                .map_err(|_| ConversionError::LrStorageOffsetDoesNotFit)?;
                        let fp_storage_offset_from_sp_by_8 =
                            i16::try_from((offset + fp_cfa_offset) / 8)
                                .map_err(|_| ConversionError::FpStorageOffsetDoesNotFit)?;
                        Ok(UnwindRuleAarch64::OffsetSpAndRestoreFpAndLr {
                            sp_offset_by_16,
                            fp_storage_offset_from_sp_by_8,
                            lr_storage_offset_from_sp_by_8,
                        })
                    }
                }
            }
            AArch64::X29 => {
                let lr_cfa_offset = register_rule_to_cfa_offset(lr_rule)?
                    .ok_or(ConversionError::FramePointerRuleDoesNotRestoreLr)?;
                let fp_cfa_offset = register_rule_to_cfa_offset(fp_rule)?
                    .ok_or(ConversionError::FramePointerRuleDoesNotRestoreFp)?;
                if *offset == 16 && fp_cfa_offset == -16 && lr_cfa_offset == -8 {
                    Ok(UnwindRuleAarch64::UseFramePointer)
                } else {
                    let sp_offset_from_fp_by_8 = u16::try_from(offset / 8)
                        .map_err(|_| ConversionError::SpOffsetFromFpDoesNotFit)?;
                    let lr_storage_offset_from_fp_by_8 =
                        i16::try_from((offset + lr_cfa_offset) / 8)
                            .map_err(|_| ConversionError::LrStorageOffsetDoesNotFit)?;
                    let fp_storage_offset_from_fp_by_8 =
                        i16::try_from((offset + fp_cfa_offset) / 8)
                            .map_err(|_| ConversionError::FpStorageOffsetDoesNotFit)?;
                    Ok(UnwindRuleAarch64::UseFramepointerWithOffsets {
                        sp_offset_from_fp_by_8,
                        fp_storage_offset_from_fp_by_8,
                        lr_storage_offset_from_fp_by_8,
                    })
                }
            }
            _ => Err(ConversionError::CfaIsOffsetFromUnknownRegister),
        },
        CfaRule::Expression(_) => Err(ConversionError::CfaIsExpression),
    }
}
