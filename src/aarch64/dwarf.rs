use core::cell::Cell;

use gimli::{
    AArch64, CfaRule, Encoding, EvaluationStorage, Reader, ReaderOffset, Register, RegisterRule,
    UnwindContextStorage, UnwindSection, UnwindTableRow,
};

use super::{
    arch::ArchAarch64,
    unwind_rule::{
        CalleeSavedRuleAarch64, CalleeSavedRulesAarch64, FrameRuleAarch64, UnwindRuleAarch64,
    },
    unwindregs::{UnwindRegsAarch64, CALLEE_SAVED_COUNT, FIRST_CALLEE_SAVED},
};

use crate::error::Error;
use crate::unwind_result::UnwindResult;

use crate::dwarf::{
    eval_cfa_rule, eval_register_rule, ConversionError, DwarfUnwindRegs, DwarfUnwinderError,
    DwarfUnwinding,
};

impl DwarfUnwindRegs for UnwindRegsAarch64 {
    fn get(&self, register: Register) -> Option<u64> {
        self.get_reg(register.0)
    }
}

/// Wraps the registers for DWARF evaluation and records whether a rule asked for a
/// callee-saved register whose value is unknown. Such a failure depends on the walk,
/// not only on the unwind information.
struct RecordUnknownReads<'a> {
    regs: &'a UnwindRegsAarch64,
    read_unknown: Cell<bool>,
}

impl<'a> RecordUnknownReads<'a> {
    fn new(regs: &'a UnwindRegsAarch64) -> Self {
        Self {
            regs,
            read_unknown: Cell::new(false),
        }
    }

    /// `err`, or `RegisterValueUnknown` if an unknown register was read.
    fn error(&self, err: DwarfUnwinderError) -> DwarfUnwinderError {
        if self.read_unknown.get() {
            DwarfUnwinderError::RegisterValueUnknown
        } else {
            err
        }
    }
}

impl DwarfUnwindRegs for RecordUnknownReads<'_> {
    fn get(&self, register: Register) -> Option<u64> {
        let value = self.regs.get_reg(register.0);
        let is_callee_saved = (FIRST_CALLEE_SAVED..FIRST_CALLEE_SAVED + CALLEE_SAVED_COUNT as u16)
            .contains(&register.0);
        if value.is_none() && is_callee_saved {
            self.read_unknown.set(true);
        }
        value
    }
}

impl DwarfUnwinding for ArchAarch64 {
    const VENDOR: gimli::Vendor = gimli::Vendor::AArch64;

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
        match translate_into_unwind_rule(unwind_info) {
            Ok(unwind_rule) => return Ok(UnwindResult::ExecRule(unwind_rule)),
            Err(_err) => {
                // Could not translate into a cacheable unwind rule. Fall back to the generic path.
                // eprintln!("Unwind rule translation failed: {:?}", err);
            }
        }

        match unwind_frame_generic::<F, R, UCS, ES>(
            section,
            unwind_info,
            encoding,
            regs,
            is_first_frame,
            read_stack,
        ) {
            Ok(return_address) => Ok(UnwindResult::Uncacheable(return_address)),
            // Another walk may know the register, so cache nothing. End this walk, as
            // UseDerefedRegister does when its register is unknown.
            Err(DwarfUnwinderError::RegisterValueUnknown) => {
                Ok(UnwindResult::UncacheableError(Error::RegisterValueUnknown))
            }
            // The failure only depends on the unwind information. The caller caches
            // the fallback rule for this address.
            Err(err) => Err(err),
        }
    }

    fn rule_if_uncovered_by_fde() -> Self::UnwindRule {
        FrameRuleAarch64::NoOpIfFirstFrameOtherwiseFp.into()
    }
}

/// Evaluate the row directly. All rules are evaluated against the register values
/// before the step.
fn unwind_frame_generic<F, R, UCS, ES>(
    section: &impl UnwindSection<R>,
    unwind_info: &UnwindTableRow<R::Offset, UCS>,
    encoding: Encoding,
    regs: &mut UnwindRegsAarch64,
    is_first_frame: bool,
    read_stack: &mut F,
) -> Result<u64, DwarfUnwinderError>
where
    F: FnMut(u64) -> Result<u64, ()>,
    R: Reader,
    UCS: UnwindContextStorage<R::Offset>,
    ES: EvaluationStorage<R>,
{
    let cfa_rule = unwind_info.cfa();
    let fp_rule = unwind_info.register(AArch64::X29);
    let lr_rule = unwind_info.register(AArch64::X30);

    let reads = RecordUnknownReads::new(regs);
    let cfa = eval_cfa_rule::<R, F, _, ES>(section, cfa_rule, encoding, &reads, read_stack)
        .ok_or_else(|| reads.error(DwarfUnwinderError::CouldNotRecoverCfa))?;

    let lr = regs.lr();
    let fp = regs.fp();
    let sp = regs.sp();

    let (fp, lr) = if !is_first_frame {
        if cfa <= sp {
            return Err(DwarfUnwinderError::StackPointerMovedBackwards);
        }
        let fp = eval_register_rule::<R, F, _, ES>(
            section, fp_rule, cfa, encoding, fp, &reads, read_stack,
        )
        .ok_or_else(|| reads.error(DwarfUnwinderError::CouldNotRecoverFramePointer))?;
        let lr = eval_register_rule::<R, F, _, ES>(
            section, lr_rule, cfa, encoding, lr, &reads, read_stack,
        )
        .ok_or_else(|| reads.error(DwarfUnwinderError::CouldNotRecoverReturnAddress))?;
        (fp, lr)
    } else {
        // For the first frame, be more lenient when encountering errors.
        // TODO: Find evidence of what this gives us. I think on macOS the prologue often has Unknown register rules
        // and we only encounter prologues for the first frame.
        let fp = eval_register_rule::<R, F, _, ES>(
            section, fp_rule, cfa, encoding, fp, regs, read_stack,
        )
        .unwrap_or(fp);
        let lr = eval_register_rule::<R, F, _, ES>(
            section, lr_rule, cfa, encoding, lr, regs, read_stack,
        )
        .unwrap_or(lr);
        (fp, lr)
    };

    let mut callee_saved = [None; CALLEE_SAVED_COUNT];
    for (i, value) in callee_saved.iter_mut().enumerate() {
        let reg = FIRST_CALLEE_SAVED + i as u16;
        let old_value = regs.callee_saved(reg);
        *value = match unwind_info.register(Register(reg)) {
            None | Some(RegisterRule::SameValue) => old_value,
            rule @ Some(_) => eval_register_rule::<R, F, _, ES>(
                section,
                rule,
                cfa,
                encoding,
                old_value.unwrap_or_default(),
                regs,
                read_stack,
            ),
        };
    }
    for (i, value) in callee_saved.into_iter().enumerate() {
        regs.set_callee_saved(FIRST_CALLEE_SAVED + i as u16, value);
    }

    regs.set_fp(fp);
    regs.set_sp(cfa);
    regs.set_lr(lr);

    Ok(lr)
}

fn register_rule_to_cfa_offset<RO: ReaderOffset>(
    rule: Option<&RegisterRule<RO>>,
) -> Result<Option<i64>, ConversionError> {
    let Some(rule) = rule else { return Ok(None) };
    match *rule {
        RegisterRule::Undefined | RegisterRule::SameValue => Ok(None),
        RegisterRule::Offset(offset) => Ok(Some(offset)),
        _ => Err(ConversionError::RegisterNotStoredRelativeToCfa),
    }
}

fn translate_into_unwind_rule<RO, UCS>(
    unwind_info: &UnwindTableRow<RO, UCS>,
) -> Result<UnwindRuleAarch64, ConversionError>
where
    RO: ReaderOffset,
    UCS: UnwindContextStorage<RO>,
{
    let mut callee_saved = CalleeSavedRulesAarch64::ALL_UNCHANGED;
    for (register, rule) in unwind_info.registers() {
        let reg = register.0;
        let is_callee_saved =
            (FIRST_CALLEE_SAVED..FIRST_CALLEE_SAVED + CALLEE_SAVED_COUNT as u16).contains(&reg);
        if !is_callee_saved {
            continue;
        }
        let callee_saved_rule = match *rule {
            RegisterRule::SameValue => CalleeSavedRuleAarch64::Unchanged,
            RegisterRule::Undefined => CalleeSavedRuleAarch64::Unknown,
            RegisterRule::Offset(offset) => CalleeSavedRuleAarch64::SavedAtCfaOffset(
                i16::try_from(offset).map_err(|_| ConversionError::CalleeSavedRuleDoesNotFit)?,
            ),
            _ => return Err(ConversionError::CalleeSavedRuleNotCacheable),
        };
        if !callee_saved.set(reg, callee_saved_rule) {
            return Err(ConversionError::CalleeSavedRuleDoesNotFit);
        }
    }

    let fp_rule = unwind_info.register(AArch64::X29);
    let lr_rule = unwind_info.register(AArch64::X30);
    let frame = translate_into_frame_rule(unwind_info.cfa(), fp_rule.as_ref(), lr_rule.as_ref())?;
    Ok(UnwindRuleAarch64::new(frame, callee_saved))
}

fn translate_into_frame_rule<RO: ReaderOffset>(
    cfa_rule: &CfaRule<RO>,
    fp_rule: Option<&RegisterRule<RO>>,
    lr_rule: Option<&RegisterRule<RO>>,
) -> Result<FrameRuleAarch64, ConversionError> {
    match cfa_rule {
        CfaRule::RegisterAndOffset { register, offset } => match *register {
            AArch64::SP => {
                let sp_offset_by_16 =
                    u16::try_from(offset / 16).map_err(|_| ConversionError::SpOffsetDoesNotFit)?;
                let lr_cfa_offset = register_rule_to_cfa_offset(lr_rule)?;
                let fp_cfa_offset = register_rule_to_cfa_offset(fp_rule)?;
                match (lr_cfa_offset, fp_cfa_offset) {
                    (None, Some(_)) => Err(ConversionError::RestoringFpButNotLr),
                    (None, None) => {
                        match lr_rule {
                            None => {
                                // The column for the return address register was omitted from the DWARF CFI table.
                                // Per spec (at least as of DWARF >= 3), this means that it should be treated
                                // as undefined. However, in practice, it seems that compilers often omit the rule
                                // to say "same value", see https://github.com/gimli-rs/gimli/issues/857 .
                                Ok(FrameRuleAarch64::OffsetSp { sp_offset_by_16 })
                            }
                            Some(RegisterRule::Undefined) => {
                                // The column for the return address was manually set to "undefined"
                                // using DW_CFA_undefined. This usually means that the function never returns
                                // and can be treated as the root of the stack.
                                Ok(
                                    FrameRuleAarch64::OffsetSpIfFirstFrameOtherwiseStackEndsHere {
                                        sp_offset_by_16,
                                    },
                                )
                            }
                            _ => Ok(FrameRuleAarch64::OffsetSp { sp_offset_by_16 }),
                        }
                    }
                    (Some(lr_cfa_offset), None) => {
                        let lr_storage_offset_from_sp_by_8 =
                            i16::try_from((offset + lr_cfa_offset) / 8)
                                .map_err(|_| ConversionError::LrStorageOffsetDoesNotFit)?;
                        Ok(FrameRuleAarch64::OffsetSpAndRestoreLr {
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
                        Ok(FrameRuleAarch64::OffsetSpAndRestoreFpAndLr {
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
                    Ok(FrameRuleAarch64::UseFramePointer)
                } else {
                    let sp_offset_from_fp_by_8 = u16::try_from(offset / 8)
                        .map_err(|_| ConversionError::SpOffsetFromFpDoesNotFit)?;
                    let lr_storage_offset_from_fp_by_8 =
                        i16::try_from((offset + lr_cfa_offset) / 8)
                            .map_err(|_| ConversionError::LrStorageOffsetDoesNotFit)?;
                    let fp_storage_offset_from_fp_by_8 =
                        i16::try_from((offset + fp_cfa_offset) / 8)
                            .map_err(|_| ConversionError::FpStorageOffsetDoesNotFit)?;
                    Ok(FrameRuleAarch64::UseFramepointerWithOffsets {
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
