use gimli::{
    CfaRule, Encoding, EvaluationResult, Expression, Location, Reader, RegisterRule,
    UnwindContextStorage, UnwindTableRow, Value, X86_64,
};

use crate::{
    arch::ArchX86_64, rules::UnwindRuleX86_64, unwind_result::UnwindResult,
    unwindregs::UnwindRegsX86_64,
};

use super::{ConversionError, DwarfUnwinderError, DwarfUnwinding};

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
        let cfa = match eval_cfa_rule(cfa_rule, pc, encoding, regs) {
            Some(cfa) => cfa,
            None => {
                // eprintln!("Could not recover CFA.");
                return Err(DwarfUnwinderError::CouldNotRecoverCfa);
            }
        };

        // eprintln!("cfa: {:x}", cfa);

        let bp = regs.bp();

        let bp = eval_rule(bp_rule, cfa, encoding, pc, bp, regs, read_mem).unwrap_or(bp);

        let return_address = match eval_rule(ra_rule, cfa, encoding, pc, pc, regs, read_mem) {
            Some(ra) => ra,
            None => {
                read_mem(cfa - 8).map_err(|_| DwarfUnwinderError::CouldNotRecoverReturnAddress)?
            }
        };

        regs.set_bp(bp);
        regs.set_sp(cfa);

        Ok(UnwindResult::Uncacheable(return_address))
    }

    fn unwind_next<F, R, S>(
        unwind_info: &UnwindTableRow<R, S>,
        encoding: Encoding,
        regs: &mut Self::UnwindRegs,
        return_address: u64, // regs.rip()
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
        let rip = return_address;
        let cfa = eval_cfa_rule(cfa_rule, rip, encoding, regs)
            .ok_or(DwarfUnwinderError::CouldNotRecoverCfa)?;
        if cfa <= regs.sp() {
            return Err(DwarfUnwinderError::StackPointerMovedBackwards);
        }

        // eprintln!("cfa: {:x}", cfa);
        // println!("rules: fp {:?}, lr {:?}", bp_rule, lr_rule);
        let bp = eval_rule(bp_rule, cfa, encoding, rip, regs.bp(), regs, read_mem)
            .ok_or(DwarfUnwinderError::CouldNotRecoverFramePointer)?;

        let return_address = match eval_rule(ra_rule, cfa, encoding, rip, rip, regs, read_mem) {
            Some(ra) => ra,
            None => {
                read_mem(cfa - 8).map_err(|_| DwarfUnwinderError::CouldNotRecoverReturnAddress)?
            }
        };

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
        RegisterRule::ValOffset(_)
        | RegisterRule::Register(_)
        | RegisterRule::Expression(_)
        | RegisterRule::ValExpression(_)
        | RegisterRule::Architectural => Err(ConversionError::RegisterNotStoredRelativeToCfa),
    }
}

fn translate_into_unwind_rule<R: gimli::Reader>(
    cfa_rule: &CfaRule<R>,
    bp_rule: &RegisterRule<R>,
    ra_rule: &RegisterRule<R>,
) -> Result<UnwindRuleX86_64, ConversionError> {
    match ra_rule {
        RegisterRule::Undefined => {
            // This is normal. Return address is at [CFA-8].
        }
        RegisterRule::Offset(offset) => {
            if *offset == -8 {
                // Weirdly explicit, but also ok.
            } else {
                // Not ok.
                return Err(ConversionError::ReturnAddressRuleWithUnexpectedOffset);
            }
        }
        RegisterRule::SameValue
        | RegisterRule::ValOffset(_)
        | RegisterRule::Register(_)
        | RegisterRule::Expression(_)
        | RegisterRule::ValExpression(_)
        | RegisterRule::Architectural => {
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
                    // let sp_offset_from_bp_by_8 = u8::try_from(offset / 8)
                    //     .map_err(|_| ConversionError::SpOffsetFromBpDoesNotFit)?;
                    // let bp_storage_offset_from_bp_by_8 = i8::try_from((offset + bp_cfa_offset) / 8)
                    //     .map_err(|_| ConversionError::BpStorageOffsetDoesNotFit)?;
                    // Ok(UnwindRuleX86_64::UseFramepointerWithOffsets {
                    //     sp_offset_from_bp_by_8,
                    //     bp_storage_offset_from_bp_by_8,
                    // })
                }
            }
            _ => Err(ConversionError::CfaIsOffsetFromUnknownRegister),
        },
        CfaRule::Expression(_) => Err(ConversionError::CfaIsExpression),
    }
}

fn eval_cfa_rule<R: gimli::Reader>(
    rule: &CfaRule<R>,
    rip: u64,
    encoding: Encoding,
    regs: &UnwindRegsX86_64,
) -> Option<u64> {
    match rule {
        CfaRule::RegisterAndOffset { register, offset } => {
            let val = match *register {
                X86_64::RSP => regs.sp(),
                X86_64::RBP => regs.bp(),
                X86_64::RA => rip,
                _ => return None,
            };
            u64::try_from(i64::try_from(val).ok()?.checked_add(*offset)?).ok()
        }
        CfaRule::Expression(expr) => eval_expr(expr.clone(), encoding, rip, regs),
    }
}

fn eval_expr<R: gimli::Reader>(
    expr: Expression<R>,
    encoding: Encoding,
    rip: u64,
    regs: &UnwindRegsX86_64,
) -> Option<u64> {
    let mut eval = expr.evaluation(encoding);
    let mut result = eval.evaluate().ok()?;
    loop {
        match result {
            EvaluationResult::Complete => break,
            EvaluationResult::RequiresRegister { register, .. } => {
                let value = match register {
                    X86_64::RSP => regs.sp(),
                    X86_64::RBP => regs.bp(),
                    X86_64::RA => rip,
                    _ => return None,
                };
                result = eval.resume_with_register(Value::Generic(value as _)).ok()?;
            }
            _ => return None,
        }
    }
    let x = &eval.as_result().last()?.location;
    if let Location::Address { address } = x {
        Some(*address)
    } else {
        None
    }
}

fn eval_rule<R, F>(
    rule: RegisterRule<R>,
    cfa: u64,
    encoding: Encoding,
    rip: u64,
    val: u64,
    regs: &UnwindRegsX86_64,
    read_mem: &mut F,
) -> Option<u64>
where
    R: gimli::Reader,
    F: FnMut(u64) -> Result<u64, ()>,
{
    match rule {
        RegisterRule::Undefined => None,
        RegisterRule::SameValue => Some(val),
        RegisterRule::Offset(offset) => {
            let cfa_plus_offset =
                u64::try_from(i64::try_from(cfa).ok()?.checked_add(offset)?).ok()?;
            read_mem(cfa_plus_offset).ok()
        }
        RegisterRule::ValOffset(offset) => {
            u64::try_from(i64::try_from(cfa).ok()?.checked_add(offset)?).ok()
        }
        RegisterRule::Register(register) => match register {
            X86_64::RSP => Some(regs.sp()),
            X86_64::RBP => Some(regs.bp()),
            _ => None,
        },
        RegisterRule::Expression(_) => {
            println!("Unimplemented RegisterRule::Expression");
            None
        }
        RegisterRule::ValExpression(expr) => eval_expr(expr, encoding, rip, regs),
        RegisterRule::Architectural => {
            println!("Unimplemented RegisterRule::Architectural");
            None
        }
    }
}
