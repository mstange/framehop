use gimli::{
    BaseAddresses, CfaRule, Reader, ReaderOffset, RegisterRule, UnwindContext, UnwindSection,
    UnwindTableRow, X86_64,
};

use crate::{
    rules::UnwindRuleX86_64, unwind_result::UnwindResult, unwindregs::UnwindRegsX86_64,
    SectionAddresses,
};

use super::{ConversionError, DwarfUnwinderError};

pub struct DwarfUnwinderX86_64<'a, R: Reader> {
    eh_frame_data: R,
    unwind_context: &'a mut UnwindContext<R>,
    bases: BaseAddresses,
}

impl<'a, R: Reader> DwarfUnwinderX86_64<'a, R> {
    pub fn new(
        eh_frame_data: R,
        unwind_context: &'a mut UnwindContext<R>,
        sections: &SectionAddresses,
    ) -> Self {
        Self {
            eh_frame_data,
            unwind_context,
            bases: BaseAddresses::default()
                .set_eh_frame(sections.eh_frame)
                .set_eh_frame_hdr(sections.eh_frame_hdr)
                .set_text(sections.text)
                .set_got(sections.got),
        }
    }

    pub fn unwind_first_with_fde<F>(
        &mut self,
        regs: &mut UnwindRegsX86_64,
        pc: u64,
        fde_offset: u32,
        read_mem: &mut F,
    ) -> Result<UnwindResult<UnwindRuleX86_64>, DwarfUnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        let mut eh_frame = gimli::EhFrame::from(self.eh_frame_data.clone());
        eh_frame.set_address_size(8);
        let fde = eh_frame.fde_from_offset(
            &self.bases,
            gimli::EhFrameOffset::from(R::Offset::from_u32(fde_offset)),
            gimli::EhFrame::cie_from_offset,
        );
        let fde = fde.map_err(DwarfUnwinderError::FdeFromOffsetFailed)?;
        let unwind_info: &UnwindTableRow<_, _> =
            match fde.unwind_info_for_address(&eh_frame, &self.bases, self.unwind_context, pc) {
                Ok(unwind_info) => unwind_info,
                Err(e) => {
                    eprintln!(
                  "unwind_info_for_address error at pc 0x{:x} using FDE at offset 0x{:x}: {:?}",
                  pc, fde_offset, e
              );
                    return Err(DwarfUnwinderError::UnwindInfoForAddressFailed(e));
                }
            };
        let cfa_rule = unwind_info.cfa();
        let bp_rule = unwind_info.register(X86_64::RBP);

        match translate_into_unwind_rule(cfa_rule, &bp_rule) {
            Ok(unwind_rule) => return Ok(UnwindResult::ExecRule(unwind_rule)),
            Err(err) => {
                eprintln!("Unwind rule translation failed: {:?}", err);
            }
        }

        // println!("cfa rule: {:?}, regs: {:?}", cfa_rule, regs);
        let cfa = eval_cfa_rule(cfa_rule, regs).ok_or(DwarfUnwinderError::CouldNotRecoverCfa)?;

        let bp = regs.bp();
        let sp = regs.sp();

        if cfa < sp {
            return Err(DwarfUnwinderError::StackPointerMovedBackwards);
        }
        // println!("cfa: {:x}", cfa);
        // println!("rules: bp {:?}, lr {:?}", bp_rule, lr_rule);
        let bp = eval_rule(bp_rule, cfa, bp, regs, read_mem).unwrap_or(bp);

        if cfa == sp {
            return Err(DwarfUnwinderError::DidNotAdvance);
        }

        let return_address =
            read_mem(cfa - 8).map_err(|_| DwarfUnwinderError::CouldNotRecoverReturnAddress)?;

        regs.set_bp(bp);
        regs.set_sp(cfa);

        Ok(UnwindResult::Uncacheable(return_address))
    }

    pub fn unwind_next_with_fde<F>(
        &mut self,
        regs: &mut UnwindRegsX86_64,
        return_address: u64,
        fde_offset: u32,
        read_mem: &mut F,
    ) -> Result<UnwindResult<UnwindRuleX86_64>, DwarfUnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        let mut eh_frame = gimli::EhFrame::from(self.eh_frame_data.clone());
        eh_frame.set_address_size(8);
        let fde = eh_frame.fde_from_offset(
            &self.bases,
            gimli::EhFrameOffset::from(R::Offset::from_u32(fde_offset)),
            gimli::EhFrame::cie_from_offset,
        );
        let fde = fde.map_err(DwarfUnwinderError::FdeFromOffsetFailed)?;
        let unwind_info: &UnwindTableRow<_, _> = match fde.unwind_info_for_address(
            &eh_frame,
            &self.bases,
            self.unwind_context,
            return_address - 1,
        ) {
            Ok(unwind_info) => unwind_info,
            Err(e) => {
                eprintln!(
                    "unwind_info_for_address error at pc 0x{:x} using FDE at offset 0x{:x}: {:?}",
                    return_address - 1,
                    fde_offset,
                    e
                );
                return Err(DwarfUnwinderError::UnwindInfoForAddressFailed(e));
            }
        };
        let cfa_rule = unwind_info.cfa();
        let bp_rule = unwind_info.register(X86_64::RBP);

        match translate_into_unwind_rule(cfa_rule, &bp_rule) {
            Ok(unwind_rule) => return Ok(UnwindResult::ExecRule(unwind_rule)),
            Err(err) => {
                eprintln!("Unwind rule translation failed: {:?}", err);
            }
        }

        // println!("cfa rule: {:?}, regs: {:?}", cfa_rule, regs);
        let cfa = eval_cfa_rule(cfa_rule, regs).ok_or(DwarfUnwinderError::CouldNotRecoverCfa)?;
        if cfa <= regs.sp() {
            return Err(DwarfUnwinderError::StackPointerMovedBackwards);
        }

        // println!("cfa: {:x}", cfa);
        // println!("rules: fp {:?}, lr {:?}", bp_rule, lr_rule);
        let bp = eval_rule(bp_rule, cfa, regs.bp(), regs, read_mem)
            .ok_or(DwarfUnwinderError::CouldNotRecoverFramePointer)?;

        let return_address =
            read_mem(cfa - 8).map_err(|_| DwarfUnwinderError::CouldNotRecoverReturnAddress)?;

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
) -> Result<UnwindRuleX86_64, ConversionError> {
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

fn eval_cfa_rule<R: gimli::Reader>(rule: &CfaRule<R>, regs: &UnwindRegsX86_64) -> Option<u64> {
    match rule {
        CfaRule::RegisterAndOffset { register, offset } => {
            let val = match *register {
                X86_64::RSP => regs.sp(),
                X86_64::RBP => regs.bp(),
                _ => return None,
            };
            u64::try_from(i64::try_from(val).ok()?.checked_add(*offset)?).ok()
        }
        CfaRule::Expression(_) => None,
    }
}

fn eval_rule<R, F>(
    rule: RegisterRule<R>,
    cfa: u64,
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
        RegisterRule::ValExpression(_) => {
            println!("Unimplemented RegisterRule::ValExpression");
            None
        }
        RegisterRule::Architectural => {
            println!("Unimplemented RegisterRule::Architectural");
            None
        }
    }
}