use gimli::{
    AArch64, BaseAddresses, CfaRule, Reader, ReaderOffset, RegisterRule, UnwindContext,
    UnwindSection, UnwindTableRow,
};

use crate::{
    rules::UnwindRuleArm64, unwind_result::UnwindResult, unwindregs::UnwindRegsArm64,
    SectionAddresses,
};

use super::DwarfUnwinderError;

pub struct DwarfUnwinderAarch64<'a, R: Reader> {
    eh_frame_data: R,
    unwind_context: &'a mut UnwindContext<R>,
    bases: BaseAddresses,
}

impl<'a, R: Reader> DwarfUnwinderAarch64<'a, R> {
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
        regs: &mut UnwindRegsArm64,
        pc: u64,
        fde_offset: u32,
        read_mem: &mut F,
    ) -> Result<UnwindResult<UnwindRuleArm64>, DwarfUnwinderError>
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
        let fp_rule = unwind_info.register(AArch64::X29);
        let lr_rule = unwind_info.register(AArch64::X30);

        match translate_into_unwind_rule(cfa_rule, &fp_rule, &lr_rule) {
            Ok(unwind_rule) => return Ok(UnwindResult::ExecRule(unwind_rule)),
            Err(err) => {
                eprintln!("Unwind rule translation failed: {:?}", err);
            }
        }

        // println!("cfa rule: {:?}, regs: {:?}", cfa_rule, regs);
        let cfa = eval_cfa_rule(cfa_rule, regs).ok_or(DwarfUnwinderError::CouldNotRecoverCfa)?;

        let lr = regs.lr();
        let fp = regs.fp();
        let sp = regs.sp();

        if cfa < sp {
            return Err(DwarfUnwinderError::StackPointerMovedBackwards);
        }
        // println!("cfa: {:x}", cfa);
        // println!("rules: fp {:?}, lr {:?}", fp_rule, lr_rule);
        let fp = eval_rule(fp_rule, cfa, fp, regs, read_mem).unwrap_or(fp);
        let lr = eval_rule(lr_rule, cfa, lr, regs, read_mem).unwrap_or(lr);

        if cfa == sp && lr == pc {
            return Err(DwarfUnwinderError::DidNotAdvance);
        }

        regs.set_fp(fp);
        regs.set_sp(cfa);
        regs.set_lr(lr);

        Ok(UnwindResult::Uncacheable(lr))
    }

    pub fn unwind_next_with_fde<F>(
        &mut self,
        regs: &mut UnwindRegsArm64,
        return_address: u64,
        fde_offset: u32,
        read_mem: &mut F,
    ) -> Result<UnwindResult<UnwindRuleArm64>, DwarfUnwinderError>
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
        let fp_rule = unwind_info.register(AArch64::X29);
        let lr_rule = unwind_info.register(AArch64::X30);

        match translate_into_unwind_rule(cfa_rule, &fp_rule, &lr_rule) {
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
        // println!("rules: fp {:?}, lr {:?}", fp_rule, lr_rule);
        let fp = eval_rule(fp_rule, cfa, regs.fp(), regs, read_mem)
            .ok_or(DwarfUnwinderError::CouldNotRecoverFramePointer)?;
        let lr = eval_rule(lr_rule, cfa, regs.lr(), regs, read_mem)
            .ok_or(DwarfUnwinderError::CouldNotRecoverReturnAddress)?;
        regs.set_fp(fp);
        regs.set_sp(cfa);
        regs.set_lr(lr);

        Ok(UnwindResult::Uncacheable(lr))
    }
}

#[derive(Clone, Debug)]
enum ConversionError {
    CfaIsExpression,
    CfaIsOffsetFromUnknownRegister,
    SpOffsetDoesNotFit,
    RegisterNotStoredRelativeToCfa,
    RestoringFpButNotLr,
    LrStorageOffsetDoesNotFit,
    FpStorageOffsetDoesNotFit,
    SpOffsetFromFpDoesNotFit,
    FramePointerRuleDoesNotRestoreLr,
    FramePointerRuleDoesNotRestoreFp,
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
    fp_rule: &RegisterRule<R>,
    lr_rule: &RegisterRule<R>,
) -> Result<UnwindRuleArm64, ConversionError> {
    match cfa_rule {
        CfaRule::RegisterAndOffset { register, offset } => match *register {
            AArch64::SP => {
                let sp_offset_by_16 =
                    u8::try_from(offset / 16).map_err(|_| ConversionError::SpOffsetDoesNotFit)?;
                let lr_cfa_offset = register_rule_to_cfa_offset(lr_rule)?;
                let fp_cfa_offset = register_rule_to_cfa_offset(fp_rule)?;
                match (lr_cfa_offset, fp_cfa_offset) {
                    (None, Some(_)) => Err(ConversionError::RestoringFpButNotLr),
                    (None, None) => Ok(UnwindRuleArm64::OffsetSp { sp_offset_by_16 }),
                    (Some(lr_cfa_offset), None) => {
                        let lr_storage_offset_from_sp_by_8 =
                            i8::try_from((offset + lr_cfa_offset) / 8)
                                .map_err(|_| ConversionError::LrStorageOffsetDoesNotFit)?;
                        Ok(UnwindRuleArm64::OffsetSpAndRestoreLr {
                            sp_offset_by_16,
                            lr_storage_offset_from_sp_by_8,
                        })
                    }
                    (Some(lr_cfa_offset), Some(fp_cfa_offset)) => {
                        let lr_storage_offset_from_sp_by_8 =
                            i8::try_from((offset + lr_cfa_offset) / 8)
                                .map_err(|_| ConversionError::LrStorageOffsetDoesNotFit)?;
                        let fp_storage_offset_from_sp_by_8 =
                            i8::try_from((offset + fp_cfa_offset) / 8)
                                .map_err(|_| ConversionError::FpStorageOffsetDoesNotFit)?;
                        Ok(UnwindRuleArm64::OffsetSpAndRestoreFpAndLr {
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
                    Ok(UnwindRuleArm64::UseFramePointer)
                } else {
                    let sp_offset_from_fp_by_8 = u8::try_from(offset / 8)
                        .map_err(|_| ConversionError::SpOffsetFromFpDoesNotFit)?;
                    let lr_storage_offset_from_fp_by_8 = i8::try_from((offset + lr_cfa_offset) / 8)
                        .map_err(|_| ConversionError::LrStorageOffsetDoesNotFit)?;
                    let fp_storage_offset_from_fp_by_8 = i8::try_from((offset + fp_cfa_offset) / 8)
                        .map_err(|_| ConversionError::FpStorageOffsetDoesNotFit)?;
                    Ok(UnwindRuleArm64::UseFramepointerWithOffsets {
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

fn eval_cfa_rule<R: gimli::Reader>(rule: &CfaRule<R>, regs: &UnwindRegsArm64) -> Option<u64> {
    match rule {
        CfaRule::RegisterAndOffset { register, offset } => {
            let val = match *register {
                AArch64::SP => regs.sp(),
                AArch64::X29 => regs.fp(),
                AArch64::X30 => regs.lr(),
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
    regs: &UnwindRegsArm64,
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
            AArch64::SP => Some(regs.sp()),
            AArch64::X29 => Some(regs.fp()),
            AArch64::X30 => Some(regs.lr()),
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
