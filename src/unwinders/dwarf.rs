use gimli::{
    AArch64, BaseAddresses, CfaRule, Reader, ReaderOffset, RegisterRule, UnwindContext,
    UnwindSection, UnwindTableRow,
};

use crate::{unwindregs::UnwindRegsArm64, SectionAddresses};

pub struct DwarfUnwinder<'a, R: Reader> {
    eh_frame_data: R,
    unwind_context: &'a mut UnwindContext<R>,
    bases: BaseAddresses,
}

#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum DwarfUnwinderError {
    #[error("Could not get the FDE for the supplied offset: {0}")]
    FdeFromOffsetFailed(#[source] gimli::Error),

    #[error("Could not find DWARF unwind info for the requested address: {0}")]
    UnwindInfoForAddressFailed(#[source] gimli::Error),

    #[error("Stack pointer moved backwards")]
    StackPointerMovedBackwards,

    #[error("Did not advance")]
    DidNotAdvance,

    #[error("Could not recover the CFA")]
    CouldNotRecoverCfa,

    #[error("Could not recover the return address")]
    CouldNotRecoverReturnAddress,

    #[error("Could not recover the frame pointer")]
    CouldNotRecoverFramePointer,
}

impl<'a, R: Reader> DwarfUnwinder<'a, R> {
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
        read_stack: &mut F,
    ) -> Result<u64, DwarfUnwinderError>
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
                    println!(
                    "unwind_info_for_address error at pc 0x{:x} using FDE at offset 0x{:x}: {:?}",
                    pc, fde_offset, e
                );
                    return Err(DwarfUnwinderError::UnwindInfoForAddressFailed(e));
                }
            };
        let cfa_rule = unwind_info.cfa();
        // println!("cfa rule: {:?}, regs: {:?}", cfa_rule, regs);
        let cfa = eval_cfa_rule(cfa_rule, regs).ok_or(DwarfUnwinderError::CouldNotRecoverCfa)?;

        let lr = regs.lr();
        let fp = regs.fp();
        let sp = regs.sp();

        if cfa < sp {
            return Err(DwarfUnwinderError::StackPointerMovedBackwards);
        }
        // println!("cfa: {:x}", cfa);
        let fp_rule = unwind_info.register(AArch64::X29);
        let lr_rule = unwind_info.register(AArch64::X30);
        // println!("rules: fp {:?}, lr {:?}", fp_rule, lr_rule);
        let fp = eval_rule(fp_rule, cfa, fp, regs, read_stack).unwrap_or(fp);
        let lr = eval_rule(lr_rule, cfa, lr, regs, read_stack).unwrap_or(lr);

        if cfa == sp && lr == pc {
            return Err(DwarfUnwinderError::DidNotAdvance);
        }

        regs.set_fp(fp);
        regs.set_sp(cfa);
        regs.set_lr(lr);

        Ok(lr)
    }

    pub fn unwind_next_with_fde<F>(
        &mut self,
        regs: &mut UnwindRegsArm64,
        return_address: u64,
        fde_offset: u32,
        read_stack: &mut F,
    ) -> Result<u64, DwarfUnwinderError>
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
            match fde.unwind_info_for_address(
                &eh_frame,
                &self.bases,
                self.unwind_context,
                return_address - 1,
            ) {
                Ok(unwind_info) => unwind_info,
                Err(e) => {
                    println!(
                    "unwind_info_for_address error at pc 0x{:x} using FDE at offset 0x{:x}: {:?}",
                    return_address - 1, fde_offset, e
                );
                    return Err(DwarfUnwinderError::UnwindInfoForAddressFailed(e));
                }
            };
        let cfa_rule = unwind_info.cfa();
        // println!("cfa rule: {:?}, regs: {:?}", cfa_rule, regs);
        let cfa = eval_cfa_rule(cfa_rule, regs).ok_or(DwarfUnwinderError::CouldNotRecoverCfa)?;
        // println!("cfa: {:x}", cfa);
        let fp_rule = unwind_info.register(AArch64::X29);
        let lr_rule = unwind_info.register(AArch64::X30);
        // println!("rules: fp {:?}, lr {:?}", fp_rule, lr_rule);
        let fp = eval_rule(fp_rule, cfa, regs.fp(), regs, read_stack)
            .ok_or(DwarfUnwinderError::CouldNotRecoverFramePointer)?;
        let lr = eval_rule(lr_rule, cfa, regs.lr(), regs, read_stack)
            .ok_or(DwarfUnwinderError::CouldNotRecoverReturnAddress)?;
        regs.set_fp(fp);
        regs.set_sp(cfa);
        regs.set_lr(lr);

        Ok(lr)
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
        CfaRule::Expression(_) => todo!("cfarule expression"),
    }
}

fn eval_rule<R, F>(
    rule: RegisterRule<R>,
    cfa: u64,
    val: u64,
    regs: &UnwindRegsArm64,
    read_stack: &mut F,
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
            read_stack(cfa_plus_offset).ok()
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
