use std::marker::PhantomData;

use gimli::{
    BaseAddresses, CfaRule, EhFrameHdr, Encoding, EvaluationResult, Expression, Location,
    ParsedEhFrameHdr, Reader, ReaderOffset, Register, RegisterRule, UnwindContext,
    UnwindContextStorage, UnwindSection, UnwindTableRow, Value,
};

use crate::{arch::Arch, unwind_result::UnwindResult, ModuleSectionAddresses};

use super::DwarfUnwinderError;

pub trait DwarfUnwinding: Arch {
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
        S: UnwindContextStorage<R>;

    fn unwind_next<F, R, S>(
        unwind_info: &UnwindTableRow<R, S>,
        encoding: Encoding,
        regs: &mut Self::UnwindRegs,
        read_mem: &mut F,
    ) -> Result<UnwindResult<Self::UnwindRule>, DwarfUnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
        R: Reader,
        S: UnwindContextStorage<R>;
}

pub struct DwarfUnwinder<'a, R: Reader, A: DwarfUnwinding + ?Sized> {
    eh_frame_data: R,
    eh_frame_hdr: Option<ParsedEhFrameHdr<R>>,
    unwind_context: &'a mut UnwindContext<R>,
    bases: BaseAddresses,
    _arch: PhantomData<A>,
}

impl<'a, R: Reader, A: DwarfUnwinding> DwarfUnwinder<'a, R, A> {
    pub fn new(
        eh_frame_data: R,
        eh_frame_hdr_data: Option<R>,
        unwind_context: &'a mut UnwindContext<R>,
        sections: &ModuleSectionAddresses,
    ) -> Self {
        let bases = BaseAddresses::default()
            .set_eh_frame(sections.eh_frame)
            .set_eh_frame_hdr(sections.eh_frame_hdr)
            .set_text(sections.text)
            .set_got(sections.got);
        let eh_frame_hdr = match eh_frame_hdr_data {
            Some(eh_frame_hdr_data) => {
                let hdr = EhFrameHdr::from(eh_frame_hdr_data);
                match hdr.parse(&bases, 8) {
                    Ok(hdr) => Some(hdr),
                    Err(_) => None,
                }
            }
            None => None,
        };
        Self {
            eh_frame_data,
            eh_frame_hdr,
            unwind_context,
            bases,
            _arch: PhantomData,
        }
    }

    pub fn get_fde_offset_for_address(&self, address: u64) -> Option<u32> {
        let eh_frame_hdr = self.eh_frame_hdr.as_ref()?;
        let table = eh_frame_hdr.table()?;
        let fde_ptr = table.lookup(address, &self.bases).ok()?;
        let fde_offset = table.pointer_to_offset(fde_ptr).ok()?;
        fde_offset.0.into_u64().try_into().ok()
    }

    pub fn unwind_first_with_fde<F>(
        &mut self,
        regs: &mut A::UnwindRegs,
        pc: u64,
        fde_offset: u32,
        read_mem: &mut F,
    ) -> Result<UnwindResult<A::UnwindRule>, DwarfUnwinderError>
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
        let encoding = fde.cie().encoding();
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
        A::unwind_first(unwind_info, encoding, regs, pc, read_mem)
    }

    pub fn unwind_next_with_fde<F>(
        &mut self,
        regs: &mut A::UnwindRegs,
        return_address: u64,
        fde_offset: u32,
        read_mem: &mut F,
    ) -> Result<UnwindResult<A::UnwindRule>, DwarfUnwinderError>
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
        let encoding = fde.cie().encoding();
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
        A::unwind_next(unwind_info, encoding, regs, read_mem)
    }
}

pub trait DwarfUnwindRegs {
    fn get(&self, register: Register) -> Option<u64>;
}

pub fn eval_cfa_rule<R: gimli::Reader, UR: DwarfUnwindRegs>(
    rule: &CfaRule<R>,
    encoding: Encoding,
    regs: &UR,
) -> Option<u64> {
    match rule {
        CfaRule::RegisterAndOffset { register, offset } => {
            let val = regs.get(*register)?;
            u64::try_from(i64::try_from(val).ok()?.checked_add(*offset)?).ok()
        }
        CfaRule::Expression(expr) => eval_expr(expr.clone(), encoding, regs),
    }
}

fn eval_expr<R: gimli::Reader, UR: DwarfUnwindRegs>(
    expr: Expression<R>,
    encoding: Encoding,
    regs: &UR,
) -> Option<u64> {
    let mut eval = expr.evaluation(encoding);
    let mut result = eval.evaluate().ok()?;
    loop {
        match result {
            EvaluationResult::Complete => break,
            EvaluationResult::RequiresRegister { register, .. } => {
                let value = regs.get(register)?;
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

pub fn eval_register_rule<R, F, UR>(
    rule: RegisterRule<R>,
    cfa: u64,
    encoding: Encoding,
    val: u64,
    regs: &UR,
    read_mem: &mut F,
) -> Option<u64>
where
    R: gimli::Reader,
    F: FnMut(u64) -> Result<u64, ()>,
    UR: DwarfUnwindRegs,
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
        RegisterRule::Register(register) => regs.get(register),
        RegisterRule::Expression(_) => {
            println!("Unimplemented RegisterRule::Expression");
            None
        }
        RegisterRule::ValExpression(expr) => eval_expr(expr, encoding, regs),
        RegisterRule::Architectural => {
            println!("Unimplemented RegisterRule::Architectural");
            None
        }
    }
}
