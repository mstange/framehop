use std::{marker::PhantomData, ops::Range};

use gimli::{
    BaseAddresses, CfaRule, EhFrameHdr, Encoding, EndianSlice, Evaluation, EvaluationResult,
    EvaluationStorage, Expression, Location, ParsedEhFrameHdr, Reader, ReaderOffset, Register,
    RegisterRule, UnwindContext, UnwindContextStorage, UnwindSection, UnwindTableRow, Value,
};

use crate::{arch::Arch, unwind_result::UnwindResult, FrameAddress, ModuleSectionAddressRanges};

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

#[derive(Clone, Debug)]
pub enum ConversionError {
    CfaIsExpression,
    CfaIsOffsetFromUnknownRegister,
    ReturnAddressRuleWithUnexpectedOffset,
    ReturnAddressRuleWasWeird,
    SpOffsetDoesNotFit,
    RegisterNotStoredRelativeToCfa,
    RestoringFpButNotLr,
    LrStorageOffsetDoesNotFit,
    FpStorageOffsetDoesNotFit,
    SpOffsetFromFpDoesNotFit,
    FramePointerRuleDoesNotRestoreLr,
    FramePointerRuleDoesNotRestoreFp,
    FramePointerRuleDoesNotRestoreBp,
    FramePointerRuleHasStrangeBpOffset,
}

pub trait DwarfUnwinding: Arch {
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
        S: UnwindContextStorage<R> + EvaluationStorage<R>;
}

pub struct DwarfUnwinder<'a, R: Reader, A: DwarfUnwinding + ?Sized, S: UnwindContextStorage<R>> {
    eh_frame_data: R,
    eh_frame_hdr: Option<ParsedEhFrameHdr<EndianSlice<'a, R::Endian>>>,
    unwind_context: &'a mut UnwindContext<R, S>,
    bases: BaseAddresses,
    _arch: PhantomData<A>,
}

impl<'a, R: Reader, A: DwarfUnwinding, S: UnwindContextStorage<R> + EvaluationStorage<R>>
    DwarfUnwinder<'a, R, A, S>
{
    pub fn new(
        eh_frame_data: R,
        eh_frame_hdr_data: Option<&'a [u8]>,
        unwind_context: &'a mut UnwindContext<R, S>,
        sections: &ModuleSectionAddressRanges,
    ) -> Self {
        fn start_addr(range: &Option<Range<u64>>) -> u64 {
            if let Some(range) = range {
                range.start
            } else {
                0
            }
        }
        let bases = BaseAddresses::default()
            .set_eh_frame(start_addr(&sections.eh_frame))
            .set_eh_frame_hdr(start_addr(&sections.eh_frame_hdr))
            .set_text(start_addr(&sections.text))
            .set_got(start_addr(&sections.got));
        let eh_frame_hdr = match eh_frame_hdr_data {
            Some(eh_frame_hdr_data) => {
                let hdr = EhFrameHdr::new(eh_frame_hdr_data, eh_frame_data.endian());
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

    pub fn unwind_frame_with_fde<F>(
        &mut self,
        regs: &mut A::UnwindRegs,
        address: FrameAddress,
        fde_offset: u32,
        read_stack: &mut F,
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
            address.address_for_lookup(),
        ) {
            Ok(unwind_info) => unwind_info,
            Err(e) => {
                return Err(DwarfUnwinderError::UnwindInfoForAddressFailed(e));
            }
        };
        A::unwind_frame::<F, R, S>(unwind_info, encoding, regs, address, read_stack)
    }
}

pub trait DwarfUnwindRegs {
    fn get(&self, register: Register) -> Option<u64>;
}

pub fn eval_cfa_rule<R: gimli::Reader, UR: DwarfUnwindRegs, S: EvaluationStorage<R>>(
    rule: &CfaRule<R>,
    encoding: Encoding,
    regs: &UR,
) -> Option<u64> {
    match rule {
        CfaRule::RegisterAndOffset { register, offset } => {
            let val = regs.get(*register)?;
            u64::try_from(i64::try_from(val).ok()?.checked_add(*offset)?).ok()
        }
        CfaRule::Expression(expr) => eval_expr::<R, UR, S>(expr.clone(), encoding, regs),
    }
}

fn eval_expr<R: gimli::Reader, UR: DwarfUnwindRegs, S: EvaluationStorage<R>>(
    expr: Expression<R>,
    encoding: Encoding,
    regs: &UR,
) -> Option<u64> {
    let mut eval = Evaluation::<R, S>::new_in(expr.0, encoding);
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

pub fn eval_register_rule<R, F, UR, S>(
    rule: RegisterRule<R>,
    cfa: u64,
    encoding: Encoding,
    val: u64,
    regs: &UR,
    read_stack: &mut F,
) -> Option<u64>
where
    R: gimli::Reader,
    F: FnMut(u64) -> Result<u64, ()>,
    UR: DwarfUnwindRegs,
    S: EvaluationStorage<R>,
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
        RegisterRule::Register(register) => regs.get(register),
        RegisterRule::Expression(expr) => {
            let val = eval_expr::<R, UR, S>(expr, encoding, regs)?;
            read_stack(val).ok()
        }
        RegisterRule::ValExpression(expr) => eval_expr::<R, UR, S>(expr, encoding, regs),
        RegisterRule::Architectural => {
            // Unimplemented
            // TODO: Find out what the architectural rules for x86_64 and for aarch64 are, if any.
            None
        }
    }
}
