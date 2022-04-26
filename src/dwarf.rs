use std::{marker::PhantomData, ops::Range};

use gimli::{
    BaseAddresses, CfaRule, CieOrFde, EhFrameHdr, Encoding, EndianSlice, Evaluation,
    EvaluationResult, EvaluationStorage, Expression, LittleEndian, Location, ParsedEhFrameHdr,
    Reader, ReaderOffset, Register, RegisterRule, UnwindContext, UnwindContextStorage,
    UnwindSection, UnwindTableRow, Value,
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
        let bases = base_addresses_for_sections(sections);
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

fn base_addresses_for_sections(sections: &ModuleSectionAddressRanges) -> BaseAddresses {
    fn start_addr(range: &Option<Range<u64>>) -> u64 {
        if let Some(range) = range {
            range.start
        } else {
            0
        }
    }
    BaseAddresses::default()
        .set_eh_frame(start_addr(&sections.eh_frame))
        .set_eh_frame_hdr(start_addr(&sections.eh_frame_hdr))
        .set_text(start_addr(&sections.text))
        .set_got(start_addr(&sections.got))
}

#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum DwarfCfiIndexError {
    #[error("EhFrame processing failed: {0}")]
    Gimli(#[from] gimli::Error),

    #[error("Could not subtract base address to create relative pc")]
    CouldNotSubtractBaseAddress,

    #[error("Relative address did not fit into u32")]
    RelativeAddressTooBig,

    #[error("FDE offset did not fit into u32")]
    FdeOffsetTooBig,
}

/// A binary search table for eh_frame FDEs. We generate this whenever a module
/// without eh_frame_hdr is added.
pub struct DwarfCfiIndex {
    /// Contains the initial address for every FDE, relative to the base address.
    /// This vector is sorted so that it can be used for binary search.
    /// It has the same length as `fde_offsets`.
    sorted_fde_pc_starts: Vec<u32>,
    /// Contains the FDE offset for every FDE. The FDE at offset `fde_offsets[i]`
    /// has a PC range which starts at `sorted_fde_pc_starts[i]`.
    fde_offsets: Vec<u32>,
}

impl DwarfCfiIndex {
    pub fn try_new(
        eh_frame_data: &[u8],
        sections: &ModuleSectionAddressRanges,
        base_address: u64,
    ) -> Result<Self, DwarfCfiIndexError> {
        let bases = base_addresses_for_sections(sections);
        let mut eh_frame = gimli::EhFrame::from(EndianSlice::new(eh_frame_data, LittleEndian));
        eh_frame.set_address_size(8);

        let mut fde_pc_and_offset = Vec::new();

        let mut cur_cie = None;
        let mut entries_iter = eh_frame.entries(&bases);
        while let Some(entry) = entries_iter.next()? {
            let fde = match entry {
                CieOrFde::Cie(cie) => {
                    cur_cie = Some(cie);
                    continue;
                }
                CieOrFde::Fde(partial_fde) => {
                    partial_fde.parse(|eh_frame, bases, cie_offset| {
                        if let Some(cie) = &cur_cie {
                            if cie.offset() == cie_offset.0 {
                                return Ok(cie.clone());
                            }
                        }
                        let cie = eh_frame.cie_from_offset(bases, cie_offset);
                        if let Ok(cie) = &cie {
                            cur_cie = Some(cie.clone());
                        }
                        cie
                    })?
                }
            };
            let pc = fde.initial_address();
            let relative_pc = pc
                .checked_sub(base_address)
                .ok_or(DwarfCfiIndexError::CouldNotSubtractBaseAddress)?;
            let relative_pc = u32::try_from(relative_pc)
                .map_err(|_| DwarfCfiIndexError::RelativeAddressTooBig)?;
            let fde_offset =
                u32::try_from(fde.offset()).map_err(|_| DwarfCfiIndexError::FdeOffsetTooBig)?;
            fde_pc_and_offset.push((relative_pc, fde_offset));
        }
        fde_pc_and_offset.sort_by_key(|(pc, _)| *pc);
        let sorted_fde_pc_starts = fde_pc_and_offset.iter().map(|(pc, _)| *pc).collect();
        let fde_offsets = fde_pc_and_offset.into_iter().map(|(_, fde)| fde).collect();
        Ok(Self {
            sorted_fde_pc_starts,
            fde_offsets,
        })
    }

    pub fn fde_offset_for_relative_address(&self, rel_lookup_address: u32) -> Option<u32> {
        let i = match self.sorted_fde_pc_starts.binary_search(&rel_lookup_address) {
            Err(0) => return None,
            Ok(i) => i,
            Err(i) => i - 1,
        };
        Some(self.fde_offsets[i])
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
