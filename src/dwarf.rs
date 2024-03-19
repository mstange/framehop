use core::marker::PhantomData;

use alloc::vec::Vec;
use gimli::{
    CfaRule, CieOrFde, DebugFrame, EhFrame, EhFrameHdr, Encoding, EndianSlice, Evaluation,
    EvaluationResult, EvaluationStorage, Expression, LittleEndian, Location, ParsedEhFrameHdr,
    Reader, ReaderOffset, Register, RegisterRule, UnwindContext, UnwindContextStorage,
    UnwindOffset, UnwindSection, UnwindTableRow, Value,
};

pub(crate) use gimli::BaseAddresses;

use crate::{arch::Arch, unwind_result::UnwindResult, ModuleSectionInfo};

#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[cfg_attr(not(feature = "std"), derive(thiserror_no_std::Error))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        is_first_frame: bool,
        read_stack: &mut F,
    ) -> Result<UnwindResult<Self::UnwindRule>, DwarfUnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
        R: Reader,
        S: UnwindContextStorage<R> + EvaluationStorage<R>;

    fn rule_if_uncovered_by_fde() -> Self::UnwindRule;
}

pub enum UnwindSectionType {
    EhFrame,
    DebugFrame,
}

pub struct DwarfUnwinder<'a, R: Reader, A: DwarfUnwinding + ?Sized, S: UnwindContextStorage<R>> {
    unwind_section_data: R,
    unwind_section_type: UnwindSectionType,
    eh_frame_hdr: Option<ParsedEhFrameHdr<EndianSlice<'a, R::Endian>>>,
    unwind_context: &'a mut UnwindContext<R, S>,
    base_svma: u64,
    bases: BaseAddresses,
    _arch: PhantomData<A>,
}

impl<'a, R: Reader, A: DwarfUnwinding, S: UnwindContextStorage<R> + EvaluationStorage<R>>
    DwarfUnwinder<'a, R, A, S>
{
    pub fn new(
        unwind_section_data: R,
        unwind_section_type: UnwindSectionType,
        eh_frame_hdr_data: Option<&'a [u8]>,
        unwind_context: &'a mut UnwindContext<R, S>,
        bases: BaseAddresses,
        base_svma: u64,
    ) -> Self {
        let eh_frame_hdr = match eh_frame_hdr_data {
            Some(eh_frame_hdr_data) => {
                let hdr = EhFrameHdr::new(eh_frame_hdr_data, unwind_section_data.endian());
                match hdr.parse(&bases, 8) {
                    Ok(hdr) => Some(hdr),
                    Err(_) => None,
                }
            }
            None => None,
        };
        Self {
            unwind_section_data,
            unwind_section_type,
            eh_frame_hdr,
            unwind_context,
            bases,
            base_svma,
            _arch: PhantomData,
        }
    }

    pub fn get_fde_offset_for_relative_address(&self, rel_lookup_address: u32) -> Option<u32> {
        let lookup_svma = self.base_svma + rel_lookup_address as u64;
        let eh_frame_hdr = self.eh_frame_hdr.as_ref()?;
        let table = eh_frame_hdr.table()?;
        let fde_ptr = table.lookup(lookup_svma, &self.bases).ok()?;
        let fde_offset = table.pointer_to_offset(fde_ptr).ok()?;
        fde_offset.0.into_u64().try_into().ok()
    }

    pub fn unwind_frame_with_fde<F>(
        &mut self,
        regs: &mut A::UnwindRegs,
        is_first_frame: bool,
        rel_lookup_address: u32,
        fde_offset: u32,
        read_stack: &mut F,
    ) -> Result<UnwindResult<A::UnwindRule>, DwarfUnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        let lookup_svma = self.base_svma + rel_lookup_address as u64;
        let unwind_section_data = self.unwind_section_data.clone();
        let unwind_info = match self.unwind_section_type {
            UnwindSectionType::EhFrame => {
                let mut eh_frame = EhFrame::from(unwind_section_data);
                eh_frame.set_address_size(8);
                self.unwind_info_for_fde(eh_frame, lookup_svma, fde_offset)
            }
            UnwindSectionType::DebugFrame => {
                let mut debug_frame = DebugFrame::from(unwind_section_data);
                debug_frame.set_address_size(8);
                self.unwind_info_for_fde(debug_frame, lookup_svma, fde_offset)
            }
        };
        if let Err(DwarfUnwinderError::UnwindInfoForAddressFailed(_)) = unwind_info {
            return Ok(UnwindResult::ExecRule(A::rule_if_uncovered_by_fde()));
        }
        let (unwind_info, encoding) = unwind_info?;
        A::unwind_frame::<F, R, S>(unwind_info, encoding, regs, is_first_frame, read_stack)
    }

    fn unwind_info_for_fde<US: UnwindSection<R>>(
        &mut self,
        unwind_section: US,
        lookup_svma: u64,
        fde_offset: u32,
    ) -> Result<(&UnwindTableRow<R, S>, Encoding), DwarfUnwinderError> {
        let fde = unwind_section.fde_from_offset(
            &self.bases,
            US::Offset::from(R::Offset::from_u32(fde_offset)),
            US::cie_from_offset,
        );
        let fde = fde.map_err(DwarfUnwinderError::FdeFromOffsetFailed)?;
        let encoding = fde.cie().encoding();
        let unwind_info: &UnwindTableRow<_, _> = fde
            .unwind_info_for_address(
                &unwind_section,
                &self.bases,
                self.unwind_context,
                lookup_svma,
            )
            .map_err(DwarfUnwinderError::UnwindInfoForAddressFailed)?;
        Ok((unwind_info, encoding))
    }
}

pub(crate) fn base_addresses_for_sections<D>(
    section_info: &mut impl ModuleSectionInfo<D>,
) -> BaseAddresses {
    let mut start_addr = |names: &[&[u8]]| -> u64 {
        names
            .iter()
            .find_map(|name| section_info.section_svma_range(name))
            .map(|r| r.start)
            .unwrap_or_default()
    };
    BaseAddresses::default()
        .set_eh_frame(start_addr(&[b"__eh_frame", b".eh_frame"]))
        .set_eh_frame_hdr(start_addr(&[b"__eh_frame_hdr", b".eh_frame_hdr"]))
        .set_text(start_addr(&[b"__text", b".text"]))
        .set_got(start_addr(&[b"__got", b".got"]))
}

#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[cfg_attr(not(feature = "std"), derive(thiserror_no_std::Error))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    pub fn try_new<R, US>(
        unwind_section: US,
        bases: BaseAddresses,
        base_svma: u64,
    ) -> Result<Self, DwarfCfiIndexError>
    where
        R: Reader,
        R::Offset: TryInto<u32>,
        US: UnwindSection<R>,
    {
        let mut fde_pc_and_offset = Vec::new();

        let mut cur_cie = None;
        let mut entries_iter = unwind_section.entries(&bases);
        while let Some(entry) = entries_iter.next()? {
            let fde = match entry {
                CieOrFde::Cie(cie) => {
                    cur_cie = Some(cie);
                    continue;
                }
                CieOrFde::Fde(partial_fde) => {
                    partial_fde.parse(|unwind_section, bases, cie_offset| {
                        if let Some(cie) = &cur_cie {
                            if cie.offset()
                                == <US::Offset as UnwindOffset<R::Offset>>::into(cie_offset)
                            {
                                return Ok(cie.clone());
                            }
                        }
                        let cie = unwind_section.cie_from_offset(bases, cie_offset);
                        if let Ok(cie) = &cie {
                            cur_cie = Some(cie.clone());
                        }
                        cie
                    })?
                }
            };
            let pc = fde.initial_address();
            let relative_pc = pc
                .checked_sub(base_svma)
                .ok_or(DwarfCfiIndexError::CouldNotSubtractBaseAddress)?;
            let relative_pc = u32::try_from(relative_pc)
                .map_err(|_| DwarfCfiIndexError::RelativeAddressTooBig)?;
            let fde_offset = <R::Offset as TryInto<u32>>::try_into(fde.offset())
                .map_err(|_| DwarfCfiIndexError::FdeOffsetTooBig)?;
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

    pub fn try_new_eh_frame<D>(
        eh_frame_data: &[u8],
        section_info: &mut impl ModuleSectionInfo<D>,
    ) -> Result<Self, DwarfCfiIndexError> {
        let bases = base_addresses_for_sections(section_info);
        let mut eh_frame = EhFrame::from(EndianSlice::new(eh_frame_data, LittleEndian));
        eh_frame.set_address_size(8);

        Self::try_new(eh_frame, bases, section_info.base_svma())
    }

    pub fn try_new_debug_frame<D>(
        debug_frame_data: &[u8],
        section_info: &mut impl ModuleSectionInfo<D>,
    ) -> Result<Self, DwarfCfiIndexError> {
        let bases = base_addresses_for_sections(section_info);
        let mut debug_frame = DebugFrame::from(EndianSlice::new(debug_frame_data, LittleEndian));
        debug_frame.set_address_size(8);

        Self::try_new(debug_frame, bases, section_info.base_svma())
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

pub fn eval_cfa_rule<R: Reader, UR: DwarfUnwindRegs, S: EvaluationStorage<R>>(
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

fn eval_expr<R: Reader, UR: DwarfUnwindRegs, S: EvaluationStorage<R>>(
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
    R: Reader,
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
        _ => None,
    }
}
