use std::marker::PhantomData;

use gimli::{
    BaseAddresses, Reader, ReaderOffset, UnwindContext, UnwindContextStorage, UnwindSection,
    UnwindTableRow,
};

use crate::{arch::Arch, unwind_result::UnwindResult, SectionAddresses};

use super::DwarfUnwinderError;

pub trait DwarfUnwinding: Arch {
    fn unwind_first<F, R, S>(
        unwind_info: &UnwindTableRow<R, S>,
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
    unwind_context: &'a mut UnwindContext<R>,
    bases: BaseAddresses,
    _arch: PhantomData<A>,
}

impl<'a, R: Reader, A: DwarfUnwinding> DwarfUnwinder<'a, R, A> {
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
            _arch: PhantomData,
        }
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
        A::unwind_first(unwind_info, regs, pc, read_mem)
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
        A::unwind_next(unwind_info, regs, read_mem)
    }
}
