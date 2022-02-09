use crate::{rules::UnwindRule, unwind_result::UnwindResult};

use super::DwarfUnwinderError;

pub trait DwarfUnwinder {
    type UnwindRegs;
    type UnwindRule: UnwindRule<UnwindRegs = Self::UnwindRegs>;

    fn unwind_first_with_fde<F>(
        &mut self,
        regs: &mut Self::UnwindRegs,
        pc: u64,
        fde_offset: u32,
        read_mem: &mut F,
    ) -> Result<UnwindResult<Self::UnwindRule>, DwarfUnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>;

    fn unwind_next_with_fde<F>(
        &mut self,
        regs: &mut Self::UnwindRegs,
        return_address: u64,
        fde_offset: u32,
        read_mem: &mut F,
    ) -> Result<UnwindResult<Self::UnwindRule>, DwarfUnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>;
}
