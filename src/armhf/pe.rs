use super::arch::ArchArmhf;
use crate::pe::{PeSections, PeUnwinderError, PeUnwinding};
use crate::unwind_result::UnwindResult;

impl PeUnwinding for ArchArmhf {
    fn unwind_frame<F, D>(
        _sections: PeSections<D>,
        _address: u32,
        _regs: &mut Self::UnwindRegs,
        _is_first_frame: bool,
        _read_stack: &mut F,
    ) -> Result<UnwindResult<Self::UnwindRule>, PeUnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
        D: core::ops::Deref<Target = [u8]>,
    {
        Err(PeUnwinderError::ArmhfUnsupported)
    }
}
