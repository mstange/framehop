use gimli::{
    Encoding, EvaluationStorage, Reader, Register, UnwindContextStorage, UnwindSection,
    UnwindTableRow,
};

use super::{arch::ArchArmhf, unwind_rule::UnwindRuleArmhf, unwindregs::UnwindRegsArmhf};

use crate::unwind_result::UnwindResult;

use crate::dwarf::{DwarfUnwindRegs, DwarfUnwinderError, DwarfUnwinding};

impl DwarfUnwindRegs for UnwindRegsArmhf {
    fn get(&self, _: Register) -> Option<u64> {
        None
    }
}

impl DwarfUnwinding for ArchArmhf {
    fn unwind_frame<F, R, UCS, ES>(
        _: &impl UnwindSection<R>,
        _: &UnwindTableRow<R::Offset, UCS>,
        _: Encoding,
        _: &mut Self::UnwindRegs,
        _: bool,
        _: &mut F,
    ) -> Result<UnwindResult<Self::UnwindRule>, DwarfUnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
        R: Reader,
        UCS: UnwindContextStorage<R::Offset>,
        ES: EvaluationStorage<R>,
    {
        Err(DwarfUnwinderError::DidNotAdvance)
    }

    fn rule_if_uncovered_by_fde() -> Self::UnwindRule {
        UnwindRuleArmhf::NoOpIfFirstFrameOtherwiseFp
    }
}
