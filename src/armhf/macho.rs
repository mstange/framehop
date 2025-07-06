use super::arch::ArchArmhf;
use super::unwind_rule::UnwindRuleArmhf;
use crate::macho::{CompactUnwindInfoUnwinderError, CompactUnwindInfoUnwinding, CuiUnwindResult};
use macho_unwind_info::Function;

impl CompactUnwindInfoUnwinding for ArchArmhf {
    fn unwind_frame(
        _: Function,
        _: bool,
        _: usize,
        _: Option<&[u8]>,
    ) -> Result<CuiUnwindResult<UnwindRuleArmhf>, CompactUnwindInfoUnwinderError> {
        Err(CompactUnwindInfoUnwinderError::ArmhfUnsupported)
    }

    fn rule_for_stub_helper(
        _: u32,
    ) -> Result<CuiUnwindResult<UnwindRuleArmhf>, CompactUnwindInfoUnwinderError> {
        Ok(CuiUnwindResult::ExecRule(UnwindRuleArmhf::NoOp))
    }
}
