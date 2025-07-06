use super::unwind_rule::UnwindRuleArmhf;
use super::unwindregs::UnwindRegsArmhf;
use crate::arch::Arch;

/// The Armhf CPU architecture.
pub struct ArchArmhf;
impl Arch for ArchArmhf {
    type UnwindRule = UnwindRuleArmhf;
    type UnwindRegs = UnwindRegsArmhf;
}
