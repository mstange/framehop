use super::unwind_rule::FrameRuleAarch64;
use super::unwindregs::UnwindRegsAarch64;
use crate::arch::Arch;

/// The Aarch64 CPU architecture.
pub struct ArchAarch64;
impl Arch for ArchAarch64 {
    type UnwindRule = FrameRuleAarch64;
    type UnwindRegs = UnwindRegsAarch64;
}
