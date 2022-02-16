use super::unwind_rule::UnwindRuleX86_64;
use super::unwindregs::UnwindRegsX86_64;
use crate::arch::Arch;

pub struct ArchX86_64;
impl Arch for ArchX86_64 {
    type UnwindRule = UnwindRuleX86_64;
    type UnwindRegs = UnwindRegsX86_64;
}
