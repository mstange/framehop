use crate::rules::UnwindRuleArm64;

pub enum UnwindResult {
    ExecRule(UnwindRuleArm64),
    Uncacheable(u64),
}
