use crate::{
    rules::{UnwindRule, UnwindRuleArm64, UnwindRuleX86_64},
    UnwindRegsArm64, UnwindRegsX86_64,
};

pub trait Arch {
    type UnwindRule: UnwindRule;
    type Regs;
}

pub struct ArchArm64;
impl Arch for ArchArm64 {
    type UnwindRule = UnwindRuleArm64;
    type Regs = UnwindRegsArm64;
}

pub struct ArchX86_64;
impl Arch for ArchX86_64 {
    type UnwindRule = UnwindRuleX86_64;
    type Regs = UnwindRegsX86_64;
}
