use crate::{
    rules::{UnwindRule, UnwindRuleArm64, UnwindRuleX86_64},
    UnwindRegsArm64, UnwindRegsX86_64,
};

pub trait Arch {
    type UnwindRegs;
    type UnwindRule: UnwindRule<UnwindRegs = Self::UnwindRegs>;
}

pub struct ArchArm64;
impl Arch for ArchArm64 {
    type UnwindRule = UnwindRuleArm64;
    type UnwindRegs = UnwindRegsArm64;
}

pub struct ArchX86_64;
impl Arch for ArchX86_64 {
    type UnwindRule = UnwindRuleX86_64;
    type UnwindRegs = UnwindRegsX86_64;
}
