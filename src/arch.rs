use crate::{
    rules::{UnwindRule, UnwindRuleAarch64, UnwindRuleX86_64},
    UnwindRegsAarch64, UnwindRegsX86_64,
};

pub trait Arch {
    type UnwindRegs;
    type UnwindRule: UnwindRule<UnwindRegs = Self::UnwindRegs>;
}

pub struct ArchAarch64;
impl Arch for ArchAarch64 {
    type UnwindRule = UnwindRuleAarch64;
    type UnwindRegs = UnwindRegsAarch64;
}

pub struct ArchX86_64;
impl Arch for ArchX86_64 {
    type UnwindRule = UnwindRuleX86_64;
    type UnwindRegs = UnwindRegsX86_64;
}
