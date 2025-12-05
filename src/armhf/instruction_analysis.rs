use super::arch::ArchArmhf;
use crate::instruction_analysis::InstructionAnalysis;

impl InstructionAnalysis for ArchArmhf {
    fn rule_from_prologue_analysis(_: &[u8], _: usize) -> Option<Self::UnwindRule> {
        None
    }

    fn rule_from_epilogue_analysis(_: &[u8], _: usize) -> Option<Self::UnwindRule> {
        None
    }
}
