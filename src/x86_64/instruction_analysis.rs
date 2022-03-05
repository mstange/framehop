use super::arch::ArchX86_64;
use crate::instruction_analysis::InstructionAnalysis;

impl InstructionAnalysis for ArchX86_64 {
    fn rule_from_prologue_analysis(
        _text_bytes_from_function_start: &[u8],
        _text_bytes_until_function_end: &[u8],
    ) -> Option<Self::UnwindRule> {
        None
    }

    fn rule_from_epilogue_analysis(
        _text_bytes_until_function_end: &[u8],
    ) -> Option<Self::UnwindRule> {
        None
    }
}
