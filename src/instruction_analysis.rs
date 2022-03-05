use crate::arch::Arch;

pub trait InstructionAnalysis: Arch {
    fn rule_from_prologue_analysis(
        text_bytes_from_function_start: &[u8],
        text_bytes_until_function_end: &[u8],
    ) -> Option<Self::UnwindRule>;

    fn rule_from_epilogue_analysis(
        text_bytes_until_function_end: &[u8],
    ) -> Option<Self::UnwindRule>;
}
