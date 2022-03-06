use crate::arch::Arch;

pub trait InstructionAnalysis: Arch {
    fn rule_from_prologue_analysis(text_bytes: &[u8], pc_offset: usize)
        -> Option<Self::UnwindRule>;

    fn rule_from_epilogue_analysis(text_bytes: &[u8], pc_offset: usize)
        -> Option<Self::UnwindRule>;
}
