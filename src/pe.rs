use crate::{arch::Arch, unwind_result::UnwindResult};
use std::ops::Range;

#[derive(thiserror::Error, Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeUnwinderError {
    #[error("failed to read unwind info memory at RVA {0:x}")]
    MissingUnwindInfoData(u32),
    #[error("failed to read instruction memory at RVA {0:x}")]
    MissingInstructionData(u32),
    #[error("failed to read stack{}", .0.map(|a| format!(" at address {a:x}")).unwrap_or_default())]
    MissingStackData(Option<u64>),
    #[error("failed to parse UnwindInfo")]
    UnwindInfoParseError,
    #[error("AArch64 is not yet supported")]
    Aarch64Unsupported,
}

pub struct PeSections<'a, D> {
    pub pdata: &'a D,
    pub rdata: Option<&'a (Range<u32>, D)>,
    pub xdata: Option<&'a (Range<u32>, D)>,
    pub text: Option<&'a (Range<u32>, D)>,
}

impl<'a, D> PeSections<'a, D>
where
    D: std::ops::Deref<Target = [u8]>,
{
    pub fn unwind_info_memory_at_rva(&self, rva: u32) -> Result<&'a [u8], PeUnwinderError> {
        [&self.rdata, &self.xdata]
            .into_iter()
            .find_map(|o| o.and_then(|m| memory_at_rva(m, rva)))
            .ok_or(PeUnwinderError::MissingUnwindInfoData(rva))
    }

    pub fn text_memory_at_rva(&self, rva: u32) -> Result<&'a [u8], PeUnwinderError> {
        self.text
            .and_then(|m| memory_at_rva(m, rva))
            .ok_or(PeUnwinderError::MissingInstructionData(rva))
    }
}

fn memory_at_rva<D: std::ops::Deref<Target = [u8]>>(
    (range, data): &(Range<u32>, D),
    address: u32,
) -> Option<&[u8]> {
    if range.contains(&address) {
        let offset = address - range.start;
        Some(&data[(offset as usize)..])
    } else {
        None
    }
}

pub trait PeUnwinding: Arch {
    fn unwind_frame<F, D>(
        sections: PeSections<D>,
        address: u32,
        regs: &mut Self::UnwindRegs,
        read_stack: &mut F,
    ) -> Result<UnwindResult<Self::UnwindRule>, PeUnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
        D: std::ops::Deref<Target = [u8]>;
}
