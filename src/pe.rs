use crate::{arch::Arch, unwind_result::UnwindResult};
use std::{ops::Range, sync::Arc};

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

/// Data and the related RVA range within the binary.
///
/// This is only used by PE unwinding.
///
/// Type arguments:
///  - `D`: The type for unwind section data. This allows carrying owned data on the
///    module, e.g. `Vec<u8>`. But it could also be a wrapper around mapped memory from
///    a file or a different process, for example. It just needs to provide a slice of
///    bytes via its `Deref` implementation.
pub struct DataAtRvaRange<D> {
    pub data: Arc<D>,
    pub rva_range: Range<u32>,
}

// Manually derive Clone due to https://github.com/rust-lang/rust/issues/26925
impl<D> Clone for DataAtRvaRange<D> {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            rva_range: self.rva_range.clone(),
        }
    }
}

pub struct PeSections<'a, D> {
    pub pdata: &'a D,
    pub rdata: Option<&'a DataAtRvaRange<D>>,
    pub xdata: Option<&'a DataAtRvaRange<D>>,
    pub text: Option<&'a DataAtRvaRange<D>>,
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
    DataAtRvaRange { data, rva_range }: &DataAtRvaRange<D>,
    address: u32,
) -> Option<&[u8]> {
    if rva_range.contains(&address) {
        let offset = address - rva_range.start;
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
        is_first_frame: bool,
        read_stack: &mut F,
    ) -> Result<UnwindResult<Self::UnwindRule>, PeUnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
        D: std::ops::Deref<Target = [u8]>;
}
