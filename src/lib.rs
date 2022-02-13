mod arcdata;
mod arch;
pub mod archunwinders;
mod cache;
mod code_address;
mod display_utils;
mod error;
mod rule_cache;
mod rules;
mod unwind_result;
mod unwinder;
mod unwinders;
mod unwindregs;

pub use code_address::CodeAddress;
pub use error::Error;
pub use unwinder::{Module, SectionAddresses, UnwindData, UnwindIterator, Unwinder};
pub use unwindregs::*;

#[cfg(target_arch = "aarch64")]
pub type CacheNative<D> = archunwinders::CacheAarch64<D>;
#[cfg(target_arch = "aarch64")]
pub type UnwinderNative<D> = archunwinders::UnwinderAarch64<D>;

#[cfg(target_arch = "x86_64")]
pub type CacheNative<D> = archunwinders::CacheX86_64<D>;
#[cfg(target_arch = "x86_64")]
pub type UnwinderNative<D> = archunwinders::UnwinderX86_64<D>;
