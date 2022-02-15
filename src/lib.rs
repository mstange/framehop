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
pub mod unwindregs;

pub use cache::{AllocationPolicy, MayAllocateDuringUnwind, MustNotAllocateDuringUnwind};
pub use code_address::CodeAddress;
pub use error::Error;
pub use unwinder::{Module, ModuleSectionAddresses, ModuleUnwindData, UnwindIterator, Unwinder};

#[cfg(target_arch = "aarch64")]
pub type CacheNative<D, P> = archunwinders::CacheAarch64<D, P>;
#[cfg(target_arch = "aarch64")]
pub type UnwindRegsNative = unwindregs::UnwindRegsAarch64;
#[cfg(target_arch = "aarch64")]
pub type UnwinderNative<D, P> = archunwinders::UnwinderAarch64<D, P>;

#[cfg(target_arch = "x86_64")]
pub type CacheNative<D, P> = archunwinders::CacheX86_64<D, P>;
#[cfg(target_arch = "x86_64")]
pub type UnwindRegsNative = unwindregs::UnwindRegsX86_64;
#[cfg(target_arch = "x86_64")]
pub type UnwinderNative<D, P> = archunwinders::UnwinderX86_64<D, P>;
