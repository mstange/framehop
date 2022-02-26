mod arcdata;
mod arch;
mod cache;
mod code_address;
mod display_utils;
mod dwarf;
mod error;
mod macho;
mod rule_cache;
mod unwind_result;
mod unwind_rule;
mod unwinder;

pub mod aarch64;
pub mod x86_64;

pub use cache::{AllocationPolicy, MayAllocateDuringUnwind, MustNotAllocateDuringUnwind};
pub use code_address::FrameAddress;
pub use error::Error;
pub use unwinder::{Module, ModuleSectionAddresses, ModuleUnwindData, UnwindIterator, Unwinder};

#[cfg(target_arch = "aarch64")]
pub type CacheNative<D, P> = aarch64::CacheAarch64<D, P>;
#[cfg(target_arch = "aarch64")]
pub type UnwindRegsNative = aarch64::UnwindRegsAarch64;
#[cfg(target_arch = "aarch64")]
pub type UnwinderNative<D, P> = aarch64::UnwinderAarch64<D, P>;

#[cfg(target_arch = "x86_64")]
pub type CacheNative<D, P> = x86_64::CacheX86_64<D, P>;
#[cfg(target_arch = "x86_64")]
pub type UnwindRegsNative = x86_64::UnwindRegsX86_64;
#[cfg(target_arch = "x86_64")]
pub type UnwinderNative<D, P> = x86_64::UnwinderX86_64<D, P>;
