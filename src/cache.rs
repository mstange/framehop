use core::ops::Deref;

use alloc::boxed::Box;

use crate::{rule_cache::RuleCache, unwind_rule::UnwindRule};

use super::arcdata::ArcDataReader;

pub use crate::rule_cache::CacheStats;

/// A trait which lets you opt into allocation-free unwinding. The two implementations of
/// this trait are [`MustNotAllocateDuringUnwind`] and [`MayAllocateDuringUnwind`].
pub trait AllocationPolicy<D: Deref<Target = [u8]>> {
    type GimliStorage: gimli::UnwindContextStorage<usize>
        + gimli::EvaluationStorage<ArcDataReader<D>>;
}

/// Require allocation-free unwinding. This is one of the two [`AllocationPolicy`]
/// implementations.
///
/// Using this means that the unwinder cache takes up more memory, because it preallocates
/// space for DWARF CFI unwind table row evaluation and for DWARF CFI expression evaluation.
/// And because those preallocations are of a fixed size, it is possible that this fixed
/// size is not large enough for certain DWARF unwinding tasks.
pub struct MustNotAllocateDuringUnwind;

/// This is only used in the implementation of [MustNotAllocateDuringUnwind] and
/// is not intended to be used by the outside world.
#[doc(hidden)]
pub struct StoreOnStack;

impl<RO: gimli::ReaderOffset> gimli::UnwindContextStorage<RO> for StoreOnStack {
    type Rules = [(gimli::Register, gimli::RegisterRule<RO>); 192];
    type Stack = [gimli::UnwindTableRow<RO, Self>; 4];
}

impl<R: gimli::Reader> gimli::EvaluationStorage<R> for StoreOnStack {
    type Stack = [gimli::Value; 64];
    type ExpressionStack = [(R, R); 4];
    type Result = [gimli::Piece<R>; 1];
}

impl<D: Deref<Target = [u8]>> AllocationPolicy<D> for MustNotAllocateDuringUnwind {
    type GimliStorage = StoreOnStack;
}

/// Allow allocation during unwinding. This is one of the two [`AllocationPolicy`]
/// implementations.
///
/// This is the preferred policy because it saves memory and places no limitations on
/// DWARF CFI evaluation.
pub struct MayAllocateDuringUnwind;
impl<D: Deref<Target = [u8]>> AllocationPolicy<D> for MayAllocateDuringUnwind {
    type GimliStorage = gimli::StoreOnHeap;
}

/// The unwinder cache. This needs to be created upfront before unwinding. During
/// unwinding, the unwinder needs exclusive access to this cache.
///
/// A single unwinder cache can be used with multiple unwinders alternatingly.
///
/// The cache stores unwind rules for addresses it has seen before, and it stores the
/// unwind context which gimli needs for DWARF CFI evaluation.
pub struct Cache<
    D: Deref<Target = [u8]>,
    R: UnwindRule,
    P: AllocationPolicy<D> = MayAllocateDuringUnwind,
> {
    pub(crate) gimli_unwind_context: Box<gimli::UnwindContext<usize, P::GimliStorage>>,
    pub(crate) rule_cache: RuleCache<R>,
}

impl<D: Deref<Target = [u8]>, R: UnwindRule, P: AllocationPolicy<D>> Cache<D, R, P> {
    pub fn new() -> Self {
        Self {
            gimli_unwind_context: Box::new(gimli::UnwindContext::new_in()),
            rule_cache: RuleCache::new(),
        }
    }
}

impl<D: Deref<Target = [u8]>, R: UnwindRule, P: AllocationPolicy<D>> Default for Cache<D, R, P> {
    fn default() -> Self {
        Self::new()
    }
}
