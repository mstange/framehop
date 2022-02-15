use std::ops::Deref;

use crate::{rule_cache::RuleCache, rules::UnwindRule};

use super::arcdata::ArcDataReader;

pub trait AllocationPolicy<D: Deref<Target = [u8]>> {
    type GimliStorage: gimli::UnwindContextStorage<ArcDataReader<D>>
        + gimli::EvaluationStorage<ArcDataReader<D>>;
}
pub struct MustNotAllocateDuringUnwind;

/// This is only used in the implementation of [MustNotAllocateDuringUnwind] and
/// is not intended to be used by the outside world.
#[doc(hidden)]
pub struct StoreOnStack;

impl<R: gimli::Reader> gimli::UnwindContextStorage<R> for StoreOnStack {
    type Rules = [(gimli::Register, gimli::RegisterRule<R>); 192];
    type Stack = [gimli::UnwindTableRow<R, Self>; 4];
}

impl<R: gimli::Reader> gimli::EvaluationStorage<R> for StoreOnStack {
    type Stack = [gimli::Value; 64];
    type ExpressionStack = [(R, R); 4];
    type Result = [gimli::Piece<R>; 1];
}

impl<D: Deref<Target = [u8]>> AllocationPolicy<D> for MustNotAllocateDuringUnwind {
    type GimliStorage = StoreOnStack;
}
pub struct MayAllocateDuringUnwind;
impl<D: Deref<Target = [u8]>> AllocationPolicy<D> for MayAllocateDuringUnwind {
    type GimliStorage = gimli::StoreOnHeap;
}

pub struct Cache<
    D: Deref<Target = [u8]>,
    R: UnwindRule,
    P: AllocationPolicy<D> = MayAllocateDuringUnwind,
> {
    pub(crate) eh_frame_unwind_context:
        Box<gimli::UnwindContext<ArcDataReader<D>, P::GimliStorage>>,
    pub(crate) rule_cache: RuleCache<R>,
}

impl<D: Deref<Target = [u8]>, R: UnwindRule, P: AllocationPolicy<D>> Cache<D, R, P> {
    pub fn new() -> Self {
        Self {
            eh_frame_unwind_context: Box::new(gimli::UnwindContext::new_in()),
            rule_cache: RuleCache::new(),
        }
    }
}

impl<D: Deref<Target = [u8]>, R: UnwindRule, P: AllocationPolicy<D>> Default for Cache<D, R, P> {
    fn default() -> Self {
        Self::new()
    }
}
