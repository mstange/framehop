use alloc::sync::Arc;
use core::{fmt::Debug, ops::Deref};

pub type ArcDataReader<D> = gimli::EndianReader<gimli::LittleEndian, ArcData<D>>;

pub struct ArcData<D: Deref<Target = [u8]>>(pub Arc<D>);

impl<D: Deref<Target = [u8]>> Deref for ArcData<D> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<D: Deref<Target = [u8]>> Clone for ArcData<D> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<D: Deref<Target = [u8]>> Debug for ArcData<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("ArcData").field(&self.0.as_ptr()).finish()
    }
}

// Safety: See the implementation for Arc. ArcData just wraps Arc, cloning ArcData just clones Arc.
unsafe impl<D: Deref<Target = [u8]>> gimli::StableDeref for ArcData<D> {}
unsafe impl<D: Deref<Target = [u8]>> gimli::CloneStableDeref for ArcData<D> {}
