use std::ops::Deref;

use super::arcdata::ArcDataReader;

pub struct Cache<D: Deref<Target = [u8]>> {
    pub(crate) eh_frame_unwind_context: Box<gimli::UnwindContext<ArcDataReader<D>>>,
    pub(crate) cache: Box<[Option<CacheEntry>; 509]>,
}

impl<D: Deref<Target = [u8]>> Cache<D> {
    pub fn new() -> Self {
        Self {
            eh_frame_unwind_context: Box::new(gimli::UnwindContext::new()),
            cache: Box::new([None; 509])
        }
    }
}

impl<D: Deref<Target = [u8]>> Default for Cache<D> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CacheEntry {
    address: u64,
    module_generation: u16,
    opcode: OpcodeArm64,
}

#[derive(Clone, Copy, Debug)]
pub enum OpcodeArm64 {
    UnwindFailed,
    /// (sp, fp, lr) = (sp, fp, lr)
    NoOp,
    /// (sp, fp, lr) = (sp + 16x, fp, lr)
    OffsetSp {
        sp_offset_by_16: u8,
    },
    /// (sp, fp, lr) = (sp + 16x, fp, *(sp + 8y))
    OffsetSpAndRestoreLr {
        sp_offset_by_16: u8,
        lr_storage_offset_from_sp_by_8: i8,
    },
    /// (sp, fp, lr) = (sp + 16x, *(sp + 8y), *(sp + 8z))
    OffsetSpAndRestoreFpAndLr {
        sp_offset_by_16: u8,
        fp_storage_offset_from_sp_by_8: i8,
        lr_storage_offset_from_sp_by_8: i8,
    },
    /// (sp, fp, lr) = (fp + 16, *fp, *(fp + 8))
    UseFramePointer,
    /// (sp, fp, lr) = (fp + 8x, *(fp + 8y), *(fp + 8z))
    UseFramepointerWithOffsets {
        sp_offset_from_fp_by_8: u8,
        fp_storage_offset_from_fp_by_8: i8,
        lr_storage_offset_from_fp_by_8: i8,
    },
}
