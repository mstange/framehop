use std::fmt::Debug;

use crate::display_utils::HexNum;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UnwindRegsArm64 {
    pub lr: Option<u64>,
    pub sp: Option<u64>,
    pub fp: Option<u64>,
}

/// On macOS arm64, system libraries are arm64e binaries, and arm64e can do pointer authentication:
/// The low bits of the pointer are the actual pointer value, and the high bits are an encrypted hash.
/// During stackwalking, we need to strip off this hash.
/// I don't know of an easy way to get the correct mask dynamically - all the potential functions
/// I've seen for this are no-ops when called from regular arm64 code.
/// So for now, we hardcode a mask that seems to work today, and worry about it if it stops working.
/// 24 bits hash + 40 bits pointer
const PTR_MASK: u64 = (1 << 40) - 1;

pub fn strip_ptr_auth(ptr: u64) -> u64 {
    ptr & PTR_MASK
}

impl UnwindRegsArm64 {
    pub fn unmasked_sp(&self) -> Option<u64> {
        self.sp.map(strip_ptr_auth)
    }
    pub fn unmasked_fp(&self) -> Option<u64> {
        self.fp.map(strip_ptr_auth)
    }
    pub fn unmasked_lr(&self) -> Option<u64> {
        self.lr.map(strip_ptr_auth)
    }
}

impl Debug for UnwindRegsArm64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnwindRegsArm64")
            .field("lr", &self.unmasked_lr().map(HexNum))
            .field("sp", &self.unmasked_sp().map(HexNum))
            .field("fp", &self.unmasked_fp().map(HexNum))
            .finish()
    }
}
