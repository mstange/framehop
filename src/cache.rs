use std::ops::Deref;

use crate::{error::Error, UnwindRegsArm64};

use super::arcdata::ArcDataReader;

pub struct Cache<D: Deref<Target = [u8]>> {
    pub(crate) eh_frame_unwind_context: Box<gimli::UnwindContext<ArcDataReader<D>>>,
    pub(crate) cache: Box<[Option<CacheEntry>; 509]>,
}

impl<D: Deref<Target = [u8]>> Cache<D> {
    pub fn new() -> Self {
        Self {
            eh_frame_unwind_context: Box::new(gimli::UnwindContext::new()),
            cache: Box::new([None; 509]),
        }
    }

    pub fn try_unwind<F>(
        &mut self,
        address: u64,
        modules_generation: u16,
        regs: &mut UnwindRegsArm64,
        read_mem: &mut F,
    ) -> CacheResult
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        let slot = (address % 509) as u16;
        if let Some(entry) = &self.cache[slot as usize] {
            if entry.modules_generation == modules_generation && entry.address == address {
                return CacheResult::Hit(entry.opcode.unwind(regs, read_mem));
            }
        }
        CacheResult::Miss(CacheHandle {
            slot,
            address,
            modules_generation,
        })
    }

    pub fn insert(&mut self, handle: CacheHandle, opcode: OpcodeArm64) {
        let CacheHandle {
            slot,
            address,
            modules_generation,
        } = handle;
        self.cache[slot as usize] = Some(CacheEntry {
            address,
            modules_generation,
            opcode,
        });
    }
}

impl<D: Deref<Target = [u8]>> Default for Cache<D> {
    fn default() -> Self {
        Self::new()
    }
}

pub enum CacheResult {
    Miss(CacheHandle),
    Hit(Result<u64, Error>),
}

pub struct CacheHandle {
    slot: u16,
    address: u64,
    modules_generation: u16,
}

#[derive(Clone, Copy, Debug)]
pub struct CacheEntry {
    address: u64,
    modules_generation: u16,
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

fn wrapping_add_signed(lhs: u64, rhs: i64) -> u64 {
    lhs.wrapping_add(rhs as u64)
}

impl OpcodeArm64 {
    fn unwind<F>(&self, regs: &mut UnwindRegsArm64, read_mem: &mut F) -> Result<u64, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        match *self {
            OpcodeArm64::UnwindFailed => return Err(Error::UnwindingFailed),
            OpcodeArm64::NoOp => {}
            OpcodeArm64::OffsetSp { sp_offset_by_16 } => {
                regs.set_sp(regs.sp() + sp_offset_by_16 as u64 * 16);
            }
            OpcodeArm64::OffsetSpAndRestoreLr {
                sp_offset_by_16,
                lr_storage_offset_from_sp_by_8,
            } => {
                let sp = regs.sp();
                let new_sp = sp + sp_offset_by_16 as u64 * 16;
                let lr_location =
                    wrapping_add_signed(sp, lr_storage_offset_from_sp_by_8 as i64 * 8);
                let new_lr = read_mem(lr_location).map_err(|_| Error::UnwindingFailed)?;
                regs.set_sp(new_sp);
                regs.set_lr(new_lr);
            }
            OpcodeArm64::OffsetSpAndRestoreFpAndLr {
                sp_offset_by_16,
                fp_storage_offset_from_sp_by_8,
                lr_storage_offset_from_sp_by_8,
            } => {
                let sp = regs.sp();
                let new_sp = sp + sp_offset_by_16 as u64 * 16;
                let lr_location =
                    wrapping_add_signed(sp, lr_storage_offset_from_sp_by_8 as i64 * 8);
                let new_lr = read_mem(lr_location).map_err(|_| Error::UnwindingFailed)?;
                let fp_location =
                    wrapping_add_signed(sp, fp_storage_offset_from_sp_by_8 as i64 * 8);
                let new_fp = read_mem(fp_location).map_err(|_| Error::UnwindingFailed)?;
                regs.set_sp(new_sp);
                regs.set_lr(new_fp);
                regs.set_lr(new_lr);
            }
            OpcodeArm64::UseFramePointer => {
                let sp = regs.sp();
                let fp = regs.fp();
                let new_sp = fp + 16;
                let new_lr = read_mem(fp + 8).map_err(|_| Error::UnwindingFailed)?;
                let new_fp = read_mem(fp).map_err(|_| Error::UnwindingFailed)?;
                if new_fp <= fp || new_sp <= sp {
                    return Err(Error::UnwindingFailed);
                }
                regs.set_sp(new_sp);
                regs.set_lr(new_fp);
                regs.set_lr(new_lr);
            }
            OpcodeArm64::UseFramepointerWithOffsets {
                sp_offset_from_fp_by_8,
                fp_storage_offset_from_fp_by_8,
                lr_storage_offset_from_fp_by_8,
            } => {
                let sp = regs.sp();
                let fp = regs.fp();
                let new_sp = fp + sp_offset_from_fp_by_8 as u64 * 8;
                let lr_location =
                    wrapping_add_signed(fp, lr_storage_offset_from_fp_by_8 as i64 * 8);
                let new_lr = read_mem(lr_location).map_err(|_| Error::UnwindingFailed)?;
                let fp_location =
                    wrapping_add_signed(fp, fp_storage_offset_from_fp_by_8 as i64 * 8);
                let new_fp = read_mem(fp_location).map_err(|_| Error::UnwindingFailed)?;
                if new_fp <= fp || new_sp <= sp {
                    return Err(Error::UnwindingFailed);
                }
                regs.set_sp(new_sp);
                regs.set_lr(new_fp);
                regs.set_lr(new_lr);
            }
        }
        Ok(regs.lr())
    }
}
