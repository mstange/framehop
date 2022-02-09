use crate::{error::Error, UnwindRegsAarch64};

use super::UnwindRule;

#[derive(Clone, Copy, Debug)]
pub enum UnwindRuleAarch64 {
    /// (sp, fp, lr) = (sp, fp, lr)
    NoOp,
    /// (sp, fp, lr) = (sp + 16x, fp, lr)
    OffsetSp { sp_offset_by_16: u16 },
    /// (sp, fp, lr) = (sp + 16x, fp, *(sp + 8y))
    OffsetSpAndRestoreLr {
        sp_offset_by_16: u16,
        lr_storage_offset_from_sp_by_8: i16,
    },
    /// (sp, fp, lr) = (sp + 16x, *(sp + 8y), *(sp + 8z))
    OffsetSpAndRestoreFpAndLr {
        sp_offset_by_16: u16,
        fp_storage_offset_from_sp_by_8: i16,
        lr_storage_offset_from_sp_by_8: i16,
    },
    /// (sp, fp, lr) = (fp + 16, *fp, *(fp + 8))
    UseFramePointer,
    /// (sp, fp, lr) = (fp + 8x, *(fp + 8y), *(fp + 8z))
    UseFramepointerWithOffsets {
        sp_offset_from_fp_by_8: u16,
        fp_storage_offset_from_fp_by_8: i16,
        lr_storage_offset_from_fp_by_8: i16,
    },
}

fn wrapping_add_signed(lhs: u64, rhs: i64) -> u64 {
    lhs.wrapping_add(rhs as u64)
}

impl UnwindRule for UnwindRuleAarch64 {
    type UnwindRegs = UnwindRegsAarch64;

    fn rule_for_stub_functions() -> Self {
        UnwindRuleAarch64::NoOp
    }
    fn rule_for_function_start() -> Self {
        UnwindRuleAarch64::NoOp
    }
    fn fallback_rule() -> Self {
        UnwindRuleAarch64::UseFramePointer
    }

    fn exec<F>(self, regs: &mut UnwindRegsAarch64, read_mem: &mut F) -> Result<u64, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        match self {
            UnwindRuleAarch64::NoOp => {}
            UnwindRuleAarch64::OffsetSp { sp_offset_by_16 } => {
                regs.set_sp(regs.sp() + sp_offset_by_16 as u64 * 16);
            }
            UnwindRuleAarch64::OffsetSpAndRestoreLr {
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
            UnwindRuleAarch64::OffsetSpAndRestoreFpAndLr {
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
                regs.set_fp(new_fp);
                regs.set_lr(new_lr);
            }
            UnwindRuleAarch64::UseFramePointer => {
                let sp = regs.sp();
                let fp = regs.fp();
                let new_sp = fp + 16;
                let new_lr = read_mem(fp + 8).map_err(|_| Error::UnwindingFailed)?;
                let new_fp = read_mem(fp).map_err(|_| Error::UnwindingFailed)?;
                if new_fp == 0 {
                    return Err(Error::StackEndReached);
                }
                if new_fp <= fp || new_sp <= sp {
                    return Err(Error::UnwindingFailed);
                }
                regs.set_sp(new_sp);
                regs.set_fp(new_fp);
                regs.set_lr(new_lr);
            }
            UnwindRuleAarch64::UseFramepointerWithOffsets {
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
                if new_fp == 0 {
                    return Err(Error::StackEndReached);
                }
                if new_fp <= fp || new_sp <= sp {
                    return Err(Error::UnwindingFailed);
                }
                regs.set_sp(new_sp);
                regs.set_fp(new_fp);
                regs.set_lr(new_lr);
            }
        }
        Ok(regs.lr())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_basic() {
        let stack = [
            1, 2, 3, 4, 0x40, 0x100200, 5, 6, 0x70, 0x100100, 7, 8, 9, 10, 0x0, 0x0,
        ];
        let mut read_mem = |addr| Ok(stack[(addr / 8) as usize]);
        let mut regs = UnwindRegsAarch64::new(0x100300, 0x10, 0x20);
        let res = UnwindRuleAarch64::NoOp.exec(&mut regs, &mut read_mem);
        assert_eq!(res, Ok(0x100300));
        assert_eq!(regs.sp(), 0x10);
        let res = UnwindRuleAarch64::UseFramePointer.exec(&mut regs, &mut read_mem);
        assert_eq!(res, Ok(0x100200));
        assert_eq!(regs.sp(), 0x30);
        assert_eq!(regs.fp(), 0x40);
        let res = UnwindRuleAarch64::UseFramePointer.exec(&mut regs, &mut read_mem);
        assert_eq!(res, Ok(0x100100));
        assert_eq!(regs.sp(), 0x50);
        assert_eq!(regs.fp(), 0x70);
        let res = UnwindRuleAarch64::UseFramePointer.exec(&mut regs, &mut read_mem);
        assert_eq!(res, Err(Error::StackEndReached));
    }
}
