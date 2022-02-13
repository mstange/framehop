use super::UnwindRule;
use crate::{error::Error, UnwindRegsX86_64};

/// For all of these: return address is *(new_sp - 8)
#[derive(Clone, Copy, Debug)]
pub enum UnwindRuleX86_64 {
    /// (sp, bp) = (sp + 8, bp)
    JustReturn,
    /// (sp, bp) = (sp + 8x, bp)
    OffsetSp { sp_offset_by_8: u16 },
    /// (sp, bp) = (sp + 8x, *(sp + 8y))
    OffsetSpAndRestoreBp {
        sp_offset_by_8: u16,
        bp_storage_offset_from_sp_by_8: i8,
    },
    /// (sp, bp) = (bp + 16, *bp)
    UseFramePointer,
}

fn wrapping_add_signed(lhs: u64, rhs: i64) -> u64 {
    lhs.wrapping_add(rhs as u64)
}

impl UnwindRule for UnwindRuleX86_64 {
    type UnwindRegs = UnwindRegsX86_64;

    fn rule_for_stub_functions() -> Self {
        UnwindRuleX86_64::JustReturn
    }
    fn rule_for_function_start() -> Self {
        UnwindRuleX86_64::JustReturn
    }
    fn fallback_rule() -> Self {
        UnwindRuleX86_64::UseFramePointer
    }

    fn exec<F>(self, regs: &mut UnwindRegsX86_64, read_mem: &mut F) -> Result<Option<u64>, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        let (new_sp, new_bp) = match self {
            UnwindRuleX86_64::JustReturn => (regs.sp() + 8, regs.bp()),
            UnwindRuleX86_64::OffsetSp { sp_offset_by_8 } => {
                (regs.sp() + sp_offset_by_8 as u64 * 8, regs.bp())
            }
            UnwindRuleX86_64::OffsetSpAndRestoreBp {
                sp_offset_by_8,
                bp_storage_offset_from_sp_by_8,
            } => {
                let sp = regs.sp();
                let new_sp = sp + sp_offset_by_8 as u64 * 8;
                let bp_location =
                    wrapping_add_signed(sp, bp_storage_offset_from_sp_by_8 as i64 * 8);
                let new_bp =
                    read_mem(bp_location).map_err(|_| Error::CouldNotReadStack(bp_location))?;
                (new_sp, new_bp)
            }
            UnwindRuleX86_64::UseFramePointer => {
                let sp = regs.sp();
                let bp = regs.bp();
                let new_sp = bp + 16;
                let new_bp = read_mem(bp).map_err(|_| Error::CouldNotReadStack(bp))?;
                if new_bp == 0 {
                    return Ok(None);
                }
                if new_bp <= bp || new_sp <= sp {
                    return Err(Error::FramepointerUnwindingMovedBackwards);
                }
                (new_sp, new_bp)
            }
        };
        let return_address =
            read_mem(new_sp - 8).map_err(|_| Error::CouldNotReadStack(new_sp - 8))?;
        regs.set_ip(return_address);
        regs.set_sp(new_sp);
        regs.set_bp(new_bp);
        Ok(Some(return_address))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_basic() {
        let stack = [
            1, 2, 0x100300, 4, 0x40, 0x100200, 5, 6, 0x70, 0x100100, 7, 8, 9, 10, 0x0, 0x0,
        ];
        let mut read_mem = |addr| Ok(stack[(addr / 8) as usize]);
        let mut regs = UnwindRegsX86_64::new(0x100400, 0x10, 0x20);
        let res = UnwindRuleX86_64::OffsetSp { sp_offset_by_8: 1 }.exec(&mut regs, &mut read_mem);
        assert_eq!(res, Ok(Some(0x100300)));
        assert_eq!(regs.ip(), 0x100300);
        assert_eq!(regs.sp(), 0x18);
        assert_eq!(regs.bp(), 0x20);
        let res = UnwindRuleX86_64::UseFramePointer.exec(&mut regs, &mut read_mem);
        assert_eq!(res, Ok(Some(0x100200)));
        assert_eq!(regs.ip(), 0x100200);
        assert_eq!(regs.sp(), 0x30);
        assert_eq!(regs.bp(), 0x40);
        let res = UnwindRuleX86_64::UseFramePointer.exec(&mut regs, &mut read_mem);
        assert_eq!(res, Ok(Some(0x100100)));
        assert_eq!(regs.ip(), 0x100100);
        assert_eq!(regs.sp(), 0x50);
        assert_eq!(regs.bp(), 0x70);
        let res = UnwindRuleX86_64::UseFramePointer.exec(&mut regs, &mut read_mem);
        assert_eq!(res, Ok(None));
    }
}
