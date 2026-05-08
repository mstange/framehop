use core::fmt::Debug;

use crate::display_utils::HexNum;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UnwindRegsX86_64 {
    ip: u64,
    regs: [u64; 16],
    valid_regs: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Reg {
    RAX,
    RDX,
    RCX,
    RBX,
    RSI,
    RDI,
    RBP,
    RSP,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

impl UnwindRegsX86_64 {
    pub fn new(ip: u64, sp: u64, bp: u64) -> Self {
        let mut r = Self {
            ip,
            regs: Default::default(),
            valid_regs: 0,
        };
        r.set_sp(sp);
        r.set_bp(bp);
        r
    }

    #[inline(always)]
    fn valid_reg_bit(reg: Reg) -> u16 {
        1u16 << (reg as u8)
    }

    #[inline(always)]
    pub fn get(&self, reg: Reg) -> u64 {
        self.regs[reg as usize]
    }
    #[inline(always)]
    pub fn get_if_set(&self, reg: Reg) -> Option<u64> {
        if self.valid_regs & Self::valid_reg_bit(reg) != 0 {
            Some(self.get(reg))
        } else {
            None
        }
    }
    #[inline(always)]
    pub fn set(&mut self, reg: Reg, value: u64) {
        self.regs[reg as usize] = value;
        self.valid_regs |= Self::valid_reg_bit(reg);
    }
    #[inline(always)]
    pub(crate) fn clear_unrestored_caller_registers(&mut self) {
        self.valid_regs &= Self::valid_reg_bit(Reg::RBP) | Self::valid_reg_bit(Reg::RSP);
    }

    #[inline(always)]
    pub fn ip(&self) -> u64 {
        self.ip
    }
    #[inline(always)]
    pub fn set_ip(&mut self, ip: u64) {
        self.ip = ip
    }

    #[inline(always)]
    pub fn sp(&self) -> u64 {
        self.get(Reg::RSP)
    }
    #[inline(always)]
    pub fn set_sp(&mut self, sp: u64) {
        self.set(Reg::RSP, sp)
    }

    #[inline(always)]
    pub fn bp(&self) -> u64 {
        self.get(Reg::RBP)
    }
    #[inline(always)]
    pub fn set_bp(&mut self, bp: u64) {
        self.set(Reg::RBP, bp)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn clear_unrestored_caller_registers_keeps_frame_registers() {
        let mut regs = UnwindRegsX86_64::new(0x100, 0x200, 0x300);
        regs.set(Reg::RAX, 0x400);
        regs.set(Reg::RBX, 0x500);

        regs.clear_unrestored_caller_registers();

        assert_eq!(regs.ip(), 0x100);
        assert_eq!(regs.get_if_set(Reg::RSP), Some(0x200));
        assert_eq!(regs.get_if_set(Reg::RBP), Some(0x300));
        assert_eq!(regs.get_if_set(Reg::RAX), None);
        assert_eq!(regs.get_if_set(Reg::RBX), None);
    }
}

impl Debug for UnwindRegsX86_64 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UnwindRegsX86_64")
            .field("ip", &HexNum(self.ip()))
            .field("rax", &self.get_if_set(Reg::RAX).map(HexNum))
            .field("rdx", &self.get_if_set(Reg::RDX).map(HexNum))
            .field("rcx", &self.get_if_set(Reg::RCX).map(HexNum))
            .field("rbx", &self.get_if_set(Reg::RBX).map(HexNum))
            .field("rsi", &self.get_if_set(Reg::RSI).map(HexNum))
            .field("rdi", &self.get_if_set(Reg::RDI).map(HexNum))
            .field("rbp", &self.get_if_set(Reg::RBP).map(HexNum))
            .field("rsp", &self.get_if_set(Reg::RSP).map(HexNum))
            .field("r8", &self.get_if_set(Reg::R8).map(HexNum))
            .field("r9", &self.get_if_set(Reg::R9).map(HexNum))
            .field("r10", &self.get_if_set(Reg::R10).map(HexNum))
            .field("r11", &self.get_if_set(Reg::R11).map(HexNum))
            .field("r12", &self.get_if_set(Reg::R12).map(HexNum))
            .field("r13", &self.get_if_set(Reg::R13).map(HexNum))
            .field("r14", &self.get_if_set(Reg::R14).map(HexNum))
            .field("r15", &self.get_if_set(Reg::R15).map(HexNum))
            .finish()
    }
}
