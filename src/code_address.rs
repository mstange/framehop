use std::num::NonZeroU64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameAddress {
    InstructionPointer(u64),
    ReturnAddress(NonZeroU64),
}

impl FrameAddress {
    pub fn from_instruction_pointer(ip: u64) -> Self {
        FrameAddress::InstructionPointer(ip)
    }

    pub fn from_return_address(return_address: u64) -> Option<Self> {
        Some(FrameAddress::ReturnAddress(NonZeroU64::new(
            return_address,
        )?))
    }

    pub fn address(self) -> u64 {
        match self {
            FrameAddress::InstructionPointer(address) => address,
            FrameAddress::ReturnAddress(address) => address.into(),
        }
    }

    pub fn address_for_lookup(self) -> u64 {
        match self {
            FrameAddress::InstructionPointer(address) => address,
            FrameAddress::ReturnAddress(address) => u64::from(address) - 1,
        }
    }

    pub fn is_return_address(self) -> bool {
        match self {
            FrameAddress::InstructionPointer(_) => false,
            FrameAddress::ReturnAddress(_) => true,
        }
    }
}
