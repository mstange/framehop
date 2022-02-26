use std::num::NonZeroU64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeAddress {
    InstructionPointer(u64),
    ReturnAddress(NonZeroU64),
}

impl CodeAddress {
    pub fn from_instruction_pointer(ip: u64) -> Self {
        CodeAddress::InstructionPointer(ip)
    }

    pub fn from_return_address(return_address: u64) -> Option<Self> {
        Some(CodeAddress::ReturnAddress(NonZeroU64::new(return_address)?))
    }

    pub fn address(self) -> u64 {
        match self {
            CodeAddress::InstructionPointer(address) => address,
            CodeAddress::ReturnAddress(address) => address.into(),
        }
    }

    pub fn address_for_lookup(self) -> u64 {
        match self {
            CodeAddress::InstructionPointer(address) => address,
            CodeAddress::ReturnAddress(address) => u64::from(address) - 1,
        }
    }

    pub fn is_return_address(self) -> bool {
        match self {
            CodeAddress::InstructionPointer(_) => false,
            CodeAddress::ReturnAddress(_) => true,
        }
    }
}
