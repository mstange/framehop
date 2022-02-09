
#[derive(Clone, Copy, Debug)]
pub enum CodeAddress {
  InstructionPointer(u64),
  ReturnAddress(u64),
}

impl CodeAddress {
  pub fn address(self) -> u64 {
    match self {
        CodeAddress::InstructionPointer(address) => address,
        CodeAddress::ReturnAddress(address) => address,
    }
  }
  pub fn address_for_lookup(self) -> u64 {
    match self {
        CodeAddress::InstructionPointer(address) => address,
        CodeAddress::ReturnAddress(address) => address - 1,
    }
  }
}