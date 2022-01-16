use crate::display_utils::{BinNum, HexNum};
use std::fmt::Debug;

pub struct OpcodeBitfield(pub u32);

impl OpcodeBitfield {
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Whether this instruction is the start of a function.
    pub fn is_function_start(&self) -> bool {
        self.0 >> 31 == 1
    }

    /// Whether there is an lsda entry for this instruction.
    pub fn has_lsda(&self) -> bool {
        (self.0 >> 30) & 0b1 == 1
    }

    /// An index into the global personalities array
    /// (TODO: ignore if has_lsda() == false?)
    pub fn personality_index(&self) -> u8 {
        ((self.0 >> 28) & 0b11) as u8
    }

    /// The architecture-specific kind of opcode this is, specifying how to
    /// interpret the remaining 24 bits of the opcode.
    pub fn kind(&self) -> u8 {
        ((self.0 >> 24) & 0b1111) as u8
    }

    /// The architecture-specific remaining 24 bits.
    pub fn specific_bits(&self) -> u32 {
        self.0 & 0xffffff
    }
}

impl From<u32> for OpcodeBitfield {
    fn from(opcode: u32) -> OpcodeBitfield {
        OpcodeBitfield::new(opcode)
    }
}

impl Debug for OpcodeBitfield {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opcode")
            .field("kind", &self.kind())
            .field("is_function_start", &self.is_function_start())
            .field("has_lsda", &self.has_lsda())
            .field("personality_index", &self.personality_index())
            .field("specific_bits", &BinNum(self.specific_bits()))
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CompressedEntryBitfield(pub u32);

/// Entries are a u32 that contains two packed values (from high to low):
/// * 8 bits: opcode index
/// * 24 bits: instruction address
impl CompressedEntryBitfield {
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// The opcode index.
    ///   * 0..global_opcodes_len => index into global palette
    ///   * global_opcodes_len..255 => index into local palette
    ///     (subtract global_opcodes_len to get the real local index)
    pub fn opcode_index(&self) -> u8 {
        (self.0 >> 24) as u8
    }

    /// The instruction address, relative to the page's first_address.
    pub fn relative_instruction_address(&self) -> u32 {
        self.0 & 0xffffff
    }
}

impl From<u32> for CompressedEntryBitfield {
    fn from(entry: u32) -> CompressedEntryBitfield {
        CompressedEntryBitfield::new(entry)
    }
}

impl Debug for CompressedEntryBitfield {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompressedEntryBitfield")
            .field("opcode_index", &HexNum(self.opcode_index()))
            .field(
                "relative_instruction_address",
                &HexNum(self.relative_instruction_address()),
            )
            .finish()
    }
}
