use std::fmt::Display;

use super::{
    nice::OpcodeBitfield, OPCODE_KIND_ARM64_DWARF, OPCODE_KIND_ARM64_FRAMEBASED,
    OPCODE_KIND_ARM64_FRAMELESS, OPCODE_KIND_NULL, OPCODE_KIND_X86_DWARF,
    OPCODE_KIND_X86_FRAMEBASED, OPCODE_KIND_X86_FRAMELESS_IMMEDIATE,
    OPCODE_KIND_X86_FRAMELESS_INDIRECT,
};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OpcodeRegX86 {
    Ebx,
    Ecx,
    Edx,
    Edi,
    Esi,
    Ebp,
}

impl OpcodeRegX86 {
    pub fn parse(n: u8) -> Option<Self> {
        match n {
            1 => Some(OpcodeRegX86::Ebx),
            2 => Some(OpcodeRegX86::Ecx),
            3 => Some(OpcodeRegX86::Edx),
            4 => Some(OpcodeRegX86::Edi),
            5 => Some(OpcodeRegX86::Esi),
            6 => Some(OpcodeRegX86::Ebp),
            _ => None,
        }
    }

    pub fn dwarf_name(&self) -> &'static str {
        match self {
            OpcodeRegX86::Ebx => "reg3",
            OpcodeRegX86::Ecx => "reg1",
            OpcodeRegX86::Edx => "reg2",
            OpcodeRegX86::Edi => "reg7",
            OpcodeRegX86::Esi => "reg6",
            OpcodeRegX86::Ebp => "reg5",
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OpcodeRegX86_64 {
    Rbx,
    R12,
    R13,
    R14,
    R15,
    Rbp,
}

impl OpcodeRegX86_64 {
    pub fn parse(n: u8) -> Option<Self> {
        match n {
            1 => Some(OpcodeRegX86_64::Rbx),
            2 => Some(OpcodeRegX86_64::R12),
            3 => Some(OpcodeRegX86_64::R13),
            4 => Some(OpcodeRegX86_64::R14),
            5 => Some(OpcodeRegX86_64::R15),
            6 => Some(OpcodeRegX86_64::Rbp),
            _ => None,
        }
    }

    pub fn dwarf_name(&self) -> &'static str {
        match self {
            OpcodeRegX86_64::Rbx => "reg3",
            OpcodeRegX86_64::R12 => "reg12",
            OpcodeRegX86_64::R13 => "reg13",
            OpcodeRegX86_64::R14 => "reg14",
            OpcodeRegX86_64::R15 => "reg15",
            OpcodeRegX86_64::Rbp => "reg6",
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OpcodeX86 {
    Null,
    FrameBased {
        stack_offset_in_bytes: u16,
        saved_regs: [Option<OpcodeRegX86>; 5],
    },
    FramelessImmediate {
        stack_size_in_bytes: u16,
        saved_regs: [Option<OpcodeRegX86>; 6],
    },
    FramelessIndirect,
    Dwarf {
        eh_frame_fde: u32,
    },
}

impl OpcodeX86 {
    pub fn parse(opcode: &OpcodeBitfield) -> Option<Self> {
        let opcode = match opcode.kind() {
            OPCODE_KIND_NULL => OpcodeX86::Null,
            OPCODE_KIND_X86_FRAMEBASED => OpcodeX86::FrameBased {
                stack_offset_in_bytes: (((opcode.0 >> 16) & 0xff) as u16) * 4,
                saved_regs: [
                    OpcodeRegX86::parse(((opcode.0 >> 12) & 0b111) as u8),
                    OpcodeRegX86::parse(((opcode.0 >> 9) & 0b111) as u8),
                    OpcodeRegX86::parse(((opcode.0 >> 6) & 0b111) as u8),
                    OpcodeRegX86::parse(((opcode.0 >> 3) & 0b111) as u8),
                    OpcodeRegX86::parse((opcode.0 & 0b111) as u8),
                ],
            },
            OPCODE_KIND_X86_FRAMELESS_IMMEDIATE => {
                let stack_size_in_bytes = (((opcode.0 >> 16) & 0xff) as u16) * 4;
                let register_count = (opcode.0 >> 10) & 0b111;
                let register_permutation = opcode.0 & 0b11_1111_1111;
                let saved_registers =
                    decode_permutation(register_count, register_permutation).ok()?;
                OpcodeX86::FramelessImmediate {
                    stack_size_in_bytes,
                    saved_regs: [
                        OpcodeRegX86::parse(saved_registers[0]),
                        OpcodeRegX86::parse(saved_registers[1]),
                        OpcodeRegX86::parse(saved_registers[2]),
                        OpcodeRegX86::parse(saved_registers[3]),
                        OpcodeRegX86::parse(saved_registers[4]),
                        OpcodeRegX86::parse(saved_registers[5]),
                    ],
                }
            }
            OPCODE_KIND_X86_FRAMELESS_INDIRECT => OpcodeX86::FramelessIndirect,
            OPCODE_KIND_X86_DWARF => OpcodeX86::Dwarf {
                eh_frame_fde: (opcode.0 & 0xffffff),
            },
            _ => return None,
        };
        Some(opcode)
    }
}

impl Display for OpcodeX86 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpcodeX86::Null => {
                write!(f, "(uncovered)")?;
            }
            OpcodeX86::FrameBased {
                stack_offset_in_bytes,
                saved_regs,
            } => {
                // ebp was set to esp before the saved registers were pushed.
                // The first pushed register is at ebp - 4 (== CFA - 12), the last at ebp - stack_offset_in_bytes.
                write!(f, "CFA=reg6+8: reg6=[CFA-8], reg16=[CFA-4]")?;
                let max_count = (*stack_offset_in_bytes / 4) as usize;
                let mut offset = *stack_offset_in_bytes + 8; // + 2 for rbp, return address
                for reg in saved_regs.iter().rev().take(max_count) {
                    if let Some(reg) = reg {
                        write!(f, ", {}=[CFA-{}]", reg.dwarf_name(), offset)?;
                    }
                    offset -= 4;
                }
            }
            OpcodeX86::FramelessImmediate {
                stack_size_in_bytes,
                saved_regs,
            } => {
                if *stack_size_in_bytes == 0 {
                    write!(f, "CFA=reg7:",)?;
                } else {
                    write!(f, "CFA=reg7+{}:", *stack_size_in_bytes)?;
                }
                write!(f, " reg16=[CFA-8]")?;
                let mut offset = 2 * 4;
                for reg in saved_regs.iter().rev().flatten() {
                    write!(f, ", {}=[CFA-{}]", reg.dwarf_name(), offset)?;
                    offset += 4;
                }
            }
            OpcodeX86::FramelessIndirect { .. } => {
                write!(f, "frameless indirect")?;
            }
            OpcodeX86::Dwarf { eh_frame_fde } => {
                write!(f, "(check eh_frame FDE 0x{:x})", eh_frame_fde)?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpcodeX86_64 {
    Null,
    FrameBased {
        stack_offset_in_bytes: u16,
        saved_regs: [Option<OpcodeRegX86_64>; 5],
    },
    FramelessImmediate {
        stack_size_in_bytes: u16,
        saved_regs: [Option<OpcodeRegX86_64>; 6],
    },
    FramelessIndirect,
    Dwarf {
        eh_frame_fde: u32,
    },
}

impl OpcodeX86_64 {
    pub fn parse(opcode: &OpcodeBitfield) -> Option<Self> {
        let opcode = match opcode.kind() {
            OPCODE_KIND_NULL => OpcodeX86_64::Null,
            OPCODE_KIND_X86_FRAMEBASED => OpcodeX86_64::FrameBased {
                stack_offset_in_bytes: (((opcode.0 >> 16) & 0xff) as u16) * 8,
                saved_regs: [
                    OpcodeRegX86_64::parse(((opcode.0 >> 12) & 0b111) as u8),
                    OpcodeRegX86_64::parse(((opcode.0 >> 9) & 0b111) as u8),
                    OpcodeRegX86_64::parse(((opcode.0 >> 6) & 0b111) as u8),
                    OpcodeRegX86_64::parse(((opcode.0 >> 3) & 0b111) as u8),
                    OpcodeRegX86_64::parse((opcode.0 & 0b111) as u8),
                ],
            },
            OPCODE_KIND_X86_FRAMELESS_IMMEDIATE => {
                let stack_size_in_bytes = (((opcode.0 >> 16) & 0xff) as u16) * 8;
                let register_count = (opcode.0 >> 10) & 0b111;
                let register_permutation = opcode.0 & 0b11_1111_1111;
                let saved_registers =
                    decode_permutation(register_count, register_permutation).ok()?;
                OpcodeX86_64::FramelessImmediate {
                    stack_size_in_bytes,
                    saved_regs: [
                        OpcodeRegX86_64::parse(saved_registers[0]),
                        OpcodeRegX86_64::parse(saved_registers[1]),
                        OpcodeRegX86_64::parse(saved_registers[2]),
                        OpcodeRegX86_64::parse(saved_registers[3]),
                        OpcodeRegX86_64::parse(saved_registers[4]),
                        OpcodeRegX86_64::parse(saved_registers[5]),
                    ],
                }
            }
            OPCODE_KIND_X86_FRAMELESS_INDIRECT => OpcodeX86_64::FramelessIndirect,
            OPCODE_KIND_X86_DWARF => OpcodeX86_64::Dwarf {
                eh_frame_fde: (opcode.0 & 0xffffff),
            },
            _ => return None,
        };
        Some(opcode)
    }
}

/// Magically unpack 6 values from 10 bits.
///
/// Background:
///
/// Let's start with a simpler example of packing a list of numbers.
/// Let's say you want to store 2 values a and b, which can each be 0, 1, or 2.
/// You can store this as x = a * 3 + b. Then you can get out (a, b) by doing a
/// division by 3 with remainder, because this has the form of n * 3 + (something less than 3)
///
/// Similar, for four values, you can use:
///
/// ```text
/// x = a * 27 + b * 9 + c * 3 + d.
///              ^^^^^^^^^^^^^^^^^ == x % 27
///                      ^^^^^^^^^ == x % 9
///                              ^ == x % 3
/// x == 27 * a + rem27
/// rem27 == 9 * b + rem9
/// rem9 == 3 * c + rem3
/// rem3 = d
/// ```
///
/// Written differently:
/// `x = d + 3 * (c + 3 * (b + (3 * a)))`
///
/// So that was the case for when all digits have the same range (0..3 in this example).
///
/// In this function we want to decode a permutation. In a permutation of n items,
/// for the first digit we can choose one of n items, for the second digit we can
/// choose one of the remaining n - 1 items, for the third one of the remaining n - 2 etc.
///
/// We have the choice between 6 registers, so n = 6 in this function.
/// Each digit is stored zero-based. So a is in 0..6, b is in 0..5, c in 0..4 etc.
///
/// We encode as (a, b, c) as c + 4 * (b + 5 * a)
/// [...]
#[inline(never)]
fn decode_permutation(count: u32, mut encoding: u32) -> Result<[u8; 6], ()> {
    if count > 6 {
        return Err(());
    }

    let mut compressed_regindexes = [0; 6];

    if count > 4 {
        compressed_regindexes[4] = encoding % 2;
        encoding /= 2;
    }
    if count > 3 {
        compressed_regindexes[3] = encoding % 3;
        encoding /= 3;
    }
    if count > 2 {
        compressed_regindexes[2] = encoding % 4;
        encoding /= 4;
    }
    if count > 1 {
        compressed_regindexes[1] = encoding % 5;
        encoding /= 5;
    }
    if count > 0 {
        compressed_regindexes[0] = encoding;
    }

    if compressed_regindexes[0] >= 6 {
        return Err(());
    }

    let mut registers = [0; 6];
    let mut used = [false; 6];
    for i in 0..count {
        let compressed_regindex = compressed_regindexes[i as usize];
        debug_assert!(compressed_regindex < 6 - i);
        let uncompressed_regindex = (0..6)
            .filter(|ri| !used[*ri])
            .nth(compressed_regindex as usize)
            .unwrap();
        used[uncompressed_regindex] = true;
        registers[i as usize] = (uncompressed_regindex + 1) as u8;
    }
    Ok(registers)
}

impl Display for OpcodeX86_64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpcodeX86_64::Null => {
                write!(f, "(uncovered)")?;
            }
            OpcodeX86_64::FrameBased {
                stack_offset_in_bytes,
                saved_regs,
            } => {
                // rbp was set to rsp before the saved registers were pushed.
                // The first pushed register is at rbp - 8 (== CFA - 24), the last at rbp - stack_offset_in_bytes.
                write!(f, "CFA=reg6+16: reg6=[CFA-16], reg16=[CFA-8]")?;
                let max_count = (*stack_offset_in_bytes / 8) as usize;
                let mut offset = *stack_offset_in_bytes + 16; // + 2 for rbp, return address
                for reg in saved_regs.iter().rev().take(max_count) {
                    if let Some(reg) = reg {
                        write!(f, ", {}=[CFA-{}]", reg.dwarf_name(), offset)?;
                    }
                    offset -= 8;
                }
            }
            OpcodeX86_64::FramelessImmediate {
                stack_size_in_bytes,
                saved_regs,
            } => {
                if *stack_size_in_bytes == 0 {
                    write!(f, "CFA=reg7:",)?;
                } else {
                    write!(f, "CFA=reg7+{}:", *stack_size_in_bytes)?;
                }
                write!(f, " reg16=[CFA-8]")?;
                let mut offset = 2 * 8;
                for reg in saved_regs.iter().rev().flatten() {
                    write!(f, ", {}=[CFA-{}]", reg.dwarf_name(), offset)?;
                    offset += 8;
                }
            }
            OpcodeX86_64::FramelessIndirect { .. } => {
                write!(f, "frameless indirect")?;
            }
            OpcodeX86_64::Dwarf { eh_frame_fde } => {
                write!(f, "(check eh_frame FDE 0x{:x})", eh_frame_fde)?;
            }
        }
        Ok(())
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OpcodeArm64 {
    Null,
    Frameless {
        stack_size_in_bytes: u16,
    },
    Dwarf {
        eh_frame_fde: u32,
    },
    FrameBased {
        // Whether each register pair was pushed
        d14_and_d15_saved: bool,
        d12_and_d13_saved: bool,
        d10_and_d11_saved: bool,
        d8_and_d9_saved: bool,

        x27_and_x28_saved: bool,
        x25_and_x26_saved: bool,
        x23_and_x24_saved: bool,
        x21_and_x22_saved: bool,
        x19_and_x20_saved: bool,
    },
}

impl OpcodeArm64 {
    pub fn parse(opcode: &OpcodeBitfield) -> Option<Self> {
        let opcode = match opcode.kind() {
            OPCODE_KIND_NULL => OpcodeArm64::Null,
            OPCODE_KIND_ARM64_FRAMELESS => OpcodeArm64::Frameless {
                stack_size_in_bytes: (((opcode.0 >> 12) & 0b1111_1111_1111) as u16) * 16,
            },
            OPCODE_KIND_ARM64_DWARF => OpcodeArm64::Dwarf {
                eh_frame_fde: (opcode.0 & 0xffffff),
            },
            OPCODE_KIND_ARM64_FRAMEBASED => OpcodeArm64::FrameBased {
                d14_and_d15_saved: ((opcode.0 >> 8) & 1) == 1,
                d12_and_d13_saved: ((opcode.0 >> 7) & 1) == 1,
                d10_and_d11_saved: ((opcode.0 >> 6) & 1) == 1,
                d8_and_d9_saved: ((opcode.0 >> 5) & 1) == 1,
                x27_and_x28_saved: ((opcode.0 >> 4) & 1) == 1,
                x25_and_x26_saved: ((opcode.0 >> 3) & 1) == 1,
                x23_and_x24_saved: ((opcode.0 >> 2) & 1) == 1,
                x21_and_x22_saved: ((opcode.0 >> 1) & 1) == 1,
                x19_and_x20_saved: (opcode.0 & 1) == 1,
            },
            _ => return None,
        };
        Some(opcode)
    }
}

impl Display for OpcodeArm64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpcodeArm64::Null => {
                write!(f, "(uncovered)")?;
            }
            OpcodeArm64::Frameless {
                stack_size_in_bytes,
            } => {
                if *stack_size_in_bytes == 0 {
                    write!(f, "CFA=reg31")?;
                } else {
                    write!(f, "CFA=reg31+{}", stack_size_in_bytes)?;
                }
            }
            OpcodeArm64::Dwarf { eh_frame_fde } => {
                write!(f, "(check eh_frame FDE 0x{:x})", eh_frame_fde)?;
            }
            OpcodeArm64::FrameBased {
                d14_and_d15_saved,
                d12_and_d13_saved,
                d10_and_d11_saved,
                d8_and_d9_saved,
                x27_and_x28_saved,
                x25_and_x26_saved,
                x23_and_x24_saved,
                x21_and_x22_saved,
                x19_and_x20_saved,
            } => {
                write!(f, "CFA=reg29+16: reg29=[CFA-16], reg30=[CFA-8]")?;
                let mut offset = 32;
                let mut next_pair = |pair_saved, a, b| {
                    if pair_saved {
                        let r = write!(f, ", {}=[CFA-{}], {}=[CFA-{}]", a, offset, b, offset + 8);
                        offset += 16;
                        r
                    } else {
                        Ok(())
                    }
                };
                next_pair(*d14_and_d15_saved, "reg14", "reg15")?;
                next_pair(*d12_and_d13_saved, "reg12", "reg13")?;
                next_pair(*d10_and_d11_saved, "reg10", "reg11")?;
                next_pair(*d8_and_d9_saved, "reg8", "reg9")?;
                next_pair(*x27_and_x28_saved, "reg27", "reg28")?;
                next_pair(*x25_and_x26_saved, "reg25", "reg26")?;
                next_pair(*x23_and_x24_saved, "reg23", "reg24")?;
                next_pair(*x21_and_x22_saved, "reg21", "reg22")?;
                next_pair(*x19_and_x20_saved, "reg19", "reg20")?;
            }
        }
        Ok(())
    }
}
