use super::arch::ArchAarch64;
use super::unwind_rule::UnwindRuleAarch64;
use crate::instruction_analysis::InstructionAnalysis;

impl InstructionAnalysis for ArchAarch64 {
    fn rule_from_prologue_analysis(
        text_bytes_from_function_start: &[u8],
        text_bytes_until_function_end: &[u8],
    ) -> Option<Self::UnwindRule> {
        unwind_rule_from_detected_prologue(
            text_bytes_from_function_start,
            text_bytes_until_function_end,
        )
    }

    fn rule_from_epilogue_analysis(
        text_bytes_until_function_end: &[u8],
    ) -> Option<Self::UnwindRule> {
        unwind_rule_from_detected_epilogue(text_bytes_until_function_end)
    }
}

struct PrologueDetectorAarch64 {
    sp_offset: i32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PrologueStepResult {
    UnexpectedInstruction(UnexpectedInstructionType),
    ValidPrologueInstruction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PrologueResult {
    ProbablyAlreadyInBody(UnexpectedInstructionType),
    FoundFunctionStart { sp_offset: i32 },
}

impl PrologueDetectorAarch64 {
    pub fn new() -> Self {
        Self { sp_offset: 0 }
    }

    pub fn analyze_slices(
        &mut self,
        slice_from_start: &[u8],
        slice_to_end: &[u8],
    ) -> PrologueResult {
        // There are at least two options of what we could do here:
        //  - We could walk forwards from the function start to the instruction pointer.
        //  - We could walk backwards from the instruction pointer to the function start.
        // Walking backwards is fine on arm64 because instructions are fixed size.
        // Walking forwards requires that we have a useful function start address.
        //
        // Unfortunately, we can't rely on having a useful function start address.
        // We get the funcion start address from the __unwind_info, which often collapses
        // consecutive functions with the same unwind rules into a single entry, discarding
        // the original function start addresses.
        // Concretely, this means that `slice_from_start` may start much earlier than the
        // current function.
        //
        // So we walk backwards. We first check the next instruction, and then
        // go backwards from the instruction pointer to the function start.
        // If the instruction we're about to execute is one that we'd expect to find in a prologue,
        // then we assume that we're in a prologue. Then we single-step backwards until we
        // either run out of instructions (which means we've definitely hit the start of the
        // function), or until we find an instruction that we would not expect in a prologue.
        // At that point we guess that this instruction must be belonging to the previous
        // function, and that we've succesfully found the start of the current function.
        if slice_to_end.len() < 4 {
            return PrologueResult::ProbablyAlreadyInBody(
                UnexpectedInstructionType::NoNextInstruction,
            );
        }
        let next_instruction = u32::from_le_bytes([
            slice_to_end[0],
            slice_to_end[1],
            slice_to_end[2],
            slice_to_end[3],
        ]);
        if !Self::is_valid_prologue_instruction(next_instruction) {
            return PrologueResult::ProbablyAlreadyInBody(UnexpectedInstructionType::Unknown);
        }
        let instructions = slice_from_start
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .rev();
        for instruction in instructions {
            if let PrologueStepResult::UnexpectedInstruction(_) =
                self.step_instruction_backwards(instruction)
            {
                break;
            }
        }
        PrologueResult::FoundFunctionStart {
            sp_offset: self.sp_offset,
        }
    }

    /// Check if the instruction indicates that we're likely in a prologue.
    pub fn is_valid_prologue_instruction(word: u32) -> bool {
        // Detect pacibsp (verify stack pointer authentication) and `mov x29, sp`.
        if word == 0xd503237f || word == 0x910003fd {
            return true;
        }

        let bits_22_to_32 = word >> 22;

        // Detect stores of register pairs to the stack.
        if bits_22_to_32 & 0b1011111001 == 0b1010100000 {
            // Section C3.3, Loads and stores.
            // Only stores that are commonly seen in prologues (bits 22, 29 and 31 are set)
            let writeback_bits = bits_22_to_32 & 0b110;
            let reference_reg = ((word >> 5) & 0b11111) as u16;
            return writeback_bits != 0b000 && reference_reg == 31;
        }
        // Detect sub instructions operating on the stack pointer.
        // Detect `add fp, sp, #0xXX` instructions
        if bits_22_to_32 & 0b1011111110 == 0b1001000100 {
            // Section C3.4, Data processing - immediate
            // unsigned add / sub imm, size class X (8 bytes)
            let result_reg = (word & 0b11111) as u16;
            let input_reg = ((word >> 5) & 0b11111) as u16;
            let is_sub = ((word >> 30) & 0b1) == 0b1;
            let expected_result_reg = if is_sub { 31 } else { 29 };
            return input_reg == 31 && result_reg == expected_result_reg;
        }
        false
    }

    /// Step backwards over one (already executed) instruction.
    pub fn step_instruction_backwards(&mut self, word: u32) -> PrologueStepResult {
        // Detect pacibsp (verify stack pointer authentication)
        if word == 0xd503237f {
            return PrologueStepResult::ValidPrologueInstruction;
        }

        // Detect stores of register pairs to the stack.
        if (word >> 25) & 0b1011111 == 0b1010100 {
            // Section C3.3, Loads and stores.
            // but only those that are commonly seen in prologues / prologues (bits 29 and 31 are set)
            let writeback_bits = (word >> 23) & 0b11;
            if writeback_bits == 0b00 {
                // Not 64-bit load/store.
                return PrologueStepResult::UnexpectedInstruction(
                    UnexpectedInstructionType::LoadStoreOfWrongSize,
                );
            }
            let is_load = ((word >> 22) & 1) != 0;
            if is_load {
                return PrologueStepResult::UnexpectedInstruction(UnexpectedInstructionType::Load);
            }
            let reference_reg = ((word >> 5) & 0b11111) as u16;
            if reference_reg != 31 {
                return PrologueStepResult::UnexpectedInstruction(
                    UnexpectedInstructionType::LoadStoreReferenceRegisterNotSp,
                );
            }
            let is_preindexed_writeback = writeback_bits == 0b11;
            let is_postindexed_writeback = writeback_bits == 0b01; // TODO: are there postindexed stores? What do they mean?
            if is_preindexed_writeback || is_postindexed_writeback {
                let imm7 = (((((word >> 15) & 0b1111111) as i16) << 9) >> 6) as i32;
                self.sp_offset -= imm7; // - to undo the instruction
            }
            return PrologueStepResult::ValidPrologueInstruction;
        }
        // Detect sub instructions operating on the stack pointer.
        if (word >> 23) & 0b111111111 == 0b110100010 {
            // Section C3.4, Data processing - immediate
            // unsigned sub imm, size class X (8 bytes)
            let result_reg = (word & 0b11111) as u16;
            let input_reg = ((word >> 5) & 0b11111) as u16;
            if result_reg != 31 || input_reg != 31 {
                return PrologueStepResult::UnexpectedInstruction(
                    UnexpectedInstructionType::AddSubNotOperatingOnSp,
                );
            }
            let mut imm12 = ((word >> 10) & 0b111111111111) as i32;
            let shift_immediate_by_12 = ((word >> 22) & 0b1) == 0b1;
            if shift_immediate_by_12 {
                imm12 <<= 12
            }
            self.sp_offset += imm12; // + to undo the sub instruction
            return PrologueStepResult::ValidPrologueInstruction;
        }
        PrologueStepResult::UnexpectedInstruction(UnexpectedInstructionType::Unknown)
    }
}

fn analyze_prologue_aarch64(slice_from_start: &[u8], slice_to_end: &[u8]) -> PrologueResult {
    let mut detector = PrologueDetectorAarch64::new();
    detector.analyze_slices(slice_from_start, slice_to_end)
}

fn unwind_rule_from_detected_prologue(
    slice_from_start: &[u8],
    slice_to_end: &[u8],
) -> Option<UnwindRuleAarch64> {
    match analyze_prologue_aarch64(slice_from_start, slice_to_end) {
        PrologueResult::ProbablyAlreadyInBody(_) => None,
        PrologueResult::FoundFunctionStart { sp_offset } => {
            let sp_offset_by_16 = u16::try_from(sp_offset / 16).ok()?;
            let rule = if sp_offset_by_16 == 0 {
                UnwindRuleAarch64::NoOp
            } else {
                UnwindRuleAarch64::OffsetSp { sp_offset_by_16 }
            };
            Some(rule)
        }
    }
}

struct EpilogueDetectorAarch64 {
    sp_offset: i32,
    fp_offset_from_initial_sp: Option<i32>,
    lr_offset_from_initial_sp: Option<i32>,
}

enum EpilogueStepResult {
    NeedMore,
    Done(EpilogueResult),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum EpilogueResult {
    ProbablyStillInBody(UnexpectedInstructionType),
    ReachedFunctionEndWithoutReturn,
    FoundReturn {
        sp_offset: i32,
        fp_offset_from_initial_sp: Option<i32>,
        lr_offset_from_initial_sp: Option<i32>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum UnexpectedInstructionType {
    LoadStoreOfWrongSize,
    Load,
    Store,
    LoadStoreReferenceRegisterNotSp,
    AddSubNotOperatingOnSp,
    NoNextInstruction,
    Unknown,
}

impl EpilogueDetectorAarch64 {
    pub fn new() -> Self {
        Self {
            sp_offset: 0,
            fp_offset_from_initial_sp: None,
            lr_offset_from_initial_sp: None,
        }
    }

    pub fn analyze_slice(&mut self, mut bytes: &[u8]) -> EpilogueResult {
        while bytes.len() >= 4 {
            let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            bytes = &bytes[4..];
            if let EpilogueStepResult::Done(result) = self.step_instruction(word) {
                return result;
            }
        }
        EpilogueResult::ReachedFunctionEndWithoutReturn
    }

    pub fn step_instruction(&mut self, word: u32) -> EpilogueStepResult {
        // Detect ret and retab
        if word == 0xd65f03c0 || word == 0xd65f0fff {
            return EpilogueStepResult::Done(EpilogueResult::FoundReturn {
                sp_offset: self.sp_offset,
                fp_offset_from_initial_sp: self.fp_offset_from_initial_sp,
                lr_offset_from_initial_sp: self.lr_offset_from_initial_sp,
            });
        }
        if (word >> 25) & 0b1011111 == 0b1010100 {
            // Section C3.3, Loads and stores.
            // but only those that are commonly seen in prologues / epilogues (bits 29 and 31 are set)
            let writeback_bits = (word >> 23) & 0b11;
            if writeback_bits == 0b00 {
                // Not 64-bit load/store.
                return EpilogueStepResult::Done(EpilogueResult::ProbablyStillInBody(
                    UnexpectedInstructionType::LoadStoreOfWrongSize,
                ));
            }
            let is_load = ((word >> 22) & 1) != 0;
            if !is_load {
                return EpilogueStepResult::Done(EpilogueResult::ProbablyStillInBody(
                    UnexpectedInstructionType::Store,
                ));
            }
            let reference_reg = ((word >> 5) & 0b11111) as u16;
            if reference_reg != 31 {
                return EpilogueStepResult::Done(EpilogueResult::ProbablyStillInBody(
                    UnexpectedInstructionType::LoadStoreReferenceRegisterNotSp,
                ));
            }
            let is_preindexed_writeback = writeback_bits == 0b11; // TODO: are there preindexed loads? What do they mean?
            let is_postindexed_writeback = writeback_bits == 0b01;
            let imm7 = (((((word >> 15) & 0b1111111) as i16) << 9) >> 6) as i32;
            let pair_reg_1 = (word & 0b11111) as u16;
            if pair_reg_1 == 29 {
                self.fp_offset_from_initial_sp = Some(self.sp_offset + imm7);
            } else if pair_reg_1 == 30 {
                self.lr_offset_from_initial_sp = Some(self.sp_offset + imm7);
            }
            let pair_reg_2 = ((word >> 10) & 0b11111) as u16;
            if pair_reg_2 == 29 {
                self.fp_offset_from_initial_sp = Some(self.sp_offset + imm7 + 8);
            } else if pair_reg_2 == 30 {
                self.lr_offset_from_initial_sp = Some(self.sp_offset + imm7 + 8);
            }
            if is_preindexed_writeback || is_postindexed_writeback {
                // TODO: check ordering here and whether we need to stop adding the immediate in the offset calculations above
                self.sp_offset += imm7;
            }
            return EpilogueStepResult::NeedMore;
        }
        if (word >> 23) & 0b111111111 == 0b100100010 {
            // Section C3.4, Data processing - immediate
            // unsigned add imm, size class X (8 bytes)
            let result_reg = (word & 0b11111) as u16;
            let input_reg = ((word >> 5) & 0b11111) as u16;
            if result_reg != 31 || input_reg != 31 {
                return EpilogueStepResult::Done(EpilogueResult::ProbablyStillInBody(
                    UnexpectedInstructionType::AddSubNotOperatingOnSp,
                ));
            }
            let mut imm12 = ((word >> 10) & 0b111111111111) as i32;
            let shift_immediate_by_12 = ((word >> 22) & 0b1) == 0b1;
            if shift_immediate_by_12 {
                imm12 <<= 12
            }
            self.sp_offset += imm12;
            return EpilogueStepResult::NeedMore;
        }
        EpilogueStepResult::Done(EpilogueResult::ProbablyStillInBody(
            UnexpectedInstructionType::Unknown,
        ))
    }
}

fn analyze_epilogue_aarch64(bytes: &[u8]) -> EpilogueResult {
    let mut detector = EpilogueDetectorAarch64::new();
    detector.analyze_slice(bytes)
}

fn unwind_rule_from_detected_epilogue(bytes: &[u8]) -> Option<UnwindRuleAarch64> {
    match analyze_epilogue_aarch64(bytes) {
        EpilogueResult::ProbablyStillInBody(_)
        | EpilogueResult::ReachedFunctionEndWithoutReturn => None,
        EpilogueResult::FoundReturn {
            sp_offset,
            fp_offset_from_initial_sp,
            lr_offset_from_initial_sp,
        } => {
            let sp_offset_by_16 = u16::try_from(sp_offset / 16).ok()?;
            let rule = match (fp_offset_from_initial_sp, lr_offset_from_initial_sp) {
                (None, None) if sp_offset_by_16 == 0 => UnwindRuleAarch64::NoOp,
                (None, None) => UnwindRuleAarch64::OffsetSp { sp_offset_by_16 },
                (None, Some(lr_offset)) => UnwindRuleAarch64::OffsetSpAndRestoreLr {
                    sp_offset_by_16,
                    lr_storage_offset_from_sp_by_8: i16::try_from(lr_offset / 8).ok()?,
                },
                (Some(_), None) => return None,
                (Some(fp_offset), Some(lr_offset)) => {
                    UnwindRuleAarch64::OffsetSpAndRestoreFpAndLr {
                        sp_offset_by_16,
                        fp_storage_offset_from_sp_by_8: i16::try_from(fp_offset / 8).ok()?,
                        lr_storage_offset_from_sp_by_8: i16::try_from(lr_offset / 8).ok()?,
                    }
                }
            };
            Some(rule)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // &[0xfd, 0x7b, 0x44, 0xa9] // ldp        fp, lr, [sp, #0x40]
    // &[0x6e, 0x02, 0x00, 0xf9] // str        x14, [x19]
    // &[0xf6, 0x57, 0x04, 0xa9] // stp        x22, x21, [sp, #0x40]
    // &[0xf8, 0x5f, 0xbc, 0xa9] // stp        x24, x23, [sp, #-0x40]!
    // &[0xfd, 0x7b, 0x03, 0xa9] // stp        fp, lr, [sp, #0x30]
    // &[0xfd, 0xc3, 0x00, 0x91] // add        fp, sp, #0x30
    // &[0xff, 0xc3, 0x01, 0x91] // add        sp, sp, #0x70
    // &[0xc0, 0x03, 0x5f, 0xd6] // ret
    // &[0xf6, 0x57, 0xc3, 0xa8] // ldp        x22, x21, [sp], #0x30
    // &[0xff, 0x03, 0x01, 0xd1] // sub        sp, sp, #0x40

    #[test]
    fn test_epilogue_1() {
        // 1000e0d18 fd 7b 44 a9     ldp        fp, lr, [sp, #0x40]
        // 1000e0d1c f4 4f 43 a9     ldp        x20, x19, [sp, #0x30]
        // 1000e0d20 f6 57 42 a9     ldp        x22, x21, [sp, #0x20]
        // 1000e0d24 ff 43 01 91     add        sp, sp, #0x50
        // 1000e0d28 c0 03 5f d6     ret

        let bytes = &[
            0xfd, 0x7b, 0x44, 0xa9, 0xf4, 0x4f, 0x43, 0xa9, 0xf6, 0x57, 0x42, 0xa9, 0xff, 0x43,
            0x01, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
        ];
        assert_eq!(
            analyze_epilogue_aarch64(bytes),
            EpilogueResult::FoundReturn {
                sp_offset: 0x50,
                fp_offset_from_initial_sp: Some(0x40),
                lr_offset_from_initial_sp: Some(0x48),
            }
        );
        assert_eq!(
            analyze_epilogue_aarch64(&bytes[4..]),
            EpilogueResult::FoundReturn {
                sp_offset: 0x50,
                fp_offset_from_initial_sp: None,
                lr_offset_from_initial_sp: None,
            }
        );
        assert_eq!(
            analyze_epilogue_aarch64(&bytes[8..]),
            EpilogueResult::FoundReturn {
                sp_offset: 0x50,
                fp_offset_from_initial_sp: None,
                lr_offset_from_initial_sp: None,
            }
        );
        assert_eq!(
            analyze_epilogue_aarch64(&bytes[12..]),
            EpilogueResult::FoundReturn {
                sp_offset: 0x50,
                fp_offset_from_initial_sp: None,
                lr_offset_from_initial_sp: None,
            }
        );
        assert_eq!(
            analyze_epilogue_aarch64(&bytes[16..]),
            EpilogueResult::FoundReturn {
                sp_offset: 0x0,
                fp_offset_from_initial_sp: None,
                lr_offset_from_initial_sp: None,
            }
        );
        assert_eq!(
            analyze_epilogue_aarch64(&bytes[20..]),
            EpilogueResult::ReachedFunctionEndWithoutReturn
        );
    }

    #[test]
    fn test_epilogue_2() {
        // 1000e0d18 fd 7b 44 a9     ldp        fp, lr, [sp, #0x40]
        // 1000e0d1c f4 4f 43 a9     ldp        x20, x19, [sp, #0x30]
        // 1000e0d20 f6 57 42 a9     ldp        x22, x21, [sp, #0x20]
        // 1000e0d24 ff 43 01 91     add        sp, sp, #0x50
        // 1000e0d28 c0 03 5f d6     ret

        let bytes = &[
            0xfd, 0x7b, 0x44, 0xa9, 0xf4, 0x4f, 0x43, 0xa9, 0xf6, 0x57, 0x42, 0xa9, 0xff, 0x43,
            0x01, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
        ];
        assert_eq!(
            unwind_rule_from_detected_epilogue(bytes),
            Some(UnwindRuleAarch64::OffsetSpAndRestoreFpAndLr {
                sp_offset_by_16: 5,
                fp_storage_offset_from_sp_by_8: 8,
                lr_storage_offset_from_sp_by_8: 9,
            })
        );
        assert_eq!(
            unwind_rule_from_detected_epilogue(&bytes[4..]),
            Some(UnwindRuleAarch64::OffsetSp { sp_offset_by_16: 5 })
        );
        assert_eq!(
            unwind_rule_from_detected_epilogue(&bytes[8..]),
            Some(UnwindRuleAarch64::OffsetSp { sp_offset_by_16: 5 })
        );
        assert_eq!(
            unwind_rule_from_detected_epilogue(&bytes[12..]),
            Some(UnwindRuleAarch64::OffsetSp { sp_offset_by_16: 5 })
        );
        assert_eq!(
            unwind_rule_from_detected_epilogue(&bytes[16..]),
            Some(UnwindRuleAarch64::NoOp)
        );
        assert_eq!(unwind_rule_from_detected_epilogue(&bytes[20..]), None);
    }

    #[test]
    fn test_prologue_1() {
        //         gimli::read::unit::parse_attribute
        // 1000dfeb8 ff 43 01 d1     sub        sp, sp, #0x50
        // 1000dfebc f6 57 02 a9     stp        x22, x21, [sp, #local_30]
        // 1000dfec0 f4 4f 03 a9     stp        x20, x19, [sp, #local_20]
        // 1000dfec4 fd 7b 04 a9     stp        x29, x30, [sp, #local_10]
        // 1000dfec8 fd 03 01 91     add        x29, sp, #0x40
        // 1000dfecc f4 03 04 aa     mov        x20, x4
        // 1000dfed0 f5 03 01 aa     mov        x21, x1

        let bytes = &[
            0xff, 0x43, 0x01, 0xd1, 0xf6, 0x57, 0x02, 0xa9, 0xf4, 0x4f, 0x03, 0xa9, 0xfd, 0x7b,
            0x04, 0xa9, 0xfd, 0x03, 0x01, 0x91, 0xf4, 0x03, 0x04, 0xaa, 0xf5, 0x03, 0x01, 0xaa,
        ];
        assert_eq!(
            unwind_rule_from_detected_prologue(&bytes[..0], &bytes[0..]),
            Some(UnwindRuleAarch64::NoOp)
        );
        assert_eq!(
            unwind_rule_from_detected_prologue(&bytes[..4], &bytes[4..]),
            Some(UnwindRuleAarch64::OffsetSp { sp_offset_by_16: 5 })
        );
        assert_eq!(
            unwind_rule_from_detected_prologue(&bytes[..8], &bytes[8..]),
            Some(UnwindRuleAarch64::OffsetSp { sp_offset_by_16: 5 })
        );
        assert_eq!(
            unwind_rule_from_detected_prologue(&bytes[..12], &bytes[12..]),
            Some(UnwindRuleAarch64::OffsetSp { sp_offset_by_16: 5 })
        );
        assert_eq!(
            unwind_rule_from_detected_prologue(&bytes[..16], &bytes[16..]),
            Some(UnwindRuleAarch64::OffsetSp { sp_offset_by_16: 5 })
        );
        assert_eq!(
            unwind_rule_from_detected_prologue(&bytes[..20], &bytes[20..]),
            None
        );
        assert_eq!(
            unwind_rule_from_detected_prologue(&bytes[..24], &bytes[24..]),
            None
        );
        assert_eq!(
            unwind_rule_from_detected_prologue(&bytes[..28], &bytes[28..]),
            None
        );
    }

    #[test]
    fn test_prologue_with_pacibsp() {
        // 1801245c4 08 58 29 b8     str        w8,[x0, w9, UXTW #0x2]
        // 1801245c8 c0 03 5f d6     ret
        //                       _malloc_zone_realloc
        // 1801245cc 7f 23 03 d5     pacibsp
        // 1801245d0 f8 5f bc a9     stp        x24,x23,[sp, #local_40]!
        // 1801245d4 f6 57 01 a9     stp        x22,x21,[sp, #local_30]
        // 1801245d8 f4 4f 02 a9     stp        x20,x19,[sp, #local_20]
        // 1801245dc fd 7b 03 a9     stp        x29,x30,[sp, #local_10]
        // 1801245e0 fd c3 00 91     add        x29,sp,#0x30
        // 1801245e4 f3 03 02 aa     mov        x19,x2
        // 1801245e8 f4 03 01 aa     mov        x20,x1

        let bytes = &[
            0x08, 0x58, 0x29, 0xb8, 0xc0, 0x03, 0x5f, 0xd6, 0x7f, 0x23, 0x03, 0xd5, 0xf8, 0x5f,
            0xbc, 0xa9, 0xf6, 0x57, 0x01, 0xa9, 0xf4, 0x4f, 0x02, 0xa9, 0xfd, 0x7b, 0x03, 0xa9,
            0xfd, 0xc3, 0x00, 0x91, 0xf3, 0x03, 0x02, 0xaa, 0xf4, 0x03, 0x01, 0xaa,
        ];
        assert_eq!(
            unwind_rule_from_detected_prologue(&bytes[..0], &bytes[0..]),
            None
        );
        assert_eq!(
            unwind_rule_from_detected_prologue(&bytes[..4], &bytes[4..]),
            None
        );
        assert_eq!(
            unwind_rule_from_detected_prologue(&bytes[..8], &bytes[8..]),
            Some(UnwindRuleAarch64::NoOp)
        );
        assert_eq!(
            unwind_rule_from_detected_prologue(&bytes[..12], &bytes[12..]),
            Some(UnwindRuleAarch64::NoOp)
        );
        assert_eq!(
            unwind_rule_from_detected_prologue(&bytes[..16], &bytes[16..]),
            Some(UnwindRuleAarch64::OffsetSp { sp_offset_by_16: 4 })
        );
        assert_eq!(
            unwind_rule_from_detected_prologue(&bytes[..20], &bytes[20..]),
            Some(UnwindRuleAarch64::OffsetSp { sp_offset_by_16: 4 })
        );
        assert_eq!(
            unwind_rule_from_detected_prologue(&bytes[..24], &bytes[24..]),
            Some(UnwindRuleAarch64::OffsetSp { sp_offset_by_16: 4 })
        );
        assert_eq!(
            unwind_rule_from_detected_prologue(&bytes[..28], &bytes[28..]),
            Some(UnwindRuleAarch64::OffsetSp { sp_offset_by_16: 4 })
        );
        assert_eq!(
            unwind_rule_from_detected_prologue(&bytes[..32], &bytes[32..]),
            None
        );
    }

    #[test]
    fn test_prologue_with_mov_fp_sp() {
        //     _tiny_free_list_add_ptr
        // 180126e94 7f 23 03 d5     pacibsp
        // 180126e98 fd 7b bf a9     stp        x29,x30,[sp, #local_10]!
        // 180126e9c fd 03 00 91     mov        x29,sp
        // 180126ea0 68 04 00 51     sub        w8,w3,#0x1

        let bytes = &[
            0x7f, 0x23, 0x03, 0xd5, 0xfd, 0x7b, 0xbf, 0xa9, 0xfd, 0x03, 0x00, 0x91, 0x68, 0x04,
            0x00, 0x51,
        ];
        assert_eq!(
            unwind_rule_from_detected_prologue(&bytes[..0], &bytes[0..]),
            Some(UnwindRuleAarch64::NoOp)
        );
        assert_eq!(
            unwind_rule_from_detected_prologue(&bytes[..4], &bytes[4..]),
            Some(UnwindRuleAarch64::NoOp)
        );
        assert_eq!(
            unwind_rule_from_detected_prologue(&bytes[..8], &bytes[8..]),
            Some(UnwindRuleAarch64::OffsetSp { sp_offset_by_16: 1 })
        );
        assert_eq!(
            unwind_rule_from_detected_prologue(&bytes[..12], &bytes[12..]),
            None
        );
    }

    #[test]
    fn test_epilogue_with_retab() {
        //         _malloc_zone_realloc epilogue
        // 18012466c e0 03 16 aa     mov        x0,x22
        // 180124670 fd 7b 43 a9     ldp        x29=>local_10,x30,[sp, #0x30]
        // 180124674 f4 4f 42 a9     ldp        x20,x19,[sp, #local_20]
        // 180124678 f6 57 41 a9     ldp        x22,x21,[sp, #local_30]
        // 18012467c f8 5f c4 a8     ldp        x24,x23,[sp], #0x40
        // 180124680 ff 0f 5f d6     retab
        // 180124684 a0 01 80 52     mov        w0,#0xd
        // 180124688 20 60 a6 72     movk       w0,#0x3301, LSL #16

        let bytes = &[
            0xe0, 0x03, 0x16, 0xaa, 0xfd, 0x7b, 0x43, 0xa9, 0xf4, 0x4f, 0x42, 0xa9, 0xf6, 0x57,
            0x41, 0xa9, 0xf8, 0x5f, 0xc4, 0xa8, 0xff, 0x0f, 0x5f, 0xd6, 0xa0, 0x01, 0x80, 0x52,
            0x20, 0x60, 0xa6, 0x72,
        ];
        assert_eq!(unwind_rule_from_detected_epilogue(bytes), None);
        assert_eq!(
            unwind_rule_from_detected_epilogue(&bytes[4..]),
            Some(UnwindRuleAarch64::OffsetSpAndRestoreFpAndLr {
                sp_offset_by_16: 4,
                fp_storage_offset_from_sp_by_8: 6,
                lr_storage_offset_from_sp_by_8: 7
            })
        );
        assert_eq!(
            unwind_rule_from_detected_epilogue(&bytes[8..]),
            Some(UnwindRuleAarch64::OffsetSp { sp_offset_by_16: 4 })
        );
        assert_eq!(
            unwind_rule_from_detected_epilogue(&bytes[12..]),
            Some(UnwindRuleAarch64::OffsetSp { sp_offset_by_16: 4 })
        );
        assert_eq!(
            unwind_rule_from_detected_epilogue(&bytes[16..]),
            Some(UnwindRuleAarch64::OffsetSp { sp_offset_by_16: 4 })
        );
        assert_eq!(
            unwind_rule_from_detected_epilogue(&bytes[20..]),
            Some(UnwindRuleAarch64::NoOp)
        );
        assert_eq!(unwind_rule_from_detected_epilogue(&bytes[24..]), None);
    }
}
