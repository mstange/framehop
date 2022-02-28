use super::arch::ArchAarch64;
use super::unwind_rule::UnwindRuleAarch64;
use crate::instruction_analysis::InstructionAnalysis;

impl InstructionAnalysis for ArchAarch64 {
    fn rule_from_prologue_analysis(
        text_bytes_from_function_start: &[u8],
    ) -> Option<Self::UnwindRule> {
        unwind_rule_from_detected_prologue(text_bytes_from_function_start)
    }

    fn rule_from_epilogue_analysis(
        text_bytes_until_function_end: &[u8],
    ) -> Option<Self::UnwindRule> {
        unwind_rule_from_detected_epilogue(text_bytes_until_function_end)
    }
}

struct PrologueDetectorAarch64 {
    /// sp_at_function_start + sp_offset == sp_at_pc
    /// To return from the function, sp_offset has to be subtracted.
    sp_offset: i32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PrologueStepResult {
    ProbablyAlreadyInBody(UnexpectedInstructionType),
    CanKeepGoing,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PrologueResult {
    ProbablyAlreadyInBody(UnexpectedInstructionType),
    FoundPcInPrologue { sp_offset: i32 },
}

impl PrologueDetectorAarch64 {
    pub fn new() -> Self {
        Self { sp_offset: 0 }
    }

    pub fn analyze_slice(&mut self, mut bytes: &[u8]) -> PrologueResult {
        while bytes.len() >= 4 {
            let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            bytes = &bytes[4..];
            if let PrologueStepResult::ProbablyAlreadyInBody(why) = self.step_instruction(word) {
                return PrologueResult::ProbablyAlreadyInBody(why);
            }
        }
        PrologueResult::FoundPcInPrologue {
            sp_offset: self.sp_offset,
        }
    }

    pub fn step_instruction(&mut self, word: u32) -> PrologueStepResult {
        if (word >> 25) & 0b1011111 == 0b1010100 {
            // Section C3.3, Loads and stores.
            // but only those that are commonly seen in prologues / prologues (bits 29 and 31 are set)
            let writeback_bits = (word >> 23) & 0b11;
            if writeback_bits == 0b00 {
                // Not 64-bit load/store.
                return PrologueStepResult::ProbablyAlreadyInBody(
                    UnexpectedInstructionType::LoadStoreOfWrongSize,
                );
            }
            let is_load = ((word >> 22) & 1) != 0;
            if is_load {
                return PrologueStepResult::ProbablyAlreadyInBody(UnexpectedInstructionType::Load);
            }
            let reference_reg = ((word >> 5) & 0b11111) as u16;
            if reference_reg != 31 {
                return PrologueStepResult::ProbablyAlreadyInBody(
                    UnexpectedInstructionType::LoadStoreReferenceRegisterNotSp,
                );
            }
            let is_preindexed_writeback = writeback_bits == 0b11;
            let is_postindexed_writeback = writeback_bits == 0b01; // TODO: are there postindexed stores? What do they mean?
            let imm7 = (((((word >> 15) & 0b1111111) as i16) << 9) >> 6) as i32;
            // let pair_reg_1 = (word & 0b11111) as u16;
            // if pair_reg_1 == 29 {
            //     self.fp_offset_from_initial_sp = Some(self.sp_offset + imm7);
            // } else if pair_reg_1 == 30 {
            //     self.lr_offset_from_initial_sp = Some(self.sp_offset + imm7);
            // }
            // let pair_reg_2 = ((word >> 10) & 0b11111) as u16;
            // if pair_reg_2 == 29 {
            //     self.fp_offset_from_initial_sp = Some(self.sp_offset + imm7 + 8);
            // } else if pair_reg_2 == 30 {
            //     self.lr_offset_from_initial_sp = Some(self.sp_offset + imm7 + 8);
            // }
            if is_preindexed_writeback || is_postindexed_writeback {
                self.sp_offset += imm7;
            }
            return PrologueStepResult::CanKeepGoing;
        }
        if (word >> 23) & 0b101111111 == 0b100100010 {
            // Section C3.4, Data processing - immediate
            // add/sub imm
            // unsigned
            // size class X (8 bytes)
            let result_reg = (word & 0b11111) as u16;
            let input_reg = ((word >> 5) & 0b11111) as u16;
            if result_reg != 31 || input_reg != 31 {
                return PrologueStepResult::ProbablyAlreadyInBody(
                    UnexpectedInstructionType::AddSubNotOperatingOnSp,
                );
            }
            let mut imm12 = ((word >> 10) & 0b111111111111) as i32;
            let is_sub = ((word >> 30) & 0b1) == 0b1;
            let shift_immediate_by_12 = ((word >> 22) & 0b1) == 0b1;
            if shift_immediate_by_12 {
                imm12 <<= 12
            }
            if is_sub {
                self.sp_offset -= imm12;
            } else {
                self.sp_offset += imm12;
            }
            return PrologueStepResult::CanKeepGoing;
        }
        PrologueStepResult::ProbablyAlreadyInBody(UnexpectedInstructionType::Unknown)
    }
}

fn analyze_prologue_aarch64(bytes: &[u8]) -> PrologueResult {
    let mut detector = PrologueDetectorAarch64::new();
    detector.analyze_slice(bytes)
}

fn unwind_rule_from_detected_prologue(bytes: &[u8]) -> Option<UnwindRuleAarch64> {
    match analyze_prologue_aarch64(bytes) {
        PrologueResult::ProbablyAlreadyInBody(_) => None,
        PrologueResult::FoundPcInPrologue { sp_offset } => {
            let sp_offset_by_16 = u16::try_from(-sp_offset / 16).ok()?;
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
        if word == 0xd65f03c0 {
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
        if (word >> 23) & 0b101111111 == 0b100100010 {
            // Section C3.4, Data processing - immediate
            // add/sub imm
            // unsigned
            // size class X (8 bytes)
            let result_reg = (word & 0b11111) as u16;
            let input_reg = ((word >> 5) & 0b11111) as u16;
            if result_reg != 31 || input_reg != 31 {
                return EpilogueStepResult::Done(EpilogueResult::ProbablyStillInBody(
                    UnexpectedInstructionType::AddSubNotOperatingOnSp,
                ));
            }
            let mut imm12 = ((word >> 10) & 0b111111111111) as i32;
            let is_sub = ((word >> 30) & 0b1) == 0b1;
            let shift_immediate_by_12 = ((word >> 22) & 0b1) == 0b1;
            if shift_immediate_by_12 {
                imm12 <<= 12
            }
            if is_sub {
                self.sp_offset -= imm12;
            } else {
                self.sp_offset += imm12;
            }
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
            unwind_rule_from_detected_prologue(&bytes[..0]),
            Some(UnwindRuleAarch64::NoOp)
        );
        assert_eq!(
            unwind_rule_from_detected_prologue(&bytes[..4]),
            Some(UnwindRuleAarch64::OffsetSp { sp_offset_by_16: 5 })
        );
        assert_eq!(
            unwind_rule_from_detected_prologue(&bytes[..8]),
            Some(UnwindRuleAarch64::OffsetSp { sp_offset_by_16: 5 })
        );
        assert_eq!(
            unwind_rule_from_detected_prologue(&bytes[..12]),
            Some(UnwindRuleAarch64::OffsetSp { sp_offset_by_16: 5 })
        );
        assert_eq!(
            unwind_rule_from_detected_prologue(&bytes[..16]),
            Some(UnwindRuleAarch64::OffsetSp { sp_offset_by_16: 5 })
        );
        assert_eq!(unwind_rule_from_detected_prologue(&bytes[..20]), None);
        assert_eq!(unwind_rule_from_detected_prologue(&bytes[..24]), None);
        assert_eq!(unwind_rule_from_detected_prologue(&bytes[..28]), None);
    }
}
