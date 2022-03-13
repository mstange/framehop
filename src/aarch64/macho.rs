use super::arch::ArchAarch64;
use super::unwind_rule::UnwindRuleAarch64;
use crate::instruction_analysis::InstructionAnalysis;
use crate::macho::{CompactUnwindInfoUnwinderError, CompactUnwindInfoUnwinding, CuiUnwindResult};
use macho_unwind_info::opcodes::OpcodeArm64;
use macho_unwind_info::Function;

impl CompactUnwindInfoUnwinding for ArchAarch64 {
    fn unwind_frame(
        function: Function,
        is_first_frame: bool,
        address_offset_within_function: usize,
        function_bytes: Option<&[u8]>,
    ) -> Result<CuiUnwindResult<UnwindRuleAarch64>, CompactUnwindInfoUnwinderError> {
        let opcode = OpcodeArm64::parse(function.opcode);
        if is_first_frame {
            if opcode == OpcodeArm64::Null {
                return Ok(CuiUnwindResult::ExecRule(UnwindRuleAarch64::NoOp));
            }
            // The pc might be in a prologue or an epilogue. The compact unwind info format ignores
            // prologues and epilogues; the opcodes only describe the function body. So we do some
            // instruction analysis to check for prologues and epilogues.
            if let Some(function_bytes) = function_bytes {
                if let Some(rule) = Self::rule_from_instruction_analysis(
                    function_bytes,
                    address_offset_within_function,
                ) {
                    // We are inside a prologue / epilogue. Ignore the opcode and use the rule from
                    // instruction analysis.
                    return Ok(CuiUnwindResult::ExecRule(rule));
                }
            }
        }

        // At this point we know with high certainty that we are in a function body.
        let r = match opcode {
            OpcodeArm64::Null => {
                return Err(CompactUnwindInfoUnwinderError::FunctionHasNoInfo);
            }
            OpcodeArm64::Frameless {
                stack_size_in_bytes,
            } => {
                if is_first_frame {
                    if stack_size_in_bytes == 0 {
                        CuiUnwindResult::ExecRule(UnwindRuleAarch64::NoOp)
                    } else {
                        CuiUnwindResult::ExecRule(UnwindRuleAarch64::OffsetSp {
                            sp_offset_by_16: stack_size_in_bytes / 16,
                        })
                    }
                } else {
                    return Err(CompactUnwindInfoUnwinderError::CallerCannotBeFrameless);
                }
            }
            OpcodeArm64::Dwarf { eh_frame_fde } => CuiUnwindResult::NeedDwarf(eh_frame_fde),
            OpcodeArm64::FrameBased { .. } => {
                CuiUnwindResult::ExecRule(UnwindRuleAarch64::UseFramePointer)
            }
            OpcodeArm64::UnrecognizedKind(kind) => {
                return Err(CompactUnwindInfoUnwinderError::BadOpcodeKind(kind))
            }
        };
        Ok(r)
    }
}
