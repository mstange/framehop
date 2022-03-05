use super::arch::ArchAarch64;
use super::unwind_rule::UnwindRuleAarch64;
use crate::macho::{
    CompactUnwindInfoUnwinderError, CompactUnwindInfoUnwinding, CuiUnwindResult, FunctionInfo,
};
use macho_unwind_info::opcodes::OpcodeArm64;
use macho_unwind_info::Function;

impl CompactUnwindInfoUnwinding for ArchAarch64 {
    fn unwind_frame(
        function: Function,
        is_first_frame: bool,
    ) -> Result<CuiUnwindResult<UnwindRuleAarch64>, CompactUnwindInfoUnwinderError> {
        let opcode = OpcodeArm64::parse(function.opcode);
        let r = match opcode {
            OpcodeArm64::Null => {
                if is_first_frame {
                    CuiUnwindResult::exec_rule(UnwindRuleAarch64::NoOp)
                } else {
                    return Err(CompactUnwindInfoUnwinderError::FunctionHasNoInfo);
                }
            }
            OpcodeArm64::Frameless {
                stack_size_in_bytes,
            } => {
                if is_first_frame {
                    if stack_size_in_bytes == 0 {
                        CuiUnwindResult::exec_rule(UnwindRuleAarch64::NoOp)
                    } else if is_first_frame {
                        CuiUnwindResult::analyze_leaf_and_exec_rule(
                            FunctionInfo {
                                function_start: function.start_address,
                                function_end: function.end_address,
                            },
                            UnwindRuleAarch64::OffsetSp {
                                sp_offset_by_16: stack_size_in_bytes / 16,
                            },
                        )
                    } else {
                        CuiUnwindResult::exec_rule(UnwindRuleAarch64::OffsetSp {
                            sp_offset_by_16: stack_size_in_bytes / 16,
                        })
                    }
                } else {
                    return Err(CompactUnwindInfoUnwinderError::CallerCannotBeFrameless);
                }
            }
            OpcodeArm64::Dwarf { eh_frame_fde } => {
                if is_first_frame {
                    CuiUnwindResult::analyze_leaf_and_use_dwarf(
                        FunctionInfo {
                            function_start: function.start_address,
                            function_end: function.end_address,
                        },
                        eh_frame_fde,
                    )
                } else {
                    CuiUnwindResult::use_dwarf(eh_frame_fde)
                }
            }
            OpcodeArm64::FrameBased { .. } => {
                if is_first_frame {
                    CuiUnwindResult::analyze_leaf_and_exec_rule(
                        FunctionInfo {
                            function_start: function.start_address,
                            function_end: function.end_address,
                        },
                        UnwindRuleAarch64::UseFramePointer,
                    )
                } else {
                    CuiUnwindResult::exec_rule(UnwindRuleAarch64::UseFramePointer)
                }
            }
            OpcodeArm64::UnrecognizedKind(kind) => {
                return Err(CompactUnwindInfoUnwinderError::BadOpcodeKind(kind))
            }
        };
        Ok(r)
    }
}
