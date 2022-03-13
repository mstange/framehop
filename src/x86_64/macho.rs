use super::arch::ArchX86_64;
use super::unwind_rule::UnwindRuleX86_64;
use crate::macho::{
    CompactUnwindInfoUnwinderError, CompactUnwindInfoUnwinding, CuiUnwindResult, CuiUnwindResult2,
    FunctionInfo,
};
use macho_unwind_info::opcodes::{OpcodeX86_64, RegisterNameX86_64};
use macho_unwind_info::Function;

impl CompactUnwindInfoUnwinding for ArchX86_64 {
    fn unwind_frame(
        function: Function,
        is_first_frame: bool,
    ) -> Result<CuiUnwindResult<UnwindRuleX86_64>, CompactUnwindInfoUnwinderError> {
        let opcode = OpcodeX86_64::parse(function.opcode);
        let r = match opcode {
            OpcodeX86_64::Null => {
                if is_first_frame {
                    CuiUnwindResult::exec_rule(UnwindRuleX86_64::JustReturn)
                } else {
                    return Err(CompactUnwindInfoUnwinderError::FunctionHasNoInfo);
                }
            }
            OpcodeX86_64::FramelessImmediate {
                stack_size_in_bytes,
                saved_regs,
            } => {
                if stack_size_in_bytes == 8 {
                    CuiUnwindResult::exec_rule(UnwindRuleX86_64::JustReturn)
                } else {
                    let function_info = if is_first_frame {
                        Some(FunctionInfo {
                            function_start: function.start_address,
                            function_end: function.end_address,
                        })
                    } else {
                        None
                    };
                    let bp_positon_from_outside = saved_regs
                        .iter()
                        .rev()
                        .flatten()
                        .position(|r| *r == RegisterNameX86_64::Rbp);
                    match bp_positon_from_outside {
                        Some(pos) => {
                            let bp_offset_from_sp =
                                stack_size_in_bytes as i32 - 2 * 8 - pos as i32 * 8;
                            let bp_storage_offset_from_sp_by_8 =
                                i16::try_from(bp_offset_from_sp / 8).map_err(|_| {
                                    CompactUnwindInfoUnwinderError::BpOffsetDoesNotFit
                                })?;
                            CuiUnwindResult {
                                result: CuiUnwindResult2::ExecRule(
                                    UnwindRuleX86_64::OffsetSpAndRestoreBp {
                                        sp_offset_by_8: stack_size_in_bytes / 8,
                                        bp_storage_offset_from_sp_by_8,
                                    },
                                ),
                                function_info,
                            }
                        }
                        None => CuiUnwindResult {
                            result: CuiUnwindResult2::ExecRule(UnwindRuleX86_64::OffsetSp {
                                sp_offset_by_8: stack_size_in_bytes / 8,
                            }),
                            function_info,
                        },
                    }
                }
            }
            OpcodeX86_64::FramelessIndirect { .. } => {
                return Err(CompactUnwindInfoUnwinderError::CantHandleFramelessIndirect)
            }
            OpcodeX86_64::Dwarf { eh_frame_fde } => {
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
            OpcodeX86_64::FrameBased { .. } => {
                if is_first_frame {
                    CuiUnwindResult::analyze_leaf_and_exec_rule(
                        FunctionInfo {
                            function_start: function.start_address,
                            function_end: function.end_address,
                        },
                        UnwindRuleX86_64::UseFramePointer,
                    )
                } else {
                    CuiUnwindResult::exec_rule(UnwindRuleX86_64::UseFramePointer)
                }
            }
            OpcodeX86_64::UnrecognizedKind(kind) => {
                return Err(CompactUnwindInfoUnwinderError::BadOpcodeKind(kind))
            }
            OpcodeX86_64::InvalidFrameless => {
                return Err(CompactUnwindInfoUnwinderError::InvalidFrameless)
            }
        };
        Ok(r)
    }
}
