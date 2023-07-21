use super::{arch::ArchX86_64, unwind_rule::UnwindRuleX86_64, unwindregs::Reg};
use crate::arch::Arch;
use crate::pe::{PeSections, PeUnwinderError, PeUnwinding};
use crate::unwind_result::UnwindResult;
use std::ops::ControlFlow;

use pe_unwind_info::x86_64::{
    FunctionEpilogInstruction, FunctionEpilogParser, FunctionTableEntries, Register, UnwindInfo,
    UnwindInfoTrailer, UnwindState,
};

struct State<'a, F> {
    regs: &'a mut <ArchX86_64 as Arch>::UnwindRegs,
    read_stack: &'a mut F,
}

impl<F> UnwindState for State<'_, F>
where
    F: FnMut(u64) -> Result<u64, ()>,
{
    fn read_register(&mut self, register: Register) -> u64 {
        self.regs.get(convert_pe_register(register))
    }

    fn read_stack(&mut self, addr: u64) -> Option<u64> {
        (self.read_stack)(addr).ok()
    }

    fn write_register(&mut self, register: Register, value: u64) {
        self.regs.set(convert_pe_register(register), value)
    }

    fn write_xmm_register(&mut self, _register: pe_unwind_info::x86_64::XmmRegister, _value: u128) {
        // Ignore
    }
}

fn convert_pe_register(r: Register) -> Reg {
    match r {
        Register::RAX => Reg::RAX,
        Register::RCX => Reg::RCX,
        Register::RDX => Reg::RDX,
        Register::RBX => Reg::RBX,
        Register::RSP => Reg::RSP,
        Register::RBP => Reg::RBP,
        Register::RSI => Reg::RSI,
        Register::RDI => Reg::RDI,
        Register::R8 => Reg::R8,
        Register::R9 => Reg::R9,
        Register::R10 => Reg::R10,
        Register::R11 => Reg::R11,
        Register::R12 => Reg::R12,
        Register::R13 => Reg::R13,
        Register::R14 => Reg::R14,
        Register::R15 => Reg::R15,
    }
}

impl PeUnwinding for ArchX86_64 {
    fn unwind_frame<F, D>(
        sections: PeSections<D>,
        address: u32,
        regs: &mut Self::UnwindRegs,
        read_stack: &mut F,
    ) -> Result<UnwindResult<Self::UnwindRule>, PeUnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
        D: std::ops::Deref<Target = [u8]>,
    {
        let entries = FunctionTableEntries::parse(sections.pdata);
        let Some(mut function) = entries.lookup(address) else {
            return Ok(UnwindResult::ExecRule(UnwindRuleX86_64::JustReturn));
        };

        let read_stack_err = |read_stack: &mut F, addr| {
            read_stack(addr).map_err(|()| PeUnwinderError::MissingStackData(Some(addr)))
        };

        let offset = address - function.begin_address.get();
        let mut is_chained = false;
        loop {
            let unwind_info_address = function.unwind_info_address.get();
            let unwind_info =
                UnwindInfo::parse(sections.unwind_info_memory_at_rva(unwind_info_address)?)
                    .ok_or(PeUnwinderError::UnwindInfoParseError)?;

            if !is_chained {
                // Check whether the address is in the function epilog. If so, we need to
                // simulate the remaining epilog instructions (unwind codes don't account for
                // unwinding from the epilog).
                let bytes = (function.end_address.get() - address) as usize;
                let instruction = &sections.text_memory_at_rva(address)?[..bytes];
                let mut epilog_parser = FunctionEpilogParser::new();
                if let Some(epilog_instructions) =
                    epilog_parser.is_function_epilog(instruction, unwind_info.frame_register())
                {
                    for instruction in epilog_instructions.iter() {
                        match instruction {
                            FunctionEpilogInstruction::AddSP(offset) => {
                                let rsp = regs.get(Reg::RSP);
                                regs.set(Reg::RSP, rsp + *offset as u64);
                            }
                            FunctionEpilogInstruction::AddSPFromFP(offset) => {
                                let fp = unwind_info
                                    .frame_register()
                                    .expect("invalid fp register offset");
                                let fp = convert_pe_register(fp);
                                let fp = regs.get(fp);
                                regs.set(Reg::RSP, fp + *offset as u64);
                            }
                            FunctionEpilogInstruction::Pop(reg) => {
                                let rsp = regs.get(Reg::RSP);
                                let val = read_stack_err(read_stack, rsp)?;
                                regs.set(convert_pe_register(*reg), val);
                                regs.set(Reg::RSP, rsp + 8);
                            }
                        }
                    }
                    break;
                }
            }

            let mut state = State { regs, read_stack };
            for (_, op) in unwind_info
                .unwind_operations()
                .skip_while(|(o, _)| !is_chained && *o as u32 > offset)
            {
                if let ControlFlow::Break(ra) = unwind_info
                    .resolve_operation(&mut state, &op)
                    .ok_or(PeUnwinderError::MissingStackData(None))?
                {
                    return Ok(UnwindResult::Uncacheable(ra));
                }
            }
            if let Some(UnwindInfoTrailer::ChainedUnwindInfo { chained }) = unwind_info.trailer() {
                is_chained = true;
                function = chained;
            } else {
                break;
            }
        }

        let rsp = regs.get(Reg::RSP);
        let ra = read_stack_err(read_stack, rsp)?;
        regs.set(Reg::RSP, rsp + 8);

        Ok(UnwindResult::Uncacheable(ra))
    }
}
