use super::{
    arch::ArchX86_64,
    unwind_rule::{OffsetOrPop, UnwindRuleX86_64},
    unwindregs::Reg,
};
use crate::arch::Arch;
use crate::pe::{PeSections, PeUnwinderError, PeUnwinding};
use crate::unwind_result::UnwindResult;
use arrayvec::ArrayVec;
use core::ops::ControlFlow;

use pe_unwind_info::x86_64::{
    FunctionEpilogInstruction, FunctionTableEntries, Register, UnwindInfo, UnwindInfoTrailer,
    UnwindOperation, UnwindState,
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

impl From<&'_ FunctionEpilogInstruction> for OffsetOrPop {
    fn from(value: &'_ FunctionEpilogInstruction) -> Self {
        match value {
            FunctionEpilogInstruction::AddSP(offset) => {
                if let Ok(v) = (offset / 8).try_into() {
                    OffsetOrPop::OffsetBy8(v)
                } else {
                    OffsetOrPop::None
                }
            }
            FunctionEpilogInstruction::Pop(reg) => OffsetOrPop::Pop(convert_pe_register(*reg)),
            _ => OffsetOrPop::None,
        }
    }
}

impl From<&'_ UnwindOperation> for OffsetOrPop {
    fn from(value: &'_ UnwindOperation) -> Self {
        match value {
            UnwindOperation::UnStackAlloc(offset) => {
                if let Ok(v) = (offset / 8).try_into() {
                    OffsetOrPop::OffsetBy8(v)
                } else {
                    OffsetOrPop::None
                }
            }
            UnwindOperation::PopNonVolatile(reg) => OffsetOrPop::Pop(convert_pe_register(*reg)),
            _ => OffsetOrPop::None,
        }
    }
}

/// The most unwind infos in one function's chain: its own and 32 chained ones, which is as
/// far as the unwinder of the .NET runtime follows a chain (`UNWIND_CHAIN_LIMIT`). The PE
/// format sets no limit. The bound also ends a cyclic chain.
const MAX_UNWIND_INFOS: usize = 33;

impl PeUnwinding for ArchX86_64 {
    fn unwind_frame<F, D>(
        sections: PeSections<D>,
        address: u32,
        regs: &mut Self::UnwindRegs,
        is_first_frame: bool,
        read_stack: &mut F,
    ) -> Result<UnwindResult<Self::UnwindRule>, PeUnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
        D: core::ops::Deref<Target = [u8]>,
    {
        let entries = FunctionTableEntries::parse(sections.pdata);
        let Some(function) = entries.lookup(address) else {
            return Ok(UnwindResult::ExecRule(UnwindRuleX86_64::JustReturn));
        };

        let read_stack_err = |read_stack: &mut F, addr| {
            read_stack(addr).map_err(|()| PeUnwinderError::MissingStackData(Some(addr)))
        };

        let unwind_info_address = function.unwind_info_address.get();
        let unwind_info =
            UnwindInfo::parse(sections.unwind_info_memory_at_rva(unwind_info_address)?)
                .ok_or(PeUnwinderError::UnwindInfoParseError)?;

        if is_first_frame {
            // Check whether the address is in the function epilog. If so, we need to
            // simulate the remaining epilog instructions (unwind codes don't account for
            // unwinding from the epilog). We only need to check this for the first unwind info (if
            // there are chained infos).
            let bytes = (function.end_address.get() - address) as usize;
            let instruction = &sections.text_memory_at_rva(address)?[..bytes];
            if let Ok(epilog_instructions) =
                FunctionEpilogInstruction::parse_sequence(instruction, unwind_info.frame_register())
            {
                // If the epilog is an optional AddSP followed by Pops, we can return a cache
                // rule.
                if let Some(rule) =
                    UnwindRuleX86_64::for_sequence_of_offset_or_pop(epilog_instructions.iter())
                {
                    return Ok(UnwindResult::ExecRule(rule));
                }

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

                let rsp = regs.get(Reg::RSP);
                let ra = read_stack_err(read_stack, rsp)?;
                regs.set(Reg::RSP, rsp + 8);

                return Ok(UnwindResult::Uncacheable(ra));
            }
        }

        // The function's unwind info and the ones it chains to. A fixed-size array, so that
        // unwinding does not allocate.
        let mut chain = ArrayVec::<UnwindInfo, MAX_UNWIND_INFOS>::new();
        chain.push(unwind_info);
        while let Some(UnwindInfoTrailer::ChainedUnwindInfo { chained }) =
            chain.last().and_then(|info| info.trailer())
        {
            let data = sections.unwind_info_memory_at_rva(chained.unwind_info_address.get())?;
            let info = UnwindInfo::parse(data).ok_or(PeUnwinderError::UnwindInfoParseError)?;
            chain
                .try_push(info)
                .map_err(|_| PeUnwinderError::UnwindInfoParseError)?;
        }

        // Get all operations across chained UnwindInfo. The first should be filtered to only those
        // operations which are before the offset in the function.
        let offset = address - function.begin_address.get();
        let operations = || {
            chain.iter().enumerate().flat_map(|(i, info)| {
                info.unwind_operations()
                    .skip_while(move |(o, _)| i == 0 && *o as u32 > offset)
                    .map(|(_, op)| op)
            })
        };

        // First check whether the operations can be expressed as a cacheable unwind rule. The
        // operations are decoded a second time below instead of being collected.
        if let Some(rule) = UnwindRuleX86_64::for_sequence_of_offset_or_pop(
            operations().map(|op| OffsetOrPop::from(&op)),
        ) {
            return Ok(UnwindResult::ExecRule(rule));
        }

        // Resolve operations to get the return address.
        let mut state = State { regs, read_stack };
        for op in operations() {
            if let ControlFlow::Break(ra) = unwind_info
                .resolve_operation(&mut state, &op)
                .ok_or(PeUnwinderError::MissingStackData(None))?
            {
                return Ok(UnwindResult::Uncacheable(ra));
            }
        }

        let rsp = regs.get(Reg::RSP);
        let ra = read_stack_err(read_stack, rsp)?;
        regs.set(Reg::RSP, rsp + 8);

        Ok(UnwindResult::Uncacheable(ra))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::super::unwindregs::UnwindRegsX86_64;
    use super::*;
    use crate::pe::DataAtRvaRange;
    use crate::unwind_rule::UnwindRule;
    use alloc::{vec, vec::Vec};
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    /// Counts this thread's allocator calls while checking is on.
    struct CheckedAllocator;
    std::thread_local! {
        static CHECKING: Cell<bool> = const { Cell::new(false) };
        static CALLS: Cell<usize> = const { Cell::new(0) };
    }

    fn note_allocator_call() {
        if CHECKING.try_with(Cell::get).unwrap_or(false) {
            let _ = CALLS.try_with(|calls| calls.set(calls.get() + 1));
        }
    }

    unsafe impl GlobalAlloc for CheckedAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            note_allocator_call();
            System.alloc(layout)
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            note_allocator_call();
            System.dealloc(ptr, layout)
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            note_allocator_call();
            System.realloc(ptr, layout, size)
        }
    }

    #[global_allocator]
    static ALLOCATOR: CheckedAllocator = CheckedAllocator;

    fn without_allocator<T>(f: impl FnOnce() -> T) -> T {
        CHECKING.set(true);
        let result = f();
        CHECKING.set(false);
        assert_eq!(CALLS.get(), 0, "the PE unwinder allocated");
        result
    }

    const UWOP_PUSH_NONVOL: u8 = 0;
    const UWOP_ALLOC_SMALL: u8 = 2;
    const UWOP_SAVE_NONVOL: u8 = 4;
    const UNW_FLAG_CHAININFO: u8 = 4;
    const RBP: u8 = 5;
    const R12: u8 = 12;

    const BEGIN: u32 = 0x1000;
    const END: u32 = 0x1100;
    const XDATA: u32 = 0x2000;
    const SP: u64 = 0x7000_0000;

    const fn code(prolog_offset: u8, op: u8, info: u8) -> [u8; 2] {
        [prolog_offset, op | info << 4]
    }

    fn runtime_function(begin: u32, end: u32, unwind_info: u32) -> impl Iterator<Item = u8> {
        [begin, end, unwind_info]
            .into_iter()
            .flat_map(|v| v.to_le_bytes())
    }

    type Sections = (Vec<u8>, DataAtRvaRange<Vec<u8>>);

    /// `.pdata` and `.xdata` for one function with a chain of unwind infos that have the
    /// given unwind codes: the function's own first, each chained to the next. The last one
    /// chains to the one at index `last_chains_to`, if given.
    fn sections(chain: &[&[[u8; 2]]], last_chains_to: Option<usize>) -> Sections {
        let mut rvas = Vec::new();
        let mut rva = XDATA;
        for (i, codes) in chain.iter().enumerate() {
            assert_eq!(codes.len() % 2, 0, "an odd count would need padding");
            rvas.push(rva);
            let is_chained = i + 1 < chain.len() || last_chains_to.is_some();
            rva += 4 + 2 * codes.len() as u32 + if is_chained { 12 } else { 0 };
        }
        let mut xdata = Vec::new();
        for (i, codes) in chain.iter().enumerate() {
            let next = rvas.get(i + 1).or(last_chains_to.map(|i| &rvas[i]));
            let flags = if next.is_some() {
                UNW_FLAG_CHAININFO
            } else {
                0
            };
            xdata.extend([1 | flags << 3, 0x10, codes.len() as u8, 0]);
            xdata.extend(codes.iter().flatten());
            if let Some(&next) = next {
                xdata.extend(runtime_function(BEGIN, END, next));
            }
        }
        let pdata = runtime_function(BEGIN, END, XDATA).collect();
        let rva_range = XDATA..rva;
        (
            pdata,
            DataAtRvaRange {
                data: xdata,
                rva_range,
            },
        )
    }

    /// Unwind one frame at `BEGIN + offset` with the stack `stack` at `SP`, applying a
    /// returned rule. Returns whether a rule was returned, the return address, and the
    /// registers.
    fn unwind(
        (pdata, xdata): &Sections,
        offset: u32,
        stack: &[u64],
    ) -> Result<(bool, u64, UnwindRegsX86_64), PeUnwinderError> {
        let mut read_stack = |addr: u64| {
            let index = addr.checked_sub(SP).ok_or(())? / 8;
            stack.get(index as usize).copied().ok_or(())
        };
        let mut regs = UnwindRegsX86_64::new(0, SP, 0);
        without_allocator(|| {
            let sections = PeSections {
                pdata,
                rdata: None,
                xdata: Some(xdata),
                text: None,
            };
            let result = ArchX86_64::unwind_frame(
                sections,
                BEGIN + offset,
                &mut regs,
                false,
                &mut read_stack,
            )?;
            Ok(match result {
                UnwindResult::ExecRule(rule) => {
                    let ra = rule.exec(false, &mut regs, &mut read_stack).unwrap();
                    (true, ra.unwrap(), regs)
                }
                UnwindResult::Uncacheable(ra) => (false, ra, regs),
            })
        })
    }

    /// sub rsp, 16 after push rbp
    const PARENT: [[u8; 2]; 2] = [code(8, UWOP_ALLOC_SMALL, 1), code(4, UWOP_PUSH_NONVOL, RBP)];
    /// A later mov [rsp+8], r12
    const SAVE_R12: [[u8; 2]; 2] = [code(0x10, UWOP_SAVE_NONVOL, R12), [1, 0]];

    #[test]
    fn chained_pops_become_a_rule_without_allocating() {
        let sections = sections(&[&[], &PARENT], None);
        let stack = [0, 0, 0xb0, 0xaa];
        let (is_rule, ra, regs) = unwind(&sections, 0x20, &stack).unwrap();
        assert!(is_rule);
        assert_eq!(ra, 0xaa);
        assert_eq!(regs.get(Reg::RBP), 0xb0);
        assert_eq!(regs.get(Reg::RSP), SP + 32);
    }

    #[test]
    fn chained_operations_resolve_without_allocating() {
        // A save is not a pop, so this has no rule.
        let sections = sections(&[&SAVE_R12, &PARENT], None);
        let stack = [0, 0xc0, 0xb0, 0xaa];
        let (is_rule, ra, regs) = unwind(&sections, 0x20, &stack).unwrap();
        assert!(!is_rule);
        assert_eq!(ra, 0xaa);
        assert_eq!(regs.get(Reg::RBP), 0xb0);
        assert_eq!(regs.get(Reg::R12), 0xc0);
        assert_eq!(regs.get(Reg::RSP), SP + 32);

        // Before the save has run, only the parent's operations apply.
        let (is_rule, ra, regs) = unwind(&sections, 0x3, &stack).unwrap();
        assert!(is_rule);
        assert_eq!(ra, 0xaa);
        assert_eq!(regs.get(Reg::RBP), 0xb0);
        assert_eq!(regs.get(Reg::R12), 0);
        assert_eq!(regs.get(Reg::RSP), SP + 32);
    }

    #[test]
    fn chain_length_is_bounded() {
        let stack = [0, 0, 0xb0, 0xaa];
        let mut chain: Vec<&[[u8; 2]]> = vec![&[]; MAX_UNWIND_INFOS - 1];
        chain.push(&PARENT);
        let (_, ra, _) = unwind(&sections(&chain, None), 0x20, &stack).unwrap();
        assert_eq!(ra, 0xaa);

        chain.insert(0, &[]);
        let result = unwind(&sections(&chain, None), 0x20, &stack);
        assert!(matches!(result, Err(PeUnwinderError::UnwindInfoParseError)));

        let cyclic = sections(&[&[], &PARENT], Some(0));
        let result = unwind(&cyclic, 0x20, &stack);
        assert!(matches!(result, Err(PeUnwinderError::UnwindInfoParseError)));
    }
}
