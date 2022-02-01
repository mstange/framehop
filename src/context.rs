use gimli::{CloneStableDeref, EndianReader, LittleEndian, StableDeref, UnwindContext};

use super::unwinders::{
    CompactUnwindInfoUnwinder, CompactUnwindInfoUnwinderError, DwarfUnwinder, DwarfUnwinderError,
    FramepointerUnwinderArm64, FramepointerUnwinderError,
};
use crate::unwindregs::UnwindRegsArm64;
use std::{
    fmt::Debug,
    ops::{Deref, Range},
    sync::Arc,
};

#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    #[error("Unwinding failed")]
    UnwindingFailed,

    #[error("The end of the stack has been reached.")]
    StackEndReached,
}

impl From<FramepointerUnwinderError> for Error {
    fn from(err: FramepointerUnwinderError) -> Self {
        match err {
            FramepointerUnwinderError::FoundStackEnd => Error::StackEndReached,
            _ => Error::UnwindingFailed,
        }
    }
}

#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
enum UnwinderError {
    #[error("Framepointer unwinding failed: {0}")]
    FramePointer(#[from] FramepointerUnwinderError),

    #[error("Compact Unwind Info unwinding failed: {0}")]
    CompactUnwindInfo(#[source] CompactUnwindInfoUnwinderError),

    #[error("DWARF unwinding failed: {0}")]
    Dwarf(#[from] DwarfUnwinderError),
}

impl From<CompactUnwindInfoUnwinderError> for UnwinderError {
    fn from(e: CompactUnwindInfoUnwinderError) -> Self {
        match e {
            CompactUnwindInfoUnwinderError::BadDwarfUnwinding(e) => UnwinderError::Dwarf(e),
            CompactUnwindInfoUnwinderError::BadFramepointerUnwinding(e) => {
                UnwinderError::FramePointer(e)
            }
            e => UnwinderError::CompactUnwindInfo(e),
        }
    }
}

type ArcDataReader<D> = EndianReader<LittleEndian, ArcData<D>>;

pub struct Cache<D: Deref<Target = [u8]>> {
    eh_frame_unwind_context: UnwindContext<ArcDataReader<D>>,
}

impl<D: Deref<Target = [u8]>> Cache<D> {
    pub fn new() -> Self {
        Self {
            eh_frame_unwind_context: UnwindContext::new(),
        }
    }
}

impl<D: Deref<Target = [u8]>> Default for Cache<D> {
    fn default() -> Self {
        Self::new()
    }
}

struct ArcData<D: Deref<Target = [u8]>>(Arc<D>);

impl<D: Deref<Target = [u8]>> Deref for ArcData<D> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl<D: Deref<Target = [u8]>> Clone for ArcData<D> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<D: Deref<Target = [u8]>> Debug for ArcData<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ArcData").field(&self.0.as_ptr()).finish()
    }
}

// Safety: See the implementation for Arc. ArcData just wraps Arc, cloning ArcData just clones Arc.
unsafe impl<D: Deref<Target = [u8]>> StableDeref for ArcData<D> {}
unsafe impl<D: Deref<Target = [u8]>> CloneStableDeref for ArcData<D> {}

pub struct Context<D: Deref<Target = [u8]>> {
    /// sorted by address_range.start
    modules: Vec<Module<D>>,
}

impl<D: Deref<Target = [u8]>> Default for Context<D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: Deref<Target = [u8]>> Context<D> {
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
        }
    }

    pub fn add_module(&mut self, module: Module<D>) {
        let insertion_index = match self
            .modules
            .binary_search_by_key(&module.address_range.start, |module| {
                module.address_range.start
            }) {
            Ok(i) => {
                eprintln!(
                    "Now we have two modules at the same start address 0x{:x}. This can't be good.",
                    module.address_range.start
                );
                i
            }
            Err(i) => i,
        };
        self.modules.insert(insertion_index, module);
    }

    pub fn remove_module(&mut self, module_address_range_start: u64) {
        if let Ok(index) = self
            .modules
            .binary_search_by_key(&module_address_range_start, |module| {
                module.address_range.start
            })
        {
            self.modules.remove(index);
        };
    }

    pub fn unwind_one_frame_from_pc<F>(
        &self,
        pc: u64,
        regs: &mut UnwindRegsArm64,
        cache: &mut Cache<D>,
        read_stack: &mut F,
    ) -> Result<u64, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        let module_index = match self.find_module_for_address(pc) {
            Some(i) => i,
            None => return Ok(FramepointerUnwinderArm64.unwind_one_frame(regs, read_stack)?),
        };
        let module = &self.modules[module_index];
        let rel_pc = (pc - module.base_address) as u32;
        match module.unwind_one_frame_from_pc(regs, pc, rel_pc, read_stack, cache) {
            Ok(ra) => Ok(ra),
            Err(UnwinderError::FramePointer(e)) => Err(e.into()),
            Err(_) => Ok(FramepointerUnwinderArm64.unwind_one_frame(regs, read_stack)?),
        }
    }

    fn find_module_for_address(&self, pc: u64) -> Option<usize> {
        let module_index = match self
            .modules
            .binary_search_by_key(&pc, |m| m.address_range.start)
        {
            Ok(i) => i,
            Err(insertion_index) => {
                if insertion_index == 0 {
                    // pc is before first known module
                    return None;
                }
                let i = insertion_index - 1;
                if self.modules[i].address_range.end <= pc {
                    // pc is after this module
                    return None;
                }
                i
            }
        };
        Some(module_index)
    }
}

pub enum UnwindData<D: Deref<Target = [u8]>> {
    CompactUnwindInfo(D),
    CompactUnwindInfoAndEhFrame(D, Arc<D>),
    EhFrameHdrAndEhFrame(D, Arc<D>),
    EhFrame(Arc<D>),
    None,
}

pub struct Module<D: Deref<Target = [u8]>> {
    #[allow(unused)]
    name: String,
    address_range: Range<u64>,
    base_address: u64,
    #[allow(unused)]
    vm_addr_at_base_addr: u64,
    sections: SectionAddresses,
    unwind_data: UnwindData<D>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SectionAddresses {
    pub text: u64,
    pub eh_frame: u64,
    pub eh_frame_hdr: u64,
    pub got: u64,
}

impl<D: Deref<Target = [u8]>> Module<D> {
    pub fn new(
        name: String,
        address_range: std::ops::Range<u64>,
        base_address: u64,
        vm_addr_at_base_addr: u64,
        sections: SectionAddresses,
        unwind_data: UnwindData<D>,
    ) -> Self {
        Self {
            name,
            address_range,
            base_address,
            vm_addr_at_base_addr,
            sections,
            unwind_data,
        }
    }

    fn unwind_one_frame_from_pc<F>(
        &self,
        regs: &mut UnwindRegsArm64,
        pc: u64,
        rel_pc: u32,
        read_stack: &mut F,
        cache: &mut Cache<D>,
    ) -> Result<u64, UnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        // println!("Unwinding at pc {} + 0x{:x} (= 0x{:x})", self.name, rel_pc, self.base_address + rel_pc as u64);
        let return_address = match &self.unwind_data {
            UnwindData::CompactUnwindInfo(data) => {
                // eprintln!("unwinding with cui in module {}", self.name);
                let mut unwinder =
                    CompactUnwindInfoUnwinder::<ArcDataReader<D>>::new(&data[..], None);
                unwinder.unwind_one_frame_from_pc(regs, pc, rel_pc, read_stack)?
            }
            UnwindData::CompactUnwindInfoAndEhFrame(unwind_data, eh_frame_data) => {
                // eprintln!("unwinding with cui and eh_frame in module {}", self.name);
                let mut dwarf_unwinder = DwarfUnwinder::new(
                    EndianReader::new(ArcData(eh_frame_data.clone()), LittleEndian),
                    &mut cache.eh_frame_unwind_context,
                    &self.sections,
                );
                let mut unwinder =
                    CompactUnwindInfoUnwinder::new(&unwind_data[..], Some(&mut dwarf_unwinder));
                let return_address =
                    unwinder.unwind_one_frame_from_pc(regs, pc, rel_pc, read_stack)?;
                drop(unwinder);
                drop(dwarf_unwinder);
                return_address
            }
            UnwindData::EhFrameHdrAndEhFrame(_, _) => todo!(),
            UnwindData::EhFrame(_) => todo!(),
            UnwindData::None => FramepointerUnwinderArm64.unwind_one_frame(regs, read_stack)?,
        };
        Ok(return_address)
    }
}
