use std::rc::Rc;

pub struct UnwindRegs {
  pc: u64,
  sp: u64,
  bp: u64,
}

pub enum Error {
  AddressOutsideKnownModules,
}

pub trait OwnedData {
  fn data(&self) -> &[u8];
}

pub struct Context<D: OwnedData> {
  /// sorted by address_range.start
  modules: Vec<ModuleAtAddress<D>>,
}

impl<D: OwnedData> Context<D> {
  pub fn unwind_frame(&self, context: UnwindRegs, pc: u64) -> Result<UnwindRegs, Error> {
      let module_index = match self
          .modules
          .binary_search_by_key(&pc, |m| m.address_range.start)
      {
          Ok(i) => i,
          Err(insertion_index) => {
              if insertion_index == 0 {
                  // pc is before first known module
                  return Err(Error::AddressOutsideKnownModules);
              }
              let i = insertion_index - 1;
              if self.modules[i].address_range.end <= pc {
                  // pc is after this module
                  return Err(Error::AddressOutsideKnownModules);
              }
              i
          }
      };
      let module = &self.modules[module_index];
      let module_relative_pc = pc - module.base_address;
      module.module.unwind_frame(context, module_relative_pc)
  }
}

pub struct ModuleAtAddress<D: OwnedData> {
  address_range: std::ops::Range<u64>,
  base_address: u64,
  module: Rc<Module<D>>,
}

pub struct Module<D: OwnedData> {
  name: String,
  vm_addr_at_base_addr: u64,
  unwind_info_data: D,
}

impl<D: OwnedData> Module<D> {
  pub fn new(name: String, unwind_info_data: D) -> Self {
      Self {
          name,
          vm_addr_at_base_addr: 0,
          unwind_info_data,
      }
  }

  pub fn unwind_frame(
      &self,
      context: UnwindRegs,
      module_relative_pc: u64,
  ) -> Result<UnwindRegs, Error> {
      Ok(context)
  }
}

#[cfg(test)]
mod tests {
  #[test]
  fn it_works() {
      let result = 2 + 2;
      assert_eq!(result, 4);
  }
}
