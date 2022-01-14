use std::rc::Rc;

pub struct UnwindContext {
    pc: u64,
    sp: u64,
    bp: u64,
}

pub enum Error {
    AddressOutsideKnownModules,
}

pub struct Lul {
    modules: Vec<ModuleAtAddress>,
}

impl Lul {
    pub fn unwind_frame(&self, context: UnwindContext, pc: u64) -> Result<UnwindContext, Error> {
        Ok(context)
    }
}

pub struct ModuleAtAddress {
    address_range: std::ops::Range<u64>,
    base_address: u64,
    module: Rc<Module>,
}

pub struct Module {
    name: String,
}

impl Module {
    pub fn unwind_frame(&self, context: UnwindContext, module_relative_pc: u64) -> Result<UnwindContext, Error> {
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
