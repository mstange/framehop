use std::ops::Deref;

use super::arcdata::ArcDataReader;

pub struct Cache<D: Deref<Target = [u8]>> {
  pub(crate) eh_frame_unwind_context: Box<gimli::UnwindContext<ArcDataReader<D>>>,
}

impl<D: Deref<Target = [u8]>> Cache<D> {
  pub fn new() -> Self {
      Self {
          eh_frame_unwind_context: Box::new(gimli::UnwindContext::new()),
      }
  }
}

impl<D: Deref<Target = [u8]>> Default for Cache<D> {
  fn default() -> Self {
      Self::new()
  }
}
