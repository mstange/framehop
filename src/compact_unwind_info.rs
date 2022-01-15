use std::fmt::Debug;
use std::result;

use bitvec::prelude::*;
use object::read::ReadRef;
use object::{LittleEndian, Pod, U16, U32};

#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    #[error("{0}")]
    Generic(&'static str),

    #[error("object read error: {0}")]
    ObjectRead(#[source] object::read::Error),

    #[error("object read error: {0} ({1})")]
    ObjectReadWithContext(&'static str, #[source] object::read::Error),
}

impl From<object::read::Error> for Error {
    fn from(e: object::read::Error) -> Self {
        Error::ObjectRead(e)
    }
}

/// The result type used within the read module.
pub type Result<T> = result::Result<T, Error>;

trait ReadError<T> {
    fn read_error(self, error: &'static str) -> Result<T>;
}

impl<T> ReadError<T> for result::Result<T, ()> {
    fn read_error(self, error: &'static str) -> Result<T> {
        self.map_err(|()| Error::Generic(error))
    }
}

impl<T> ReadError<T> for result::Result<T, object::read::Error> {
    fn read_error(self, context: &'static str) -> Result<T> {
        self.map_err(|error| Error::ObjectReadWithContext(context, error))
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct CompactUnwindInfoHeader {
    /// The version. :Only version 1 is currently defined
    pub version: U32<LittleEndian>,

    /// The array of U32<LittleEndian> global opcodes (offset relative to start of root page).
    ///
    /// These may be indexed by "compressed" second-level pages.
    pub global_opcodes_offset: U32<LittleEndian>,
    pub global_opcodes_len: U32<LittleEndian>,

    /// The array of U32<LittleEndian> global personality codes (offset relative to start of root page).
    ///
    /// Personalities define the style of unwinding that an unwinder should use,
    /// and how to interpret the LSDA entries for a function (see below).
    pub personalities_offset: U32<LittleEndian>,
    pub personalities_len: U32<LittleEndian>,

    /// The array of [`PageEntry`]'s describing the second-level pages
    /// (offset relative to start of root page).
    pub pages_offset: U32<LittleEndian>,
    pub pages_len: U32<LittleEndian>,
    // After this point there are several dynamically-sized arrays whose precise
    // order and positioning don't matter, because they are all accessed using
    // offsets like the ones above. The arrays are:

    // global_opcodes: [u32; global_opcodes_len],
    // personalities: [u32; personalities_len],
    // pages: [PageEntry; pages_len],
    // lsdas: [LsdaEntry; unknown_len],
}

#[derive(Clone, Copy)]
pub struct Opcode(BitArray<[u8; 4], Msb0>);

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PageEntry {
    /// The first address mapped by this page.
    ///
    /// This is useful for binary-searching for the page that can map
    /// a specific address in the binary (the primary kind of lookup
    /// performed by an unwinder).
    pub first_address: U32<LittleEndian>,

    /// Offset of the second-level page.
    ///
    /// This may point to either a [`RegularPage`] or a [`CompressedPage`].
    /// Which it is can be determined by the 32-bit "kind" value that is at
    /// the start of both layouts.
    pub page_offset: U32<LittleEndian>,

    /// Base offset into the lsdas array that entries in this page will be
    /// relative to.
    pub lsda_index_offset: U32<LittleEndian>,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RegularPage {
    /// Always 2 (use to distinguish from CompressedPage).
    pub kind: U32<LittleEndian>,

    /// The Array of [`RegularEntry`]'s (offset relative to **start of this page**).
    pub entries_offset: U16<LittleEndian>,
    pub entries_len: U16<LittleEndian>,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CompressedPage {
    /// Always 3 (use to distinguish from RegularPage).
    pub kind: U32<LittleEndian>,

    /// The array of compressed u32 entries (offset relative to **start of this page**).
    ///
    /// Entries are a u32 that contains two packed values (from highest to lowest bits):
    /// * 8 bits: opcode index
    ///   * 0..global_opcodes_len => index into global palette
    ///   * global_opcodes_len..255 => index into local palette (subtract global_opcodes_len)
    /// * 24 bits: instruction address
    ///   * address is relative to this page's first_address!
    pub entries_offset: U16<LittleEndian>,
    pub entries_len: U16<LittleEndian>,

    /// The array of u32 local opcodes for this page (offset relative to **start of this page**).
    pub local_opcodes_offset: U16<LittleEndian>,
    pub local_opcodes_len: U16<LittleEndian>,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RegularEntry {
    /// The address in the binary for this entry (absolute).
    pub instruction_address: U32<LittleEndian>,

    /// The opcode for this address.
    pub opcode: Opcode,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CompressedEntry(BitArray<[u8; 4], Msb0>);

unsafe impl Pod for CompactUnwindInfoHeader {}
unsafe impl Pod for PageEntry {}
unsafe impl Pod for RegularPage {}
unsafe impl Pod for CompressedPage {}
unsafe impl Pod for RegularEntry {}
unsafe impl Pod for Opcode {}
unsafe impl Pod for CompressedEntry {}

impl CompactUnwindInfoHeader {
    /// Read the dyld cache header.
    pub fn parse<'data, R: ReadRef<'data>>(data: R) -> Result<&'data Self> {
        data.read_at::<CompactUnwindInfoHeader>(0)
            .read_error("Could not read CompactUnwindInfoHeader")
    }

    /// Return the list of global opcodes.
    pub fn global_opcodes<'data, R: ReadRef<'data>>(&self, data: R) -> Result<&'data [Opcode]> {
        data.read_slice_at::<Opcode>(
            self.global_opcodes_offset.get(LittleEndian).into(),
            self.global_opcodes_len.get(LittleEndian) as usize,
        )
        .read_error("Invalid global_opcodes size or alignment")
    }

    /// Return the list of pages.
    pub fn pages<'data, R: ReadRef<'data>>(&self, data: R) -> Result<&'data [PageEntry]> {
        data.read_slice_at::<PageEntry>(
            self.pages_offset.get(LittleEndian).into(),
            self.pages_len.get(LittleEndian) as usize,
        )
        .read_error("Invalid pages size or alignment")
    }
}

impl Opcode {
    /// Whether this instruction is the start of a function.
    pub fn is_start(&self) -> u8 {
        self.0[0..1].load_le()
    }

    /// Whether there is an lsda entry for this instruction.
    pub fn has_lsda(&self) -> u8 {
        self.0[1..2].load_le()
    }

    /// An index into the global personalities array
    /// (TODO: ignore if has_lsda == false?)
    pub fn personality_index(&self) -> u8 {
        self.0[2..4].load_le()
    }

    /// The architecture-specific kind of opcode this is, specifying how to
    /// interpret the remaining 24 bits of the opcode.
    pub fn opcode_kind(&self) -> u8 {
        self.0[4..8].load_le()
    }
}

impl Debug for Opcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Opcode").field(&self.0).finish()
    }
}

impl PageEntry {
    pub fn is_regular_page<'data, R: ReadRef<'data>>(&self, data: R) -> Result<bool> {
        let kind = data
            .read_at::<U32<LittleEndian>>(self.page_offset.get(LittleEndian).into())
            .read_error("Could not read page kind")?
            .get(LittleEndian);
        Ok(kind == 2)
    }

    pub fn parse_regular_page<'data, R: ReadRef<'data>>(
        &self,
        data: R,
    ) -> Result<&'data RegularPage> {
        RegularPage::parse(data, self.page_offset.get(LittleEndian).into())
    }

    pub fn parse_compressed_page<'data, R: ReadRef<'data>>(
        &self,
        data: R,
    ) -> Result<&'data RegularPage> {
        RegularPage::parse(data, self.page_offset.get(LittleEndian).into())
    }
}

impl RegularPage {
    pub fn parse<'data, R: ReadRef<'data>>(data: R, offset: u64) -> Result<&'data Self> {
        data.read_at::<Self>(offset)
            .read_error("Could not read RegularPage")
    }

    pub fn entries<'data, R: ReadRef<'data>>(
        &self,
        data: R,
        page_start_offset: u64,
    ) -> Result<&'data [RegularEntry]> {
        let relative_entries_offset: u64 = self.entries_offset.get(LittleEndian).into();
        let entries_len: usize = self.entries_len.get(LittleEndian).into();
        let entries_offset = page_start_offset
            .checked_add(relative_entries_offset)
            .unwrap(); // todo turn into error
        data.read_slice_at::<RegularEntry>(entries_offset, entries_len)
            .read_error("Could not read RegularPage entries")
    }
}

impl CompressedPage {
    pub fn parse<'data, R: ReadRef<'data>>(data: R, offset: u64) -> Result<&'data Self> {
        data.read_at::<Self>(offset)
            .read_error("Could not read CompressedPage")
    }

    pub fn entries<'data, R: ReadRef<'data>>(
        &self,
        data: R,
        page_start_offset: u64,
    ) -> Result<&'data [CompressedEntry]> {
        let relative_entries_offset: u64 = self.entries_offset.get(LittleEndian).into();
        let entries_len: usize = self.entries_len.get(LittleEndian).into();
        let entries_offset = page_start_offset
            .checked_add(relative_entries_offset)
            .unwrap(); // todo turn into error
        data.read_slice_at::<CompressedEntry>(entries_offset, entries_len)
            .read_error("Could not read CompressedPage entries")
    }

    /// Return the list of local opcodes.
    pub fn local_opcodes<'data, R: ReadRef<'data>>(&self, data: R) -> Result<&'data [Opcode]> {
        data.read_slice_at::<Opcode>(
            self.local_opcodes_offset.get(LittleEndian).into(),
            self.local_opcodes_len.get(LittleEndian) as usize,
        )
        .read_error("Invalid local_opcodes size or alignment")
    }
}

impl RegularEntry {}

/// Entries are a u32 that contains two packed values (from high to low):
/// * 8 bits: opcode index
///   * 0..global_opcodes_len => index into global palette
///   * global_opcodes_len..255 => index into local palette
///     (subtract global_opcodes_len to get the real local index)
/// * 24 bits: instruction address
///   * address is relative to this page's first_address!
///
impl CompressedEntry {
    /// Whether this instruction is the start of a function.
    pub fn opcode_index(&self) -> u8 {
        self.0[0..8].load_le()
    }

    /// Whether there is an lsda entry for this instruction.
    pub fn relative_instr_address(&self) -> u32 {
        self.0[8..24].load_le()
    }
}
