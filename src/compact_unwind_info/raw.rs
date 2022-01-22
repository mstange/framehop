use std::fmt::Debug;
use std::result;

use zerocopy::{FromBytes, LayoutVerified};

use crate::display_utils::HexNum;
use crate::unaligned::{U16, U32};

// Written with help from https://gankra.github.io/blah/compact-unwinding/

#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    #[error("{0}")]
    Generic(&'static str),
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

impl<T> ReadError<T> for Option<T> {
    fn read_error(self, error: &'static str) -> Result<T> {
        self.ok_or(Error::Generic(error))
    }
}

#[derive(FromBytes, Debug, Clone, Copy)]
#[repr(C)]
pub struct CompactUnwindInfoHeader {
    /// The version. Only version 1 is currently defined
    pub version: U32,

    /// The array of U32 global opcodes (offset relative to start of root page).
    ///
    /// These may be indexed by "compressed" second-level pages.
    pub global_opcodes_offset: U32,
    pub global_opcodes_len: U32,

    /// The array of U32 global personality codes (offset relative to start of root page).
    ///
    /// Personalities define the style of unwinding that an unwinder should use,
    /// and how to interpret the LSDA entries for a function (see below).
    pub personalities_offset: U32,
    pub personalities_len: U32,

    /// The array of [`PageEntry`]'s describing the second-level pages
    /// (offset relative to start of root page).
    pub pages_offset: U32,
    pub pages_len: U32,
    // After this point there are several dynamically-sized arrays whose precise
    // order and positioning don't matter, because they are all accessed using
    // offsets like the ones above. The arrays are:

    // global_opcodes: [u32; global_opcodes_len],
    // personalities: [u32; personalities_len],
    // pages: [PageEntry; pages_len],
    // lsdas: [LsdaEntry; unknown_len],
}

trait ReadIntoRef {
    fn read_at<T: FromBytes>(&self, offset: u64) -> Option<&T>;
    fn read_slice_at<T: FromBytes>(&self, offset: u64, len: usize) -> Option<&[T]>;
}

impl<'a> ReadIntoRef for [u8] {
    fn read_at<T: FromBytes>(&self, offset: u64) -> Option<&T> {
        let offset: usize = offset.try_into().ok()?;
        let end: usize = offset.checked_add(core::mem::size_of::<T>())?;
        let lv = LayoutVerified::<&[u8], T>::new(self.get(offset..end)?)?;
        Some(lv.into_ref())
    }

    fn read_slice_at<T: FromBytes>(&self, offset: u64, len: usize) -> Option<&[T]> {
        let offset: usize = offset.try_into().ok()?;
        let end: usize = offset.checked_add(core::mem::size_of::<T>().checked_mul(len)?)?;
        let lv = LayoutVerified::<&[u8], [T]>::new_slice(self.get(offset..end)?)?;
        Some(lv.into_slice())
    }
}

impl CompactUnwindInfoHeader {
    /// Read the dyld cache header.
    pub fn parse(data: &[u8]) -> Result<&Self> {
        data.read_at::<CompactUnwindInfoHeader>(0)
            .read_error("Could not read CompactUnwindInfoHeader")
    }

    pub fn global_opcodes_offset(&self) -> u32 {
        self.global_opcodes_offset.into()
    }

    pub fn global_opcodes_len(&self) -> u32 {
        self.global_opcodes_len.into()
    }

    pub fn pages_offset(&self) -> u32 {
        self.pages_offset.into()
    }

    pub fn pages_len(&self) -> u32 {
        self.pages_len.into()
    }

    /// Return the list of global opcodes.
    pub fn global_opcodes<'data>(&self, data: &'data [u8]) -> Result<&'data [U32]> {
        data.read_slice_at::<U32>(
            self.global_opcodes_offset().into(),
            self.global_opcodes_len() as usize,
        )
        .read_error("Invalid global_opcodes size or alignment")
    }

    /// Return the list of pages.
    pub fn pages<'data>(&self, data: &'data [u8]) -> Result<&'data [PageEntry]> {
        data.read_slice_at::<PageEntry>(self.pages_offset().into(), self.pages_len() as usize)
            .read_error("Invalid pages size or alignment")
    }
}

#[derive(FromBytes, Clone, Copy)]
#[repr(C)]
pub struct PageEntry {
    /// The first address mapped by this page.
    ///
    /// This is useful for binary-searching for the page that can map
    /// a specific address in the binary (the primary kind of lookup
    /// performed by an unwinder).
    pub first_address: U32,

    /// Offset of the second-level page.
    ///
    /// This may point to either a [`RegularPage`] or a [`CompressedPage`].
    /// Which it is can be determined by the 32-bit "kind" value that is at
    /// the start of both layouts.
    pub page_offset: U32,

    /// Base offset into the lsdas array that entries in this page will be
    /// relative to.
    pub lsda_index_offset: U32,
}

impl PageEntry {
    pub fn page_offset(&self) -> u32 {
        self.page_offset.into()
    }

    pub fn first_address(&self) -> u32 {
        self.first_address.into()
    }

    pub fn lsda_index_offset(&self) -> u32 {
        self.lsda_index_offset.into()
    }

    pub fn page_kind(&self, data: &[u8]) -> Result<u32> {
        let kind = *data
            .read_at::<U32>(self.page_offset().into())
            .read_error("Could not read page kind")?;
        Ok(kind.into())
    }
}

impl Debug for PageEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PageEntry")
            .field("first_address", &HexNum(self.first_address()))
            .field("page_offset", &HexNum(self.page_offset()))
            .field("lsda_index_offset", &HexNum(self.lsda_index_offset()))
            .finish()
    }
}

pub const PAGE_KIND_SENTINEL: u32 = 1; // used in the last page, whose first_address is the end address
pub const PAGE_KIND_REGULAR: u32 = 2;
pub const PAGE_KIND_COMPRESSED: u32 = 3;

#[derive(FromBytes, Debug, Clone, Copy)]
#[repr(C)]
pub struct RegularPage {
    /// Always 2 (use to distinguish from CompressedPage).
    pub kind: U32,

    /// The Array of [`RegularEntry`]'s (offset relative to **start of this page**).
    pub entries_offset: U16,
    pub entries_len: U16,
}

impl RegularPage {
    pub fn parse(data: &[u8], page_offset: u64) -> Result<&Self> {
        data.read_at::<Self>(page_offset)
            .read_error("Could not read RegularPage")
    }

    pub fn entries_offset(&self) -> u16 {
        self.entries_offset.into()
    }

    pub fn entries_len(&self) -> u16 {
        self.entries_len.into()
    }

    pub fn entries<'data>(
        &self,
        data: &'data [u8],
        page_offset: u32,
    ) -> Result<&'data [RegularEntry]> {
        let relative_entries_offset = self.entries_offset();
        let entries_len: usize = self.entries_len().into();
        let entries_offset = page_offset as u64 + relative_entries_offset as u64;
        data.read_slice_at::<RegularEntry>(entries_offset, entries_len)
            .read_error("Could not read RegularPage entries")
    }
}

#[derive(FromBytes, Debug, Clone, Copy)]
#[repr(C)]
pub struct CompressedPage {
    /// Always 3 (use to distinguish from RegularPage).
    pub kind: U32,

    /// The array of compressed u32 entries (offset relative to **start of this page**).
    ///
    /// Entries are a u32 that contains two packed values (from highest to lowest bits):
    /// * 8 bits: opcode index
    ///   * 0..global_opcodes_len => index into global palette
    ///   * global_opcodes_len..255 => index into local palette (subtract global_opcodes_len)
    /// * 24 bits: instruction address
    ///   * address is relative to this page's first_address!
    pub entries_offset: U16,
    pub entries_len: U16,

    /// The array of u32 local opcodes for this page (offset relative to **start of this page**).
    pub local_opcodes_offset: U16,
    pub local_opcodes_len: U16,
}

impl CompressedPage {
    pub fn parse(data: &[u8], page_offset: u64) -> Result<&Self> {
        data.read_at::<Self>(page_offset)
            .read_error("Could not read CompressedPage")
    }

    pub fn entries_offset(&self) -> u16 {
        self.entries_offset.into()
    }

    pub fn entries_len(&self) -> u16 {
        self.entries_len.into()
    }

    pub fn local_opcodes_offset(&self) -> u16 {
        self.local_opcodes_offset.into()
    }

    pub fn local_opcodes_len(&self) -> u16 {
        self.local_opcodes_len.into()
    }

    pub fn entries<'data>(&self, data: &'data [u8], page_offset: u32) -> Result<&'data [U32]> {
        let relative_entries_offset = self.entries_offset();
        let entries_len: usize = self.entries_len().into();
        let entries_offset = page_offset as u64 + relative_entries_offset as u64;
        data.read_slice_at::<U32>(entries_offset, entries_len)
            .read_error("Could not read CompressedPage entries")
    }

    /// Return the list of local opcodes.
    pub fn local_opcodes<'data>(
        &self,
        data: &'data [u8],
        page_offset: u32,
    ) -> Result<&'data [U32]> {
        let relative_local_opcodes_offset = self.local_opcodes_offset();
        let local_opcodes_len: usize = self.local_opcodes_len().into();
        let local_opcodes_offset = page_offset as u64 + relative_local_opcodes_offset as u64;
        data.read_slice_at::<U32>(local_opcodes_offset, local_opcodes_len)
            .read_error("Invalid local_opcodes size or alignment")
    }
}

#[derive(FromBytes, Debug, Clone, Copy)]
#[repr(C)]
pub struct RegularEntry {
    /// The address in the binary for this entry (absolute).
    pub instruction_address: U32,

    /// The opcode for this address.
    pub opcode: U32,
}

impl RegularEntry {
    pub fn instruction_address(&self) -> u32 {
        self.instruction_address.into()
    }

    pub fn opcode(&self) -> u32 {
        self.opcode.into()
    }
}

pub const OPCODE_KIND_NULL: u8 = 0;

pub const OPCODE_KIND_X86_FRAMEBASED: u8 = 1;
pub const OPCODE_KIND_X86_FRAMELESS_IMMEDIATE: u8 = 2;
pub const OPCODE_KIND_X86_FRAMELESS_INDIRECT: u8 = 3;
pub const OPCODE_KIND_X86_DWARF: u8 = 4;

pub const OPCODE_KIND_ARM64_FRAMELESS: u8 = 2;
pub const OPCODE_KIND_ARM64_DWARF: u8 = 3;
pub const OPCODE_KIND_ARM64_FRAMEBASED: u8 = 4;
