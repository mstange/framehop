use std::fmt::{Debug, LowerHex};
use std::result;

use object::read::ReadRef;
use object::{LittleEndian, Pod, U16, U32};

// Some code taken from https://github.com/getsentry/symbolic/blob/81ce0bbeb4079d2a5b519dbf6ed022027199c0be/symbolic-debuginfo/src/macho/compact.rs#L1662-L1746 (MIT)
// with help from https://gankra.github.io/blah/compact-unwinding/

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

#[derive(Clone, Copy, Debug)]
pub struct Opcode(U32<LittleEndian>);

#[repr(C)]
#[derive(Clone, Copy)]
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
pub struct CompressedEntry(U32<LittleEndian>);

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

pub struct OpcodeBitfield(u32);

impl OpcodeBitfield {
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Whether this instruction is the start of a function.
    pub fn is_function_start(&self) -> bool {
        self.0 >> 31 == 1
    }

    /// Whether there is an lsda entry for this instruction.
    pub fn has_lsda(&self) -> bool {
        (self.0 >> 30) & 0b1 == 1
    }

    /// An index into the global personalities array
    /// (TODO: ignore if has_lsda() == false?)
    pub fn personality_index(&self) -> u8 {
        ((self.0 >> 28) & 0b11) as u8
    }

    /// The architecture-specific kind of opcode this is, specifying how to
    /// interpret the remaining 24 bits of the opcode.
    pub fn opcode_kind(&self) -> u8 {
        ((self.0 >> 24) & 0b1111) as u8
    }
}

impl From<&Opcode> for OpcodeBitfield {
    fn from(opcode: &Opcode) -> OpcodeBitfield {
        OpcodeBitfield::new(opcode.0.get(LittleEndian))
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Arm64Opcode {
    Frameless {
        stack_size_in_bytes: u16,
    },
    Dwarf {
        eh_frame_cie: u32,
    },
    FrameBased {
        // Whether each register pair was pushed
        d14_and_d15_saved: bool,
        d12_and_d13_saved: bool,
        d10_and_d11_saved: bool,
        d8_and_d9_saved: bool,

        x27_and_x28_saved: bool,
        x25_and_x26_saved: bool,
        x23_and_x24_saved: bool,
        x21_and_x22_saved: bool,
        x19_and_x20_saved: bool,
    },
}

impl TryFrom<&OpcodeBitfield> for Arm64Opcode {
    type Error = ();

    fn try_from(opcode: &OpcodeBitfield) -> std::result::Result<Self, Self::Error> {
        match opcode.opcode_kind() {
            2 => Ok(Arm64Opcode::Frameless {
                stack_size_in_bytes: (((opcode.0 >> 12) & 0b1111_1111_1111) as u16) * 16,
            }),
            3 => Ok(Arm64Opcode::Dwarf {
                eh_frame_cie: (opcode.0 & 0xffffff),
            }),
            4 => Ok(Arm64Opcode::FrameBased {
                d14_and_d15_saved: ((opcode.0 >> 8) & 1) == 1,
                d12_and_d13_saved: ((opcode.0 >> 7) & 1) == 1,
                d10_and_d11_saved: ((opcode.0 >> 6) & 1) == 1,
                d8_and_d9_saved: ((opcode.0 >> 5) & 1) == 1,
                x27_and_x28_saved: ((opcode.0 >> 4) & 1) == 1,
                x25_and_x26_saved: ((opcode.0 >> 3) & 1) == 1,
                x23_and_x24_saved: ((opcode.0 >> 2) & 1) == 1,
                x21_and_x22_saved: ((opcode.0 >> 1) & 1) == 1,
                x19_and_x20_saved: (opcode.0 & 1) == 1,
            }),
            _ => Err(()),
        }
    }
}

impl Debug for OpcodeBitfield {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let arm64_opcode: Option<Arm64Opcode> = self.try_into().ok();
        f.debug_struct("Opcode")
            .field("opcode_kind", &self.opcode_kind())
            .field("is_function_start", &self.is_function_start())
            .field("has_lsda", &self.has_lsda())
            .field("personality_index", &self.personality_index())
            .field("as_arm64", &arm64_opcode)
            .finish()
    }
}

impl PageEntry {
    pub fn page_offset(&self) -> u64 {
        self.page_offset.get(LittleEndian).into()
    }

    pub fn first_address(&self) -> u32 {
        self.first_address.get(LittleEndian)
    }

    pub fn lsda_index_offset(&self) -> u32 {
        self.lsda_index_offset.get(LittleEndian)
    }

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
    ) -> Result<&'data CompressedPage> {
        CompressedPage::parse(data, self.page_offset.get(LittleEndian).into())
    }
}

struct HexNum<N: LowerHex>(N);

impl<N: LowerHex> Debug for HexNum<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::LowerHex::fmt(&self.0, f)
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
    pub fn local_opcodes<'data, R: ReadRef<'data>>(
        &self,
        data: R,
        page_start_offset: u64,
    ) -> Result<&'data [Opcode]> {
        let relative_local_opcodes_offset: u64 = self.local_opcodes_offset.get(LittleEndian).into();
        let local_opcodes_len: usize = self.local_opcodes_len.get(LittleEndian).into();
        let local_opcodes_offset = page_start_offset
            .checked_add(relative_local_opcodes_offset)
            .unwrap(); // todo turn into error
        data.read_slice_at::<Opcode>(local_opcodes_offset, local_opcodes_len)
            .read_error("Invalid local_opcodes size or alignment")
    }
}

impl RegularEntry {
    pub fn instruction_address(&self) -> u32 {
        self.instruction_address.get(LittleEndian)
    }

    pub fn opcode(&self) -> OpcodeBitfield {
        let opcode = &self.opcode;
        opcode.into()
    }
}

impl From<&CompressedEntry> for CompressedEntryBitfield {
    fn from(entry: &CompressedEntry) -> CompressedEntryBitfield {
        CompressedEntryBitfield::new(entry.0.get(LittleEndian))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CompressedEntryBitfield(pub u32);

/// Entries are a u32 that contains two packed values (from high to low):
/// * 8 bits: opcode index
/// * 24 bits: instruction address
impl CompressedEntryBitfield {
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// The opcode index.
    ///   * 0..global_opcodes_len => index into global palette
    ///   * global_opcodes_len..255 => index into local palette
    ///     (subtract global_opcodes_len to get the real local index)
    pub fn opcode_index(&self) -> u8 {
        (self.0 >> 24) as u8
    }

    /// The instruction address, relative to the page's first_address.
    pub fn relative_instruction_address(&self) -> u32 {
        self.0 & 0xffffff
    }
}

impl Debug for CompressedEntryBitfield {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompressedEntryBitfield")
            .field("opcode_index", &HexNum(self.opcode_index()))
            .field(
                "relative_instruction_address",
                &HexNum(self.relative_instruction_address()),
            )
            .finish()
    }
}
