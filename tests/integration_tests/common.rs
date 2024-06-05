use std::{borrow::Cow, io::Read, ops::Range, path::Path};

use object::{Object, ObjectSection, ObjectSegment};

use framehop::*;

pub fn add_object<U>(unwinder: &mut U, objpath: &Path, base_avma: u64)
where
    U: Unwinder<Module = Module<Vec<u8>>>,
{
    let mut buf = Vec::new();
    let mut file = std::fs::File::open(objpath).unwrap();
    file.read_to_end(&mut buf).unwrap();

    let file = object::File::parse(&buf[..]).expect("Could not parse object file");

    struct Module<'a>(object::File<'a, &'a [u8]>);

    impl ModuleSectionInfo<Vec<u8>> for Module<'_> {
        fn base_svma(&self) -> u64 {
            relative_address_base(&self.0)
        }

        fn section_svma_range(&mut self, name: &[u8]) -> Option<Range<u64>> {
            let section = self.0.section_by_name_bytes(name)?;
            Some(section.address()..section.address() + section.size())
        }

        fn section_data(&mut self, name: &[u8]) -> Option<Vec<u8>> {
            match self.0.section_by_name_bytes(name) {
                Some(section) => section.data().ok().map(|data| data.to_owned()),
                None if name == b".debug_frame" => {
                    let section = self.0.section_by_name_bytes(b"__zdebug_frame")?;
                    get_uncompressed_section_data(&section).map(|d| d.into_owned())
                }
                None => None,
            }
        }

        fn segment_svma_range(&mut self, name: &[u8]) -> Option<Range<u64>> {
            let segment = self
                .0
                .segments()
                .find(|s| s.name_bytes() == Ok(Some(name)))?;
            Some(segment.address()..segment.address() + segment.size())
        }

        fn segment_data(&mut self, name: &[u8]) -> Option<Vec<u8>> {
            let segment = self
                .0
                .segments()
                .find(|s| s.name_bytes() == Ok(Some(name)))?;
            segment.data().ok().map(|data| data.to_owned())
        }
    }

    let module = framehop::Module::new(
        objpath.to_string_lossy().to_string(),
        base_avma..(base_avma + buf.len() as u64),
        base_avma,
        Module(file),
    );
    unwinder.add_module(module);
}

fn get_uncompressed_section_data<'a>(
    section: &impl object::ObjectSection<'a>,
) -> Option<Cow<'a, [u8]>> {
    let section_data = section.uncompressed_data().ok()?;

    // Make sure the data is actually decompressed.
    if section.name_bytes().ok()?.starts_with(b"__zdebug_")
        && section_data.starts_with(b"ZLIB\0\0\0\0")
    {
        // Object's built-in compressed section handling didn't detect this as a
        // compressed section. This happens on Go binaries which use compressed
        // sections like __zdebug_ranges, which is generally uncommon on macOS, so
        // object's mach-O parser doesn't handle them.
        // But we want to handle them.
        // Go stopped using zdebug sections for ELF files in https://github.com/golang/go/issues/50796
        // but still uses them for mach-O builds.
        let b = section_data.get(8..12)?;
        let uncompressed_size = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let compressed_bytes = &section_data[12..];

        let mut decompressed = Vec::with_capacity(uncompressed_size as usize);
        let mut decompress = flate2::Decompress::new(true);
        decompress
            .decompress_vec(
                compressed_bytes,
                &mut decompressed,
                flate2::FlushDecompress::Finish,
            )
            .ok()?;
        Some(Cow::Owned(decompressed))
    } else {
        Some(section_data)
    }
}

/// Relative addresses are u32 offsets which are relative to some "base address".
///
/// This function computes that base address. It is defined as follows:
///
///  - For Windows binaries, the base address is the "image base address".
///  - For mach-O binaries, the base address is the vmaddr of the __TEXT segment.
///  - For ELF binaries, the base address is zero.
///
/// Stand-alone mach-O dylibs usually have a base address of zero because their
/// __TEXT segment is at address zero.
///
/// In the following cases, the base address is usually non-zero:
///
///  - The "image base address" of Windows binaries is usually non-zero.
///  - mach-O executable files (not dylibs) usually have their __TEXT segment at
///    address 0x100000000.
///  - mach-O libraries in the dyld shared cache have a __TEXT segment at some
///    non-zero address in the cache.
pub fn relative_address_base<'data>(object_file: &impl object::Object<'data>) -> u64 {
    if let Some(text_segment) = object_file
        .segments()
        .find(|s| s.name() == Ok(Some("__TEXT")))
    {
        // This is a mach-O image. "Relative addresses" are relative to the
        // vmaddr of the __TEXT segment.
        return text_segment.address();
    }

    // For PE binaries, relative_address_base() returns the image base address.
    // Otherwise it returns zero. This gives regular ELF images a base address of zero,
    // which is what we want.
    object_file.relative_address_base()
}
