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

    fn section_data<'a>(section: &impl ObjectSection<'a>) -> Option<Vec<u8>> {
        section.data().ok().map(|data| data.to_owned())
    }

    let file = object::File::parse(&buf[..]).expect("Could not parse object file");

    let base_svma = relative_address_base(&file);

    let text = file.section_by_name(".text");
    let stubs = file.section_by_name("__stubs");
    let stub_helper = file.section_by_name("__stub_helper");
    let text_env = file.section_by_name("__text_env");
    let unwind_info = file.section_by_name("__unwind_info");
    let eh_frame = file.section_by_name(".eh_frame");
    let got = file.section_by_name(".got");
    let eh_frame_hdr = file.section_by_name(".eh_frame_hdr");
    let debug_frame = file
        .section_by_name(".debug_frame")
        .or_else(|| file.section_by_name("__zdebug_frame"));

    let unwind_data = match (
        unwind_info.as_ref().and_then(section_data),
        eh_frame.as_ref().and_then(section_data),
        eh_frame_hdr.as_ref().and_then(section_data),
        debug_frame,
    ) {
        (Some(unwind_info), eh_frame, _, _) => {
            framehop::ModuleUnwindData::CompactUnwindInfoAndEhFrame(unwind_info, eh_frame)
        }
        (None, Some(eh_frame), Some(eh_frame_hdr), _) => {
            framehop::ModuleUnwindData::EhFrameHdrAndEhFrame(eh_frame_hdr, eh_frame)
        }
        (None, Some(eh_frame), None, _) => framehop::ModuleUnwindData::EhFrame(eh_frame),
        (None, None, _, Some(debug_frame)) => {
            eprintln!("Have debug_frame!");
            if let Some(section_data) = get_uncompressed_section_data(&debug_frame) {
                let debug_frame_data = Vec::from(section_data);
                framehop::ModuleUnwindData::DebugFrame(debug_frame_data)
            } else {
                framehop::ModuleUnwindData::None
            }
        }
        (None, None, _, _) => framehop::ModuleUnwindData::None,
    };

    let text_data = if let Some(text_segment) = file
        .segments()
        .find(|segment| segment.name_bytes() == Ok(Some(b"__TEXT")))
    {
        let (start, size) = text_segment.file_range();
        let avma_range = base_avma + start..base_avma + start + size;
        text_segment
            .data()
            .ok()
            .map(|data| TextByteData::new(data.to_owned(), avma_range))
    } else if let Some(text_section) = &text {
        if let Some((start, size)) = text_section.file_range() {
            let avma_range = base_avma + start..base_avma + start + size;
            text_section
                .data()
                .ok()
                .map(|data| TextByteData::new(data.to_owned(), avma_range))
        } else {
            None
        }
    } else {
        None
    };

    fn svma_range<'a>(section: &Option<impl ObjectSection<'a>>) -> Option<Range<u64>> {
        section
            .as_ref()
            .map(|section| section.address()..section.address() + section.size())
    }

    let module = framehop::Module::new(
        objpath.to_string_lossy().to_string(),
        base_avma..(base_avma + buf.len() as u64),
        base_avma,
        ModuleSvmaInfo {
            base_svma,
            text: svma_range(&text),
            text_env: svma_range(&text_env),
            stubs: svma_range(&stubs),
            stub_helper: svma_range(&stub_helper),
            eh_frame: svma_range(&eh_frame),
            eh_frame_hdr: svma_range(&eh_frame_hdr),
            got: svma_range(&got),
        },
        unwind_data,
        text_data,
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
pub fn relative_address_base<'data: 'file, 'file>(
    object_file: &'file impl object::Object<'data, 'file>,
) -> u64 {
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
