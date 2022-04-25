use std::{io::Read, ops::Range, path::Path, sync::Arc};

use object::{Object, ObjectSection, ObjectSegment};

use framehop::*;

pub fn add_object<U>(unwinder: &mut U, objpath: &Path, base_address: u64)
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

    let text = file
        .section_by_name("__text")
        .or_else(|| file.section_by_name(".text"));
    let stubs = file.section_by_name("__stubs");
    let stub_helper = file.section_by_name("__stub_helper");
    let text_env = file.section_by_name("__text_env");
    let unwind_info = file.section_by_name("__unwind_info");
    let eh_frame = file
        .section_by_name("__eh_frame")
        .or_else(|| file.section_by_name(".eh_frame"));
    let got = file
        .section_by_name("__got")
        .or_else(|| file.section_by_name(".got"));
    let eh_frame_hdr = file.section_by_name(".eh_frame_hdr");

    let unwind_data = match (
        unwind_info.as_ref().and_then(section_data),
        eh_frame.as_ref().and_then(section_data),
        eh_frame_hdr.as_ref().and_then(section_data),
    ) {
        (Some(unwind_info), eh_frame, _) => {
            framehop::ModuleUnwindData::CompactUnwindInfoAndEhFrame(
                unwind_info,
                eh_frame.map(Arc::new),
            )
        }
        (None, Some(eh_frame), Some(eh_frame_hdr)) => {
            framehop::ModuleUnwindData::EhFrameHdrAndEhFrame(eh_frame_hdr, Arc::new(eh_frame))
        }
        (None, Some(eh_frame), None) => framehop::ModuleUnwindData::EhFrame(Arc::new(eh_frame)),
        (None, None, _) => framehop::ModuleUnwindData::None,
    };

    let text_data = if let Some(text_segment) = file
        .segments()
        .find(|segment| segment.name_bytes() == Ok(Some(b"__TEXT")))
    {
        let (start, size) = text_segment.file_range();
        let address_range = base_address + start..base_address + start + size;
        text_segment
            .data()
            .ok()
            .map(|data| TextByteData::new(data.to_owned(), address_range))
    } else if let Some(text_section) = &text {
        if let Some((start, size)) = text_section.file_range() {
            let address_range = base_address + start..base_address + start + size;
            text_section
                .data()
                .ok()
                .map(|data| TextByteData::new(data.to_owned(), address_range))
        } else {
            None
        }
    } else {
        None
    };

    fn address_range<'a>(
        section: &Option<impl ObjectSection<'a>>,
        base_address: u64,
    ) -> Option<Range<u64>> {
        section
            .as_ref()
            .and_then(|section| section.file_range())
            .map(|(start, size)| base_address + start..base_address + start + size)
    }

    let module = framehop::Module::new(
        objpath.to_string_lossy().to_string(),
        base_address..(base_address + buf.len() as u64),
        base_address,
        ModuleSectionAddressRanges {
            text: address_range(&text, base_address),
            text_env: address_range(&text_env, base_address),
            stubs: address_range(&stubs, base_address),
            stub_helper: address_range(&stub_helper, base_address),
            eh_frame: address_range(&eh_frame, base_address),
            eh_frame_hdr: address_range(&eh_frame_hdr, base_address),
            got: address_range(&got, base_address),
        },
        unwind_data,
        text_data,
    );
    unwinder.add_module(module);
}
