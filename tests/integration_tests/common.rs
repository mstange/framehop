use std::{io::Read, path::Path, sync::Arc};

use object::{Object, ObjectSection};

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
            framehop::ModuleUnwindData::EhFrameHdrAndEhFrame(
                Arc::new(eh_frame_hdr),
                Arc::new(eh_frame),
            )
        }
        (None, Some(eh_frame), None) => framehop::ModuleUnwindData::EhFrame(Arc::new(eh_frame)),
        (None, None, _) => framehop::ModuleUnwindData::None,
    };

    let text_data = text.as_ref().and_then(section_data);

    let module = framehop::Module::new(
        base_address..(base_address + buf.len() as u64),
        base_address,
        ModuleSectionAddresses {
            text: base_address
                + text
                    .and_then(|s| s.file_range())
                    .map_or(0, |(start, _end)| start),
            eh_frame: base_address
                + eh_frame
                    .and_then(|s| s.file_range())
                    .map_or(0, |(start, _end)| start),
            eh_frame_hdr: base_address
                + eh_frame_hdr
                    .and_then(|s| s.file_range())
                    .map_or(0, |(start, _end)| start),
            got: base_address
                + got
                    .and_then(|s| s.file_range())
                    .map_or(0, |(start, _end)| start),
        },
        unwind_data,
        text_data,
    );
    unwinder.add_module(module);
}
