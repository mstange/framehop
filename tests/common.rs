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
        (Some(unwind_info), Some(eh_frame), _) => {
            framehop::UnwindData::CompactUnwindInfoAndEhFrame(unwind_info, Some(Arc::new(eh_frame)))
        }
        (Some(unwind_info), None, _) => {
            framehop::UnwindData::CompactUnwindInfoAndEhFrame(unwind_info, None)
        }
        (None, Some(eh_frame), Some(eh_frame_hdr)) => {
            framehop::UnwindData::EhFrameHdrAndEhFrame(eh_frame_hdr, Arc::new(eh_frame))
        }
        (None, Some(eh_frame), None) => framehop::UnwindData::EhFrame(Arc::new(eh_frame)),
        (None, None, _) => framehop::UnwindData::None,
    };

    let module = framehop::Module::new(
        objpath.file_name().unwrap().to_string_lossy().to_string(),
        base_address..(base_address + buf.len() as u64),
        base_address,
        0,
        SectionAddresses {
            text: text.map_or(0, |s| s.address()),
            eh_frame: eh_frame.map_or(0, |s| s.address()),
            eh_frame_hdr: eh_frame_hdr.map_or(0, |s| s.address()),
            got: got.map_or(0, |s| s.address()),
        },
        unwind_data,
    );
    unwinder.add_module(module);
}
