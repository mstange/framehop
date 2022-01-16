use std::{fs::File, io::Read};

use rul::compact_unwind_info::{CompactUnwindInfoHeader, OpcodeBitfield};

fn main() {
    let mut data = Vec::new();
    let mut file = File::open("fixtures/rustup.__unwind_info").unwrap();
    file.read_to_end(&mut data).unwrap();
    let data = &data[..];
    let header = CompactUnwindInfoHeader::parse(data).unwrap();
    let opcodes: Vec<OpcodeBitfield> = header
        .global_opcodes(data)
        .unwrap()
        .iter()
        .map(Into::into)
        .collect();
    println!("global opcodes: {:#?}", opcodes);
    let pages = header.pages(data).unwrap();
    let regular_pages: Vec<_> = pages
        .iter()
        .filter_map(|page| {
            if page.is_regular_page(data).unwrap() {
                Some((page, page.parse_regular_page(data).unwrap()))
            } else {
                None
            }
        })
        .collect();
    println!("regular pages: {:#?}", regular_pages);
    let compressed_pages: Vec<_> = pages
        .iter()
        .filter_map(|page| {
            if page.is_regular_page(data).unwrap() {
                None
            } else {
              Some((page, page.parse_compressed_page(data).unwrap()))
            }
        })
        .collect();
    println!("compressed pages: {:#?}", compressed_pages);
}
