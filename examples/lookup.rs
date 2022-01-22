use std::{fs::File, io::Read};

use framehop::compact_unwind_info::{
    CompactUnwindInfoHeader, CompressedEntryBitfield, CompressedPage, OpcodeBitfield, PageEntry,
    RegularEntry, RegularPage, PAGE_KIND_COMPRESSED, PAGE_KIND_REGULAR,
};

fn main() {
    let mut args = std::env::args().skip(1);
    if args.len() < 1 {
        eprintln!("Usage: {} <pc>", std::env::args().next().unwrap());
        std::process::exit(1);
    }
    let pc = args.next().unwrap();
    let pc: u32 = if let Some(hexstr) = pc.strip_prefix("0x") {
        u32::from_str_radix(hexstr, 16).unwrap()
    } else {
        pc.parse().unwrap()
    };

    let mut data = Vec::new();
    let mut file = File::open("fixtures/rustup.__unwind_info").unwrap();
    file.read_to_end(&mut data).unwrap();

    let data = &data[..];
    let header = CompactUnwindInfoHeader::parse(data).unwrap();
    let global_opcodes = header.global_opcodes(data).unwrap();
    let pages = header.pages(data).unwrap();
    let page_index = match pages.binary_search_by_key(&pc, PageEntry::first_address) {
        Ok(i) => i,
        Err(insertion_index) => {
            if insertion_index == 0 {
                eprintln!("pc before start address of first page");
                std::process::exit(1);
            }
            insertion_index - 1
        }
    };
    let page_entry = &pages[page_index];
    let page_start_offset = page_entry.page_offset();
    match page_entry.page_kind(data).unwrap() {
        PAGE_KIND_REGULAR => {
            eprintln!(
                "Found pc in regular page starting at 0x{:x}",
                page_entry.first_address()
            );
            let page = RegularPage::parse(data, page_start_offset.into()).unwrap();
            let entries = page.entries(data, page_start_offset).unwrap();
            let entry_index =
                match entries.binary_search_by_key(&pc, RegularEntry::instruction_address) {
                    Ok(i) => i,
                    Err(insertion_index) => {
                        if insertion_index == 0 {
                            eprintln!(
                                "pc before start instruction address of first entry in this page"
                            );
                            std::process::exit(1);
                        }
                        insertion_index - 1
                    }
                };
            let entry = &entries[entry_index];
            let opcode = entry.opcode();
            eprintln!(
                "Found entry with instruction address 0x{:x} and opcode: {:#?}",
                entry.instruction_address(),
                opcode
            );
        }
        PAGE_KIND_COMPRESSED => {
            eprintln!(
                "Found pc in compressed page starting at 0x{:x}",
                page_entry.first_address()
            );
            let page = CompressedPage::parse(data, page_start_offset.into()).unwrap();
            let entries = page.entries(data, page_start_offset).unwrap();
            let rel_pc = pc - page_entry.first_address();
            let entry_index = match entries.binary_search_by_key(&rel_pc, |&entry| {
                let bitfield = CompressedEntryBitfield::new(entry.into());
                bitfield.relative_instruction_address()
            }) {
                Ok(i) => i,
                Err(insertion_index) => {
                    if insertion_index == 0 {
                        eprintln!(
                            "pc before start instruction address of first entry in this page"
                        );
                        std::process::exit(1);
                    }
                    insertion_index - 1
                }
            };

            let entry = CompressedEntryBitfield::new(entries[entry_index].into());
            let instruction_address =
                page_entry.first_address() + entry.relative_instruction_address();
            let opcode_index: usize = entry.opcode_index().into();
            let (local_or_global, opcode): (&'static str, OpcodeBitfield) =
                if opcode_index < global_opcodes.len() {
                    (
                        "global",
                        OpcodeBitfield::new(global_opcodes[opcode_index].into()),
                    )
                } else {
                    let local_opcodes = page.local_opcodes(data, page_start_offset).unwrap();
                    let local_index = opcode_index - global_opcodes.len();
                    (
                        "local",
                        OpcodeBitfield::new(local_opcodes[local_index].into()),
                    )
                };
            eprintln!(
                "Found entry with instruction address 0x{:x} (0x{:x} + 0x{:x}) and {} opcode: {:#?}",
                instruction_address,
                page_entry.first_address(),
                entry.relative_instruction_address(),
                local_or_global,
                opcode
            );
        }
        _ => {}
    }
}
