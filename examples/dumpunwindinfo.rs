use std::{fs::File, io::Read};

use object::ObjectSection;
use rul::compact_unwind_info::{
    OpcodeArm64, CompactUnwindInfoHeader, CompressedEntryBitfield, CompressedPage, OpcodeBitfield,
    RegularPage, PAGE_KIND_COMPRESSED, PAGE_KIND_REGULAR,
};

fn main() {
    let mut args = std::env::args_os().skip(1);
    if args.len() < 1 {
        eprintln!("Usage: {} <path>", std::env::args().next().unwrap());
        std::process::exit(1);
    }
    let path = args.next().unwrap();

    let mut data = Vec::new();
    let mut file = File::open(path).unwrap();
    file.read_to_end(&mut data).unwrap();
    let data = &data[..];

    let file = object::File::parse(data).expect("Could not parse object file");
    use object::Object;
    let unwind_info_data_section = file
        .section_by_name_bytes(b"__unwind_info")
        .expect("Could not find __unwind_info section");
    let data = unwind_info_data_section.data().unwrap();

    let header = CompactUnwindInfoHeader::parse(data).unwrap();
    let global_opcodes = header.global_opcodes(data).unwrap();
    let global_opcode_count = global_opcodes.len();
    let pages = header.pages(data).unwrap();
    println!(
        "Compact unwind info with {} pages and {} global opcodes",
        pages.len(),
        global_opcodes.len()
    );
    println!();
    for page in pages {
        let first_address = page.first_address();
        let page_offset = page.page_offset();
        match page.page_kind(data).unwrap() {
            PAGE_KIND_REGULAR => {
                let page = RegularPage::parse(data, page_offset.into()).unwrap();
                let entries = page.entries(data, page_offset).unwrap();
                println!(
                    "0x{:08x}: Regular page with {} entries",
                    first_address,
                    entries.len()
                );
                for entry in entries {
                    print_entry(entry.instruction_address(), entry.opcode());
                }
                println!();
            }
            PAGE_KIND_COMPRESSED => {
                let page = CompressedPage::parse(data, page_offset.into()).unwrap();
                let entries = page.entries(data, page_offset).unwrap();
                let local_opcodes = page.local_opcodes(data, page_offset).unwrap();
                println!(
                    "0x{:08x}: Compressed page with {} entries and {} local opcodes",
                    first_address,
                    entries.len(),
                    local_opcodes.len()
                );
                for entry in entries {
                    let entry = CompressedEntryBitfield::new((*entry).into());
                    let instruction_address = first_address + entry.relative_instruction_address();
                    let opcode_index = entry.opcode_index() as usize;
                    let opcode: u32 = if opcode_index < global_opcode_count {
                        global_opcodes[opcode_index].into()
                    } else {
                        local_opcodes[opcode_index - global_opcode_count].into()
                    };
                    print_entry(instruction_address, opcode);
                }
                println!();
            }
            _ => {}
        }
    }
}

fn print_entry(instruction_address: u32, opcode: u32) {
    let opcode = OpcodeBitfield::new(opcode);
    match OpcodeArm64::parse(&opcode) {
        Some(opcode) => println!("  0x{:08x}: {}", instruction_address, opcode),
        None => println!(
            "  0x{:08x}: unknown opcode kind {}",
            instruction_address,
            opcode.kind()
        ),
    }
}
