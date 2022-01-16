use std::{fs::File, io::Read};

use object::ObjectSection;
use rul::compact_unwind_info::{
    Arm64Opcode, CompactUnwindInfoHeader, CompressedEntryBitfield, OpcodeBitfield,
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
        let page_start_offset = page.page_offset();
        if page.is_regular_page(data).unwrap() {
            let page = page.parse_regular_page(data).unwrap();
            let entries = page.entries(data, page_start_offset).unwrap();
            println!(
                "{:08x} Regular page with {} entries",
                first_address,
                entries.len()
            );
            for entry in entries {
                let instruction_address = entry.instruction_address();
                let opcode = entry.opcode();
                match Arm64Opcode::try_from(&opcode) {
                    Ok(opcode) => println!("{:08x} {}", instruction_address, opcode),
                    Err(_) => println!("{:08x} with unknown opcode kind", instruction_address),
                }
            }
            println!();
        } else {
            let page = page.parse_compressed_page(data).unwrap();
            let entries = page.entries(data, page_start_offset).unwrap();
            let local_opcodes = page.local_opcodes(data, page_start_offset).unwrap();
            println!(
                "{:08x} Compressed page with {} entries and {} local opcodes",
                first_address,
                entries.len(),
                local_opcodes.len()
            );
            for entry in entries {
                let entry = CompressedEntryBitfield::from(entry);
                let instruction_address = first_address + entry.relative_instruction_address();
                let opcode_index = entry.opcode_index() as usize;
                let opcode = if opcode_index < global_opcode_count {
                    &global_opcodes[opcode_index]
                } else {
                    &local_opcodes[opcode_index - global_opcode_count]
                };
                let opcode = OpcodeBitfield::from(opcode);
                match Arm64Opcode::try_from(&opcode) {
                    Ok(opcode) => println!("{:08x} {}", instruction_address, opcode),
                    Err(_) => println!("{:08x} with unknown opcode kind", instruction_address),
                }
            }
            println!();
        }
    }
}
