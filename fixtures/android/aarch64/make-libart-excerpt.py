#!/usr/bin/env python3
"""Build the libart-excerpt.eh_frame and libart-excerpt.eh_frame_hdr fixtures.

The input is libart.so from the ART mainline module on a Pixel 6, whose
.eh_frame is at 0xd3d00 and .eh_frame_hdr at 0xb32b0. The fixture keeps these
addresses and contains only the CIE and the FDEs covering the given pcs. The
FDEs' CIE pointers and pc-relative pc_begin fields are rewritten for their new
offsets, and .eh_frame_hdr is regenerated.

The fixtures in this directory were made with:

    make-libart-excerpt.py libart.so . 41e98c 73f000 74e77c 765580
"""

import struct
import sys

EH_FRAME_ADDR = 0xD3D00
EH_FRAME_HDR_ADDR = 0xB32B0


def read_section(data, name):
    """Returns (address, contents) of the named section of a little-endian ELF64 file."""
    assert data[:6] == b"\x7fELF\x02\x01", "not a little-endian ELF64 file"
    (shoff,) = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)

    def header(i):
        return struct.unpack_from("<IIQQQQ", data, shoff + i * shentsize)

    strtab_off = header(shstrndx)[4]
    for i in range(shnum):
        sh_name, _, _, addr, offset, size = header(i)
        end = data.index(b"\0", strtab_off + sh_name)
        if data[strtab_off + sh_name : end] == name:
            return addr, data[offset : offset + size]
    raise ValueError(f"no {name} section")


def records(eh_frame):
    off = 0
    while off + 4 <= len(eh_frame):
        (length,) = struct.unpack_from("<I", eh_frame, off)
        if length == 0:
            break
        assert length != 0xFFFFFFFF, "DWARF64 not supported"
        (cie_ptr,) = struct.unpack_from("<I", eh_frame, off + 4)
        yield off, length + 4, cie_ptr
        off += length + 4


def fde_pc_range(eh_frame, off):
    (pc_rel, pc_len) = struct.unpack_from("<iI", eh_frame, off + 8)
    pc_begin = EH_FRAME_ADDR + off + 8 + pc_rel
    return pc_begin, pc_begin + pc_len


def main():
    if len(sys.argv) < 4:
        sys.exit(f"usage: {sys.argv[0]} <libart.so> <out-dir> <hex pc>...")
    lib, out_dir, *pcs = sys.argv[1:]
    pcs = [int(pc, 16) for pc in pcs]
    data = open(lib, "rb").read()
    eh_frame_addr, eh_frame = read_section(data, b".eh_frame")
    eh_frame_hdr_addr, _ = read_section(data, b".eh_frame_hdr")
    assert (eh_frame_addr, eh_frame_hdr_addr) == (EH_FRAME_ADDR, EH_FRAME_HDR_ADDR), (
        "unexpected section addresses; is this the right libart.so?"
    )

    cie_off = None
    fdes = []
    for off, size, cie_ptr in records(eh_frame):
        if cie_ptr == 0:
            continue
        lo, hi = fde_pc_range(eh_frame, off)
        if any(lo <= pc < hi for pc in pcs):
            this_cie = off + 4 - cie_ptr
            assert cie_off in (None, this_cie), "FDEs with different CIEs"
            cie_off = this_cie
            fdes.append((lo, off, size))
    assert len(fdes) == len(pcs), f"found {len(fdes)} FDEs for {len(pcs)} pcs"
    fdes.sort()

    (cie_len,) = struct.unpack_from("<I", eh_frame, cie_off)
    out = bytearray(eh_frame[cie_off : cie_off + cie_len + 4])
    table = []
    for lo, off, size in fdes:
        new_off = len(out)
        rec = bytearray(eh_frame[off : off + size])
        struct.pack_into("<I", rec, 4, new_off + 4)
        struct.pack_into("<i", rec, 8, lo - (EH_FRAME_ADDR + new_off + 8))
        out += rec
        table.append((lo, EH_FRAME_ADDR + new_off))
    out += b"\0\0\0\0"

    hdr = bytearray(b"\x01\x1b\x03\x3b")
    hdr += struct.pack("<i", EH_FRAME_ADDR - (EH_FRAME_HDR_ADDR + 4))
    hdr += struct.pack("<I", len(table))
    for pc, fde_addr in table:
        hdr += struct.pack("<ii", pc - EH_FRAME_HDR_ADDR, fde_addr - EH_FRAME_HDR_ADDR)

    open(f"{out_dir}/libart-excerpt.eh_frame", "wb").write(out)
    open(f"{out_dir}/libart-excerpt.eh_frame_hdr", "wb").write(hdr)
    for lo, off, size in fdes:
        print(f"FDE pc {lo:#x} (original offset {off:#x}, {size:#x} bytes)")
    print(f".eh_frame: {len(out):#x} bytes, .eh_frame_hdr: {len(hdr):#x} bytes")


if __name__ == "__main__":
    main()
