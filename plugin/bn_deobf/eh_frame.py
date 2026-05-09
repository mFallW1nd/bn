"""Minimal DWARF .eh_frame FDE decoder for BN Deobfuscator.

Walks a binary's `.eh_frame` section and yields `(start, end)` tuples — one per
function — without parsing CFI instructions. ARM64 ELF typically encodes FDE
PC fields as `DW_EH_PE_pcrel | DW_EH_PE_sdata4`; we support that plus a few
adjacent encodings. Unsupported encodings raise; callers should fall back to
BN's own function bounds in that case.

Pure functions: input is a BinaryView, output is `list[tuple[int, int]]`.
No mutations, no logging side effects.
"""

from __future__ import annotations

import struct


# DWARF augmentation pointer encoding constants (from gcc/dwarf2.h).
DW_EH_PE_absptr  = 0x00
DW_EH_PE_uleb128 = 0x01
DW_EH_PE_udata2  = 0x02
DW_EH_PE_udata4  = 0x03
DW_EH_PE_udata8  = 0x04
DW_EH_PE_sleb128 = 0x09
DW_EH_PE_sdata2  = 0x0a
DW_EH_PE_sdata4  = 0x0b
DW_EH_PE_sdata8  = 0x0c

DW_EH_PE_pcrel    = 0x10  # high nibble (offset 0x10)
DW_EH_PE_textrel  = 0x20
DW_EH_PE_datarel  = 0x30
DW_EH_PE_funcrel  = 0x40
DW_EH_PE_aligned  = 0x50

DW_EH_PE_indirect = 0x80
DW_EH_PE_omit     = 0xff


class EhFrameError(Exception):
    """Raised on unsupported encodings or malformed input."""


def _read_uleb128(buf: bytes, off: int) -> tuple[int, int]:
    val = 0
    shift = 0
    while True:
        b = buf[off]
        off += 1
        val |= (b & 0x7f) << shift
        if (b & 0x80) == 0:
            return val, off
        shift += 7


def _read_sleb128(buf: bytes, off: int) -> tuple[int, int]:
    val = 0
    shift = 0
    while True:
        b = buf[off]
        off += 1
        val |= (b & 0x7f) << shift
        shift += 7
        if (b & 0x80) == 0:
            if shift < 64 and (b & 0x40):
                val -= 1 << shift
            return val, off


def _read_encoded(buf: bytes, off: int, enc: int, base_addr: int) -> tuple[int, int]:
    """Decode a value using one DW_EH_PE encoding. base_addr is the runtime
    address of the field being read (for DW_EH_PE_pcrel)."""
    fmt = enc & 0x0f
    rel = enc & 0x70

    if fmt == DW_EH_PE_absptr:
        v = struct.unpack_from("<Q", buf, off)[0]; off += 8
    elif fmt == DW_EH_PE_uleb128:
        v, off = _read_uleb128(buf, off)
    elif fmt == DW_EH_PE_udata2:
        v = struct.unpack_from("<H", buf, off)[0]; off += 2
    elif fmt == DW_EH_PE_udata4:
        v = struct.unpack_from("<I", buf, off)[0]; off += 4
    elif fmt == DW_EH_PE_udata8:
        v = struct.unpack_from("<Q", buf, off)[0]; off += 8
    elif fmt == DW_EH_PE_sleb128:
        v, off = _read_sleb128(buf, off)
    elif fmt == DW_EH_PE_sdata2:
        v = struct.unpack_from("<h", buf, off)[0]; off += 2
    elif fmt == DW_EH_PE_sdata4:
        v = struct.unpack_from("<i", buf, off)[0]; off += 4
    elif fmt == DW_EH_PE_sdata8:
        v = struct.unpack_from("<q", buf, off)[0]; off += 8
    else:
        raise EhFrameError(f"unsupported encoding format 0x{fmt:x}")

    if rel == 0:
        pass
    elif rel == DW_EH_PE_pcrel:
        v = (base_addr + v) & 0xFFFFFFFFFFFFFFFF
    else:
        raise EhFrameError(f"unsupported encoding relation 0x{rel:x}")

    if enc & DW_EH_PE_indirect:
        raise EhFrameError("DW_EH_PE_indirect not supported")
    return v, off


def parse_eh_frame(bv) -> list[tuple[int, int]]:
    """Return [(start, end), ...] for every FDE in `bv.get_section_by_name('.eh_frame')`.

    On unsupported encodings or missing section, returns an empty list. Errors
    inside individual records are swallowed (best-effort): the partial list of
    successfully-decoded ranges is returned.
    """
    sec = bv.get_section_by_name(".eh_frame")
    if sec is None:
        return []

    section_addr = sec.start
    section_size = sec.end - sec.start
    buf = bv.read(section_addr, section_size)
    if not buf or len(buf) < 4:
        return []

    cies: dict[int, int] = {}     # offset_in_section -> fde_pc_encoding
    out: list[tuple[int, int]] = []

    off = 0
    while off + 4 <= len(buf):
        rec_off = off
        length = struct.unpack_from("<I", buf, off)[0]; off += 4
        if length == 0:
            break
        if length == 0xFFFFFFFF:
            return out  # 64-bit length not in libtiny.so; bail with what we have
        rec_end = off + length
        if rec_end > len(buf):
            break

        cie_id = struct.unpack_from("<I", buf, off)[0]; off += 4

        if cie_id == 0:
            # CIE: parse augmentation 'R' to extract FDE PC encoding.
            try:
                fde_enc = _parse_cie_fde_encoding(buf, off, rec_end)
            except Exception:
                fde_enc = None
            if fde_enc is not None:
                cies[rec_off] = fde_enc
        else:
            # FDE: cie_id is offset back to the CIE.
            cie_off = (off - 4) - cie_id
            fde_enc = cies.get(cie_off)
            if fde_enc is not None:
                try:
                    pc_addr_field = section_addr + off
                    pc_begin, off2 = _read_encoded(buf, off, fde_enc, pc_addr_field)
                    # pc_range uses the same encoding minus the relation high nibble.
                    range_enc = fde_enc & 0x0f
                    pc_range, _ = _read_encoded(buf, off2, range_enc, 0)
                    if pc_range > 0:
                        out.append((pc_begin, pc_begin + pc_range))
                except Exception:
                    pass

        off = rec_end

    out.sort()
    return out


def _parse_cie_fde_encoding(buf: bytes, off: int, end: int) -> int | None:
    """Extract the FDE PC encoding ('R' field) from a CIE header.

    Returns the encoding byte, or None if the CIE has no 'R' augmentation.
    Only handles 'z[PLR]' style augmentation strings — the common case.
    """
    # version
    version = buf[off]; off += 1
    if version not in (1, 3, 4):
        return None
    # augmentation string (NUL-terminated)
    aug_start = off
    while off < end and buf[off] != 0:
        off += 1
    if off >= end:
        return None
    aug = buf[aug_start:off].decode("ascii", errors="replace")
    off += 1   # skip NUL
    if not aug.startswith("z"):
        return None

    # code_alignment_factor (uleb128)
    _, off = _read_uleb128(buf, off)
    # data_alignment_factor (sleb128)
    _, off = _read_sleb128(buf, off)
    # return_address_register: uleb128 in v3+, single byte in v1
    if version == 1:
        off += 1
    else:
        _, off = _read_uleb128(buf, off)

    # augmentation_data length (uleb128)
    aug_len, off = _read_uleb128(buf, off)
    aug_data_end = off + aug_len

    fde_enc = None
    for ch in aug[1:]:                         # skip leading 'z'
        if ch == "P":
            if off >= aug_data_end:
                return None
            personality_enc = buf[off]; off += 1
            try:
                _, off = _read_encoded(buf, off, personality_enc, 0)
            except Exception:
                return None
        elif ch == "L":
            off += 1                            # one-byte LSDA encoding
        elif ch == "R":
            if off >= aug_data_end:
                return None
            fde_enc = buf[off]; off += 1
        else:
            # unknown augmentation — bail out
            return None

    return fde_enc
