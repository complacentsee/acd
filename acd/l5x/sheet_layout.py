"""Per-routine FBD/SFC sheet size + orientation.

Studio (V31+) stores a graphical routine's sheet size and orientation as two
attribute records in ``Comments.Dat`` -- ``SHEETSIZE`` (a paper-size index) and
``SHEETLAYOUT`` (an orientation flag) -- NOT as the display string and NOT in
the routine's own comps/nameless records. The comments parser does not ingest
these (they carry no text), so they are parsed here directly from the stream.

Record layout (little-endian), located by the UTF-16 attribute name:
  fafa | len u32 | id u32 | .. | 68 00 | prog_key u32@0x12 | rkey u16@0x16 |
  .. | 00 24 name_len | <name utf16> | .. c4 00 00 00 (DINT) .. | value u32 @ end

``value`` is the ms_sizeList index for SHEETSIZE and the orientation flag for
SHEETLAYOUT; ``0xFFFFFFFF`` means "unset" -> the Studio default (Letter/
Landscape). The record's owner is the pair (program, routine): ``prog_key``'s
low 16 bits equal every routine's ``comment_id`` (shared program id) and
``rkey`` equals the u16 at the routine comps record offset 0x10 (the per-routine
id). Matching on the pair is required -- ``rkey`` alone collides across programs.

Older files (V16..V30) predate this mechanism and carry no such records; the
lookup returns None for them and the caller falls back to fail-closed behaviour.
"""
import struct
from typing import Dict, Optional, Tuple

_FAFA = b"\xfa\xfa"
_UNSET = 0xFFFFFFFF

# ms_sizeList order from RxSheetLayout (Services.DLL). Corpus-witnessed:
# 0/1/2/4/7; 3/5/6 (A/C/D) are from the same ordered table.
INDEX_TO_SIZE = {
    0: "Letter - 8.5 x 11 in",
    1: "Legal - 8.5 x 14 in",
    2: "Tabloid - 11 x 17 in",
    3: "A - 8.5 x 11 in",
    4: "B - 11 x 17 in",
    5: "C - 17 x 22 in",
    6: "D - 22 x 34 in",
    7: "E - 34 x 44 in",
}
ORIENT_TO_STR = {0: "Landscape", 1: "Portrait"}

# Routine per-routine id: u16 at this comps-record offset (the value Studio also
# echoes into the SHEETSIZE/SHEETLAYOUT record's rkey field).
_ROUTINE_KEY_OFF = 0x10


def _parse_named(dat: bytes, name: str) -> Dict[Tuple[int, int], int]:
    """(prog_key_lo16, rkey) -> value, for every record carrying ``name``."""
    out: Dict[Tuple[int, int], int] = {}
    needle = name.encode("utf-16-le")
    pos = 0
    while True:
        i = dat.find(needle, pos)
        if i < 0:
            break
        pos = i + 1
        start = dat.rfind(_FAFA, 0, i)
        end = dat.find(_FAFA, i + len(needle))
        if start < 0:
            continue
        rec = dat[start:end] if end > 0 else dat[start:]
        if len(rec) < 0x1A:
            continue
        prog = struct.unpack_from("<I", rec, 0x12)[0] & 0xFFFF
        rkey = struct.unpack_from("<H", rec, 0x16)[0]
        value = struct.unpack_from("<I", rec, len(rec) - 4)[0]
        out[(prog, rkey)] = value
    return out


def build_sheet_layout_rows(comments_dat: bytes):
    """Rows ``(prog, rkey, size_index, orient)`` for the ``sheet_layout`` table.

    One row per routine that owns a SHEETSIZE record; the ``0xFFFFFFFF`` unset
    sentinel is normalised to 0 (the Studio default) here so the table always
    holds a concrete index/orientation.
    """
    sizes = _parse_named(comments_dat, "SHEETSIZE")
    orients = _parse_named(comments_dat, "SHEETLAYOUT")
    rows = []
    for (prog, rkey), si in sizes.items():
        oi = orients.get((prog, rkey), 0)
        si = 0 if si == _UNSET else si
        oi = 0 if oi == _UNSET else oi
        rows.append((prog, rkey, si, oi))
    return rows


def sheet_size_of(cur, comment_id: int,
                  routine_record: bytes) -> Optional[Tuple[str, str]]:
    """Resolve (size, orientation) strings for one routine from the DB, or None.

    None means no record for this routine (an older, pre-V31 file) OR an index
    outside the known table -- both fail closed, so the caller emits nothing
    rather than a guessed sheet.
    """
    if len(routine_record) < _ROUTINE_KEY_OFF + 2:
        return None
    rkey = struct.unpack_from("<H", routine_record, _ROUTINE_KEY_OFF)[0]
    row = cur.execute(
        "SELECT size_index, orient FROM sheet_layout WHERE prog=? AND rkey=?",
        (comment_id & 0xFFFF, rkey)).fetchone()
    if row is None:
        return None
    size = INDEX_TO_SIZE.get(row[0])
    orient = ORIENT_TO_STR.get(row[1])
    if size is None or orient is None:
        return None
    return size, orient
