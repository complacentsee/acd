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

Pre-V31 files (V16..V30 witnessed on V16/V20/V24) store the sheet through a
hidden per-routine TAG instead: the routine's ``disc`` field (u16 @ body 0x10,
the same per-routine id V31+ echoes into its SHEETSIZE record) names a
program-scoped tag ``__SL<disc>`` whose main_record[0x24] data_table_instance
points at a cip-0x6a ``$hash$`` backing; that backing's ext attr 0x66 value is
``index u32 | orient u32``. ``_sl_chain_lookup`` follows the chain with the
standard attr-table walk (``CompsRecord.read_value_attrs``), so a coincidental
attr-id byte pattern inside element data can never be misread as the size.

V21 uses a different mechanism: it AES-encrypts the whole comps database with the
standard config-5 key (transparent, not user source protection), and stores each
FBD routine's sheet in a per-program ``RxDataCollection`` record whose decrypted
body carries attribute id ``0x66`` = ``(index u32, orient u32)``. ``build_
v21_sheet_rows`` decrypts and harvests those, keyed by the record's program id
(comps ``kind`` == program ``comment_id``). Because that key is the program, not
the routine, the size is applied only when a program maps to exactly ONE such
record (one FBD routine) -- a program with several FBD routines is ambiguous and
falls back to fail-closed. (A V21 routine DOES have a plaintext-named
``__SL<disc>`` tag, but its data_table_instance is the 0xFFFFFFFF sentinel --
the chain returns None there and defers to the V21 table.)
"""
import struct
from typing import Dict, Optional, Tuple

from acd.record.comps import (CompsRecord, _SP_KEY_BY_CONFIG, _sp_aes,
                              _sp_cbc)

_FAFA = b"\xfa\xfa"
_UNSET = 0xFFFFFFFF
_SP_MARK = b"\xaa\x96\xaa\x0a"
# Attribute id 0x66 (len 0x10) inside a decrypted V21 sheet record; its value's
# first two u32s are the size index and orientation.
_V21_SIZE_ATTR = b"\x66\x00\x00\x00\x10\x00\x00\x00"

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


def _decrypt_sp_tail(rec: bytes) -> Optional[bytes]:
    """Decrypt a config-5 SP-framed comps record's tail, or None. PKCS7-checked."""
    mi = rec.find(_SP_MARK)
    if mi < 0 or mi + 18 > len(rec):
        return None
    declared = struct.unpack_from("<I", rec, mi + 12)[0]
    config = rec[mi + 17]
    if config not in _SP_KEY_BY_CONFIG:
        return None
    ct_len = declared + 16 - declared % 16
    ct = rec[mi + 18:mi + 18 + ct_len]
    if len(ct) != ct_len or ct_len % 16:
        return None
    try:
        pt = _sp_cbc(ct, _sp_aes(config, _SP_KEY_BY_CONFIG[config]), ct_len // 16)
    except Exception:  # noqa: BLE001
        return None
    pad = pt[-1] if pt else 0
    if not (1 <= pad <= 16) or pt[-pad:] != bytes([pad]) * pad:
        return None
    return pt[:-pad]


def build_v21_sheet_rows(cur):
    """Rows ``(cid, size_index, orient)`` from V21 encrypted per-program sheet
    records (one per FBD routine). Decrypts every ``RxDataCollection`` child that
    is config-5 SP-framed and carries the attr-0x66 size value; the row key is the
    program id (comps ``kind`` == program ``comment_id``). Empty on non-V21 files
    (they have no SP-framed records).
    """
    rows = []
    for (rr,) in cur.execute(
            "SELECT record FROM comps WHERE parent_id IN "
            "(SELECT object_id FROM comps WHERE comp_name='RxDataCollection')"):
        rec = bytes(rr)
        if len(rec) < 18:
            continue
        body = _decrypt_sp_tail(rec)
        if body is None:
            continue
        j = body.rfind(_V21_SIZE_ATTR)
        if j < 0 or j + 16 > len(body):
            continue
        idx = struct.unpack_from("<I", body, j + 8)[0]
        ori = struct.unpack_from("<I", body, j + 12)[0]
        if idx >= 13 or ori >= 2:
            continue
        cid = struct.unpack_from("<H", rec, 16)[0]
        rows.append((cid, idx, ori))
    return rows


def _sl_chain_lookup(cur, comment_id: int,
                     disc: int) -> Optional[Tuple[int, int]]:
    """Pre-V31 (size_index, orient) via the hidden ``__SL<disc>`` tag, or None.

    The tag is matched on its exact name AND its owning program's comment_id
    (u16 @ body 0x0c) -- the name alone can collide across programs. Exactly one
    live candidate is required; its main_record[0x24] data_table_instance names
    the cip-0x6a backing whose attr-0x66 value is ``index u32 | orient u32``.
    Any break in the chain returns None (fail closed). Deleted-relic rows
    (no FAFA-family record) are excluded so a stale tag from a removed routine
    can never shadow the live one.
    """
    try:
        # The hidden sheet tag names the discriminator either in decimal
        # (__SL42620) or zero-padded hex (__SL0000a67c); query both spellings.
        # The comment_id + single-candidate gates below keep the resolution
        # unambiguous, and the '0000'-prefixed hex form cannot collide with a
        # decimal spelling of the same disc.
        rows = cur.execute(
            "SELECT object_id, record FROM comps WHERE comp_name IN (?, ?)",
            ("__SL%d" % disc, "__SL%08x" % disc)).fetchall()
    except Exception:  # noqa: BLE001
        return None
    if not rows:
        return None
    try:
        dead = CompsRecord.dead_oids(cur, True)
    except Exception:  # noqa: BLE001
        dead = frozenset()
    cands = []
    for oid, rr in rows:
        if rr is None or oid in dead:
            continue
        rec = bytes(rr)
        if len(rec) < 74:
            continue
        if struct.unpack_from("<H", rec, 0x0c)[0] != comment_id & 0xFFFF:
            continue
        cands.append(rec)
    if len(cands) != 1:
        return None
    dti = struct.unpack_from("<I", cands[0], 14 + 0x24)[0]
    if dti in (0, 0xFFFFFFFF):
        return None
    brow = cur.execute(
        "SELECT record FROM comps WHERE object_id=?", (dti,)).fetchone()
    if brow is None or brow[0] is None:
        return None
    attrs = CompsRecord.read_value_attrs(bytes(brow[0]), True, body_mode=True)
    val = attrs.get(0x66)
    if val is None or len(val) < 8:
        return None
    return (struct.unpack_from("<I", val, 0)[0],
            struct.unpack_from("<I", val, 4)[0])


def sheet_size_of(cur, comment_id: int,
                  routine_record: bytes) -> Optional[Tuple[str, str]]:
    """Resolve (size, orientation) strings for one routine from the DB, or None.

    Tries the V31+ ``sheet_layout`` table (keyed by program+routine id), then the
    pre-V31 ``__SL<disc>`` hidden-tag chain, then the V21 ``sheet_layout_v21``
    table (keyed by program id, applied only when that program owns exactly one
    sheet record). None -- no record, an ambiguous program, or an index outside
    the known table -- fails closed, so the caller emits nothing rather than a
    guessed sheet.
    """
    if len(routine_record) < _ROUTINE_KEY_OFF + 2:
        return None
    rkey = struct.unpack_from("<H", routine_record, _ROUTINE_KEY_OFF)[0]
    row = cur.execute(
        "SELECT size_index, orient FROM sheet_layout WHERE prog=? AND rkey=?",
        (comment_id & 0xFFFF, rkey)).fetchone()
    if row is None:
        row = _sl_chain_lookup(cur, comment_id, rkey)
    if row is None:
        v21 = cur.execute(
            "SELECT size_index, orient FROM sheet_layout_v21 WHERE cid=?",
            (comment_id & 0xFFFF,)).fetchall()
        if len(v21) != 1:   # 0 = not V21; >1 = ambiguous program, fail closed
            return None
        row = v21[0]
    size = INDEX_TO_SIZE.get(row[0])
    orient = ORIENT_TO_STR.get(row[1])
    if size is None or orient is None:
        return None
    return size, orient
