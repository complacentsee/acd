"""Decode an FBD (Function Block Diagram) routine's graphical content.

An FBD routine's sheet -- blocks, IRef/ORef references, wires, attachments and
their user-placed X/Y coordinates -- is stored in the routine's ``nameless``
subtree (the same storage ST/SFC use): a container -> region -> Sheet tree whose
element records carry a u16 ``kind`` discriminator, coordinates as u32 X/Y at a
header-dependent base, and operands through the shared ``@<hex>@`` -> comps
name resolution. ``decode_fbd`` walks it and renders ``<FBDContent>``; the sheet
size/orientation are supplied by the caller (from acd.l5x.sheet_layout).

Fully fail-closed: an untabled block kind, an unresolved operand, a duplicate
element key, a wire/attachment referencing an unknown element, a textbox with no
resolved text, or a missing sheet size all return None, so the routine keeps its
empty ``<Routine>`` (element_missing) rather than emit a wrong or partial sheet.
"""
import struct
import re
from xml.sax.saxutils import quoteattr

from acd.record.source_protection import sp_decrypt_nameless_element

IREF, OREF, TEXTBOX, WIRE, ATTACH = 0x0e, 0x0d, 0x81, 0x11, 0x88
# On-sheet AOI call, wire connectors and the connector-name record they point at
AOICALL, ICON, OCON, CONNNAME = 0x8a, 0x0f, 0x10, 0x71
# The AOI call's optional empty property child
AOIPROP = 0x9c7
SHEET, ELEMGROUP, WIREGROUP, TBGROUP, ATGROUP = 0x03, 0x07, 0x09, 0x83, 0x87

KIND2TYPE = {
    0x0a: 'ADD', 0x13: 'SCL', 0x14: 'ALM', 0x15: 'SEL', 0x19: 'HLL',
    0x1d: 'SRTP', 0x21: 'BAND', 0x22: 'BOR', 0x24: 'BNOT', 0x26: 'LPF',
    0x2e: 'SSUM', 0x39: 'RLIM', 0x3a: 'DERV', 0x3b: 'MINC', 0x3d: 'OSRI',
    0x44: 'RAD', 0x48: 'ABS', 0x4d: 'COS', 0x4f: 'DIV', 0x52: 'MUL',
    0x55: 'SUB', 0x5b: 'TONR', 0x5c: 'EQU', 0x5d: 'GEQ', 0x5e: 'GRT',
    0x5f: 'LEQ', 0x63: 'NEQ',
    # pin-space types: wide datatype-derived mask, not the VISIBLE_PIN_BITS u32
    0x0b: 'TOT', 0x1b: 'PIDE', 0x29: 'PI', 0x58: 'CTUD',
    0x18: 'FGEN', 0x1a: 'MAVE',
}
PIDE_KIND = 0x1b
# Array-parameter block types: the block owns one kind-0x77 group of kind-0x75
# array records ([operand fffeff][name fffeff] each), rendered as <Array>
# children. Each array parameter also occupies one pin slot after the output
# collector, so the datatype pinmap shifts by the instance's array count.
ARRAY_TYPES = {'FGEN', 'MAVE'}
ARRAY_GROUP, ARRAY_ELEM = 0x77, 0x75

# Pin-space FBD block types: their VisiblePins mask is a WIDE little-endian bit
# array (base+9, or the PIDE prelude-keyed offset below), not the u32 at base+8
# that VISIBLE_PIN_BITS decodes. Unlike the simpler blocks, their pin NAMES are
# NOT tabled -- they are DERIVED from the block's own datatype member list in the
# ACD (TagInfo/Comps), so the ~40-pin PIDE vocabulary and the PI/CTUD/TOT maps
# come straight from the project. See _pins_from_mask / _datatype_pinmap.
PINSPACE_TYPES = {'CTUD', 'PI', 'PIDE', 'TOT', 'FGEN', 'MAVE'}
# Read-window bytes for the wide mask -- a generous upper bound. Trailing bytes
# past the real mask are zero, and a set bit with no datatype member fails
# closed, so an over-wide window only adds safety.
PIN_MASK_BYTES = {'CTUD': 8, 'PI': 8, 'TOT': 8, 'PIDE': 24, 'FGEN': 8, 'MAVE': 8}
# Hidden 'ulBoolInput<n>' input bit-collector members: the SECOND and later ones
# each reserve one firmware pin slot ahead of the following pins (the only
# structural "phantom" in the Logix FB pin numbering; the first collector and all
# output collectors reserve nothing). This is a read over member NAMES -- a
# derivation, not a per-type value. PIN_ULINPUT.match(name).group(1) -> n.
PIN_ULINPUT = re.compile(r"^ulBoolInput(\d+)$")
# PIDE's mask offset from base depends on the record generation, read off the
# structure itself: the fixed prelude length = offset of the operand string
# marker. V16-era records (prelude 48) start the mask at +12; the V20+/V31+
# shape (prelude 76/80) at +9. Any other prelude is an unknown layout ->
# fail closed.
_PIDE_MASK_DELTA_BY_PRELUDE = {48: 12, 76: 9, 80: 9}
# MAVE/FGEN use the same prelude-keyed scheme (relative to their effective
# base, after MAVE's extra leading word); only the 76/80 shapes are corpus-
# attested for them, so the V16 shape fails closed until evidenced.
_ARRAY_MASK_DELTA_BY_PRELUDE = {76: 9, 80: 9}

VISIBLE_PIN_BITS = {
    'ABS': {10: 'Source', 12: 'Dest'},
    'ADD': {10: 'SourceA', 11: 'SourceB', 13: 'Dest'},
    'ALM': {11: 'In', 13: 'HLimit', 14: 'LLimit', 22: 'HHAlarm', 23: 'HAlarm', 24: 'LAlarm', 25: 'LLAlarm'},
    'BAND': {11: 'In1', 12: 'In2', 13: 'In3', 21: 'Out'},
    'BNOT': {11: 'In', 14: 'Out'},
    'BOR': {11: 'In1', 12: 'In2', 13: 'In3', 14: 'In4', 15: 'In5', 21: 'Out'},
    'COS': {10: 'Source', 12: 'Dest'},
    'DERV': {11: 'In', 13: 'ByPass', 20: 'Out'},
    'DIV': {10: 'SourceA', 11: 'SourceB', 13: 'Dest'},
    # EQU shares the comparison-block pin layout (EnableIn@9, SourceA@10,
    # SourceB@11, Dest@13); EnableIn is corpus-attested for the GEQ/LEQ siblings.
    'EQU': {9: 'EnableIn', 10: 'SourceA', 11: 'SourceB', 13: 'Dest'},
    'GEQ': {9: 'EnableIn', 10: 'SourceA', 11: 'SourceB', 13: 'Dest'},
    'GRT': {10: 'SourceA', 11: 'SourceB', 13: 'Dest'},
    'HLL': {11: 'In', 12: 'HighLimit', 13: 'LowLimit', 17: 'Out'},
    'LEQ': {9: 'EnableIn', 10: 'SourceA', 11: 'SourceB', 13: 'Dest'},
    'LPF': {11: 'In', 21: 'Out'},
    'MINC': {11: 'In', 12: 'Reset', 16: 'Out'},
    'MUL': {10: 'SourceA', 11: 'SourceB', 13: 'Dest'},
    'NEQ': {10: 'SourceA', 11: 'SourceB', 13: 'Dest'},
    'OSRI': {11: 'InputBit', 14: 'OutputBit'},
    'RAD': {10: 'Source', 12: 'Dest'},
    'RLIM': {11: 'In', 14: 'ByPass', 21: 'Out'},
    'SCL': {9: 'EnableIn', 11: 'In', 12: 'InRawMax', 13: 'InRawMin', 14: 'InEUMax', 15: 'InEUMin', 16: 'Limiting', 19: 'Out'},
    'SEL': {9: 'EnableIn', 11: 'In1', 12: 'In2', 13: 'SelectorIn', 16: 'Out'},
    'SRTP': {9: 'EnableIn', 11: 'In', 12: 'CycleTime', 17: 'MaxHeatTime', 18: 'MinHeatTime', 21: 'EnableOut', 23: 'HeatOut', 25: 'HeatTimePercent'},
    'SSUM': {3: 'In1', 5: 'Select1', 6: 'In2', 8: 'Select2', 9: 'In3', 11: 'Select3', 12: 'In4', 14: 'Select4', 15: 'In5', 17: 'Select5', 18: 'In6', 20: 'Select6', 21: 'In7', 23: 'Select7', 24: 'In8', 26: 'Select8', 30: 'Out'},
    'SUB': {10: 'SourceA', 11: 'SourceB', 13: 'Dest'},
    'TONR': {11: 'TimerEnable', 12: 'PRE', 13: 'Reset', 16: 'ACC', 19: 'DN'},
}
MASK_DELTA = {'SSUM': 9}
FAM_OK = {'SSUM': {'S'}}

WIRE_PARAM = {
    'ADD:L': {2: 'SourceA', 3: 'SourceB', 5: 'Dest'},
    'ADD:S': {2: 'SourceA', 3: 'SourceB', 5: 'Dest'},
    'BAND:L': {3: 'In1', 4: 'In2', 13: 'Out'},
    'BAND:S': {3: 'In1', 4: 'In2', 5: 'In3', 13: 'Out'},
    'BNOT:L': {3: 'In', 6: 'Out'}, 'BNOT:S': {3: 'In', 6: 'Out'},
    'BOR:L': {3: 'In1', 4: 'In2', 13: 'Out'}, 'BOR:S': {3: 'In1', 4: 'In2', 13: 'Out'},
    'DIV:S': {2: 'SourceA', 3: 'SourceB', 5: 'Dest'},
    'GEQ:L': {1: 'EnableIn', 2: 'SourceA', 3: 'SourceB', 5: 'Dest'},
    'GRT:S': {2: 'SourceA', 3: 'SourceB', 5: 'Dest'},
    'LEQ:L': {1: 'EnableIn', 2: 'SourceA', 3: 'SourceB', 5: 'Dest'},
    'LEQ:S': {2: 'SourceA', 3: 'SourceB', 5: 'Dest'},
    'MUL:L': {2: 'SourceA', 5: 'Dest'},
    'NEQ:L': {2: 'SourceA', 3: 'SourceB', 5: 'Dest'},
    'SCL:L': {3: 'In', 4: 'InRawMax', 5: 'InRawMin', 6: 'InEUMax', 7: 'InEUMin', 8: 'Limiting', 11: 'Out'},
    'SCL:S': {3: 'In', 4: 'InRawMax', 6: 'InEUMax', 11: 'Out'},
    'SEL:L': {3: 'In1', 4: 'In2', 5: 'SelectorIn', 8: 'Out'},
    'SEL:S': {3: 'In1', 5: 'SelectorIn', 8: 'Out'},
    'SRTP:S': {1: 'EnableIn', 3: 'In', 10: 'MinHeatTime', 13: 'EnableOut', 15: 'HeatOut'},
    'SSUM:S': {3: 'In1', 5: 'Select1', 6: 'In2', 8: 'Select2', 9: 'In3', 11: 'Select3', 12: 'In4', 14: 'Select4', 15: 'In5', 17: 'Select5', 18: 'In6', 20: 'Select6', 21: 'In7', 23: 'Select7', 24: 'In8', 26: 'Select8', 30: 'Out'},
    # legacy pairs observed in the corpus wire evidence
    'ABS:L': {2: 'Source', 4: 'Dest'},
    'DERV:L': {3: 'In', 5: 'ByPass', 12: 'Out'},
    'DIV:L': {2: 'SourceA', 3: 'SourceB', 5: 'Dest'},
    'LPF:L': {3: 'In', 13: 'Out'},
    'SUB:L': {2: 'SourceA', 3: 'SourceB', 5: 'Dest'},
}
# NB: pin-space types (PIDE/PI/CTUD/TOT) are NOT in WIRE_PARAM -- their wire
# param names are derived from the block's datatype pinmap (a wire index is a
# pin bit), the same source as VisiblePins. See _wparam in _decode.

TYPE_RANK = {'IRef': 0, 'ORef': 1, 'ICon': 2, 'OCon': 3, 'Block': 4,
             'AddOnInstruction': 5, 'TextBox': 6}
_TOK = re.compile(r"@([0-9a-fA-F]+)@")
_AMP = re.compile(r"^&([0-9a-fA-F]+)(.*)$")


def _kind(r):
    return struct.unpack_from("<H", r, 16)[0] if len(r) >= 18 else -1


def _operand_oid(er):
    """object_id of the block operand's base tag (its first @<hex>@ token)."""
    txt = _rawtext(er)
    if not txt:
        return None
    m = _TOK.search(txt)
    return int(m.group(1), 16) if m else None


def _block_datatype(cur, operand_oid, operand_name):
    """DataType name for a pin-space block operand, or None (fail closed).

    Prefer the operand's OWN comps record (a unique object_id -- no cross-scope
    name collision): its DataType OID at record offset 0x2A resolves to the
    datatype's comp_name. Fall back to the tag_datatype map by base name when the
    record is too short to carry 0x2A (some V36 tags), and there fail closed if
    the name is ambiguous (maps to more than one datatype).
    """
    if operand_oid is not None:
        row = cur.execute("SELECT record FROM comps WHERE object_id=?",
                          (operand_oid,)).fetchone()
        if row and row[0] is not None:
            rb = bytes(row[0])
            if len(rb) >= 0x2E:
                dt_oid = struct.unpack_from("<I", rb, 0x2A)[0]
                r2 = cur.execute(
                    "SELECT comp_name FROM comps WHERE object_id=?",
                    (dt_oid,)).fetchone()
                if r2 and r2[0]:
                    return r2[0]
    if operand_name:
        base = operand_name.split('.')[0].split('[')[0]
        dts = cur.execute(
            "SELECT DISTINCT datatype FROM tag_datatype WHERE tagname=?",
            (base,)).fetchall()
        if len(dts) == 1:
            return dts[0][0]
    return None


def _datatype_pinmap(cur, datatype, array_slots=()):
    """{pin_bit: (member_name, hidden)} for a datatype, or None (no members).

    Without arrays: pin_bit(member@ordinal) = ordinal + 1 + reserved, where
    reserved counts the hidden ulBoolInput<n>=2..> members before it (each
    such second+ input bit-collector reserves one firmware pin slot). Names
    and order come entirely from the datatype member list, so no per-type pin
    table is needed.

    ``array_slots``: the pin slots the block instance's array parameters
    occupy (each 0x75 array record states its slot: MAVE StorageArray=9 /
    WeightArray=10, FGEN X1=7 Y1=8 X2=9 Y2=10). Members then fill the FREE
    slots in ordinal order -- except that the first hidden ``ulBoolOutput1``
    fills AFTER the member that follows it (a MAVE block: EnableOut=11,
    collector=12, Out=13; with no arrays the collector keeps its ordinal
    slot, CTUD-attested).
    """
    rows = cur.execute(
        "SELECT name, hidden FROM datatype_members WHERE datatype=? "
        "ORDER BY ordinal", (datatype,)).fetchall()
    if not rows:
        return None
    order = [(name, bool(hidden)) for name, hidden in rows]
    if array_slots:
        for i, (name, hidden) in enumerate(order):
            if hidden and name == 'ulBoolOutput1':
                if i + 1 < len(order):
                    order[i], order[i + 1] = order[i + 1], order[i]
                break
    taken = set(array_slots)
    out = {}
    slot = 0
    for name, hidden in order:
        slot += 1
        while slot in taken:
            slot += 1
        out[slot] = (name, hidden)
        mm = PIN_ULINPUT.match(name or "")
        if hidden and mm and int(mm.group(1)) >= 2:
            slot += 1
    return out


def _pins_from_mask(er, base, bt, pinmap):
    """VisiblePins string for a pin-space block via its derived pinmap, or None.

    Reads the wide little-endian mask at its per-generation offset and maps
    ascending set bits through ``pinmap``; a set bit with no member, a bit that
    maps to a hidden member, or an unknown PIDE prelude rejects the element.
    """
    delta = 9
    if bt == 'PIDE':
        j = er.find(b'\xff\xfe\xff')
        if j < 0:
            return None
        delta = _PIDE_MASK_DELTA_BY_PRELUDE.get(j - base)
        if delta is None:
            return None
    elif bt in ARRAY_TYPES:
        j = er.find(b'\xff\xfe\xff')
        if j < 0:
            return None
        delta = _ARRAY_MASK_DELTA_BY_PRELUDE.get(j - base)
        if delta is None:
            return None
    nb = PIN_MASK_BYTES[bt]
    if len(er) < base + delta + nb:
        return None
    mask = int.from_bytes(er[base + delta:base + delta + nb], "little")
    pins = []
    for b in range(nb * 8):
        if mask & (1 << b):
            e = pinmap.get(b)
            if e is None or e[1]:
                return None
            pins.append(e[0])
    return " ".join(pins)


def _pide_autotune(cur, eo):
    """Resolve a PIDE block's AutotuneTag property child, or fail.

    Returns (ok, name_or_None): the block may own at most ONE child -- a
    kind-0x80 property record holding two strings, an operand reference
    (empty => the property is unset) and the literal property name
    ``AutotuneTag``. Anything else is an unknown shape -> (False, None).
    """
    kids = _rows(cur, eo)
    if not kids:
        return True, None
    if len(kids) != 1:
        return False, None
    ko, kr = kids[0]
    if _kind(kr) != 0x80 or _rows(cur, ko):
        return False, None
    j = kr.find(b'\xff\xfe\xff')
    if j < 0 or len(kr) < j + 4:
        return False, None
    n = kr[j + 3]
    if n == 0xFF:
        return False, None
    end = j + 4 + 2 * n
    if len(kr) < end + 4 or kr[end:end + 3] != b'\xff\xfe\xff':
        return False, None
    n2 = kr[end + 3]
    prop = kr[end + 4:end + 4 + 2 * n2].decode("utf-16-le", "replace")
    if prop != 'AutotuneTag':
        return False, None
    if n == 0:
        return True, None
    name = _operand(cur, kr)
    if name is None:
        return False, None
    return True, name


def _rows(cur, pid):
    # A source-protected project encrypts each graphical element record at rest
    # (config-on-the-wire framing); decrypt transparently so the walk below sees
    # a normal element. Plaintext records carry no marker and pass through
    # unchanged, so unprotected routines are a byte-for-byte no-op.
    return [(o, sp_decrypt_nameless_element(bytes(r))) for (o, r) in cur.execute(
        "SELECT object_id, record FROM nameless WHERE parent_id=?", (pid,)).fetchall()]


def _has_children(cur, oid):
    return cur.execute("SELECT 1 FROM nameless WHERE parent_id=? LIMIT 1", (oid,)).fetchone() is not None


def _rawtext(r):
    j = r.find(b'\xff\xfe\xff')
    if j < 0:
        return ""
    if len(r) < j + 4:
        return None
    n = r[j + 3]
    p = j + 4
    if n == 0xFF:
        if len(r) < j + 6:
            return None
        n = struct.unpack_from("<H", r, j + 4)[0]
        p = j + 6
    if len(r) < p + 2 * n:
        return None
    return r[p:p + 2 * n].decode("utf-16-le", "replace")


def _deref(cur, oid, depth=0):
    if depth > 6:
        return None
    row = cur.execute("SELECT comp_name FROM comps WHERE object_id=?", (oid,)).fetchone()
    if not row or not row[0]:
        return None
    nm = row[0]
    m = _AMP.match(nm)
    if m:
        parent = _deref(cur, int(m.group(1), 16), depth + 1)
        return (parent + m.group(2)) if parent is not None else None
    return nm


def _resolve_text(cur, txt):
    out, last = [], 0
    for m in _TOK.finditer(txt):
        nm = _deref(cur, int(m.group(1), 16))
        if nm is None:
            return None
        out.append(txt[last:m.start()])
        out.append(nm)
        last = m.end()
    out.append(txt[last:])
    return "".join(out)


def _operand(cur, r):
    txt = _rawtext(r)
    if not txt:
        return None
    res = _resolve_text(cur, txt)
    return res if res else None


def _read_str(r, j):
    """(text, next_offset) for the fffeff string at offset j, or (None, 0)."""
    if r[j:j + 3] != b'\xff\xfe\xff' or len(r) < j + 4:
        return None, 0
    n = r[j + 3]
    p = j + 4
    if n == 0xFF:
        if len(r) < j + 6:
            return None, 0
        n = struct.unpack_from("<H", r, j + 4)[0]
        p = j + 6
    if len(r) < p + 2 * n:
        return None, 0
    return r[p:p + 2 * n].decode("utf-16-le", "replace"), p + 2 * n


def _block_arrays(cur, eo, base):
    """Resolve an array-parameter block's <Array> children, or fail.

    The block owns exactly ONE kind-0x77 group; its children are kind-0x75
    array records with no further children, each holding two consecutive
    fffeff strings: the operand reference (empty => the parameter is unbound)
    and the array parameter name. The pin-slot u32 sits at the header-family
    ``base`` offset (20 short / 24 long) -- a fixed 24 read a constant 0xCA
    on short-header records, colliding every array on one bogus slot. Returns
    (ok, [(name, operand_or_None, slot), ...]); any other shape, an
    unresolved operand or a duplicate name/slot is unknown -> (False, None).
    """
    kids = _rows(cur, eo)
    if len(kids) != 1:
        return False, None
    go, gr = kids[0]
    if _kind(gr) != ARRAY_GROUP:
        return False, None
    arrays = []
    for ao, ar in _rows(cur, go):
        if _kind(ar) != ARRAY_ELEM or _rows(cur, ao):
            return False, None
        if len(ar) < base + 8:
            return False, None
        slot = struct.unpack_from("<I", ar, base)[0]
        j = ar.find(b'\xff\xfe\xff')
        if j < 0:
            return False, None
        op_txt, nxt = _read_str(ar, j)
        if op_txt is None:
            return False, None
        name, _ = _read_str(ar, nxt)
        if not name:
            return False, None
        operand = None
        if op_txt:
            operand = _resolve_text(cur, op_txt)
            if not operand:
                return False, None
        arrays.append((name, operand, slot))
    names = [a[0] for a in arrays]
    slots = [a[2] for a in arrays]
    if (not arrays or len(set(names)) != len(names)
            or len(set(slots)) != len(slots) or 0 in slots):
        return False, None
    return True, sorted(arrays)


def decode_fbd(cur, routine_oid, short_header, sheet_size=None,
               sheet_orientation=None, textbox_text=None, textbox_text_v20=None):
    if sheet_size is None or sheet_orientation is None:
        return None
    try:
        return _decode(cur, routine_oid, short_header, sheet_size,
                       sheet_orientation, textbox_text or {},
                       textbox_text_v20 or {})
    except Exception:
        return None


def _decode(cur, oid, sh, size, orient, tbtext, tbtext_v20):
    fam = 'S' if sh else 'L'
    base = 20 if sh else 24

    sub = {}
    frontier = [oid]
    seen = set()
    while frontier:
        nxt = []
        for pid in frontier:
            for o, r in _rows(cur, pid):
                if o in seen:
                    continue
                seen.add(o)
                sub[o] = r
                nxt.append(o)
        frontier = nxt
    if not sub:
        return None

    sheets = [(o, r) for o, r in sub.items() if _kind(r) == SHEET]
    if not sheets:
        return None
    if len(sheets) == 1:
        ordered = sheets
    else:
        # Each sheet record stores its display Number explicitly: the u32
        # immediately before the description's fffeff marker (both header
        # families, reference-verified). The numbers must be exactly 1..N or
        # the layout is unknown -> fail closed.
        nums = []
        for _, r in sheets:
            j = r.find(b'\xff\xfe\xff')
            if j < 4:
                return None
            nums.append(struct.unpack_from("<I", r, j - 4)[0])
        if sorted(nums) != list(range(1, len(sheets) + 1)):
            return None
        ordered = [s2 for _, s2 in sorted(zip(nums, sheets),
                                          key=lambda t: t[0])]

    # ID assignment order: type rank, then the Block TYPE name, then operand,
    # then position. The type-name component is load-bearing: OEM orders a
    # MUL before a PIDE even when the PIDE's operand sorts first (corpus:
    # 116/116 routines consistent; operand-only ordering broke on exactly
    # that shape). Non-Block elements contribute '' so their order is
    # unchanged. IDs run through the whole routine in sheet order.
    def _idkey(e):
        return (TYPE_RANK[e[1]],
                e[6] if e[1] in ('Block', 'AddOnInstruction') else '',
                e[4] if e[4] is not None else '', e[2], e[3])

    def _wparam(bt, idx, pinmap):
        # A pin-space block's wire index is its pin bit -- resolve through the
        # same datatype-derived pinmap as VisiblePins. A u32-mask block's wire
        # index is its VISIBLE_PIN_BITS bit minus 8 (minus 0 for SSUM, whose
        # mask is already low-based) -- every instance-diffed WIRE_PARAM pair
        # is a subset of this relation. Fail closed on an unknown index.
        if isinstance(pinmap, frozenset):
            # AOI call: the wire index is the parameter's comp object id.
            row = cur.execute(
                "SELECT comp_name FROM comps WHERE object_id=?",
                (idx,)).fetchone()
            return row[0] if row and row[0] in pinmap else None
        if pinmap is not None:
            en = pinmap.get(idx)
            return None if en is None or en[1] else en[0]
        tab = VISIBLE_PIN_BITS.get(bt)
        if tab is None:
            return None
        return tab.get(idx + (0 if bt == 'SSUM' else 8))

    # ---- pass 1: parse + globally ID-assign every sheet's elements ----
    idmap = {}
    etype = {}
    epin = {}
    per_sheet = []          # (es_sorted, desc_xml, wgs, ags)
    next_id = 0
    for soid, srec in ordered:
        sdesc = _rawtext(srec)
        if sdesc is None or "@" in sdesc:
            return None
        desc_xml = []
        if sdesc != "":
            desc_xml.append("<Description>\n<![CDATA[%s]]>\n</Description>" % sdesc)

        childgroups = _rows(cur, soid)
        if any(_kind(r) not in (ELEMGROUP, WIREGROUP, TBGROUP, ATGROUP)
               for _, r in childgroups):
            return None
        egs = [o for o, r in childgroups if _kind(r) == ELEMGROUP]
        wgs = [o for o, r in childgroups if _kind(r) == WIREGROUP]
        tgs = [o for o, r in childgroups if _kind(r) == TBGROUP]
        ags = [o for o, r in childgroups if _kind(r) == ATGROUP]

        elems = []
        for go in egs:
            for eo, er in _rows(cur, go):
                k = _kind(er)
                if k in (IREF, OREF):
                    if _has_children(cur, eo):
                        return None
                    op = _operand(cur, er)
                    if op is None:
                        return None
                    x = struct.unpack_from("<I", er, base)[0]
                    y = struct.unpack_from("<I", er, base + 4)[0]
                    elems.append([eo, 'IRef' if k == IREF else 'ORef', x, y, op, None, None])
                elif k in (ICON, OCON):
                    # Wire connector: X/Y at base, then the oid of a kind-0x71
                    # connector-name record holding the Name string.
                    if _has_children(cur, eo) or len(er) < base + 12:
                        return None
                    x = struct.unpack_from("<I", er, base)[0]
                    y = struct.unpack_from("<I", er, base + 4)[0]
                    nref = struct.unpack_from("<I", er, base + 8)[0]
                    nrow = cur.execute(
                        "SELECT record FROM nameless WHERE object_id=?",
                        (nref,)).fetchone()
                    if not nrow:
                        return None
                    # The connector-name record is fetched outside _rows, so it
                    # needs the same transparent SP decrypt (a no-op on plaintext).
                    nrec = sp_decrypt_nameless_element(bytes(nrow[0]))
                    nm = _rawtext(nrec) if _kind(nrec) == CONNNAME else None
                    if not nm or "@" in nm:
                        return None
                    elems.append([eo, 'ICon' if k == ICON else 'OCon',
                                  x, y, nm, None, None])
                elif k == AOICALL:
                    # On-sheet AOI call: X/Y at the standard base offsets;
                    # after the operand string a u16 count of visibility
                    # toggles, each [param comp oid][flag==1]. VisiblePins =
                    # the definition's parameters in authored order where
                    # Visible or toggled (aoi_pins staging table).
                    for ko, kr in _rows(cur, eo):
                        if _kind(kr) != AOIPROP or _rows(cur, ko):
                            return None
                    if len(er) < base + 8:
                        return None
                    x = struct.unpack_from("<I", er, base)[0]
                    y = struct.unpack_from("<I", er, base + 4)[0]
                    j = er.find(b'\xff\xfe\xff')
                    if j < 0:
                        return None
                    op_txt, nxt = _read_str(er, j)
                    if not op_txt:
                        return None
                    op = _resolve_text(cur, op_txt)
                    if not op:
                        return None
                    aoi_name = _block_datatype(cur, _operand_oid(er), op)
                    if aoi_name is None:
                        return None
                    prows = cur.execute(
                        "SELECT name, visible FROM aoi_pins WHERE aoi=? "
                        "ORDER BY ordinal", (aoi_name,)).fetchall()
                    if not prows:
                        return None
                    pset = {nm for nm, _ in prows}
                    if nxt + 2 > len(er):
                        return None
                    tcount = struct.unpack_from("<H", er, nxt)[0]
                    q = nxt + 2
                    toggled = set()
                    for _i in range(tcount):
                        if q + 8 > len(er):
                            return None
                        toid = struct.unpack_from("<I", er, q)[0]
                        tflag = struct.unpack_from("<I", er, q + 4)[0]
                        if tflag != 1:
                            return None
                        trow = cur.execute(
                            "SELECT comp_name FROM comps WHERE object_id=?",
                            (toid,)).fetchone()
                        if not trow or trow[0] not in pset:
                            return None
                        toggled.add(trow[0])
                        q += 8
                    pins_str = " ".join(
                        nm for nm, vis in prows if vis or nm in toggled)
                    elems.append([eo, 'AddOnInstruction', x, y, op, pins_str,
                                  aoi_name, None, frozenset(pset), None])
                elif k in KIND2TYPE:
                    bt = KIND2TYPE[k]
                    if bt in FAM_OK and fam not in FAM_OK[bt]:
                        return None
                    autotune = None
                    arrays = None
                    if bt == 'PIDE':
                        ok, autotune = _pide_autotune(cur, eo)
                        if not ok:
                            return None
                    elif bt in ARRAY_TYPES:
                        ok, arrays = _block_arrays(cur, eo, base)
                        if not ok:
                            return None
                    elif _has_children(cur, eo):
                        return None
                    op = _operand(cur, er)
                    if op is None:
                        return None
                    x = struct.unpack_from("<I", er, base)[0]
                    y = struct.unpack_from("<I", er, base + 4)[0]
                    pinmap = None
                    if bt in PINSPACE_TYPES:
                        dt = _block_datatype(cur, _operand_oid(er), op)
                        if dt is None:
                            return None
                        pinmap = _datatype_pinmap(
                            cur, dt,
                            [a[2] for a in arrays] if arrays else ())
                        if pinmap is None:
                            return None
                        pins_str = _pins_from_mask(er, base, bt, pinmap)
                        if pins_str is None:
                            return None
                    else:
                        moff = base + MASK_DELTA.get(bt, 8)
                        if len(er) < moff + 4:
                            return None
                        mask = struct.unpack_from("<I", er, moff)[0]
                        tab = VISIBLE_PIN_BITS.get(bt)
                        if tab is None:
                            return None
                        pins = []
                        for b in range(32):
                            if mask & (1 << b):
                                if b not in tab:
                                    return None
                                pins.append(tab[b])
                        pins_str = " ".join(pins)
                    elems.append([eo, 'Block', x, y, op, pins_str, bt, autotune,
                                  pinmap, arrays])
                else:
                    return None

        for go in tgs:
            for eo, er in _rows(cur, go):
                if _kind(er) != TEXTBOX or _has_children(cur, eo):
                    return None
                x = struct.unpack_from("<I", er, base)[0]
                y = struct.unpack_from("<I", er, base + 4)[0]
                if sh:
                    # old-layout (V20) files carry no global md; record[28:32]
                    # holds the FO text index (0xFFFFFFFF = none) resolved via
                    # the FO_<n> map -- the same mechanism SFC uses.
                    fo = struct.unpack_from("<I", er, 28)[0]
                    txt = None if fo == 0xFFFFFFFF else tbtext_v20.get(fo)
                else:
                    md = struct.unpack_from("<I", er, 20)[0]
                    txt = tbtext.get("MD%d" % md)
                if txt is None:
                    return None
                elems.append([eo, 'TextBox', x, y, None, None, txt])

        if not elems:
            # An empty sheet is legal; OEM keeps its Description (a desc-only
            # <Sheet>) and self-closes an undescribed one. Stray wires or
            # attachments on an empty sheet are an unknown shape.
            for go in wgs + ags:
                if _rows(cur, go):
                    return None
            per_sheet.append((None, desc_xml, None, None))
            continue

        es = sorted(elems, key=_idkey)
        keys = set()
        for e in es:
            key = _idkey(e)
            if key in keys:
                return None
            keys.add(key)
        for e in es:
            idmap[e[0]] = next_id
            next_id += 1
            etype[e[0]] = (e[1], e[6])
            epin[e[0]] = e[8] if len(e) > 8 else None
        per_sheet.append((es, desc_xml, wgs, ags))

    # ---- pass 2: wires / attachments + XML per sheet ----
    sheet_xml = []
    for n, (es, desc_xml, wgs, ags) in enumerate(per_sheet):
        if es is None:
            if desc_xml:
                sheet_xml.append('<Sheet Number="%d">\n%s\n</Sheet>'
                                 % (n + 1, "\n".join(desc_xml)))
            else:
                sheet_xml.append('<Sheet Number="%d"/>' % (n + 1))
            continue

        el_xml = []
        for e in es:
            i = idmap[e[0]]
            typ = e[1]
            if typ in ('IRef', 'ORef'):
                el_xml.append('<%s ID="%d" X="%d" Y="%d" Operand=%s HideDesc="false"/>'
                              % (typ, i, e[2], e[3], quoteattr(e[4])))
            elif typ in ('ICon', 'OCon'):
                el_xml.append('<%s ID="%d" X="%d" Y="%d" Name=%s/>'
                              % (typ, i, e[2], e[3], quoteattr(e[4])))
            elif typ == 'AddOnInstruction':
                el_xml.append('<AddOnInstruction Name=%s ID="%d" X="%d" Y="%d" Operand=%s VisiblePins=%s/>'
                              % (quoteattr(e[6]), i, e[2], e[3],
                                 quoteattr(e[4]), quoteattr(e[5])))
            elif typ == 'Block':
                at = ' AutotuneTag=%s' % quoteattr(e[7]) \
                    if len(e) > 7 and e[7] else ''
                head = ('<Block Type="%s" ID="%d" X="%d" Y="%d" Operand=%s VisiblePins=%s HideDesc="false"%s'
                        % (e[6], i, e[2], e[3], quoteattr(e[4]), quoteattr(e[5]), at))
                arrays = e[9] if len(e) > 9 and e[9] else None
                if arrays:
                    inner = "\n".join(
                        '<Array Name=%s%s/>' % (
                            quoteattr(nm),
                            (' Operand=%s' % quoteattr(opnd)) if opnd else '')
                        for nm, opnd, _slot in arrays)
                    el_xml.append('%s>\n%s\n</Block>' % (head, inner))
                else:
                    el_xml.append('%s/>' % head)
            elif typ == 'TextBox':
                el_xml.append('<TextBox ID="%d" X="%d" Y="%d" Width="0"><Text><![CDATA[%s]]></Text></TextBox>'
                              % (i, e[2], e[3], e[6]))

        wires = []
        for go in wgs:
            for wo, wr in _rows(cur, go):
                if _kind(wr) != WIRE or len(wr) < base + 16:
                    return None
                fo = struct.unpack_from("<I", wr, base)[0]
                fp = struct.unpack_from("<I", wr, base + 4)[0]
                to = struct.unpack_from("<I", wr, base + 8)[0]
                tp = struct.unpack_from("<I", wr, base + 12)[0]
                if fo not in idmap or to not in idmap:
                    return None
                wires.append((fo, fp, to, tp))

        resolved = []
        for fo, fp, to, tp in wires:
            fattr = tattr = ""
            fname = tname = ""
            ft, fbt = etype[fo]
            tt, tbt = etype[to]
            if ft in ('Block', 'AddOnInstruction'):
                fname = _wparam(fbt, fp, epin.get(fo))
                if fname is None:
                    return None
                fattr = ' FromParam="%s"' % fname
            if tt in ('Block', 'AddOnInstruction'):
                tname = _wparam(tbt, tp, epin.get(to))
                if tname is None:
                    return None
                tattr = ' ToParam="%s"' % tname
            resolved.append((idmap[fo], idmap[to], fattr, tattr, fname, tname))
        # Same-endpoint wire pairs (several wires between one element pair) are
        # ordered ALPHABETICALLY by param name -- corpus: OEM lists DevDeadband,
        # ProgAutoReq, ProgProgReq (names ordered; their pin indices 61, 67, 64
        # are not), and DevHLimit before DevLLimit.
        wire_xml = ['<Wire FromID="%d"%s ToID="%d"%s/>' % (w[0], w[2], w[1], w[3])
                    for w in sorted(resolved, key=lambda w: (w[0], w[1], w[4], w[5]))]

        att = []
        for go in ags:
            for ao, ar in _rows(cur, go):
                if _kind(ar) != ATTACH or len(ar) < base + 8:
                    return None
                fo = struct.unpack_from("<I", ar, base)[0]
                to = struct.unpack_from("<I", ar, base + 4)[0]
                if fo not in idmap or to not in idmap:
                    return None
                att.append((idmap[fo], idmap[to]))
        att_xml = ['<Attachment FromID="%d" ToID="%d"/>' % (a, b)
                   for a, b in sorted(att)]

        body = desc_xml + el_xml + wire_xml + att_xml
        sheet_xml.append('<Sheet Number="%d">\n%s\n</Sheet>'
                         % (n + 1, "\n".join(body)))

    return ('<FBDContent SheetSize=%s SheetOrientation=%s>\n%s\n</FBDContent>'
            % (quoteattr(size), quoteattr(orient), "\n".join(sheet_xml)))
