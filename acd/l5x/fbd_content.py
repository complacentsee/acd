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

IREF, OREF, TEXTBOX, WIRE, ATTACH = 0x0e, 0x0d, 0x81, 0x11, 0x88
SHEET, ELEMGROUP, WIREGROUP, TBGROUP, ATGROUP = 0x03, 0x07, 0x09, 0x83, 0x87

KIND2TYPE = {
    0x0a: 'ADD', 0x13: 'SCL', 0x14: 'ALM', 0x15: 'SEL', 0x19: 'HLL',
    0x1d: 'SRTP', 0x21: 'BAND', 0x22: 'BOR', 0x24: 'BNOT', 0x26: 'LPF',
    0x2e: 'SSUM', 0x39: 'RLIM', 0x3a: 'DERV', 0x3b: 'MINC', 0x3d: 'OSRI',
    0x44: 'RAD', 0x48: 'ABS', 0x4d: 'COS', 0x4f: 'DIV', 0x52: 'MUL',
    0x55: 'SUB', 0x5b: 'TONR', 0x5d: 'GEQ', 0x5e: 'GRT', 0x5f: 'LEQ',
    0x63: 'NEQ',
    # pin-space types: wide datatype-derived mask, not the VISIBLE_PIN_BITS u32
    0x0b: 'TOT', 0x1b: 'PIDE', 0x29: 'PI', 0x58: 'CTUD',
}
PIDE_KIND = 0x1b

# Pin-space FBD block types: their VisiblePins mask is a WIDE little-endian bit
# array (base+9, or the PIDE prelude-keyed offset below), not the u32 at base+8
# that VISIBLE_PIN_BITS decodes. Unlike the simpler blocks, their pin NAMES are
# NOT tabled -- they are DERIVED from the block's own datatype member list in the
# ACD (TagInfo/Comps), so the ~40-pin PIDE vocabulary and the PI/CTUD/TOT maps
# come straight from the project. See _pins_from_mask / _datatype_pinmap.
PINSPACE_TYPES = {'CTUD', 'PI', 'PIDE', 'TOT'}
# Read-window bytes for the wide mask -- a generous upper bound. Trailing bytes
# past the real mask are zero, and a set bit with no datatype member fails
# closed, so an over-wide window only adds safety.
PIN_MASK_BYTES = {'CTUD': 8, 'PI': 8, 'TOT': 8, 'PIDE': 24}
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

TYPE_RANK = {'IRef': 0, 'ORef': 1, 'Block': 2, 'TextBox': 3}
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


def _datatype_pinmap(cur, datatype):
    """{pin_bit: (member_name, hidden)} for a datatype, or None (no members).

    pin_bit(member@ordinal) = ordinal + 1 + reserved, where reserved counts the
    hidden ulBoolInput<n>=2..> members before it (each such second+ input
    bit-collector reserves one firmware pin slot). Names and order come entirely
    from the datatype member list, so no per-type pin table is needed.
    """
    rows = cur.execute(
        "SELECT name, hidden FROM datatype_members WHERE datatype=? "
        "ORDER BY ordinal", (datatype,)).fetchall()
    if not rows:
        return None
    out = {}
    reserved = 0
    for i, (name, hidden) in enumerate(rows):
        out[i + 1 + reserved] = (name, bool(hidden))
        mm = PIN_ULINPUT.match(name or "")
        if hidden and mm and int(mm.group(1)) >= 2:
            reserved += 1
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
    return [(o, bytes(r)) for (o, r) in cur.execute(
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


def _operand(cur, r):
    txt = _rawtext(r)
    if not txt:
        return None
    out, last = [], 0
    for m in _TOK.finditer(txt):
        nm = _deref(cur, int(m.group(1), 16))
        if nm is None:
            return None
        out.append(txt[last:m.start()])
        out.append(nm)
        last = m.end()
    out.append(txt[last:])
    res = "".join(out)
    return res if res else None


def decode_fbd(cur, routine_oid, short_header, sheet_size=None,
               sheet_orientation=None, textbox_text=None):
    if sheet_size is None or sheet_orientation is None:
        return None
    try:
        return _decode(cur, routine_oid, short_header, sheet_size,
                       sheet_orientation, textbox_text or {})
    except Exception:
        return None


def _decode(cur, oid, sh, size, orient, tbtext):
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
    if len(sheets) != 1:
        return None
    soid, srec = sheets[0]

    sdesc = _rawtext(srec)
    if sdesc is None or "@" in sdesc:
        return None
    desc_xml = []
    if sdesc != "":
        desc_xml.append("<Description>\n<![CDATA[%s]]>\n</Description>" % sdesc)

    childgroups = _rows(cur, soid)
    if any(_kind(r) not in (ELEMGROUP, WIREGROUP, TBGROUP, ATGROUP) for _, r in childgroups):
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
            elif k in KIND2TYPE:
                bt = KIND2TYPE[k]
                if bt in FAM_OK and fam not in FAM_OK[bt]:
                    return None
                autotune = None
                if bt == 'PIDE':
                    ok, autotune = _pide_autotune(cur, eo)
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
                    pinmap = _datatype_pinmap(cur, dt)
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
                elems.append([eo, 'Block', x, y, op, pins_str, bt, autotune, pinmap])
            else:
                return None

    for go in tgs:
        for eo, er in _rows(cur, go):
            if _kind(er) != TEXTBOX or _has_children(cur, eo):
                return None
            md = struct.unpack_from("<I", er, 20)[0]
            x = struct.unpack_from("<I", er, base)[0]
            y = struct.unpack_from("<I", er, base + 4)[0]
            txt = tbtext.get("MD%d" % md)
            if txt is None:
                return None
            elems.append([eo, 'TextBox', x, y, None, None, txt])

    if not elems:
        if desc_xml:
            return None
        for go in wgs + ags + tgs:
            if _rows(cur, go):
                return None
        return ('<FBDContent SheetSize=%s SheetOrientation=%s>\n<Sheet Number="1"/>\n</FBDContent>'
                % (quoteattr(size), quoteattr(orient)))

    # ID assignment order: type rank, then the Block TYPE name, then operand,
    # then position. The type-name component is load-bearing: OEM orders a
    # MUL before a PIDE even when the PIDE's operand sorts first (corpus:
    # 116/116 routines consistent; operand-only ordering broke on exactly
    # that shape). Non-Block elements contribute '' so their order is
    # unchanged.
    def _idkey(e):
        return (TYPE_RANK[e[1]], e[6] if e[1] == 'Block' else '',
                e[4] if e[4] is not None else '', e[2], e[3])
    es = sorted(elems, key=_idkey)
    keys = set()
    for e in es:
        key = _idkey(e)
        if key in keys:
            return None
        keys.add(key)
    idmap = {e[0]: i for i, e in enumerate(es)}
    etype = {e[0]: (e[1], e[6]) for e in es}
    epin = {e[0]: (e[8] if len(e) > 8 else None) for e in es}

    el_xml = []
    for i, e in enumerate(es):
        typ = e[1]
        if typ in ('IRef', 'ORef'):
            el_xml.append('<%s ID="%d" X="%d" Y="%d" Operand=%s HideDesc="false"/>'
                          % (typ, i, e[2], e[3], quoteattr(e[4])))
        elif typ == 'Block':
            at = ' AutotuneTag=%s' % quoteattr(e[7]) \
                if len(e) > 7 and e[7] else ''
            el_xml.append('<Block Type="%s" ID="%d" X="%d" Y="%d" Operand=%s VisiblePins=%s HideDesc="false"%s/>'
                          % (e[6], i, e[2], e[3], quoteattr(e[4]), quoteattr(e[5]), at))
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
    def _wparam(bt, idx, pinmap):
        # A pin-space block's wire index is its pin bit -- resolve through the
        # same datatype-derived pinmap as VisiblePins; other blocks use the
        # tabled WIRE_PARAM. Fail closed on an unknown / hidden index.
        if pinmap is not None:
            e = pinmap.get(idx)
            return None if e is None or e[1] else e[0]
        return WIRE_PARAM.get("%s:%s" % (bt, fam), {}).get(idx)

    resolved = []
    for fo, fp, to, tp in wires:
        fattr = tattr = ""
        fname = tname = ""
        ft, fbt = etype[fo]
        tt, tbt = etype[to]
        if ft == 'Block':
            fname = _wparam(fbt, fp, epin.get(fo))
            if fname is None:
                return None
            fattr = ' FromParam="%s"' % fname
        if tt == 'Block':
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
    att_xml = ['<Attachment FromID="%d" ToID="%d"/>' % (a, b) for a, b in sorted(att)]

    body = desc_xml + el_xml + wire_xml + att_xml
    return ('<FBDContent SheetSize=%s SheetOrientation=%s>\n<Sheet Number="1">\n%s\n</Sheet>\n</FBDContent>'
            % (quoteattr(size), quoteattr(orient), "\n".join(body)))
