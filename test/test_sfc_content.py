"""Unit tests for decode_sfc: Simultaneous branches, Stop document order,
TextBox (X, Y) ordering, and the branch Y-tie fail-closed gate.

Seeds a synthetic nameless subtree (V33-era layout, base shift d=0) through
the shared staging schema; no ACD pool needed.
"""
import struct

from test.seeded_db import seeded_cursor
from acd.l5x.sfc_content import decode_sfc

ROUTINE = 1000
SHEET = ("Letter - 8.5 x 11 in", "Landscape")


def _h(n):
    return struct.pack("<I", 0xAA000000 | n)


def _text(s):
    return b"\xff\xfe\xff" + bytes([len(s)]) + s.encode("utf-16-le")


def _rec(kind, selfhash, body=b"", tail=b""):
    # [len-4][flags][cid][selfhash][kind u16][0 u16] + body from offset 20
    r = bytearray(20)
    struct.pack_into("<I", r, 4, 0x01000000)
    r[12:16] = selfhash
    struct.pack_into("<H", r, 16, kind)
    r += body + tail
    struct.pack_into("<I", r, 0, len(r) - 4)
    return bytes(r)


def _u32s(*vals):
    return b"".join(struct.pack("<I", v) for v in vals)


def _descbox(h, dx=10, dy=20):
    # len must be exactly 32: 20 header + X@24 Y@28
    return _rec(130, h, _u32s(0, dx, dy))


def _step(h, dbh, x, y, op):
    # X@24 Y@28 db@36 flags@40; zero pad through 60 so the d=-4 probe
    # (descbox at 32) fails and the shift is unambiguous
    body = _u32s(0, x, y, 0, struct.unpack("<I", dbh)[0], 0x12, 0, 0, 0, 0)
    return _rec(1003, h, body, _text(op))


def _trans(h, dbh, ch, x, y, op):
    body = _u32s(0, x, y, 0, struct.unpack("<I", dbh)[0],
                 struct.unpack("<I", ch)[0])
    return _rec(1006, h, body, _text(op))


def _stop(h, dbh, x, y, op):
    body = _u32s(0, x, y, 0, struct.unpack("<I", dbh)[0], 0)
    return _rec(1021, h, body, _text(op))


def _branch(kind, h, grph, y, prio=False):
    body = _u32s(0, 0, y, struct.unpack("<I", grph)[0])
    if prio:
        body += _u32s(1)
    return _rec(kind, h, body)


def _leggroup(h, leg_hashes):
    body = _u32s(0) + struct.pack("<H", len(leg_hashes)) + b"".join(leg_hashes)
    return _rec(1012, h, body)


def _leg(kind, h):
    return _rec(kind, h, _u32s(0, 0))


def _textbox(h, x, y, md=7):
    r = _rec(129, h, _u32s(md, x, y))
    assert len(r) == 32
    return r


def _cond(h2003, h2002, h2001, line="a := 1;"):
    # 2003 container (u32@24 == 2) -> child 2002 (count@24 + hash array)
    # -> child 2001 line record
    c3 = _rec(2003, h2003, _u32s(0, 2))
    c2 = _rec(2002, h2002, _u32s(0) + struct.pack("<H", 1) + h2001)
    c1 = _rec(2001, h2001, b"", _text(line))
    return c3, c2, c1


def _decode(rows):
    nameless = [(oid, parent, rec) for oid, parent, rec in rows]
    cur = seeded_cursor()
    cur.executemany("INSERT INTO nameless VALUES (?,?,?)", nameless)
    return decode_sfc(cur, ROUTINE, _prove_sheet=SHEET, textbox_text={})


def _base_chart():
    """One step + one transition (with condition body), all under ROUTINE."""
    c3, c2, c1 = _cond(_h(30), _h(31), _h(32))
    rows = [
        (1, ROUTINE, _step(_h(1), _h(2), 100, 40, "Step_001")),
        (2, ROUTINE, _descbox(_h(2))),
        (3, ROUTINE, _trans(_h(3), _h(4), _h(30), 100, 140, "Tran_001")),
        (4, ROUTINE, _descbox(_h(4))),
        (30, ROUTINE, c3),
        (31, 30, c2),
        (32, 31, c1),
    ]
    return rows


def test_simultaneous_branches_and_stop_document_order():
    rows = _base_chart()
    rows += [
        (5, ROUTINE, _branch(1019, _h(5), _h(6), 200)),
        (6, ROUTINE, _leggroup(_h(6), [_h(7), _h(8)])),
        (7, ROUTINE, _leg(1015, _h(7))),
        (8, ROUTINE, _leg(1015, _h(8))),
        (9, ROUTINE, _branch(1020, _h(9), _h(10), 400)),
        (10, ROUTINE, _leggroup(_h(10), [_h(11), _h(12)])),
        (11, ROUTINE, _leg(1016, _h(11))),
        (12, ROUTINE, _leg(1016, _h(12))),
        (13, ROUTINE, _stop(_h(13), _h(14), 100, 500, "Stop_001")),
        (14, ROUTINE, _descbox(_h(14))),
    ]
    out = _decode(rows)
    assert out is not None
    assert ('<Branch ID="2" Y="200" BranchType="Simultaneous" '
            'BranchFlow="Diverge">') in out
    assert ('<Branch ID="5" Y="400" BranchType="Simultaneous" '
            'BranchFlow="Converge">') in out
    assert "Priority" not in out.split("Simultaneous")[1].split(">")[0]
    # Stop ID follows the branch/leg range but the element is emitted after
    # every Branch in the document
    assert '<Stop ID="8"' in out
    assert out.index("<Stop") > out.rindex("</Branch>")


def test_selection_branch_priority_kept():
    rows = _base_chart()
    rows += [
        (5, ROUTINE, _branch(1017, _h(5), _h(6), 200, prio=True)),
        (6, ROUTINE, _leggroup(_h(6), [_h(7), _h(8)])),
        (7, ROUTINE, _leg(1013, _h(7))),
        (8, ROUTINE, _leg(1013, _h(8))),
    ]
    out = _decode(rows)
    assert out is not None
    assert ('<Branch ID="2" Y="200" BranchType="Selection" '
            'BranchFlow="Diverge" Priority="Default">') in out


def test_branch_y_tie_fails_closed():
    rows = _base_chart()
    rows += [
        (5, ROUTINE, _branch(1017, _h(5), _h(6), 200, prio=True)),
        (6, ROUTINE, _leggroup(_h(6), [_h(7)])),
        (7, ROUTINE, _leg(1013, _h(7))),
        (8, ROUTINE, _branch(1017, _h(8), _h(9), 200, prio=True)),
        (9, ROUTINE, _leggroup(_h(9), [_h(10)])),
        (10, ROUTINE, _leg(1013, _h(10))),
    ]
    assert _decode(rows) is None


def test_textbox_x_tie_sorts_by_y():
    rows = _base_chart()
    rows += [
        (5, ROUTINE, _textbox(_h(5), 300, 200)),
        (6, ROUTINE, _textbox(_h(6), 300, 100)),
    ]
    out = _decode(rows)
    assert out is not None
    first = out.index('X="300" Y="100"')
    second = out.index('X="300" Y="200"')
    assert first < second


def test_textbox_exact_position_tie_fails_closed():
    rows = _base_chart()
    rows += [
        (5, ROUTINE, _textbox(_h(5), 300, 100)),
        (6, ROUTINE, _textbox(_h(6), 300, 100)),
    ]
    assert _decode(rows) is None
