"""Unit tests for the V20 (old-layout, d=-4) TextBox text path.

Two layers:
  * ``build_textbox_text_v20_rows`` parsing a synthetic ``FO_<n>`` Comments.Dat
    record (kind 5 @0x0c, cid u16@0x10, UTF-16LE name @0x21, UTF-16LE body), and
    its fail-closed rejections;
  * ``decode_sfc`` binding a V20 TextBox to its text through ``record[28:32]``
    (0xFFFFFFFF == no text) against a seeded ``textbox_text_v20`` map.

No ACD pool needed -- a synthetic d=-4 nameless subtree is staged directly.
"""
import struct

from test.seeded_db import seeded_cursor
from acd.l5x.sfc_content import decode_sfc
from acd.l5x.textbox_text import build_textbox_text_v20_rows

ROUTINE = 1000
SHEET = ("Letter - 8.5 x 11 in", "Landscape")


# --------------------------------------------------------------------------- #
# 1. build_textbox_text_v20_rows                                              #
# --------------------------------------------------------------------------- #
def _fo_record(cid, idx, text, kind=5, name=None):
    """A fafa 'FO_<idx>' record: name UTF-16LE @0x21, kind @0x0c, cid @0x10."""
    rec = bytearray(0x21)
    rec[0:2] = b"\xfa\xfa"
    struct.pack_into("<H", rec, 0x0c, kind)
    struct.pack_into("<I", rec, 0x10, cid & 0xFFFF)
    nm = (name if name is not None else "FO_%d" % idx).encode("utf-16-le")
    rec += nm + b"\x00\x00" + text.encode("utf-16-le") + b"\x00\x00"
    return bytes(rec)


def test_v20_row_parse_basic():
    dat = _fo_record(0x67ac, 0, "Wait 0.5 seconds\r\nbetween reads")
    rows = build_textbox_text_v20_rows(dat)
    assert rows == [(0x67ac, 0, "Wait 0.5 seconds\r\nbetween reads")]


def test_v20_row_parse_multidigit_and_multi_cid():
    dat = (_fo_record(0x67ac, 0, "first")
           + _fo_record(0x67ac, 12, "twelfth")
           + _fo_record(0xbba5, 0, "other program")
           + b"\xfa\xfa")
    rows = build_textbox_text_v20_rows(dat)
    assert (0x67ac, 0, "first") in rows
    assert (0x67ac, 12, "twelfth") in rows
    assert (0xbba5, 0, "other program") in rows
    assert len(rows) == 3


def test_v20_row_dedup_keeps_first():
    dat = _fo_record(1, 0, "keep") + _fo_record(1, 0, "drop") + b"\xfa\xfa"
    rows = build_textbox_text_v20_rows(dat)
    assert rows == [(1, 0, "keep")]


def test_v20_row_rejects_wrong_kind():
    # a kind-8 tag-description record that happens to be named FO_0 is not a
    # textbox record and must be skipped (discriminator = kind 5).
    dat = _fo_record(1, 0, "not a textbox", kind=8)
    assert build_textbox_text_v20_rows(dat) == []


def test_v20_row_rejects_non_fo_and_no_digits():
    # "FO_" with no trailing digits, and an unrelated name, are both skipped.
    assert build_textbox_text_v20_rows(_fo_record(1, 0, "x", name="FO_")) == []
    assert build_textbox_text_v20_rows(_fo_record(1, 0, "x", name="SHWR")) == []


def test_v20_row_ignores_incidental_fo_in_body():
    # an "FO_0" substring inside another record's text (not at offset 0x21) must
    # not be mistaken for a textbox record.
    dat = _fo_record(1, 0, "see FO_9 elsewhere") + b"\xfa\xfa"
    rows = build_textbox_text_v20_rows(dat)
    assert rows == [(1, 0, "see FO_9 elsewhere")]


# --------------------------------------------------------------------------- #
# 2. decode_sfc V20 (d=-4) TextBox binding                                    #
# --------------------------------------------------------------------------- #
def _h(n):
    return struct.pack("<I", 0xAA000000 | n)


def _text(s):
    return b"\xff\xfe\xff" + bytes([len(s)]) + s.encode("utf-16-le")


def _rec(kind, selfhash, body=b"", tail=b""):
    r = bytearray(20)
    struct.pack_into("<I", r, 4, 0x01000000)
    r[12:16] = selfhash
    struct.pack_into("<H", r, 16, kind)
    r += body + tail
    struct.pack_into("<I", r, 0, len(r) - 4)
    return bytes(r)


def _u32s(*vals):
    return b"".join(struct.pack("<I", v) for v in vals)


def _descbox_d4(h, dx=10, dy=20):
    # d=-4 descbox length must be exactly 28 (32 + d): DescX@20 DescY@24
    r = _rec(130, h, _u32s(dx, dy))
    assert len(r) == 28
    return r


def _step_d4(h, dbh, x, y, op):
    # d=-4: X@20 Y@24 db@32 flags@36 agr@52; offset-36 slot (flags=0) is not a
    # descbox hash, so the d=0 probe fails and the shift resolves to -4.
    body = _u32s(x, y, 0, struct.unpack("<I", dbh)[0], 0, 0, 0, 0) + _u32s(0)
    return _rec(1003, h, body, _text(op))


def _trans_d4(h, dbh, ch, x, y, op):
    # d=-4: X@20 Y@24 zero@28 db@32 cond@36
    body = _u32s(x, y, 0, struct.unpack("<I", dbh)[0],
                 struct.unpack("<I", ch)[0], 0)
    return _rec(1006, h, body, _text(op))


def _cond_d4(h2003, h2002, h2001, line="a := 1;"):
    c3 = _rec(2003, h2003, _u32s(0, 2))
    # d=-4: the 2002 line-count u16 sits at offset 20 (24 + d)
    c2 = _rec(2002, h2002, struct.pack("<H", 1) + h2001)
    c1 = _rec(2001, h2001, b"", _text(line))
    return c3, c2, c1


def _textbox_d4(h, x, y, idx):
    # d=-4 TextBox: X@20 Y@24 text-index@28 (0xFFFFFFFF = no text)
    r = _rec(129, h, _u32s(x, y, idx & 0xFFFFFFFF))
    assert len(r) == 32
    return r


def _base_chart_d4():
    c3, c2, c1 = _cond_d4(_h(30), _h(31), _h(32))
    return [
        (1, ROUTINE, _step_d4(_h(1), _h(2), 100, 40, "Step_001")),
        (2, ROUTINE, _descbox_d4(_h(2))),
        (3, ROUTINE, _trans_d4(_h(3), _h(4), _h(30), 100, 140, "Tran_001")),
        (4, ROUTINE, _descbox_d4(_h(4))),
        (30, ROUTINE, c3),
        (31, 30, c2),
        (32, 31, c1),
    ]


def _decode_d4(rows, v20map):
    cur = seeded_cursor()
    cur.executemany("INSERT INTO nameless VALUES (?,?,?)", rows)
    return decode_sfc(cur, ROUTINE, _prove_sheet=SHEET, textbox_text={},
                      textbox_text_v20=v20map)


def test_v20_textbox_resolves_text_by_index():
    rows = _base_chart_d4()
    rows.append((5, ROUTINE, _textbox_d4(_h(5), 20, 200, 0)))
    out = _decode_d4(rows, {0: "Wait 0.5 seconds\r\nbetween reads"})
    assert out is not None
    assert ('<TextBox ID="2" X="20" Y="200" Width="0">'
            '<Text><![CDATA[Wait 0.5 seconds\r\nbetween reads]]>'
            '</Text></TextBox>') in out


def test_v20_textbox_ffffffff_stays_empty():
    # the 0xFFFFFFFF sentinel means "no text": empty self-closing TextBox even
    # when the routine's cid has an FO_0 record.
    rows = _base_chart_d4()
    rows.append((5, ROUTINE, _textbox_d4(_h(5), 20, 200, 0xFFFFFFFF)))
    out = _decode_d4(rows, {0: "should not appear"})
    assert out is not None
    assert '<TextBox ID="2" X="20" Y="200" Width="0"/>' in out
    assert "should not appear" not in out


def test_v20_textbox_missing_index_fails_closed():
    # index present but no matching FO row -> empty (no wrong text).
    rows = _base_chart_d4()
    rows.append((5, ROUTINE, _textbox_d4(_h(5), 20, 200, 3)))
    out = _decode_d4(rows, {0: "Wait"})
    assert out is not None
    assert '<TextBox ID="2" X="20" Y="200" Width="0"/>' in out
    assert "Wait" not in out
