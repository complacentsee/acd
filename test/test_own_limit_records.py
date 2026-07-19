"""Unit tests for the component-OWN engineering-limit comment records.

A long-header tag's own @Min/@Max is an rt-1 record (kind byte 0x02/0x03 at
raw[27]) whose value is the trailing CIP-typed integer -- decoded by
CommentsRecord._parse_long_own_limit and staged as a member_ref=kind row with
an EMPTY tag_reference. The structural gates (exact length, integer CIP code,
width-consistent sub_record_length) fail closed on everything else.
"""

import struct
from types import SimpleNamespace

from acd.record.comments import CommentsRecord

PARENT = 0x70C_006B


def _limit_record(kind, value, cip=0xC4, width=4, rev=1, srl=None,
                  parent=PARENT, token=0) -> bytes:
    srl = (14 + width) if srl is None else srl
    body = bytearray(18 + srl)
    struct.pack_into("<H", body, 2, token)   # raw[16:18] = member token
    body[13] = kind
    struct.pack_into("<H", body, 14, rev)
    struct.pack_into("<I", body, 18, cip)
    body[len(body) - width:] = value.to_bytes(width, "little", signed=True)
    return (struct.pack("<I", 0x0A + len(body))
            + struct.pack("<HHHI", 1, 1, srl, parent)
            + bytes(body))


def _dat(raw):
    return SimpleNamespace(identifier=64250,
                           record=SimpleNamespace(record_buffer=raw))


def test_dint_max_parses_with_kind_and_empty_operand():
    row = CommentsRecord.parse(_dat(_limit_record(0x03, 2147483647, rev=7)))
    assert row is not None
    assert row[3] == "2147483647"    # record_string = the value
    assert row[8] == 0x03            # member_ref = kind (Max)
    assert row[6] == ""              # tag_reference: component-own
    assert row[2] == 0               # object_id inert to description lookups
    assert row[5] == PARENT
    assert row[10] == 7              # revision appended by parse()


def test_dint_min_parses_negative():
    row = CommentsRecord.parse(_dat(_limit_record(0x02, -2147483648)))
    assert row is not None and row[3] == "-2147483648" and row[8] == 0x02


def test_int_width_follows_cip_code():
    row = CommentsRecord.parse(_dat(_limit_record(0x03, -300, cip=0xC3,
                                                  width=2)))
    assert row is not None and row[3] == "-300"


def test_fail_closed_gates():
    # REAL (float formatting unwitnessed for this form).
    assert CommentsRecord._parse_long_own_limit(
        _limit_record(0x03, 1, cip=0xCA)) is None
    # Unknown CIP code.
    assert CommentsRecord._parse_long_own_limit(
        _limit_record(0x03, 1, cip=0x99)) is None
    # sub_record_length inconsistent with the type width.
    assert CommentsRecord._parse_long_own_limit(
        _limit_record(0x03, 1, srl=20)) is None
    # Not a limit kind byte.
    assert CommentsRecord._parse_long_own_limit(
        _limit_record(0x01, 1)) is None


def test_member_token_staged_in_object_id():
    # A definition-scope (cip 0x6C) record carries the member token at raw[16:18];
    # it is staged in the object_id slot for load_definition_member_limits.
    row = CommentsRecord.parse(
        _dat(_limit_record(0x03, 7, cip=0xC2, width=1,
                           parent=(0x036A << 16) | 0x6C, token=0x75B0)))
    assert row is not None
    assert row[2] == 0x75B0          # object_id = member token
    assert row[6] == ""              # empty operand
    assert row[8] == 0x03            # kind


def test_load_definition_member_limits_end_to_end():
    import sqlite3
    from acd.l5x.base import load_definition_member_limits
    db = sqlite3.connect(":memory:")
    cur = db.cursor()
    cur.execute("CREATE TABLE comps(object_id int, parent_id int, "
                "comp_name text, record BLOB)")
    cur.execute("CREATE TABLE member_resolve(k INTEGER PRIMARY KEY, name TEXT)")
    cur.execute("CREATE TABLE comments(seq_number int, sub_record_length int, "
                "object_id int, record_string text, record_type int, "
                "parent int, tag_reference text, rung_content int, "
                "member_ref int, owner_ref int, revision int)")
    CID, TOK = 0x036A, 0x75B0
    # UDT 'SP_IOL_EX260' -> RxTypeMemberCollection -> member comp (cip 0x6C,
    # comment_id CID at record[12:14]).
    mrec = bytearray(14)
    struct.pack_into("<H", mrec, 10, 0x6C)
    struct.pack_into("<H", mrec, 12, CID)
    cur.execute("INSERT INTO comps VALUES (10, 0, 'SP_IOL_EX260', NULL)")
    cur.execute("INSERT INTO comps VALUES (20, 10, 'RxTypeMemberCollection', "
                "NULL)")
    cur.execute("INSERT INTO comps VALUES (30, 20, 'Port_Number', ?)",
                (bytes(mrec),))
    cur.execute("INSERT INTO member_resolve VALUES (?, 'Port_Number')",
                ((CID << 16) | TOK,))
    for kind, val in ((2, "0"), (3, "7")):
        cur.execute("INSERT INTO comments VALUES "
                    "(0,15,?,?,1,?,'',0,?,?,0)",
                    (TOK, val, (CID << 16) | 0x6C, kind, kind))
    got = load_definition_member_limits(cur)
    assert got == {("SP_IOL_EX260", "PORT_NUMBER"): ("0", "7")}


def test_load_definition_member_limits_fail_closed_half_pair():
    import sqlite3
    from acd.l5x.base import load_definition_member_limits
    db = sqlite3.connect(":memory:")
    cur = db.cursor()
    cur.execute("CREATE TABLE comps(object_id int, parent_id int, "
                "comp_name text, record BLOB)")
    cur.execute("CREATE TABLE member_resolve(k INTEGER PRIMARY KEY, name TEXT)")
    cur.execute("CREATE TABLE comments(seq_number int, sub_record_length int, "
                "object_id int, record_string text, record_type int, "
                "parent int, tag_reference text, rung_content int, "
                "member_ref int, owner_ref int, revision int)")
    CID, TOK = 0x036A, 0x75B0
    mrec = bytearray(14)
    struct.pack_into("<H", mrec, 10, 0x6C)
    struct.pack_into("<H", mrec, 12, CID)
    cur.execute("INSERT INTO comps VALUES (10, 0, 'D', NULL)")
    cur.execute("INSERT INTO comps VALUES (20, 10, 'RxTypeMemberCollection', "
                "NULL)")
    cur.execute("INSERT INTO comps VALUES (30, 20, 'M', ?)", (bytes(mrec),))
    cur.execute("INSERT INTO member_resolve VALUES (?, 'M')",
                ((CID << 16) | TOK,))
    # only Max present -> withheld
    cur.execute("INSERT INTO comments VALUES (0,15,?,'7',1,?,'',0,3,3,0)",
                (TOK, (CID << 16) | 0x6C))
    assert load_definition_member_limits(cur) == {}
