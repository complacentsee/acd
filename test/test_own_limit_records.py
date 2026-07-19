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
                  parent=PARENT) -> bytes:
    srl = (14 + width) if srl is None else srl
    body = bytearray(18 + srl)
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
