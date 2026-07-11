"""Unit tests for the comments record grammar + CommentsRecord.parse flow.

Pins the P6.5 grammar expansion: the body switch's `_` default parses every
non-enumerated record_type as a utf_16_record (they share the operand
layout), record_type 12 keeps a raw-bytes body for the UDI parser, and --
critically -- parse() still DROPS default-parsed types that failed the hand
walkers' operand validation gates, exactly as the old raw-branch
AttributeError did. The validated hand walkers remain the decoders of
record; the grammar formalizes the layout.
"""

import struct
from types import SimpleNamespace

from acd.generated.comments.fafa_coments import FafaComents
from acd.record.comments import CommentsRecord

OID = 0x0BEEF


def _record(rt, body, seq=1, srl=0x6B, parent=0x70068) -> bytes:
    return (struct.pack("<I", 0x0A + len(body))
            + struct.pack("<HHHI", seq, rt, srl, parent)
            + body)


def _operand_body(operand=".5", text="hello", object_id=OID) -> bytes:
    return (bytes(8) + struct.pack("<I", object_id) + bytes(4)
            + operand.encode("utf-16-le") + b"\x00\x00"
            + bytes(12)
            + text.encode() + b"\x00")


def _udi_body(udi_type="UDI_HISTORY", text="rev note") -> bytes:
    return (bytes(8) + struct.pack("<II", 7, 0)
            + udi_type.encode("utf-16-le") + b"\x00\x00"
            + text.encode() + b"\x00")


def _dat(raw):
    return SimpleNamespace(identifier=64250,
                           record=SimpleNamespace(record_buffer=raw))


def test_default_case_parses_other_types_as_operand_records():
    r = FafaComents.from_bytes(_record(8, _operand_body()))
    assert r.body.tag_reference.value == ".5"
    assert r.body.object_id == OID
    assert r.body.record_string == "hello"


def test_type12_body_stays_raw_for_the_udi_parser():
    r = FafaComents.from_bytes(_record(12, _udi_body()))
    assert bytes(r.body.data) == _udi_body()


def test_parse_recovers_valid_operand_comment():
    row = CommentsRecord.parse(_dat(_record(8, _operand_body())))
    assert row is not None
    assert row[6] == ".5" and row[3] == "hello" and row[2] == OID


def test_parse_still_drops_gate_failing_default_types():
    # An operand without the './[' qualifier prefix fails the hand walker's
    # validation gate; before the grammar default existed such a record fell
    # to the raw-bytes branch and dropped -- it must still drop.
    row = CommentsRecord.parse(_dat(_record(8, _operand_body(operand="x5"))))
    assert row is None


def test_parse_udi_revision_note_roundtrip():
    row = CommentsRecord.parse(_dat(_record(12, _udi_body())))
    assert row is not None
    assert row[6] == "__REVISION_NOTE__" and row[3] == "rev note"
    # Non-history UDI records are not stored.
    assert CommentsRecord.parse(
        _dat(_record(12, _udi_body(udi_type="UDI_OTHER")))) is None


def test_parse_classic_operand_type_unchanged():
    row = CommentsRecord.parse(_dat(_record(3, _operand_body(operand="[2]",
                                                             text="t"))))
    assert row is not None and row[6] == "[2]" and row[3] == "t"
