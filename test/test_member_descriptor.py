"""Unit tests for the MemberDescriptor blob grammar (kaitai).

The grammar decodes a datatype's per-member descriptor (extended attribute
0x6E + i): the UTF-16LE inline name span, radix, data-type id, dimension,
the BIT-overlay fields (offset / bit_number / host_ordinal / target_key),
hidden, the legacy 0x74 access word (whose presence doubles as the
completeness gate the old fixed-offset readers enforced), and the real
ExternalAccess byte at 0xA0. Every field is size-guarded and reads as None
when the blob truncates before it.
"""

import struct

from acd.generated.comps.member_descriptor import MemberDescriptor

NAME = "MyMember".encode("utf-16-le")


def _blob() -> bytearray:
    b = bytearray(0xA8)   # nominal 168 bytes
    b[0:len(NAME)] = NAME
    struct.pack_into(
        "<IIIIIIII", b, 0x54,
        5,            # radix
        0xBEEF,       # data_type_id
        3,            # dimension
        0x10,         # offset
        7,            # bit_number
        0x800,        # host_ordinal
        0xFFFFFFFF,   # target_key
        1,            # hidden
    )
    struct.pack_into("<I", b, 0x74, 1)   # legacy access word
    b[0xA0] = 2                          # ExternalAccess: Read Only
    return b


def test_full_blob_decodes_every_field():
    m = MemberDescriptor.from_bytes(bytes(_blob()))
    assert m.name_raw.startswith(NAME)
    assert (m.radix, m.data_type_id, m.dimension) == (5, 0xBEEF, 3)
    assert (m.offset, m.bit_number, m.host_ordinal) == (0x10, 7, 0x800)
    assert m.target_key == 0xFFFFFFFF
    assert (m.hidden, m.legacy_access_word, m.external_access_byte) == (1, 1, 2)


def test_name_field_clamps_to_its_span_and_truncation():
    # The name span ends at 0x53 (radix starts at 0x54).
    assert len(MemberDescriptor.from_bytes(bytes(_blob())).name_raw) == 0x54
    # A blob shorter than the span yields the bytes that remain.
    m = MemberDescriptor.from_bytes(bytes(_blob()[:0x20]))
    assert m.name_raw == bytes(_blob()[:0x20])
    # Below the 2-byte minimum the name reads as absent.
    assert MemberDescriptor.from_bytes(b"\x01").name_raw is None


def test_completeness_gate_boundary_0x78():
    b = bytes(_blob())
    # One byte short of the legacy word -> None (old readers raised here);
    # at the boundary -> present while the 0xA0 byte is still absent.
    short = MemberDescriptor.from_bytes(b[:0x77])
    assert short.legacy_access_word is None
    assert short.hidden == 1 and short.target_key == 0xFFFFFFFF
    at = MemberDescriptor.from_bytes(b[:0x78])
    assert at.legacy_access_word == 1
    assert at.external_access_byte is None


def test_external_access_byte_boundary_0xa1():
    b = bytes(_blob())
    assert MemberDescriptor.from_bytes(b[:0xA0]).external_access_byte is None
    assert MemberDescriptor.from_bytes(b[:0xA1]).external_access_byte == 2


def test_bit_overlay_fields_guarded_individually():
    b = bytes(_blob())
    m = MemberDescriptor.from_bytes(b[:0x70])
    # 0x70 holds offset/bit_number/host_ordinal/target_key but not hidden.
    assert (m.offset, m.bit_number, m.host_ordinal) == (0x10, 7, 0x800)
    assert m.target_key == 0xFFFFFFFF and m.hidden is None
    m2 = MemberDescriptor.from_bytes(b[:0x58])
    assert m2.radix == 5 and m2.data_type_id is None
