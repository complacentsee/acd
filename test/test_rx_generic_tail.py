"""Unit tests for the RxGeneric extended-attribute tail (kaitai grammar).

The generated parser reads ``count_record - 1`` counted attribute records and
then ONE trailing ``last_attribute_record`` (whose data spans ``len_value - 4``
bytes) -- the record's final attribute, which the counted loop never reaches.
The whole tail is a lazy instance, so a record whose tail is encrypted
(source-protected) or has a garbage ``count_record`` still exposes its
plaintext prelude and main_record; accessing ``extended_records`` raises
exactly where the old eager parse used to, which the elements.py fallback
paths rely on.

Record layout produced by the builder below:
    [14B prelude][60B main_record][u32 len_record][u32 count_record]
    then (count_record - 1) x (u32 attribute_id, u32 len_value, len_value
    bytes), then optionally the last record (u32 id, u32 len_value,
    len_value - 4 bytes).
"""

import struct

import pytest

from acd.generated.comps.rx_generic import RxGeneric


def _record(attrs, last=None, declared_count=None, tail_extra=b"") -> bytes:
    """Assemble a plaintext RxGeneric record from (id, value) pairs.

    ``count_record`` counts the trailing slot too: the parser reads
    ``count_record - 1`` counted attrs, then the optional last record.
    """
    rec = struct.pack("<IIHHH", 1, 2, 3, 0x68, 7) + bytes(60)
    count = (len(attrs) + 1) if declared_count is None else declared_count
    rec += struct.pack("<II", 0, count)
    for attr_id, value in attrs:
        rec += struct.pack("<II", attr_id, len(value)) + value
    if last is not None:
        attr_id, value = last
        rec += struct.pack("<II", attr_id, len(value) + 4) + value
    return rec + tail_extra


def test_counted_attrs_and_last_record():
    r = RxGeneric.from_bytes(
        _record([(0x01, b"AB"), (0x02, b"CDEF")], last=(0x6A, b"XY"))
    )
    assert [(a.attribute_id, bytes(a.value)) for a in r.extended_records] == [
        (0x01, b"AB"),
        (0x02, b"CDEF"),
    ]
    assert r.last_attribute_record.attribute_id == 0x6A
    assert bytes(r.last_attribute_record.value) == b"XY"


def test_empty_tail_has_no_last_record():
    r = RxGeneric.from_bytes(_record([]))
    assert r.extended_records == []
    # The guarded field is simply absent; consumers use getattr.
    assert getattr(r, "last_attribute_record", None) is None


def test_garbage_count_keeps_prelude_readable():
    """A source-protected/garbage tail must not defeat the plaintext prelude,
    but the ext-attr access must still raise (the fallback paths catch it)."""
    r = RxGeneric.from_bytes(_record([(0x01, b"AB")], declared_count=0x7FFFFFF0))
    assert r.cip_type == 0x68
    assert r.comment_id == 7
    assert r.main_record is not None
    with pytest.raises(Exception):
        r.extended_records


def test_short_trailing_garbage_is_ignored():
    """A tail shorter than one attr header (8 bytes) is skipped, not fatal."""
    r = RxGeneric.from_bytes(_record([(0x01, b"AB")], tail_extra=b"\x00\x01\x02"))
    assert [(a.attribute_id, bytes(a.value)) for a in r.extended_records] == [
        (0x01, b"AB")
    ]
    assert getattr(r, "last_attribute_record", None) is None


def test_bogus_last_len_value_skips_value():
    """A last record whose len_value overruns the buffer (or is < 4) keeps its
    id readable but yields no value, mirroring the tolerant hand-walkers."""
    raw = _record([(0x01, b"AB")]) + struct.pack("<II", 0x6A, 0xFFFF) + b"xx"
    r = RxGeneric.from_bytes(raw)
    last = r.last_attribute_record
    assert last.attribute_id == 0x6A
    assert getattr(last, "value", None) is None
