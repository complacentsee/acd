"""Unit tests for the AOI seal-trailer parser (encoded_data.aoi_seal_trailer).

The seal sits at the END of ext-attr 0x1 as [u64 EditedDate microseconds][u32
SignatureID]([u32 SafetySignatureID])[zero pad]. It is located by the millisecond-
aligned in-range timestamp, NOT by a byte-position walk, so an unsealed definition's
tail cannot masquerade as a seal.
"""

import struct

from acd.l5x.encoded_data import aoi_seal_trailer

TS_2011 = 1312466283500000   # 2011-08-04T13:58:03.500Z (a cfg3 PackMLv3 seal)
TS_2021 = 1631739585494000   # 2021-09-15T20:59:45.494Z (a safety AOI seal)


def _a1(head, ts, sid, ssid=None):
    b = bytes(head) + struct.pack("<Q", ts) + struct.pack("<I", sid)
    if ssid is not None:
        b += struct.pack("<I", ssid)
    return b + bytes(20)  # zero pad to the attribute end


def test_signature_only_trailer():
    r = aoi_seal_trailer(_a1(16, TS_2011, 0x8A6C4E60))
    assert r == ("8A6C4E60", None, TS_2011)


def test_safety_trailer_reads_safety_signature_id():
    r = aoi_seal_trailer(_a1(16, TS_2021, 0xF7205DB4, 0x26462568))
    assert r == ("F7205DB4", "26462568", TS_2021)


def test_zero_signature_id_is_unsealed():
    assert aoi_seal_trailer(_a1(16, TS_2011, 0)) is None


def test_high_zero_signature_bytes():
    # SignatureID with zero high bytes still reads as a full u32.
    r = aoi_seal_trailer(_a1(16, TS_2011, 0x0000ABCD))
    assert r == ("0000ABCD", None, TS_2011)


def test_no_timestamp_anchor_is_not_a_seal():
    # A zero-tailed u32 with no ms-aligned in-range timestamp before it (a plaintext
    # definition's own tail) must NOT be read as a seal.
    plain = bytes(24) + struct.pack("<I", 0x12345678) + bytes(20)
    assert aoi_seal_trailer(plain) is None


def test_non_ms_aligned_timestamp_rejected():
    # A microsecond value that is not millisecond-aligned is not a Studio timestamp.
    assert aoi_seal_trailer(_a1(16, TS_2011 + 1, 0x8A6C4E60)) is None


def test_empty_and_none():
    assert aoi_seal_trailer(None) is None
    assert aoi_seal_trailer(b"") is None
