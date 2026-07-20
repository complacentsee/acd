"""Unit tests for <SafetyInfo> attribute derivation.

Covers the SafetyLevel enum read (replacing a hardcode) and the suppression of
the spurious all-zero @SafetySignature that an unsigned project stores.
"""
import struct

from acd.l5x import elements as E

try:
    from .seeded_db import seeded_cursor
except ImportError:
    from seeded_db import seeded_cursor

_ANCHOR = bytes.fromhex("34030000ffffffff00000000ffffffff")


def _safety_controller_record(level_byte, locked=0, cfg_io=0, anch_off=58):
    """A minimal SafetyController comps record with the anchor at `anch_off`."""
    rec = bytearray(anch_off) + bytearray(_ANCHOR) + bytearray(300)
    rec[anch_off + 78] = locked
    rec[anch_off + 80] = cfg_io
    rec[anch_off + 214] = level_byte
    return bytes(rec)


def _cur_with_safety_controller(rec):
    return seeded_cursor(comps=[(1, 0, "SafetyController", 0, 256, rec)])


def test_safety_level_sil3_from_enum():
    s = E._safety_info_attr_string(
        _cur_with_safety_controller(_safety_controller_record(3)), False)
    assert 'SafetyLevel="SIL3/PLe"' in s


def test_safety_level_sil2_from_enum():
    s = E._safety_info_attr_string(
        _cur_with_safety_controller(_safety_controller_record(2)), False)
    assert 'SafetyLevel="SIL2/PLd"' in s


def test_safety_level_unknown_enum_omitted():
    # Fail closed: any value that is not a known SIL enum drops the attribute.
    s = E._safety_info_attr_string(
        _cur_with_safety_controller(_safety_controller_record(9)), False)
    assert "SafetyLevel" not in s


def test_safety_level_absent_for_short_header():
    s = E._safety_info_attr_string(
        _cur_with_safety_controller(_safety_controller_record(3)), True)
    assert "SafetyLevel" not in s


def _nameless_948(sigword, date_utf16=b"", time_utf16=b""):
    nr = bytearray(24)
    nr[8:16] = bytes.fromhex("948fc2c747add9f3")
    nr[20:24] = struct.pack("<I", sigword)
    nr += date_utf16 + b"\x00\x00" + time_utf16 + b"\x00\x00"
    return bytes(nr)


def test_zero_signature_record_is_suppressed():
    cur = seeded_cursor()
    cur.execute("INSERT INTO nameless VALUES (?,?,?)", (1, 0, _nameless_948(0)))
    # rec (2nd arg) carries no long-header signature either -> None overall.
    assert E._safety_signature_attr_value(cur, b"\x00" * 64) is None


def test_nonzero_signature_record_is_kept():
    cur = seeded_cursor()
    cur.execute("INSERT INTO nameless VALUES (?,?,?)",
                (1, 0, _nameless_948(0x12345678)))
    val = E._safety_signature_attr_value(cur, b"\x00" * 64)
    assert val is not None and val.startswith("12345678")
