"""Unit tests for the deleted-module tombstone gate.

A device-collection row whose comps record carries cip word 0x8069 (0x69 with
bit 15 set) is a deleted-module placeholder: it has no identity ext-attrs and
Studio never exports it. Live modules always carry 0x0069.
"""

import struct

from acd.l5x.elements import _is_tombstone_module


def _rec(cip: int, size: int = 64) -> bytes:
    b = bytearray(size)
    struct.pack_into("<H", b, 10, cip)
    return bytes(b)


def test_tombstone_cip_word_is_dropped():
    assert _is_tombstone_module(_rec(0x8069)) is True


def test_live_module_is_kept():
    assert _is_tombstone_module(_rec(0x0069)) is False


def test_short_or_absent_record_is_kept():
    # A record too short to carry the cip word is not a tombstone claim;
    # downstream identity recovery handles it as today.
    assert _is_tombstone_module(b"\x00" * 11) is False
    assert _is_tombstone_module(None) is False


def test_other_deleted_families_are_not_matched():
    # Only the module family's tombstone (0x8069); other high-bit words are
    # not this gate's business.
    assert _is_tombstone_module(_rec(0x8068)) is False
