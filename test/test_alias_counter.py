"""Unit tests for alias resolution recursing into a UDT-nested legacy struct.

A non-BOOL alias that lands inside a COUNTER/TIMER/CONTROL member (which is in
_ALIAS_ELEM_BITS) must resolve to the named sub-member via that struct's TagInfo
layout (e.g. Clear.ACC), not fail closed to the Base fallback. A legacy struct
with no layout keeps failing closed.
"""
from acd.l5x.alias import TagAliasResolver

# COUNTER member layout: hidden control word, then PRE (bit 32) and ACC (bit 64).
_COUNTER = [
    ("CTL", "DINT", 0, None, True, None),
    ("PRE", "DINT", 4, None, False, None),
    ("ACC", "DINT", 8, None, False, None),
]


class _Resolver(TagAliasResolver):
    def __init__(self, layout):
        self._taginfo_layout = layout
        self._short_header = False


def test_recurses_into_counter_acc():
    layout = {
        "UDT_X": [("Clear", "COUNTER", 0, None, False, None)],
        "COUNTER": _COUNTER,
        "@size@COUNTER": 12,
    }
    r = _Resolver(layout)
    # bit 64 = byte 8 = ACC inside the COUNTER member 'Clear'.
    assert r._alias_walk_members("UDT_X", 64, False) == "Clear.ACC"


def test_counter_member_start_is_whole_member():
    layout = {
        "UDT_X": [("Clear", "COUNTER", 0, None, False, None)],
        "COUNTER": _COUNTER,
        "@size@COUNTER": 12,
    }
    r = _Resolver(layout)
    assert r._alias_walk_members("UDT_X", 0, False) == "Clear"


def test_legacy_struct_without_layout_fails_closed():
    # No COUNTER layout entry -> the mid-member recursion cannot resolve, so the
    # walk fails closed (Base fallback), exactly as before.
    layout = {"UDT_X": [("Clear", "COUNTER", 0, None, False, None)]}
    r = _Resolver(layout)
    assert r._alias_walk_members("UDT_X", 64, False) is None


def test_plain_dint_member_unchanged():
    # A non-legacy member resolves as its whole member at its start, untouched.
    layout = {"UDT_X": [("Speed", "DINT", 0, None, False, None)]}
    r = _Resolver(layout)
    assert r._alias_walk_members("UDT_X", 0, False) == "Speed"
