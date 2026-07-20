"""Unit tests for <QuickWatchLists> and <ParameterConnections> renderers."""
import struct

from acd.l5x.controller_lists import (
    build_parameter_connections,
    build_quick_watch_lists,
)

try:
    from .seeded_db import seeded_cursor
except ImportError:
    from seeded_db import seeded_cursor


def _cstr(s):
    return b"\xff\xfe\xff" + bytes([len(s)]) + s.encode("utf-16-le")


def _qwl_record(name, entries):
    # entries: (ref_str, marker); ref_str like '@0000000a@'
    rec = bytearray(16)                     # header (len/flags/parent/oid)
    rec += struct.pack("<I", 0x0001089E)    # class @0x10
    rec += _cstr(name)                       # name @0x14
    rec += struct.pack("<I", len(entries))
    for ref, marker in entries:
        rec += _cstr(ref) + struct.pack("<H", marker) + b"\x00" * 10
    return bytes(rec)


def _pc_record(direction, scope_oid, s1, s2):
    rec = bytearray(16)                      # header
    rec += struct.pack("<I", 0x0001089F)     # class @0x10
    rec += struct.pack("<I", 0xFFFFFFFF)     # filler @0x14
    rec += struct.pack("<I", direction)      # @0x18
    rec += struct.pack("<I", scope_oid)      # @0x1c
    rec += _cstr(s1) + _cstr(s2)
    return bytes(rec)


def _cur(comps, nameless):
    cur = seeded_cursor(comps=comps)
    cur.executemany("INSERT INTO nameless VALUES (?,?,?)", nameless)
    return cur


def test_qwl_controller_entries_sorted_lists_sorted():
    comps = [
        (10, 0, "gBeta", 0, 256, b""),
        (11, 0, "gAlpha", 0, 256, b""),
    ]
    nameless = [
        (1, 0, _qwl_record("Zeta", [("@0000000a@", 0x6B), ("@0000000b@", 0x6B)])),
        (2, 0, _qwl_record("Able", [("@0000000b@", 0x6B)])),
    ]
    out = build_quick_watch_lists(_cur(comps, nameless))
    # lists alphabetical: Able before Zeta; within Zeta, gAlpha before gBeta.
    assert out == (
        '<QuickWatchLists>'
        '<QuickWatchList Name="Able">'
        '<WatchTag Specifier="gAlpha" Scope=""/>'
        '</QuickWatchList>'
        '<QuickWatchList Name="Zeta">'
        '<WatchTag Specifier="gAlpha" Scope=""/>'
        '<WatchTag Specifier="gBeta" Scope=""/>'
        '</QuickWatchList>'
        '</QuickWatchLists>')


def test_qwl_program_scope_after_controller():
    comps = [
        (10, 0, "gCtrl", 0, 256, b""),
        (20, 30, "pTag", 0, 256, b""),        # tag in a program
        (30, 40, "MyProg", 0, 256, b""),       # the program
        (40, 0, "RxProgramCollection", 0, 256, b""),
    ]
    nameless = [
        (1, 0, _qwl_record("L", [("@00000014@", 0x68), ("@0000000a@", 0x6B)])),
    ]
    out = build_quick_watch_lists(_cur(comps, nameless))
    # controller entry first, program-scope entry last with its program Scope.
    assert ('<WatchTag Specifier="gCtrl" Scope=""/>'
            '<WatchTag Specifier="pTag" Scope="MyProg"/>') in out


def test_qwl_unresolved_ref_drops_block():
    nameless = [(1, 0, _qwl_record("L", [("@deadbeef@", 0x6B)]))]
    assert build_quick_watch_lists(_cur([], nameless)) == ""


def test_qwl_absent_is_empty():
    assert build_quick_watch_lists(_cur([], [])) == ""


def test_parameter_connections_direction_ordering_and_endpoints():
    comps = [
        (5, 0, "RTC", 0, 256, b""),           # scope program
        (0xA, 0, "qA", 0, 256, b""),
        (0xB, 0, "qB", 0, 256, b""),
        (0x14, 0, "Ig", 0, 256, b""),
        (0x1E, 0, "Conn", 0, 256, b""),
        (0x28, 0, "M", 0, 256, b""),
    ]
    # stored order: dir2, dir3  -> emit dir3 first, then dir2 (reversed among dir2)
    nameless = [
        (1, 0, _pc_record(2, 5, "@00000014@.@0000001e@.@00000028@", "@0000000a@")),
        (2, 0, _pc_record(3, 5, "@0000000b@", "@00000014@.@0000001e@.@00000028@")),
    ]
    out = build_parameter_connections(_cur(comps, nameless))
    assert out == (
        '<ParameterConnections>'
        '<ParameterConnection EndPoint1="\\RTC.qB" EndPoint2="Ig.Conn.M"/>'
        '<ParameterConnection EndPoint1="Ig.Conn.M" EndPoint2="\\RTC.qA"/>'
        '</ParameterConnections>')


def test_parameter_connections_absent_is_empty():
    assert build_parameter_connections(_cur([], [])) == ""
