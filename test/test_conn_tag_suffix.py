"""Unit tests for the Connection Input/OutputTagSuffix derivation.

The authoritative suffix is the backing I/O tag's comp name
('&<modhex>[:<slot>]:<suffix>', reached via the connection record's ext-attr
0x190/0x191); the first-EPATH-instance heuristic remains only as the fallback
for records without the attribute.
"""

import struct
from types import SimpleNamespace

from acd.l5x.connections import _conn_backing_suffix, _conn_modern_attrs

try:
    from .seeded_db import seeded_cursor
except ImportError:   # collected with test/ as the rootdir
    from seeded_db import seeded_cursor


def _cp(cpath=b"\x20\x04\x24\x64", in_size=4, out_size=0):
    return SimpleNamespace(
        priority=None, input_connection_type=None,
        input_production_trigger=None, cpath_words=0, cpath_raw=cpath,
        input_size=in_size, output_size=out_size, timeout_multiplier=None,
        network_delay_multiplier=None, max_observed_delay_raw=None,
        reaction_time_units=None)


def test_backing_suffix_from_comp_name():
    cur = seeded_cursor(comps=[(0x123, 0, "&5eefcfac:1:SO", 0, 256, b"")])
    ea = {0x191: struct.pack("<I", 0x123)}
    assert _conn_backing_suffix(cur, ea, 0x191) == "SO"


def test_backing_suffix_slotless_form():
    cur = seeded_cursor(comps=[(0x124, 0, "&5eefcfac:I1", 0, 256, b"")])
    ea = {0x190: struct.pack("<I", 0x124)}
    assert _conn_backing_suffix(cur, ea, 0x190) == "I1"


def test_backing_suffix_fails_closed():
    cur = seeded_cursor(comps=[(0x125, 0, "NotABackingTag", 0, 256, b"")])
    assert _conn_backing_suffix(
        cur, {0x190: struct.pack("<I", 0x125)}, 0x190) is None
    assert _conn_backing_suffix(cur, {}, 0x190) is None
    assert _conn_backing_suffix(cur, {0x190: b"\x01"}, 0x190) is None


def test_modern_attrs_prefers_backing_suffix_over_heuristic():
    # Assembly instance 0x64 (not 1, not a safety instance) -> heuristic 'I';
    # the backing-tag suffix overrides it.
    out = _conn_modern_attrs(_cp(), 49, in_sfx="SI")
    assert out["InputTagSuffix"] == "SI"
    out = _conn_modern_attrs(_cp(), 49)
    assert out["InputTagSuffix"] == "I"


def test_modern_attrs_size_gate_still_applies():
    # No input side -> no suffix even when the backing tag resolves.
    out = _conn_modern_attrs(_cp(in_size=0), 49, in_sfx="SI")
    assert "InputTagSuffix" not in out
