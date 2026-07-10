"""Unit tests for the shared module-identity recovery chain.

``_module_identity_e1`` is the single implementation of the three recovery
copies that had drifted apart (ModuleBuilder.build, the _pass_modules modid
map, the :C-owner map). Tier order: (1) parse the truncated comps ``record``
buffer and take ext-attr 0x001; (2) alias the identity stored inline behind
the 44 02 00 00 marker, trusted only on a record that parsed as a cip-0x69
module; (3) recover from the untruncated comps_full stream (cip-checked at
body+10). comment_id comes from the parsed prelude, else from comps_full but
only when comps_full yielded a usable (>= 0x30) blob -- callers map a None
comment_id to the all-zero fallback Module.
"""

import sqlite3
import struct

from acd.l5x.module_builder import _module_identity_e1

LONG_OFF = 148   # CompsRecord._LONG_BODY_OFF

MODID = 0x333


def _identity(size=0x40) -> bytes:
    b = bytearray(size)
    struct.pack_into("<I", b, 0x2C, MODID)
    return bytes(b)


def _record(cip_type=0x69, comment_id=7, attrs=()) -> bytes:
    """A truncated comps `record` buffer RxGeneric can parse."""
    rec = struct.pack("<IIHHH", 1, 2, 3, cip_type, comment_id) + bytes(60)
    rec += struct.pack("<II", 0, len(attrs) + 1)
    for attr_id, value in attrs:
        rec += struct.pack("<II", attr_id, len(value)) + value
    return rec


def _cur(full_rows=()):
    con = sqlite3.connect(":memory:")
    cur = con.cursor()
    cur.execute("CREATE TABLE comps_full (object_id INTEGER, record BLOB)")
    for oid, rec in full_rows:
        cur.execute("INSERT INTO comps_full VALUES (?, ?)", (oid, rec))
    return cur


def _full_record(cip_type=0x69, comment_id=9, attrs=()) -> bytes:
    """An untruncated comps_full payload (long-header: 148B header + body)."""
    return b"\x00" * LONG_OFF + _record(cip_type, comment_id, attrs)


def test_tier1_record_attr_0x001():
    raw = _record(attrs=[(0x001, _identity())])
    e1, cid, src = _module_identity_e1(_cur(), 1, raw, short_header=False)
    assert src == "record" and cid == 7
    assert struct.unpack_from("<I", e1, 0x2C)[0] == MODID


def test_tier2_marker_only_on_parsed_module_record():
    # cip-0x69 record with no 0x001 attr; identity inline behind the marker.
    raw = _record() + b"\x44\x02\x00\x00" + _identity()
    e1, cid, src = _module_identity_e1(_cur(), 1, raw, short_header=False)
    assert src == "marker" and cid == 7
    assert struct.unpack_from("<I", e1, 0x2C)[0] == MODID


def test_marker_not_trusted_on_unparseable_buffer():
    # A garbage buffer that happens to contain the marker must fall through
    # to comps_full, not alias whatever follows the coincidental bytes.
    raw = b"\x00" * 8 + b"\x44\x02\x00\x00" + _identity()
    full = _full_record(attrs=[(0x001, _identity())])
    e1, cid, src = _module_identity_e1(
        _cur([(1, full)]), 1, raw, short_header=False)
    assert src == "full" and cid == 9
    assert struct.unpack_from("<I", e1, 0x2C)[0] == MODID


def test_tier3_parse_failure_recovers_from_comps_full():
    full = _full_record(attrs=[(0x001, _identity())])
    e1, cid, src = _module_identity_e1(
        _cur([(1, full)]), 1, b"\x00" * 8, short_header=False)
    assert src == "full" and cid == 9
    assert struct.unpack_from("<I", e1, 0x2C)[0] == MODID


def test_not_a_module_yields_no_comment_id():
    # cip 0x68 in both the record buffer and comps_full: not provably a
    # module -> comment_id None (callers emit the all-zero fallback Module).
    raw = _record(cip_type=0x68, attrs=[(0x001, _identity())])
    full = _full_record(cip_type=0x68, attrs=[(0x001, _identity())])
    e1, cid, src = _module_identity_e1(
        _cur([(1, full)]), 1, raw, short_header=False)
    assert cid is None and e1 == b""


def test_unusable_comps_full_keeps_comment_id_none():
    # Parse failure + a cip-0x69 comps_full row whose 0x001 is too short:
    # the blob is not adopted and comment_id stays None, preserving the
    # all-zero fallback mapping.
    full = _full_record(attrs=[(0x001, b"\x00" * 8)])
    e1, cid, src = _module_identity_e1(
        _cur([(1, full)]), 1, b"\x00" * 8, short_header=False)
    assert cid is None and len(e1) < 0x30


def test_parsed_comment_id_survives_comps_full_adoption():
    # Record parses (cid 7) but its 0x001 is short and there is no marker;
    # the blob comes from comps_full (cid 9) while comment_id stays the
    # parsed prelude's.
    raw = _record(attrs=[(0x001, b"\x00" * 8)])
    full = _full_record(attrs=[(0x001, _identity())])
    e1, cid, src = _module_identity_e1(
        _cur([(1, full)]), 1, raw, short_header=False)
    assert src == "full" and cid == 7
    assert struct.unpack_from("<I", e1, 0x2C)[0] == MODID
