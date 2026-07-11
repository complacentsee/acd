"""Unit tests for the record-length bounding in
acd.l5x.module_builder._build_rxdata_holders (P6.7a(2)).

On a long-header project each RxDataCollection child's raw is trimmed to its
declared record length (comps_family.record_length - 148) so the
<public>/<UDCN>/<CF> raw-tail scans never read the appended sub-blobs the
size-eos comps buffer exposes. When no declared length is stored the raw is
left as-is; short-header records are left as-is. (The declared length used to
be read from a comps_full side table, retired in P6.9 C8 in favour of the
comps_family.record_length column.)
"""

import struct

from acd.l5x.module_builder import _build_rxdata_holders

try:
    from seeded_db import seeded_cursor
except ImportError:
    from test.seeded_db import seeded_cursor

_FAFA = 64250   # a live holder's winner family


def _child_body(cid, body_len, extra=b""):
    """A comps `record` (body) at least ``body_len`` bytes, cid at [12:14],
    plus optional appended bytes (the post-flip sub-blob region)."""
    b = bytearray(max(body_len, 14))
    b[12:14] = struct.pack("<H", cid)
    return bytes(b) + extra


def _seed(cid=0x1234, declared_body=200, appended=300):
    """Long-header collection + one child. The comps body carries the declared
    region plus ``appended`` extra bytes (simulating the un-truncated buffer);
    comps_family declares record_length = 148 + declared_body for the child."""
    child_oid = 5001
    body = _child_body(cid, declared_body, extra=b"\x99" * appended)
    record_length = 148 + declared_body
    comps = [
        (100, 0, "RxDataCollection", 0, 0, b"\x00" * 20),
        (child_oid, 100, "$hash$", 0, 256, body),
    ]
    comps_family = [(child_oid, _FAFA, 1, record_length)]
    return (seeded_cursor(comps=comps, comps_family=comps_family),
            cid, child_oid, declared_body)


def test_long_header_trims_to_declared_length():
    cur, cid, child_oid, declared = _seed(appended=300)
    holders = _build_rxdata_holders(cur, short_header=False)
    (oid, raw), = holders[cid]
    assert oid == child_oid
    assert len(raw) == declared        # appended 300 bytes trimmed off


def test_short_header_left_untrimmed():
    cur, cid, child_oid, declared = _seed(appended=300)
    holders = _build_rxdata_holders(cur, short_header=True)
    (oid, raw), = holders[cid]
    assert len(raw) == declared + 300  # short-header buffers are already size-eos


def test_noop_when_buffer_within_declared_length():
    # An already-truncated buffer (no appended bytes) is left untouched.
    cur, cid, child_oid, declared = _seed(appended=0)
    holders = _build_rxdata_holders(cur, short_header=False)
    (oid, raw), = holders[cid]
    assert len(raw) == declared


def test_missing_record_length_leaves_raw_untouched():
    cid, child_oid = 0x1234, 5001
    body = _child_body(cid, 200, extra=b"\x99" * 300)
    cur = seeded_cursor(comps=[
        (100, 0, "RxDataCollection", 0, 0, b"\x00" * 20),
        (child_oid, 100, "$hash$", 0, 256, body),
    ])  # no comps_family row -> LEFT JOIN yields NULL record_length
    holders = _build_rxdata_holders(cur, short_header=False)
    (oid, raw), = holders[cid]
    assert len(raw) == 500             # untouched when no declared length available


def test_cid_key_survives_trim():
    # The cid key (raw[12:14]) sits well before any trim boundary.
    cur, cid, child_oid, declared = _seed(cid=0xBEEF, appended=300)
    holders = _build_rxdata_holders(cur, short_header=False)
    assert cid in holders and len(holders[cid][0][1]) == declared
