"""Unit tests for the comps family/liveness accumulation (P6.9 C1).

``_walk_comps_records`` returns, alongside the dedup winner maps, the per-oid
``fafa_seen`` liveness signal (>=1 FAFA-family record exists) and the dedup
winner's stream identifier. Pinned here on synthetic short-header records
(the short header is identical for both families, so the family accumulation
— which keys only on ``record.identifier`` — is exercised for both): a
dual-family oid is fafa_seen, an FDFD-only oid is not, and the winner is the
record with the largest full stream payload regardless of family order.
"""

import struct
from types import SimpleNamespace

from acd.l5x.export_l5x import _walk_comps_records
from acd.record.comps import CompsRecord
from test.seeded_db import seeded_cursor

FAFA = 64250   # 0xFAFA
FDFD = 65021   # 0xFDFD

_BODY_OFF = 94   # short-header body offset (both families)
_NAME_OFF = 20


def _payload(object_id, name="C", body=b"\x00" * 8) -> bytes:
    buf = bytearray(_BODY_OFF)
    buf[0:4] = struct.pack("<I", _BODY_OFF + len(body))
    buf[8:10] = struct.pack("<H", 1)
    buf[10:12] = struct.pack("<H", 256)
    buf[12:16] = struct.pack("<I", object_id)
    buf[16:20] = struct.pack("<I", 0x42)
    nb = name.encode("utf-16-le") + b"\x00\x00"
    buf[_NAME_OFF:_NAME_OFF + len(nb)] = nb
    return bytes(buf) + body


def _dat(raw, identifier):
    return SimpleNamespace(identifier=identifier,
                           record=SimpleNamespace(record_buffer=raw))


def test_dual_family_oid_is_fafa_seen_and_fafa_wins_on_larger_payload():
    records = [
        _dat(_payload(1, body=b"\xfd" * 4), FDFD),
        _dat(_payload(1, body=b"\xfa" * 9), FAFA),   # strictly larger payload
    ]
    comps, fulls, winner, fafa_seen = _walk_comps_records(records, True)
    assert set(comps) == {1}
    assert fafa_seen == {1}
    assert winner[1] == FAFA
    assert fulls[1] == _payload(1, body=b"\xfa" * 9)


def test_fdfd_only_oid_is_not_fafa_seen():
    records = [_dat(_payload(2, body=b"\xfd" * 6), FDFD)]
    comps, _fulls, winner, fafa_seen = _walk_comps_records(records, True)
    assert set(comps) == {2}
    assert fafa_seen == set()
    assert winner[2] == FDFD


def test_fafa_seen_even_when_fdfd_record_wins_the_dedup():
    # Pathological ordering guard: liveness must come from FAMILY PRESENCE,
    # not from which record wins the payload-length dedup.
    records = [
        _dat(_payload(3, body=b"\xfa" * 4), FAFA),
        _dat(_payload(3, body=b"\xfd" * 9), FDFD),   # larger -> FDFD wins
    ]
    _comps, _fulls, winner, fafa_seen = _walk_comps_records(records, True)
    assert winner[3] == FDFD
    assert fafa_seen == {3}


def test_keep_first_on_equal_payload_length():
    records = [
        _dat(_payload(4, name="First", body=b"\x01" * 5), FAFA),
        _dat(_payload(4, name="Later", body=b"\x02" * 5), FDFD),
    ]
    comps, _fulls, winner, fafa_seen = _walk_comps_records(records, True)
    assert comps[4][2] == "First"
    assert winner[4] == FAFA
    assert fafa_seen == {4}


def test_unparseable_record_is_skipped_but_families_still_accumulate():
    records = [
        _dat(_payload(5), 0x1234),                    # unknown identifier -> None
        _dat(_payload(5, body=b"\x07" * 3), FAFA),
    ]
    comps, _fulls, winner, fafa_seen = _walk_comps_records(records, True)
    assert set(comps) == {5}
    assert winner[5] == FAFA
    assert fafa_seen == {5}


# --- CompsRecord.dead_oids (P6.9 C2/C3 liveness gate) ---------------------- #
# The enumeration/scan gates all funnel through dead_oids: on a long-header
# project a dual/FAFA-live oid (fafa_seen=1) is admitted and an FDFD-only relic
# (fafa_seen=0) is suppressed; on a short-header project the set is empty (the
# realignment is a no-op there; short-header liveness is C6). These pins stand
# in for the "dual PUMP_MOTOR_2 admitted / dead M116 suppressed" invariant.
def _cur_with_family(rows, comps=()):
    return seeded_cursor(comps=comps, comps_family=rows)


def test_dead_oids_long_header_suppresses_fdfd_only_admits_live():
    cur = _cur_with_family([
        (100, FAFA, 1),   # FAFA-live       -> admitted
        (200, FDFD, 1),   # dual (fafa_seen) -> admitted (winner may be FDFD)
        (300, FDFD, 0),   # FDFD-only relic  -> suppressed
    ])
    assert CompsRecord.dead_oids(cur, short_header=False) == frozenset({300})


def test_dead_oids_short_header_is_empty():
    cur = _cur_with_family([(300, FDFD, 0), (400, FDFD, 0)])
    assert CompsRecord.dead_oids(cur, short_header=True) == frozenset()


def test_dead_oids_empty_when_family_table_absent():
    # Older staging schema without comps_family: gate degrades to no-op.
    import sqlite3
    cur = sqlite3.connect(":memory:").cursor()
    cur.execute("CREATE TABLE comps(object_id int)")
    assert CompsRecord.dead_oids(cur, short_header=False) == frozenset()


def test_dead_oids_cached_per_cursor():
    cur = _cur_with_family([(300, FDFD, 0)])
    first = CompsRecord.dead_oids(cur, short_header=False)
    # Mutating the table after the first call must not change the cached answer.
    cur.execute("INSERT INTO comps_family VALUES (301, ?, 0)", (FDFD,))
    assert CompsRecord.dead_oids(cur, short_header=False) is first
