"""Unit tests for the connection parameter blob decoder (acd.record.blobs).

``ConnectionParams`` decodes ext-attr 0x01 of a cip-0x69 connection record:
one structure serving module I/O, consumed-tag (fmt 9) and produced-tag
(fmt 10) connections. Every field is length-guarded (None when the blob ends
before it); the embedded ConnectionPath is exposed clamped (cpath_raw) so
consumers can distinguish a complete path from a truncated one.
"""

import struct

from acd.record.blobs import ConnectionParams

REMOTE = b"remoteTag"
EPATH = b"\x20\x04\x24\x66"


def _blob() -> bytearray:
    b = bytearray(786)
    struct.pack_into("<H", b, 0, 48)          # fmt: StandardDataDriven
    struct.pack_into("<I", b, 2, 20000)       # RPI us
    struct.pack_into("<H", b, 6, 0x65)        # InputCxnPoint
    struct.pack_into("<H", b, 12, 10)         # InputSize
    struct.pack_into("<H", b, 20, 0x64)       # OutputCxnPoint
    struct.pack_into("<H", b, 26, 6)          # OutputSize
    struct.pack_into("<H", b, 34, len(REMOTE))
    b[36:36 + len(REMOTE)] = REMOTE
    b[298] = 3                                # EventID
    b[302] = 2                                # InputProductionTrigger
    struct.pack_into("<I", b, 308, 1)         # send_event_trigger
    struct.pack_into("<H", b, 314, 25)        # max observed delay raw
    b[316] = 4                                # TimeoutMultiplier
    struct.pack_into("<H", b, 317, 2)         # NetworkDelayMultiplier
    struct.pack_into("<H", b, 321, 5)         # ProduceCount
    b[323] = 2                                # transport: unicast
    struct.pack_into("<I", b, 324, 1)         # UnicastPermitted
    b[357] = 2                                # Priority: Scheduled
    b[366] = 1                                # InputConnectionType: Multicast
    b[370] = len(EPATH) // 2                  # cpath words
    b[371:371 + len(EPATH)] = EPATH
    struct.pack_into("<III", b, 774, 500, 10000, 2000)   # min/max/default RPI
    return b


def test_full_blob_decodes_every_field():
    cp = ConnectionParams.from_bytes(bytes(_blob()))
    assert (cp.fmt, cp.rpi_us) == (48, 20000)
    assert cp.fmt_dword == 48 | ((20000 & 0xFFFF) << 16)
    assert (cp.input_cxn_point, cp.input_size) == (0x65, 10)
    assert (cp.output_cxn_point, cp.output_size) == (0x64, 6)
    assert cp.remote_len == len(REMOTE) and cp.remote_tag_bytes == REMOTE
    assert (cp.event_id, cp.input_production_trigger) == (3, 2)
    assert (cp.send_event_trigger, cp.max_observed_delay_raw) == (1, 25)
    assert (cp.timeout_multiplier, cp.network_delay_multiplier) == (4, 2)
    assert (cp.produce_count, cp.transport, cp.unicast_permitted) == (5, 2, 1)
    assert (cp.priority, cp.input_connection_type) == (2, 1)
    assert cp.cpath_words == 2 and cp.cpath_raw == EPATH
    assert (cp.min_rpi_us, cp.max_rpi_us, cp.default_rpi_us) == (500, 10000, 2000)


def test_fmt_dword_covers_the_bytes_after_fmt():
    # The produced-tag gate compares u32@0, so nonzero bytes at 2..3 (the RPI
    # low half) must surface there while fmt (u16) is unaffected.
    b = _blob()
    struct.pack_into("<H", b, 0, 10)
    struct.pack_into("<I", b, 2, 500)
    cp = ConnectionParams.from_bytes(bytes(b))
    assert cp.fmt == 10
    assert cp.fmt_dword == 10 | ((500 & 0xFFFF) << 16)


def test_transport_gate_boundary_324():
    b = bytes(_blob())
    assert ConnectionParams.from_bytes(b[:323]).transport is None
    assert ConnectionParams.from_bytes(b[:324]).transport == 2


def test_produce_gate_boundary_786():
    b = bytes(_blob())
    assert ConnectionParams.from_bytes(b[:785]).default_rpi_us is None
    assert ConnectionParams.from_bytes(b[:786]).default_rpi_us == 2000


def test_cpath_clamps_but_reads_none_before_371():
    b = bytes(_blob())
    assert ConnectionParams.from_bytes(b[:370]).cpath_raw is None
    # Truncated mid-path: the raw prefix is exposed (first-instance decoding
    # still works on it) while its length no longer matches cpath_words*2
    # (so the full-path renderer refuses it).
    cp = ConnectionParams.from_bytes(b[:373])
    assert cp.cpath_words == 2 and cp.cpath_raw == EPATH[:2]


def test_remote_tag_none_when_declared_length_overruns():
    b = _blob()
    struct.pack_into("<H", b, 34, 9)
    cp = ConnectionParams.from_bytes(bytes(b[:40]))   # ends mid remote-tag
    assert cp.remote_len == 9 and cp.remote_tag_bytes is None


def test_empty_blob_reads_all_none():
    cp = ConnectionParams.from_bytes(b"")
    assert cp.fmt is None and cp.transport is None and cp.cpath_raw is None
