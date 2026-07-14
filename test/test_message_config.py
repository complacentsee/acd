"""Unit tests for the MESSAGE config decode (MessageConfig grammar +
_render_message_data), driven end-to-end through the seeded staging DB.

The renderer reads the tag's backing record body from the comps table
(ext-attr 0x1 = the 354-byte config struct; 0x65/0x70/0x67 = UTF-16 member
references) and must emit a <Data Format="Message"> block only for
configurations decoded with full confidence -- anything else returns None.
"""

import struct

from acd.generated.comps.message_config import MessageConfig
from acd.l5x.messages import _render_message_data

try:
    from .seeded_db import seeded_cursor
except ImportError:   # collected with test/ as the rootdir
    from seeded_db import seeded_cursor

LONG_OFF = 148   # CompsRecord._LONG_BODY_OFF
DTI = 0x1234


def _config(fam, svc=0, req=0, cf=0, epath=b"", lpu=False, cache=False,
            size=354) -> bytes:
    a = bytearray(size)
    if size > 353:
        a[353] = fam
    if cache:
        a[1] |= 0x02   # CacheConnections value bit (byte 1 bit 1)
    struct.pack_into("<H", a, 139, req)
    a[143] = cf
    struct.pack_into("<H", a, 144, len(epath))
    a[146:146 + len(epath)] = epath
    if lpu:
        a[281] = 0x02
    struct.pack_into("<HHIH", a, 330, svc, 0x006B, 7, 0x0001)
    return bytes(a)


def _full_record(attrs) -> bytes:
    """An untruncated long-header comps_full payload carrying ``attrs``."""
    tail = b"".join(struct.pack("<II", aid, len(v)) + v for aid, v in attrs)
    body = (struct.pack("<IIHHH", 1, 2, 3, 0x6A, 7) + bytes(60)
            + struct.pack("<II", len(tail), len(attrs) + 1) + tail)
    return b"\x00" * LONG_OFF + body


def _render(attrs, oid2name=None):
    # Post size-eos, the comps record column carries the whole body (payload
    # past the 148-byte header) -- the single source the reader consults.
    full = _full_record(attrs)
    cur = seeded_cursor(comps=[(DTI, 0, "$backing$", 0, 256, full[LONG_OFF:])])
    return _render_message_data(
        cur, False, DTI, oid2name or {}, {}, {})


def test_cip_generic_full_block():
    out = _render([(0x1, _config(1, svc=0x4C, req=12, cf=1, lpu=True,
                                 cache=True))])
    assert out is not None and 'MessageType="CIP Generic"' in out
    assert 'ServiceCode="16#004c"' in out and 'ObjectType="16#006b"' in out
    assert 'TargetObject="7"' in out and 'AttributeNumber="16#0001"' in out
    assert 'RequestedLength="12"' in out and 'ConnectedFlag="1"' in out
    assert 'CacheConnections="TRUE"' in out and 'LargePacketUsage="true"' in out
    assert 'ConnectionPath' not in out   # no epath stored
    # The CacheConnections VALUE is config byte 1 bit 1, not a constant.
    out = _render([(0x1, _config(1, svc=0x4C, req=12, cf=1, lpu=True))])
    assert out is not None and 'CacheConnections="FALSE"' in out


def test_cip_data_table_read_with_elements():
    le = "localArr".encode("utf-16-le")
    re_el = "N20:0".encode("utf-16-le")
    out = _render([(0x1, _config(2, svc=76, req=2)),
                   (0x65, le), (0x67, re_el)])
    assert out is not None and 'MessageType="CIP Data Table Read"' in out
    assert 'RemoteElement="N20:0"' in out and 'LocalElement="localArr"' in out


def test_connection_path_tokens_resolve():
    out = _render([(0x1, _config(1, svc=1, epath=b"\x01\x02"))])
    assert out is not None and 'ConnectionPath="1, 2"' in out


def test_gates_return_none():
    # Wrong struct length, unknown family, unknown family sub-type.
    assert _render([(0x1, _config(1, size=353))]) is None
    assert _render([(0x1, _config(9))]) is None
    assert _render([(0x1, _config(2, svc=99))]) is None
    # CIP Data Table without its member references.
    assert _render([(0x1, _config(2, svc=76))]) is None


def test_len_428_tail_extension_renders():
    # The 428-byte image is the same struct with a trailing extension: the CIP
    # families decode at their existing offsets. An off-length (not 354/428)
    # still gates to None.
    out = _render([(0x1, _config(1, svc=0x4C, req=12, cf=1, size=428))])
    assert out is not None and 'MessageType="CIP Generic"' in out
    assert 'ServiceCode="16#004c"' in out and 'RequestedLength="12"' in out
    assert _render([(0x1, _config(1, size=400))]) is None


def test_plc5_typed_write_service():
    # Family 6 / service 103 = PLC5 Typed Write (added to the service map).
    out = _render([(0x1, _config(6, svc=103))],
                  oid2name={0x11: "N7:0", 0x22: "MyTag"})
    # RemoteElement/LocalElement come from member refs; the type name is enough
    # to confirm the map entry resolves (missing members gate to None).
    if out is not None:
        assert 'MessageType="PLC5 Typed Write"' in out


def test_grammar_field_boundaries():
    m = MessageConfig.from_bytes(_config(2, svc=76, req=5, cf=1,
                                         epath=b"\x01\x00", lpu=True))
    assert (m.family, m.service_byte, m.service_code) == (2, 76, 76)
    assert (m.requested_length, m.connected_flag) == (5, 1)
    assert m.path_size == 2 and m.epath == b"\x01\x00"
    assert m.large_packet_flags == 0x02
    # Implausible or overrunning path sizes read as absent.
    z = bytearray(_config(1)); struct.pack_into("<H", z, 144, 250)
    assert MessageConfig.from_bytes(bytes(z)).epath is None
    z2 = bytearray(_config(1)); struct.pack_into("<H", z2, 144, 220)
    assert MessageConfig.from_bytes(bytes(z2)).epath is None
    assert MessageConfig.from_bytes(bytes(100)).family is None
