"""Unit pins for the long-header FDFD comps grammar body offset (P6.9 C5).

The FdfdComps header's last field is the 124-byte record_name window at 0x18,
so the header ends at 0x18 + 124 = 148 -- the SAME body offset as the FAFA form
(u4 record_length + 144-byte header). The historical grammar declared the header
size as 155, over-counting by 7 and shifting every FDFD comps.record body into
garbage. These tests pin the corrected structural 148 so a future regression
(a silent re-widening) fails loudly instead of silently mis-decoding ~27k pool
rows. The whole family gate that makes the flip safe is exercised by the pool
gauntlet; here we pin only the grammar geometry.
"""

import struct
from io import BytesIO
from types import SimpleNamespace

from kaitaistruct import KaitaiStream
from acd.generated.comps.fdfd_comps import FdfdComps
from acd.record.comps import CompsRecord

FDFD = 65021   # 0xFDFD
_HDR = 148     # structural FDFD header end == body offset
_NAME_OFF = 0x18
_NAME_WINDOW = 124


def _fdfd_payload(object_id=0xAABBCCDD, parent_id=0x11223344, name="EthPort1",
                  seq=7, record_type=256, body=b"\x01\x64\x65\x66" * 5) -> bytes:
    """Assemble a long-header FDFD stream payload: 148-byte header + body@148."""
    buf = bytearray(_HDR)
    struct.pack_into("<H", buf, 0x04, seq)
    struct.pack_into("<H", buf, 0x0A, record_type)
    struct.pack_into("<I", buf, 0x10, object_id)
    struct.pack_into("<I", buf, 0x14, parent_id)
    nb = name.encode("utf-16-le") + b"\x00\x00"
    assert _NAME_OFF + len(nb) <= _HDR, "test name must fit in the 124B window"
    buf[_NAME_OFF:_NAME_OFF + len(nb)] = nb
    return bytes(buf) + body


def _parse(payload):
    return FdfdComps(len(payload) + 6, KaitaiStream(BytesIO(payload)))


def test_name_window_ends_at_148():
    assert _NAME_OFF + _NAME_WINDOW == _HDR


def test_header_fields_and_body_start_at_148():
    body = b"\x01\x64\x65\x66\x99\x88\x77"
    r = _parse(_fdfd_payload(name="Motor_A", body=body))
    assert (r.header.object_id, r.header.parent_id, r.header.record_name.value,
            r.header.seq_number, r.header.record_type) == (
        0xAABBCCDD, 0x11223344, "Motor_A", 7, 256)
    # record_buffer is the body AFTER the 148-byte header -- not 155.
    assert r.record_buffer == body


def test_body_starts_at_148_not_155():
    # A 7-byte marker at the very start of the body proves the seam is at 148:
    # under the old 155 grammar those 7 bytes would be swallowed by the header.
    marker = b"\xde\xad\xbe\xef\x01\x02\x03"
    r = _parse(_fdfd_payload(body=marker + b"\x64\x65\x66"))
    assert r.record_buffer[:7] == marker


def test_compsrecord_parse_returns_body_at_148():
    body = b"\x01\x64\x65\x66\x10\x20"
    payload = _fdfd_payload(name="P", record_type=512, body=body)
    dat = SimpleNamespace(identifier=FDFD, len_record=len(payload) + 6,
                          record=SimpleNamespace(record_buffer=payload))
    t = CompsRecord.parse(dat, short_header=False)
    assert t == (0xAABBCCDD, 0x11223344, "P", 7, 512, body)
