"""Unit tests for the controller properties blob decoder (acd.record.blobs).

``ControllerProps`` decodes ext-attr 0x1 of the controller record: the
classic time-slice block (gated by the 0x5A marker byte at 16 plus the
share-flags byte at 25 being present), the RedundancyEnabled flag at 14,
and the size families (62 = classic V20.01 save; the ForceData gate keys
on {62, 70}).
"""

import struct

from acd.record.blobs import ControllerProps


def _blob(size=62, marker=0x5A) -> bytes:
    b = bytearray(size)
    struct.pack_into("<H", b, 4, 20)     # time slice
    b[14] = 1                            # redundancy
    struct.pack_into("<H", b, 16, 90 if marker == 0x5A else 0)
    struct.pack_into("<H", b, 18, 50)    # data-table pad
    b[25] = 1                            # share unused time slice
    return bytes(b)


def test_classic_blob_decodes():
    p = ControllerProps.from_bytes(_blob())
    assert p.size == 62 and p.time_slice == 20
    assert p.redundancy_flag == 1
    assert p.classic_marker == 0x5A and p.io_memory_pad == 90
    assert p.data_table_pad == 50 and p.share_flags == 1


def test_modern_blob_has_zero_marker():
    p = ControllerProps.from_bytes(_blob(size=70, marker=0))
    assert p.size == 70 and p.classic_marker == 0


def test_truncation_guards():
    b = _blob()
    assert ControllerProps.from_bytes(b[:25]).share_flags is None
    assert ControllerProps.from_bytes(b[:26]).share_flags == 1
    assert ControllerProps.from_bytes(b[:14]).redundancy_flag is None
    assert ControllerProps.from_bytes(b[:15]).redundancy_flag == 1
    e = ControllerProps.from_bytes(b"")
    assert e.size == 0 and e.time_slice is None and e.classic_marker is None
