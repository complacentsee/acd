"""Plain-Python decoders for fixed-offset attribute-payload blobs.

Structures whose layout is version-stable but whose buffers arrive at
arbitrary lengths, where every field must degrade to absent (None)
independently and parts of the payload are variable-length. The record
families themselves (comps/comments/sbregion) are kaitai grammars; these
dataclasses cover attribute payloads a grammar fits poorly.
"""

import struct
from dataclasses import dataclass
from typing import Optional


def _u8(b: bytes, off: int) -> Optional[int]:
    return b[off] if len(b) > off else None


def _u16(b: bytes, off: int) -> Optional[int]:
    return struct.unpack_from("<H", b, off)[0] if len(b) >= off + 2 else None


def _u32(b: bytes, off: int) -> Optional[int]:
    return struct.unpack_from("<I", b, off)[0] if len(b) >= off + 4 else None


@dataclass(frozen=True)
class ConnectionParams:
    """The connection parameter blob: ext-attr 0x01 of a cip-0x69 connection
    record under a RxMapConnectionCollection (371..786 bytes observed).

    One structure serves three connection kinds, distinguished by the leading
    format word: module I/O connections (formats 5/6/7, 23..25, 28/29,
    48..50), consumed-tag connections (format 9) and produced-tag connections
    (format 10); each kind populates its own region. Every field is
    length-guarded and reads None when the blob ends before it -- consumers
    keep their own gates and value mapping.
    """
    # -- common head --
    fmt: Optional[int]                    # u16 @0    connection-format word
    fmt_dword: Optional[int]              # u32 @0    fmt plus the two bytes
    #   after it; the produced-tag gate historically compares this full dword
    #   against format 10, so it is preserved verbatim.
    rpi_us: Optional[int]                 # u32 @2    requested packet interval
    input_cxn_point: Optional[int]        # u16 @6
    input_size: Optional[int]             # u16 @12
    output_cxn_point: Optional[int]       # u16 @20
    output_size: Optional[int]            # u16 @26
    # -- consumed-tag fields (format 9) --
    remote_len: Optional[int]             # u16 @34   RemoteTag ASCII length
    remote_tag_bytes: Optional[bytes]     # @36, remote_len bytes (None when
    #   the declared length overruns the blob)
    # -- shared trailer --
    event_id: Optional[int]               # u8  @298  EventID
    input_production_trigger: Optional[int]   # u8 @302 (0=Cyclic, 2=Application)
    send_event_trigger: Optional[int]     # u32 @308  ProgrammaticallySend...
    max_observed_delay_raw: Optional[int]  # u16 @314  count of 0.128us units
    timeout_multiplier: Optional[int]     # u8  @316
    network_delay_multiplier: Optional[int]   # u16 @317
    produce_count: Optional[int]          # u16 @321  ProduceCount
    transport: Optional[int]              # u8  @323  2 == unicast
    unicast_permitted: Optional[int]      # u32 @324  UnicastPermitted (0/1)
    priority: Optional[int]               # u8  @357  (1=High, 2=Scheduled)
    input_connection_type: Optional[int]  # u8  @366  (2=Unicast, 1=Multicast)
    # -- embedded ConnectionPath EPATH --
    cpath_words: Optional[int]            # u8  @370  length in 16-bit words
    cpath_raw: Optional[bytes]            # @371, up to cpath_words*2 bytes;
    #   clamped to what the blob holds (consumers decide whether a partial
    #   path is usable), None only when the blob ends before 371.
    # -- produced-tag RPI triple (format 10) --
    min_rpi_us: Optional[int]             # u32 @774
    max_rpi_us: Optional[int]             # u32 @778
    default_rpi_us: Optional[int]         # u32 @782

    @classmethod
    def from_bytes(cls, blob: bytes) -> "ConnectionParams":
        wc = _u8(blob, 370)
        return cls(
            fmt=_u16(blob, 0),
            fmt_dword=_u32(blob, 0),
            rpi_us=_u32(blob, 2),
            input_cxn_point=_u16(blob, 6),
            input_size=_u16(blob, 12),
            output_cxn_point=_u16(blob, 20),
            output_size=_u16(blob, 26),
            remote_len=_u16(blob, 34),
            remote_tag_bytes=(
                blob[36:36 + _u16(blob, 34)]
                if _u16(blob, 34) is not None
                and 36 + _u16(blob, 34) <= len(blob) else None),
            event_id=_u8(blob, 298),
            input_production_trigger=_u8(blob, 302),
            send_event_trigger=_u32(blob, 308),
            max_observed_delay_raw=_u16(blob, 314),
            timeout_multiplier=_u8(blob, 316),
            network_delay_multiplier=_u16(blob, 317),
            produce_count=_u16(blob, 321),
            transport=_u8(blob, 323),
            unicast_permitted=_u32(blob, 324),
            priority=_u8(blob, 357),
            input_connection_type=_u8(blob, 366),
            cpath_words=wc,
            cpath_raw=(blob[371:371 + wc * 2] if wc is not None else None),
            min_rpi_us=_u32(blob, 774),
            max_rpi_us=_u32(blob, 778),
            default_rpi_us=_u32(blob, 782),
        )
