from dataclasses import dataclass
from io import BytesIO
from sqlite3 import Cursor
from typing import Optional

from acd.database.dbextract import DatRecord
from kaitaistruct import KaitaiStream

from acd.generated.comps.fafa_comps import FafaComps
from acd.generated.comps.fdfd_comps import FdfdComps

# Comps record identifiers (little-endian u16).
_FAFA_IDENTIFIER = 64250  # 0xFAFA primary records
_FDFD_IDENTIFIER = 65021  # 0xFDFD secondary / sub records

# --- SHORT (V10..V21) comps header layout ------------------------------------
# RSLogix5000 V21-and-earlier store comps with a FAFA/FDFD header that is 4 bytes
# SHORTER than V24+ (the V24+ "long" header inserts a zero u32 at payload offset
# 12, pushing object_id/parent/name +4). The shared kaitai FafaComps/FdfdComps
# parsers use the LONG (V30+/V36) offsets, so on a short-header file they read
# object_id/parent/name 4 bytes too far: ~444/6285 records survive, names lose 2
# leading chars (FuncGen->ncGen), and parent_id reads the name bytes -> the
# ControllerBuilder query "parent_id==0 AND record_type==256" returns 0 rows and
# raises "Does not contain exactly one root controller node".
#
# These are ABSOLUTE offsets within dat_record.record.record_buffer (the payload
# after the 6-byte stream framing) and are IDENTICAL for FAFA and FDFD in the
# short layout. record_type sits at offset 10 in BOTH families (so it parses
# correctly today regardless). Verified against acdgen's proven v21 parse and on
# v21_gm_FuncGen.ACD (6285/6285 FAFA names decode; controller query -> exactly 1)
# and empirically across V10..V20 pool samples (word@12 != 0 == short header).
_SH_SEQ_OFF = 8     # u16 per-collection ordinal (cosmetic for export)
_SH_RTYPE_OFF = 10  # u16 record_type (256=component, 0=collection)
_SH_OBJID_OFF = 12  # u32 object_id (self_lcg / CompUId)
_SH_PARENT_OFF = 16  # u32 parent_id
_SH_NAME_OFF = 20    # UTF-16LE NUL-terminated record_name
_SH_NAME_END = 102   # name field window end (82-byte window)
_SH_BODY_OFF = 110   # record_buffer (body) start; read to END of payload
#   (do NOT compute body length from the @0 record_length: it is the primary-
#    record length and is < total payload for records carrying appended sub-blobs,
#    which would truncate large datatype/tag bodies.)


def record_uses_short_header(record_buffer: bytes) -> bool:
    """Structural autodetect: True for the V10..V21 short comps header.

    The V24+ long header inserts a zero u32 at payload offset 12; the short
    header has the object_id (self_lcg, always nonzero) there. Validated across
    V10..V36 pool samples (V10-V21 -> short, V24-V36 -> long). Version-table-free.
    Pass a FAFA component record's payload (``dat_record.record.record_buffer``).
    """
    if len(record_buffer) < 16:
        return False
    return int.from_bytes(record_buffer[12:16], "little") != 0


@dataclass
class RecordData:
    object_id: int
    record_length: int
    seq_number: int
    record_type: int
    dat_record: DatRecord


@dataclass
class CompsRecord:
    _cur: Cursor
    dat_record: DatRecord

    def __post_init__(self):
        entry = CompsRecord.parse(self.dat_record)
        if entry is None:
            return
        self._cur.execute(f"DELETE FROM comps WHERE object_id={entry[0]}")
        self._cur.execute("INSERT INTO comps VALUES (?, ?, ?, ?, ?, ?)", entry)

    @staticmethod
    def parse(dat_record: DatRecord, short_header: bool = False) -> Optional[tuple]:
        """Parse a FAFA/FDFD comps record into the comps-table 6-tuple.

        ``short_header`` selects the V10..V21 shorter header layout (see the
        offset constants above); otherwise the shared kaitai parsers are used
        exactly as before (V24+/V30+/V36 — no behaviour change). Returns
        ``(object_id, parent_id, record_name, seq_number, record_type,
        record_buffer)`` or ``None`` for non-comps identifiers.
        """
        if short_header:
            return CompsRecord._parse_short(dat_record)

        if dat_record.identifier == _FAFA_IDENTIFIER:
            r = FafaComps.from_bytes(dat_record.record.record_buffer)
        elif dat_record.identifier == _FDFD_IDENTIFIER:
            r = FdfdComps(
                dat_record.len_record,
                KaitaiStream(BytesIO(dat_record.record.record_buffer)),
            )
        else:
            return None
        return (
            r.header.object_id,
            r.header.parent_id,
            r.header.record_name.value,
            r.header.seq_number,
            r.header.record_type,
            r.record_buffer,
        )

    @staticmethod
    def _parse_short(dat_record: DatRecord) -> Optional[tuple]:
        """Manual V10..V21 FAFA/FDFD header parse (absolute offsets above)."""
        if dat_record.identifier not in (_FAFA_IDENTIFIER, _FDFD_IDENTIFIER):
            return None
        buf = dat_record.record.record_buffer
        if len(buf) < _SH_BODY_OFF:
            return None
        record_type = int.from_bytes(buf[_SH_RTYPE_OFF:_SH_RTYPE_OFF + 2], "little")
        object_id = int.from_bytes(buf[_SH_OBJID_OFF:_SH_OBJID_OFF + 4], "little")
        parent_id = int.from_bytes(buf[_SH_PARENT_OFF:_SH_PARENT_OFF + 4], "little")
        record_name = CompsRecord._decode_utf16z(buf[_SH_NAME_OFF:_SH_NAME_END])
        seq_number = int.from_bytes(buf[_SH_SEQ_OFF:_SH_SEQ_OFF + 2], "little")
        record_buffer = buf[_SH_BODY_OFF:]
        return (object_id, parent_id, record_name, seq_number, record_type, record_buffer)

    @staticmethod
    def _decode_utf16z(buf: bytes) -> str:
        """Decode a NUL-terminated UTF-16LE name (walk u16 units to 0x0000)."""
        units = []
        for i in range(0, len(buf) - 1, 2):
            u = buf[i] | (buf[i + 1] << 8)
            if u == 0:
                break
            units.append(u)
        try:
            return "".join(chr(u) for u in units)
        except ValueError:
            return ""
