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
# object_id/parent/name 4 bytes too far: most records fail to survive, names lose
# 2 leading chars, and parent_id reads the name bytes -> the ControllerBuilder
# query "parent_id==0 AND record_type==256" returns 0 rows and raises "Does not
# contain exactly one root controller node".
#
# These are ABSOLUTE offsets within dat_record.record.record_buffer (the payload
# after the 6-byte stream framing) and are IDENTICAL for FAFA and FDFD in the
# short layout. record_type sits at offset 10 in BOTH families (so it parses
# correctly today regardless). Verified against acdgen's proven v21 parse on a
# real short-header project (all FAFA names decode; controller query -> exactly 1)
# and empirically across V10..V20 sample projects (word@12 != 0 == short header).
_SH_SEQ_OFF = 8     # u16 per-collection ordinal (cosmetic for export)
_SH_RTYPE_OFF = 10  # u16 record_type (256=component, 0=collection)
_SH_OBJID_OFF = 12  # u32 object_id (self_lcg / CompUId)
_SH_PARENT_OFF = 16  # u32 parent_id
_SH_NAME_OFF = 20    # UTF-16LE NUL-terminated record_name
_SH_NAME_END = 102   # name field window end (82-byte window)
# record_buffer (body) start = 94, NOT 110: the body the builders/RxGeneric parse
# must START at the 14-byte RxGeneric prelude (parent/unique_tag/rfv/cip_type/
# comment_id), which begins at payload offset 94 (its cip_type lands at payload
# 104 == the header cip). (acdgen's "body@110" is the content AFTER that prelude.)
# Proven on short-header pool files: @94 -> 661/661 component bodies parse with the
# correct cip distribution (0x6b/0x6a/0x6c/0x68); @110 -> all cip_type=0 garbage.
# read to END of payload (the @0 record_length undercounts records w/ sub-blobs).
_SH_BODY_OFF = 94
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

    # ------------------------------------------------------------------ #
    # Tag VALUE reader (Step 6b) — design value from ext attr 0x66        #
    # ------------------------------------------------------------------ #
    # A tag's design/initial value is NOT in the tag's own comps record. The
    # tag main_record @0x24 holds ``data_table_instance`` (u32); the comps row
    # whose object_id == that value is a cip-0x6a "$hash$" backing carrying
    # ext attrs [0x01, 0x64, 0x65, 0x66]:
    #   0x64 = 16-byte runtime cache (ALL-ZERO on disk — the WRONG source)
    #   0x65 = 2-byte CIP type code (0xc4=DINT, 0x8f__=system struct, ...)
    #   0x66 = the design value, byte-exact (THE source)
    # Two truncations stop the stock parsers from ever reaching 0x66:
    #   1) FafaComps.record_buffer trims to record_length(@0)-148, but the
    #      @0 length undercounts backings with sub-blobs -> 0x66 is in the tail.
    #   2) RxGeneric loops range(count_record-1) and stops before 0x66.
    # So this reader takes the FULL stream payload (DatRecord.record.record_buffer
    # = len_record-6, untruncated) and walks attribute records to end-of-body,
    # ignoring count_record. See read_tag_value.

    # Body offset within the FULL stream payload (== record_buffer start):
    #   LONG (V24+)   = 148 (record_length u32 [4] + 144-byte header)
    #   SHORT(V10-V21)= 94  (== _SH_BODY_OFF)
    _LONG_BODY_OFF = 148

    @staticmethod
    def body_offset(short_header: bool) -> int:
        """Full-payload offset of the RxGeneric body (prelude) for the family."""
        return _SH_BODY_OFF if short_header else CompsRecord._LONG_BODY_OFF

    @staticmethod
    def read_value_attrs(full_payload: bytes, short_header: bool) -> dict:
        """Walk a cip-0x6a backing's body and return {attribute_id: bytes}.

        ``full_payload`` MUST be the untruncated stream payload
        (DatRecord.record.record_buffer), NOT FafaComps.record_buffer. Returns
        an empty dict on any structural problem so callers fall back to today's
        zero-placeholder behaviour.

        Body layout (from body_offset): 14B RxGeneric prelude + 60B main_record,
        then at body+74: u32 len_record, u32 count_record, then a sequence of
        (u32 attribute_id, u32 len_value, len_value bytes) attribute records.
        We walk to buffer exhaustion (NOT count_record) so 0x66 is captured.
        """
        out: dict = {}
        try:
            off = CompsRecord.body_offset(short_header)
            body = full_payload[off:]
            # prelude(14) + main_record(60) = 74, then len_record/count_record.
            pos = 74 + 8  # skip len_record(4)+count_record(4)
            n = len(body)
            while pos + 8 <= n:
                attr_id = int.from_bytes(body[pos:pos + 4], "little")
                ln = int.from_bytes(body[pos + 4:pos + 8], "little")
                pos += 8
                if ln < 0 or pos + ln > n:
                    break
                out[attr_id] = body[pos:pos + ln]
                pos += ln
        except Exception:
            return {}
        return out

    @staticmethod
    def read_tag_value(full_payload: bytes, short_header: bool):
        """Return (value_bytes, cip_type_code) from a cip-0x6a backing, or None.

        value_bytes = ext attr 0x66 (the design value); cip_type_code = ext attr
        0x65 (u16, 0 if absent). Returns None when 0x66 is missing so callers
        keep today's zero-placeholder behaviour.
        """
        attrs = CompsRecord.read_value_attrs(full_payload, short_header)
        if 0x66 not in attrs:
            return None
        type_code = 0
        if 0x65 in attrs and len(attrs[0x65]) >= 2:
            type_code = int.from_bytes(attrs[0x65][0:2], "little")
        return attrs[0x66], type_code

    # ------------------------------------------------------------------ #
    # AOI prototype-default reader — __DEFVAL_* consolidated image        #
    # ------------------------------------------------------------------ #
    # AOI Parameter/LocalTag prototype DEFAULTS are NOT stored on the per-tag
    # cip-0x6b/0x6c record (its main_record@0x24 data_table_instance is 0/0xffffffff
    # and its ext-0x66 is a sentinel). Each AOI instead has exactly ONE hidden
    # controller-scope tag named ``__DEFVAL_<8hex>`` (comps record_type 264) whose:
    #   main_record@0x1c (u32) = datatype-ref -> the AOI's datatype comp
    #                            (record_type 256 under RxDataTypeCollection,
    #                             comp_name == the AOI name)
    #   main_record@0x24 (u32) = data_table_instance -> a cip-0x6a $hash$ backing
    # That backing's ext-0x66 is the CONSOLIDATED prototype image of the WHOLE AOI
    # struct (one instance image laid out per the AOI datatype member layout). Its
    # length == @size@<AOI> from TagInfo.XML (an integrity invariant). Per-child
    # value images are slices at the member's TagInfo byte offset/width.
    #
    # Proven on MachineA acd.db: AOI_A image size 1328; PacketMax@128 = 82;
    # ResetSign SignCommandCode@624 = 01 00 00 00 43 00 ('C').

    @staticmethod
    def read_aoi_defval_image(cur, aoi_name: str, short_header: bool):
        """Return the AOI's consolidated __DEFVAL prototype image, or None.

        Resolves: aoi_name -> RxDataTypeCollection datatype oid -> the __DEFVAL
        whose main_record@0x1c == that oid -> its main_record@0x24
        data_table_instance -> the cip-0x6a backing's ext-0x66. Best-effort: any
        failure / missing record returns None so callers degrade to today's
        no-value behaviour (no regression).
        """
        try:
            cur.execute(
                "SELECT object_id FROM comps WHERE comp_name=? AND parent_id="
                "(SELECT object_id FROM comps WHERE comp_name='RxDataTypeCollection')",
                (aoi_name,),
            )
            row = cur.fetchone()
            if not row:
                return None
            dt_oid = row[0]

            cur.execute(
                "SELECT record FROM comps WHERE comp_name LIKE '__DEFVAL%'"
            )
            dti = None
            for (rec,) in cur.fetchall():
                if rec is None:
                    continue
                rb = bytes(rec)
                # comps.record == record_buffer (body after the header). The
                # 60-byte main_record sits at body[14:74] (14B RxGeneric prelude).
                if len(rb) < 74:
                    continue
                main = rb[14:74]
                dtref = int.from_bytes(main[0x1c:0x1c + 4], "little")
                if dtref == dt_oid:
                    dti = int.from_bytes(main[0x24:0x24 + 4], "little")
                    break
            if not dti or dti == 0xFFFFFFFF:
                return None

            cur.execute(
                "SELECT record FROM comps_full WHERE object_id=?", (dti,)
            )
            brow = cur.fetchone()
            if not brow or brow[0] is None:
                return None
            attrs = CompsRecord.read_value_attrs(bytes(brow[0]), short_header)
            return attrs.get(0x66)
        except Exception:
            return None

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
