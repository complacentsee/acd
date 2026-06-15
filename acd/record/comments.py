import re
import struct
from dataclasses import dataclass
from sqlite3 import Cursor
from typing import Optional

from acd.database.dbextract import DatRecord
from acd.generated.comments.fafa_coments import FafaComents


@dataclass
class CommentsRecord:
    _cur: Cursor
    dat_record: DatRecord

    def __post_init__(self):
        entry = CommentsRecord.parse(self.dat_record)
        if entry is not None:
            self._cur.execute("INSERT INTO comments VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", entry)

    @staticmethod
    def _parse_udi_body(body: bytes) -> Optional[tuple]:
        """Parse a UDI (type-12) fafa record body.

        UDI records store metadata like the AOI RevisionNote.  The body layout is:
          [0:8]   8 bytes unknown
          [8:12]  4 bytes some_id
          [12:16] 4 bytes flags
          [16:]   UTF-16LE null-terminated UDI-type string (e.g. "UDI_HISTORY")
                  followed by null padding, then a null-terminated ASCII text string.

        Returns (udi_type, text) or None if the structure is not recognized.
        """
        if len(body) < 20:
            return None
        try:
            # UDI type string starts at offset 16 (after 8 unknown + 4 id + 4 flags).
            utf16_start = 16
            pos = utf16_start
            code_units = []
            while pos + 1 < len(body):
                cu = struct.unpack_from("<H", body, pos)[0]
                if cu == 0:
                    break
                code_units.append(cu)
                pos += 2
            udi_type = "".join(chr(cu) for cu in code_units)
            # Skip null terminator and any subsequent null padding.
            pos += 2
            while pos < len(body) and body[pos] == 0:
                pos += 1
            # Read null-terminated ASCII text.
            text_end = body.find(b"\x00", pos)
            if text_end <= pos:
                return None
            text = body[pos:text_end].decode("utf-8", errors="replace")
            return (udi_type, text)
        except Exception:
            return None

    @staticmethod
    def _parse_short_operand_body(raw: bytes) -> Optional[tuple]:
        """Parse a V10..V21 short-header operand comment record (types 3/4/5).

        These RSLogix-style operand comments store, per member/bit/array element:
          [0:4]   u32 record_length
          [4:6]   u16 seq_number
          [6:8]   u16 record_type
          [8:10]  u16 sub_record_length
          [10:14] u32 parent  (== the owning component's comment_id)
        then the body (raw[14:]):
          [0:6]   six zero bytes
          [6:8]   u16 member key (a per-element discriminator)
          [8:12]  u32 object_id (controller/scope object, constant per project)
          [12]    one pad byte (0x00)
          [13:]   UTF-16LE NUL-terminated OPERAND string ("[3]", ".5", ".DINT[1]")
          [..]    UTF-16LE NUL-terminated comment text (newlines kept as CR/LF)

        Returns the 9-tuple matching the comments table schema, or None.  The
        operand goes into the tag_reference column and the comment text into
        record_string so the existing comments-table join can read both.
        """
        if len(raw) < 14:
            return None
        record_length = struct.unpack_from("<I", raw, 0)[0]
        seq_number = struct.unpack_from("<H", raw, 4)[0]
        sub_record_length = struct.unpack_from("<H", raw, 8)[0]
        parent = struct.unpack_from("<I", raw, 10)[0]
        body = raw[14:]
        if len(body) < 14:
            return None
        member_key = struct.unpack_from("<H", body, 6)[0]
        object_id = struct.unpack_from("<I", body, 8)[0]

        def _utf16z(buf: bytes, pos: int):
            cus = []
            while pos + 1 < len(buf):
                cu = struct.unpack_from("<H", buf, pos)[0]
                pos += 2
                if cu == 0:
                    break
                cus.append(cu)
            return "".join(chr(c) for c in cus), pos

        operand, pos = _utf16z(body, 13)
        text, _ = _utf16z(body, pos)
        if not operand:
            return None
        return (
            seq_number,
            sub_record_length,
            object_id,
            text,
            struct.unpack_from("<H", raw, 6)[0],  # record_type
            parent,
            operand,        # tag_reference column carries the L5X Operand
            0,              # rung_content
            member_key,     # member_ref column carries the per-element key
        )

    @staticmethod
    def _parse_short_desc_body(raw: bytes) -> Optional[tuple]:
        """Parse a V10..V21 short-header OWN-description record (types 1/2).

        These carry a component's own Description (tag/datatype/module/program/
        routine) in UTF-16LE, unlike the V24+ long-header AsciiRecord whose text
        is UTF-8.  Header (same as the operand record):
          [0:4]   u32 record_length
          [4:6]   u16 seq_number
          [6:8]   u16 record_type   (1 or 2)
          [8:10]  u16 sub_record_length (== the owner component's cip_type)
          [10:14] u32 parent        (== the owner component's comment_id)
        then the body (raw[14:]):
          [0:4]   u32 member_ref    (0 for the component's own description,
                                      nonzero for a sub-element description)
          [4:8]   u32 rung_content  (nonzero for rung-level comments)
          [8:15]  7 bytes (object_id/pad region)
          [15:]   UTF-16LE NUL-terminated description text (CR/LF kept)

        The description text starts at body offset 15 (odd within the record).
        Returns the 9-tuple matching the comments table schema, or None.

        Keying: the comment is stored with ``parent == comment_id`` (the raw
        parent field) so the short-header own-description lookup mirrors the
        existing short-header OPERAND lookup (which also keys on comment_id).
        ``object_id`` is forced to 0 so the RoutineBuilder rung-comment join
        (rung_index = object_id - 1) can never mis-assign one of these records to
        a rung (rung_index = -1 is filtered): the short-header rung-comment ->
        rung-number link is LCG-scrambled and not yet cracked, so we deliberately
        do not attach rung comments here.
        """
        if len(raw) < 14:
            return None
        seq_number = struct.unpack_from("<H", raw, 4)[0]
        cip_type = struct.unpack_from("<H", raw, 8)[0]
        comment_id = struct.unpack_from("<I", raw, 10)[0]
        body = raw[14:]
        if len(body) < 16:
            return None
        member_ref = struct.unpack_from("<I", body, 0)[0]
        rung_content = struct.unpack_from("<I", body, 4)[0]

        pos = 15
        cus = []
        while pos + 1 < len(body):
            cu = struct.unpack_from("<H", body, pos)[0]
            pos += 2
            if cu == 0:
                break
            cus.append(cu)
        text = "".join(chr(c) for c in cus)
        if not text:
            return None
        return (
            seq_number,
            cip_type,        # sub_record_length column carries the owner cip_type
            0,               # object_id forced 0 (no rung mis-assignment)
            text,
            struct.unpack_from("<H", raw, 6)[0],  # record_type (1 or 2)
            comment_id,      # parent column == owner comment_id (short-header key)
            "",              # tag_reference (own descriptions have no operand)
            rung_content,
            member_ref,
        )

    @staticmethod
    def parse(dat_record: DatRecord, short_header: bool = False) -> Optional[tuple]:
        if dat_record.identifier != 64250:
            return None
        raw_full = bytes(dat_record.record.record_buffer)
        # V10..V21 short-header operand comments (member/bit/array element
        # comments) use a different body layout than V24+ long-header records.
        # Decode them here so TagBuilder can emit <Comment Operand="..."> children.
        # Long-header export is untouched: this branch is gated on short_header
        # and falls through to the original parser on any failure.
        if short_header and len(raw_full) >= 8:
            try:
                rt = struct.unpack_from("<H", raw_full, 6)[0]
                # Operand comment record types observed across V10..V21 projects:
                #   3/4/5  array/bit/element comments on atomic tags
                #   6      IO-module .DATA comments
                #   7      array-of-struct element.bit comments ("[0].10")
                #   9/10/11 UDT-member comments (".DINT[1]", ".BOOL[19]")
                # All share the same body layout (operand UTF-16 at body+13).
                # Types 1/2 (plain own-description) and the long-header UTF-16
                # record types are deliberately excluded.
                if rt in (0x03, 0x04, 0x05, 0x06, 0x07, 0x09, 0x0A, 0x0B):
                    parsed = CommentsRecord._parse_short_operand_body(raw_full)
                    if parsed is not None:
                        return parsed
                # Own-description records (component Description text) in UTF-16LE.
                # The shared FafaComents AsciiRecord decodes these as UTF-8 (the
                # V24+ layout), which mangles short-header UTF-16 text, so parse
                # them here. Falls through to the original parser on any failure.
                if rt in (0x01, 0x02):
                    parsed = CommentsRecord._parse_short_desc_body(raw_full)
                    if parsed is not None:
                        return parsed
            except Exception:
                pass
        try:
            r = FafaComents.from_bytes(dat_record.record.record_buffer)
            # Type-12 (0x0C) records carry UDI metadata such as the AOI RevisionNote.
            # The body is raw bytes; parse it to extract the text.
            if r.header.record_type == 12:
                parsed = CommentsRecord._parse_udi_body(bytes(r.body))
                if parsed is None:
                    return None
                udi_type, text = parsed
                # Only store UDI_HISTORY records (RevisionNote) for now.
                if udi_type != "UDI_HISTORY":
                    return None
                return (
                    r.header.seq_number,
                    r.header.sub_record_length,
                    1,              # object_id placeholder (not used for lookup)
                    text,
                    r.header.record_type,
                    r.header.parent,
                    "__REVISION_NOTE__",
                    0,              # rung_content
                    0,              # member_ref
                )
            if r.header.record_type in (0x03, 0x04, 0x0D, 0x0E):
                tag_ref = r.body.tag_reference.value
            else:
                tag_ref = ""
            # For AsciiRecord (type 1 or 2), extract bytes [4:8] of unknown_1.
            # This value is non-zero for rung-level comments and zero for internal
            # metadata strings (FBDRoutineDescription, MainProgramLocalTagDescription, etc.).
            if r.header.record_type in (0x01, 0x02) and len(bytes(r.body.unknown_1)) >= 8:
                rung_content = struct.unpack_from("<I", bytes(r.body.unknown_1), 4)[0]
            else:
                rung_content = 0
            # Extract bytes [0:4] of unknown_1 as member_ref.
            # For the object's own description (DataType, AOI, etc.) this is zero.
            # For sub-element descriptions (UDT members, AOI parameters/local tags)
            # this is non-zero, enabling callers to filter to just the object-level description.
            if r.header.record_type in (0x01, 0x02) and len(bytes(r.body.unknown_1)) >= 4:
                member_ref = struct.unpack_from("<I", bytes(r.body.unknown_1), 0)[0]
            else:
                member_ref = 0
            return (
                r.header.seq_number,
                r.header.sub_record_length,
                r.body.object_id,
                r.body.record_string,
                r.header.record_type,
                r.header.parent,
                tag_ref,
                rung_content,
                member_ref,
            )
        except Exception:
            return None

    def replace_tag_references(self, sb_rec):
        m = re.findall("@[A-Za-z0-9]*@", sb_rec)
        for tag in m:
            tag_no = tag[1:-1]
            tag_id = int(tag_no, 16)
            self._cur.execute(
                "SELECT object_id, comp_name FROM comps WHERE object_id=" + str(tag_id)
            )
            results = self._cur.fetchall()
            sb_rec = sb_rec.replace(tag, results[0][1])
        return sb_rec
