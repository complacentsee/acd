import struct
from dataclasses import dataclass
from sqlite3 import Cursor
from typing import Optional

from acd.database.dbextract import DatRecord
from acd.generated.comments.fafa_coments import FafaComents
from acd.record.comps import (
    _SP_KEYS, _SP_KEY_HINT, _SP_MARKER, _sp_aes, _sp_cbc,
)


def _decrypt_sp_comment_text(raw_full: bytes) -> Optional[str]:
    """Recover the plaintext text of a source-protected comment record, or None.

    A source-protected project AES-256-CBC encrypts the comment record's text
    tail with the SAME project key used for the comps ext-attr tails (the marker
    ``aa 96 aa 0a`` then the ciphertext at marker+18, IV = 16 zero bytes). The
    decrypted body mirrors the plaintext AsciiRecord body --
    ``[member_ref u32][rung_content u32][object_id u32][UTF-8 text][NUL][PKCS7]``
    -- so the text begins 12 bytes in. The record's lookup keys (record_type,
    parent, member_ref) are already correct in the parsed record (they live in the
    plaintext header, which the kaitai parser reads); only the text tail is
    encrypted, so the caller keeps its parsed keys and swaps in this text.

    The project config is shared with the comps decryptor, so the cached
    ``_SP_KEY_HINT`` config is tried first; a candidate is accepted when its
    plaintext ends in valid PKCS7 padding and the text region is valid UTF-8.
    """
    mi = raw_full.find(_SP_MARKER)
    if mi < 0:
        return None
    ct = raw_full[mi + 18:]
    nblocks = len(ct) // 16
    if nblocks < 1:
        return None
    order = list(_SP_KEYS)
    hint = _SP_KEY_HINT[0]
    if hint is not None:
        order.sort(key=lambda kv: 0 if kv[0] == hint else 1)
    for config, key in order:
        aes = _sp_aes(config, key)
        pt = _sp_cbc(ct, aes, nblocks)
        if len(pt) < 13:
            continue
        pad = pt[-1]
        if not (1 <= pad <= 16) or pt[-pad:] != bytes([pad]) * pad:
            continue
        body = pt[12:-pad]
        seg = body.split(b"\x00", 1)[0]
        try:
            text = seg.decode("utf-8")
        except UnicodeDecodeError:
            continue
        # A correct key yields a printable description; reject random plaintext
        # from a wrong key (it would fail UTF-8 above, but also guard short noise).
        if not text or sum(c.isprintable() or c in "\r\n\t" for c in text) < len(text) * 0.8:
            continue
        _SP_KEY_HINT[0] = config
        return text
    return None


@dataclass
class CommentsRecord:
    _cur: Cursor
    dat_record: DatRecord

    def __post_init__(self):
        entry = CommentsRecord.parse(self.dat_record)
        if entry is not None:
            self._cur.execute("INSERT INTO comments VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", entry)

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
          [0:2]   u16 OWNER ORDINAL: zero for a controller-scope (cip-0x6B)
                  comment (the header parent alone owns it), the owning tag's
                  scope-local 0x6B ordinal for a program-scope (cip-0x68)
                  comment -- the short-header analog of the long-header
                  owner_ref, here in the record header at raw[14:16].
          [2:6]   four zero bytes
          [6:8]   u16 member key (a per-element discriminator)
          [8:12]  u32 object_id (controller/scope object, constant per project)
          [12]    one pad byte (0x00)
          [13:]   UTF-16LE NUL-terminated OPERAND string ("[3]", ".5", ".DINT[1]")
          [..]    UTF-16LE NUL-terminated comment text (newlines kept as CR/LF)

        The record HEADER carries the scope/owner cip discriminators: raw[8:10]
        = scope cip (0x68 program / 0x6B controller), raw[12:14] = owner cip
        (0x6B on a program-scope record, 0 on a controller-scope one).

        Returns the 10-tuple matching the comments table schema, or None.  The
        operand goes into the tag_reference column and the comment text into
        record_string so the existing comments-table join can read both.
        """
        if len(raw) < 16:
            return None
        record_length = struct.unpack_from("<I", raw, 0)[0]
        seq_number = struct.unpack_from("<H", raw, 4)[0]
        sub_record_length = struct.unpack_from("<H", raw, 8)[0]
        scope_cip = struct.unpack_from("<H", raw, 8)[0]
        owner_cip = struct.unpack_from("<H", raw, 12)[0]
        owner_ord = struct.unpack_from("<H", raw, 14)[0]
        body = raw[14:]
        if len(body) < 14:
            return None
        # Structural guard: a controller-scope operand body begins with six zero
        # bytes and a zero pad at body[12]; a program-scope operand body carries
        # its owner ordinal at body[0:2] (== raw[14:16]) with body[2:6] still
        # zero, and is recognised only under its exact header discriminators
        # (scope cip 0x68 + owner cip 0x6B). Non-operand records fail both and
        # return None so the caller degrades gracefully. The type is an ordinal,
        # not an enum, so this must reject cleanly for every record_type.
        _controller_form = (body[0:6] == b"\x00\x00\x00\x00\x00\x00")
        _program_form = (
            scope_cip == 0x68 and owner_cip == 0x6B and owner_ord != 0
            and body[2:6] == b"\x00\x00\x00\x00")
        if (not _controller_form and not _program_form) or body[12] != 0:
            return None
        member_key = struct.unpack_from("<H", body, 6)[0]
        object_id = struct.unpack_from("<I", body, 8)[0]
        # Attribution keys, aligned to the long-header owner path so a
        # program-scope tag resolves identically:
        #   controller-scope: parent = raw[10:14] (the bare scope comment_id),
        #     owner_ref = 0 (the parent alone owns the row -- today's behaviour).
        #   program-scope: parent = raw[8:12] = (comment_id << 16) | 0x0068 (the
        #     shared program-scope key, == TagBuilder's comment_id*0x10000+cip),
        #     owner_ref = raw[12:16] = (ordinal << 16) | 0x006B (the owning tag's
        #     own key, == its comp record[14:18]).
        if _program_form:
            parent = struct.unpack_from("<I", raw, 8)[0]
            owner_ref = struct.unpack_from("<I", raw, 12)[0]
        else:
            parent = struct.unpack_from("<I", raw, 10)[0]
            owner_ref = 0

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
        # Reject control characters in the operand: a genuine operand path is
        # printable ("[3]", ".5", ".MEMBER", "MemberName"). This rejects records
        # whose body coincidentally has the zero prefix but is not text.
        if any((ord(c) < 0x20 and c != "\t") for c in operand):
            return None
        # AOI UDI metadata (UDI_HISTORY RevisionNote) shares this body layout but
        # is not a tag operand comment; leave it to the UDI parser by bailing out
        # so the caller falls through to the shared FafaComents path.
        if operand.startswith("UDI_"):
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
            owner_ref,      # owner_ref: program-scope owning-tag key (0 = ctrl)
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
            0,               # owner_ref (long-header concept; not decoded short)
        )

    @staticmethod
    def _parse_long_operand_body(raw: bytes) -> Optional[tuple]:
        """Parse a V24+ long-header operand/member/array comment from raw bytes.

        The shared kaitai FafaComents only builds the Utf16Record (operand) body
        for record_type 3/4/13/14; the other operand-bearing types (5/6/7/8 =
        member/bit/array-element comments, and higher ordinals) fall to its
        raw-bytes branch, where the downstream parse() raises on the missing
        ``object_id`` attribute and the record is dropped. They use the SAME
        Utf16Record layout, so decode it directly here. ``raw`` is the record
        buffer:
          [0:4]  record_length          [4:6]  seq_number
          [6:8]  record_type            [8:10] sub_record_length
          [10:14] parent (== comment_id*0x10000 + cip_type)
        then body = raw[14:] (the Utf16Record):
          [0:4]  OWNER REFERENCE: the owning comp's own comment key (u32 @14
                 of the comp record: cip u16 -- 0x006B for tags -- and a
                 scope-local ordinal u16). Nonzero on rows whose header parent
                 is a SHARED program-scope (cip-0x68) key; 0 when the parent
                 key alone identifies the tag. Attribution cross-validated
                 537/537 vs OEM across three long-header projects.
          [4:8]  unknown   [8:12] object_id (the OPERAND's member/element
                 token id, e.g. 5982+bit-index -- NOT the owning tag)
          [12]   pad
          [13]   KIND discriminator: 0x01 comment, 0x02 Min, 0x03 Max,
                 0x05 EngineeringUnit (byte-confirmed across V24..V36 pool
                 files; record_type is an ordinal and cannot discriminate)
          [16:]  UTF-16LE NUL-term OPERAND, then for text kinds 12 unknown
                 bytes + a UTF-8 NUL-term TEXT; for Min/Max no text at all --
                 the value is the record's TRAILING 4-byte little-endian REAL.

        A real operand is a qualifier relative to the tag (leading '.' or '[');
        requiring that plus printable text rejects the few non-operand records
        that also reach the raw branch. Returns the comments 9-tuple or None.
        The kind goes into the member_ref column (previously hard-coded 0 here,
        and no consumer filters member_ref on operand rows) so TagBuilder can
        route rows to <Comments>/<EngineeringUnits>/<Maxes>/<Mins>; Min/Max
        rows store the REAL rendered in the Logix Decorated style (the form the
        OEM emits inside <Max>/<Min>) in record_string.
        """
        if len(raw) < 14:
            return None
        seq_number = struct.unpack_from("<H", raw, 4)[0]
        record_type = struct.unpack_from("<H", raw, 6)[0]
        sub_record_length = struct.unpack_from("<H", raw, 8)[0]
        parent = struct.unpack_from("<I", raw, 10)[0]
        body = raw[14:]
        if len(body) < 16:
            return None
        owner_ref = struct.unpack_from("<I", body, 0)[0]
        object_id = struct.unpack_from("<I", body, 8)[0]
        pos = 16
        cus = []
        while pos + 1 < len(body):
            cu = struct.unpack_from("<H", body, pos)[0]
            pos += 2
            if cu == 0:
                break
            cus.append(cu)
        if not cus:
            return None
        operand = "".join(chr(c) for c in cus)
        if operand[0] not in ".[":
            return None
        if any((ord(c) < 0x20 and c != "\t") for c in operand):
            return None
        kind = body[13]
        if kind in (0x04, 0x21):
            # A kind-0x04 operand row is a member CROSS-REFERENCE (where-used
            # I/O flags as text, e.g. "OI"); kind-0x21 is an AlarmCondition
            # trigger tag-name binding whose mid-string text would surface as a
            # truncated <Comment>. Neither is a comment and the reference export
            # emits neither -- same operand-row layout, so drop both here or
            # they leak in as spurious <Comment> rows.
            return None
        if kind in (0x02, 0x03):
            # Min/Max: the payload is the trailing little-endian REAL (there is
            # no text, which is why these records used to decode to '' and be
            # dropped). Render it in the Decorated style at staging so the
            # builder emits it verbatim.
            if len(body) < pos + 4:
                return None
            from acd.l5x.tag_value import _fmt_real_decorated
            value_text = _fmt_real_decorated(
                struct.unpack("<f", body[-4:])[0])
            return (
                seq_number,
                sub_record_length,
                object_id,
                value_text,
                record_type,
                parent,
                operand,
                0,
                kind,
                owner_ref,
            )
        tpos = pos + 12  # skip the 12-byte unknown_3 region
        end = body.find(b"\x00", tpos)
        if end < 0:
            end = len(body)
        text = body[tpos:end].decode("utf-8", errors="replace")
        if not text:
            return None
        return (
            seq_number,
            sub_record_length,
            object_id,
            text,
            record_type,
            parent,
            operand,
            0,
            kind,
            owner_ref,
        )

    _UDI_EXT_HELP_MARKER = "UDI_EXT_HELP".encode("utf-16-le") + b"\x00\x00"
    _UDI_HISTORY_MARKER = "UDI_HISTORY".encode("utf-16-le") + b"\x00\x00"

    @staticmethod
    def _parse_udi_text(raw: bytes, short_header: bool, marker: bytes,
                        tag_ref: str, object_id: int) -> Optional[tuple]:
        """Parse an AOI UDI text record (help text / revision note), or None.

        The record carries the text after the NUL-terminated UDI type-string
        marker (plus zero padding), keyed by the AOI's comment id in the header
        parent field. The text encoding follows the header family: UTF-16LE on
        short-header (V10-V21) files, NUL-terminated UTF-8 on long-header ones.
        The kaitai path reads only the long-header UTF-8 form, mangling the
        short-header UTF-16 text, so decode from raw bytes gated on the exact
        type-string marker. Stored under a tag_reference sentinel so
        own_description never surfaces it as a Description.
        """
        i = raw.find(marker)
        if i < 0 or len(raw) < 14:
            return None
        seq_number = struct.unpack_from("<H", raw, 4)[0]
        record_type = struct.unpack_from("<H", raw, 6)[0]
        sub_record_length = struct.unpack_from("<H", raw, 8)[0]
        parent = struct.unpack_from("<I", raw, 10)[0]
        pos = i + len(marker)
        if short_header:
            while (pos + 1 < len(raw)
                    and struct.unpack_from("<H", raw, pos)[0] == 0):
                pos += 2
            cus = []
            while pos + 1 < len(raw):
                cu = struct.unpack_from("<H", raw, pos)[0]
                pos += 2
                if cu == 0:
                    break
                cus.append(cu)
            text = "".join(chr(c) for c in cus)
        else:
            while pos < len(raw) and raw[pos] == 0:
                pos += 1
            end = raw.find(b"\x00", pos)
            if end < 0:
                end = len(raw)
            text = raw[pos:end].decode("utf-8", errors="replace")
        if not text:
            return None
        return (
            seq_number,
            sub_record_length,
            object_id,
            text,
            record_type,
            parent,
            tag_ref,
            0,
            0,
            0,
        )

    @staticmethod
    def _parse_sp_operand_body(raw: bytes) -> Optional[tuple]:
        """Parse a SOURCE-PROTECTED long-header operand record, or None.

        An SP project AES-256-CBC encrypts the record tail from the comps
        marker (ciphertext at marker+18, IV = 0, PKCS7), which lands
        mid-operand: the plaintext keeps the whole header -- including the
        kind byte at body[13] -- plus the first UTF-16 code unit(s) of the
        operand (typically just the leading '.'), and the decrypted tail is
        the operand remainder + the standard 12-byte pad + UTF-8 text (or the
        trailing REAL for Min/Max): exactly the layout
        _parse_long_operand_body reads on a plaintext record. Key selection
        mirrors _decrypt_sp_comment_text (cached-config first; accept on
        valid PKCS7 + the operand gates + strict UTF-8 text).
        """
        if len(raw) < 30:
            return None
        mi = raw.find(_SP_MARKER, 14)
        # The marker must sit beyond the fixed operand-body prelude (body[16]
        # == raw[30] is where the operand starts); an earlier hit is not an
        # operand-tail encryption.
        if mi < 30:
            return None
        seq_number = struct.unpack_from("<H", raw, 4)[0]
        record_type = struct.unpack_from("<H", raw, 6)[0]
        sub_record_length = struct.unpack_from("<H", raw, 8)[0]
        parent = struct.unpack_from("<I", raw, 10)[0]
        body = raw[14:]
        if len(body) < 16:
            return None
        owner_ref = struct.unpack_from("<I", body, 0)[0]
        object_id = struct.unpack_from("<I", body, 8)[0]
        kind = body[13]
        if kind in (0x04, 0x21):
            # Non-comment operand-row kinds (member cross-reference 0x04, alarm-
            # trigger binding 0x21); drop before attempting the decrypt.
            return None
        prefix = raw[30:mi]
        ct = raw[mi + 18:]
        nblocks = len(ct) // 16
        if nblocks < 1:
            return None
        order = list(_SP_KEYS)
        hint = _SP_KEY_HINT[0]
        if hint is not None:
            order.sort(key=lambda kv: 0 if kv[0] == hint else 1)
        for config, key in order:
            pt = _sp_cbc(ct, _sp_aes(config, key), nblocks)
            if len(pt) < 1:
                continue
            pad = pt[-1]
            if not (1 <= pad <= 16) or pt[-pad:] != bytes([pad]) * pad:
                continue
            blob = prefix + pt[:-pad]
            pos = 0
            cus = []
            while pos + 1 < len(blob):
                cu = struct.unpack_from("<H", blob, pos)[0]
                pos += 2
                if cu == 0:
                    break
                cus.append(cu)
            if not cus:
                continue
            operand = "".join(chr(c) for c in cus)
            if operand[0] not in ".[":
                continue
            if any((ord(c) < 0x20 and c != "\t") for c in operand):
                continue
            if kind in (0x02, 0x03):
                if len(blob) < pos + 4:
                    continue
                from acd.l5x.tag_value import _fmt_real_decorated
                text = _fmt_real_decorated(
                    struct.unpack("<f", blob[-4:])[0])
            else:
                tpos = pos + 12
                end = blob.find(b"\x00", tpos)
                if end < 0:
                    end = len(blob)
                try:
                    text = blob[tpos:end].decode("utf-8")
                except UnicodeDecodeError:
                    continue
                if not text:
                    continue
            _SP_KEY_HINT[0] = config
            return (
                seq_number,
                sub_record_length,
                object_id,
                text,
                record_type,
                parent,
                operand,
                0,
                kind,
                owner_ref,
            )
        return None

    @staticmethod
    def parse(dat_record: DatRecord, short_header: bool = False) -> Optional[tuple]:
        result = CommentsRecord._parse_core(dat_record, short_header)
        sp_recovered = False
        if result is None:
            # _parse_core dropped the record whole. On a source-protected rt-1/2
            # record that is a decode artefact, not a real rejection, so recover
            # it by hand -- see _parse_sp_ascii_record.
            result = CommentsRecord._parse_sp_ascii_record(dat_record, short_header)
            if result is None:
                return None
            sp_recovered = True
        # Source-protected DESCRIPTION records carry the text AES-encrypted
        # after the comps marker; the parsers above recover the lookup keys
        # (from the plaintext header) but a garbage text. Swap in the decrypted
        # text when the marker is present so the recovered keys map to the real
        # Description. Gated to rows WITHOUT an operand (tag_reference == ''):
        # SP operand rows are decoded whole by _parse_sp_operand_body (their
        # text does not sit at the description layout's offset 12, so this
        # swap would corrupt them).
        try:
            raw_full = bytes(dat_record.record.record_buffer)
            if not sp_recovered and _SP_MARKER in raw_full and not result[6]:
                text = _decrypt_sp_comment_text(raw_full)
                if text is not None:
                    result = result[:3] + (text,) + result[4:]
        except Exception:
            pass
        # Operand-comment revision: Studio keeps prior edits of an operand comment
        # in Comments.Dat and the reference export emits only the LATEST. The
        # revision is a u16 at raw offset 28 (body[14:16]) of a long-header operand
        # record (body[12]==0, body[13] a comment/Min/Max/EngUnit kind). 0 for
        # short-header and non-operand rows -> the max-revision dedup is a no-op
        # there. Appended as the 11th comments-table column.
        revision = 0
        try:
            raw_full = bytes(dat_record.record.record_buffer)
            if (not short_header and len(raw_full) >= 30
                    and raw_full[26] == 0x00
                    and raw_full[27] in (0x01, 0x02, 0x03, 0x05)):
                revision = struct.unpack_from("<H", raw_full, 28)[0]
        except Exception:
            revision = 0
        return result + (revision,)

    @staticmethod
    def _parse_sp_ascii_record(
        dat_record: DatRecord, short_header: bool = False
    ) -> Optional[tuple]:
        """Recover a source-protected rt-1/2 description record _parse_core drops.

        The kaitai AsciiRecord grammar decodes the body's trailing text field as
        UTF-8 EAGERLY. Under source protection that field is ciphertext, so
        whenever it happens not to be valid UTF-8 the whole record parse raises
        and _parse_core returns None -- dropping the record's keys along with its
        text, even though every key is in the PLAINTEXT header (source protection
        replaces only the text tail).

        So hand-walk the header at the AsciiRecord offsets -- body starts at
        raw[14]: member_ref u32@14, rung_content u32@18, object_id u32@27, text
        raw[44:]; header: seq u16@4, record_type u16@6, sub_record_length u16@8,
        parent u32@10 -- and take the text from the shared SP decryptor.

        Pure fallback: fires only for a long-header rt-1/2 record that carries the
        marker, is currently dropped whole, AND whose decrypt validates. It
        therefore cannot regress a record that parses today.
        """
        if short_header or dat_record.identifier != 64250:
            return None
        try:
            raw = bytes(dat_record.record.record_buffer)
        except Exception:
            return None
        if len(raw) < 44 or _SP_MARKER not in raw:
            return None
        record_type = struct.unpack_from("<H", raw, 6)[0]
        if record_type not in (0x01, 0x02):
            return None
        text = _decrypt_sp_comment_text(raw)
        if text is None:
            return None
        member_ref = struct.unpack_from("<I", raw, 14)[0]
        return (
            struct.unpack_from("<H", raw, 4)[0],    # seq_number
            struct.unpack_from("<H", raw, 8)[0],    # sub_record_length
            struct.unpack_from("<I", raw, 27)[0],   # object_id
            text,                                   # record_string
            record_type,
            struct.unpack_from("<I", raw, 10)[0],   # parent
            "",                                     # tag_reference (rt-1/2: none)
            struct.unpack_from("<I", raw, 18)[0],   # rung_content
            member_ref,
            member_ref,                             # owner_ref (same slot on rt-1/2)
        )

    @staticmethod
    def _parse_core(dat_record: DatRecord, short_header: bool = False) -> Optional[tuple]:
        if dat_record.identifier != 64250:
            return None
        raw_full = bytes(dat_record.record.record_buffer)
        # AOI AdditionalHelpText (UDI_EXT_HELP) -- both header families; the
        # marker gate is exact, and neither downstream parser handles these
        # (the short operand parser bails on UDI_ and the kaitai mangles the
        # short-header layout).
        if CommentsRecord._UDI_EXT_HELP_MARKER in raw_full:
            parsed = CommentsRecord._parse_udi_text(
                raw_full, short_header, CommentsRecord._UDI_EXT_HELP_MARKER,
                "__EXT_HELP__", 0)
            if parsed is not None:
                return parsed
        # UDI_HISTORY (RevisionNote): the long-header UTF-8 form is handled by
        # the kaitai path below; short-header stores the text UTF-16LE, which
        # that path mangles, so decode it here (family-aware) for short-header.
        if short_header and CommentsRecord._UDI_HISTORY_MARKER in raw_full:
            parsed = CommentsRecord._parse_udi_text(
                raw_full, short_header, CommentsRecord._UDI_HISTORY_MARKER,
                "__REVISION_NOTE__", 1)
            if parsed is not None:
                return parsed
        # V10..V21 short-header operand comments (member/bit/array element
        # comments) use a different body layout than V24+ long-header records.
        # Decode them here so TagBuilder can emit <Comment Operand="..."> children.
        # Long-header export is untouched: this branch is gated on short_header
        # and falls through to the original parser on any failure.
        if short_header and len(raw_full) >= 8:
            try:
                rt = struct.unpack_from("<H", raw_full, 6)[0]
                # Own-description records (component Description text) in UTF-16LE.
                # The shared FafaComents AsciiRecord decodes these as UTF-8 (the
                # V24+ layout), which mangles short-header UTF-16 text, so parse
                # them here. Falls through to the original parser on any failure.
                if rt in (0x01, 0x02):
                    parsed = CommentsRecord._parse_short_desc_body(raw_full)
                    if parsed is not None:
                        return parsed
                # Everything else is an operand/member/array-element comment.
                # record_type here is the comment's ORDINAL within its parent
                # group (observed 3..36 across V10..V21), NOT a fixed type enum:
                # a tag/datatype with N member comments emits records numbered up
                # to ~N+2. They all share one body layout (six zero bytes + a
                # UTF-16 operand at body+13). _parse_short_operand_body validates
                # the structure and returns None for the non-operand records that
                # also land here (UDI metadata, etc.), so attempting it for every
                # non-1/2 type recovers comments the old fixed {3..11} allowlist
                # dropped (e.g. rt 8, 12 and 15-36) without misparsing anything.
                else:
                    parsed = CommentsRecord._parse_short_operand_body(raw_full)
                    if parsed is not None:
                        return parsed
            except Exception:
                pass
        # V24+ long-header operand/member/array comments whose record_type is not
        # one of the four the kaitai decodes (3/4/13/14). 1/2 = own descriptions,
        # 12 = UDI metadata -- handled below; every other type is attempted as an
        # operand record here. record_type is an ORDINAL within the parent group,
        # not a type enum, so even the ordinals genuine controller records use
        # elsewhere (23/25) are legitimate operand comments on a tag with enough
        # of them (a 1,113-comment tag reaches ordinals far beyond both); the
        # structural gates in the parser (leading './[' operand, printable,
        # non-empty text) reject real controller records, which then fall to the
        # kaitai path exactly as before.
        # A source-protected record's operand tail is AES-encrypted from the
        # comps marker (the plaintext parse below would yield a mojibake operand
        # that the emission validator rejects), so try the SP-aware parse FIRST
        # for any marker-bearing operand-family record -- including the kaitai
        # ordinals 3/4/13/14, whose kaitai parse is equally mojibake under SP.
        if not short_header and len(raw_full) >= 8:
            try:
                rt = struct.unpack_from("<H", raw_full, 6)[0]
                if (rt not in (0x01, 0x02, 0x0C)
                        and _SP_MARKER in raw_full):
                    parsed = CommentsRecord._parse_sp_operand_body(raw_full)
                    if parsed is not None:
                        return parsed
                if rt not in (0x01, 0x02, 0x03, 0x04, 0x0C, 0x0D, 0x0E):
                    parsed = CommentsRecord._parse_long_operand_body(raw_full)
                    if parsed is not None:
                        return parsed
            except Exception:
                pass
        try:
            r = FafaComents.from_bytes(dat_record.record.record_buffer)
            # Type-12 (0x0C) records carry UDI metadata such as the AOI RevisionNote.
            # The body is a raw-bytes record; parse it to extract the text.
            if r.header.record_type == 12:
                parsed = CommentsRecord._parse_udi_body(bytes(r.body.data))
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
                    0,              # owner_ref
                )
            # The grammar's switch default now parses every other record_type as
            # a utf_16_record too (formalizing that they share the operand
            # layout), but those types remain the domain of the validated hand
            # walkers above -- a record of one of them reaching this point
            # already failed the operand gates, and before the default existed
            # it fell to the raw-bytes branch and dropped here on the missing
            # body attributes. Keep dropping it explicitly.
            if r.header.record_type not in (0x01, 0x02, 0x03, 0x04,
                                            0x0D, 0x0E, 0x17, 0x19):
                return None
            if r.header.record_type in (0x03, 0x04, 0x0D, 0x0E):
                tag_ref = r.body.tag_reference.value
            else:
                tag_ref = ""
            # An OPERAND row (raw[27]) whose kind is a member cross-reference
            # (0x04, where-used flags) or an AlarmCondition trigger binding
            # (0x21) is not a comment -- same body layout as the hand-walked
            # ordinals, so gate both here too. rt-1/2 description rows use the
            # same slot for the member_ref low byte and are NOT filtered.
            if (tag_ref and tag_ref[:1] in (".", "[")
                    and len(raw_full) >= 28
                    and raw_full[26] == 0x00
                    and raw_full[27] in (0x04, 0x21)):
                return None
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
            # The owner-reference slot (body[0:4] == raw[14:18]) is the owning
            # comp's own comment key on operand rows (see
            # _parse_long_operand_body); read it from the raw bytes so the
            # kaitai-decoded ordinals (3/4/13/14) can be attributed under a
            # shared program-scope parent key too. On rt-1/2 description rows
            # the same slot is the member_ref already extracted above.
            owner_ref = (
                struct.unpack_from("<I", raw_full, 14)[0]
                if not short_header and len(raw_full) >= 18 else 0
            )
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
                owner_ref,
            )
        except Exception:
            return None
