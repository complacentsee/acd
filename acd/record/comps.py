import weakref
from dataclasses import dataclass
from io import BytesIO
from sqlite3 import Cursor
from typing import Optional

from acd.database.dbextract import DatRecord
from kaitaistruct import KaitaiStream

from acd.generated.comps.fafa_comps import FafaComps
from acd.generated.comps.fdfd_comps import FdfdComps
from acd.generated.comps.short_comps import ShortComps
# The source-protection marker, key table and CBC helper are shared with the
# comments text tail and the SbRegion rung buffer, so they live in the module
# that owns the format. Re-exported here: this module is the historical import
# site for them.
from acd.record.source_protection import (  # noqa: F401
    _SP_AES_CACHE, _SP_CT_OFFSET, _SP_KEY_HINT, _SP_KEYS, _SP_MARKER,
    _sp_aes, _sp_cbc,
)

# Comps record identifiers (little-endian u16).
_FAFA_IDENTIFIER = 64250  # 0xFAFA primary records
_FDFD_IDENTIFIER = 65021  # 0xFDFD secondary / sub records

# Per-cursor memos for record_attrs (the body-direct attr read) and dead_oids
# (the liveness set). One export owns one cursor, and the builders re-read the
# same comps rows many ways; entries die with the cursor, so consecutive exports
# in one process never share state.
_RECORD_ATTRS_CACHE: "weakref.WeakKeyDictionary[Cursor, dict]" = weakref.WeakKeyDictionary()
_DEAD_OIDS_CACHE: "weakref.WeakKeyDictionary[Cursor, frozenset]" = weakref.WeakKeyDictionary()

# --- Source-protection-at-rest (comps ext-attr tail) -------------------------
# A source-protected project keeps each comps record's main_record PLAINTEXT but
# AES-256-CBC encrypts the extended-attribute tail (which carries the value
# backing's 0x66 design value). The encrypted tail replaces the plaintext
# len_record/count_record at body+78 with a fixed marker + 14-byte framing; the
# ciphertext starts at marker + _SP_CT_OFFSET and is a whole number of 16-byte
# blocks. The decrypted plaintext is the ordinary ext-attr table: u32 attr-count
# then (u32 attribute_id, u32 len_value, len_value bytes) records.
#
# This tail carries no config byte, so the key is found by search: the config is
# project-wide, so the first key that validates is cached in _SP_KEY_HINT and
# tried first thereafter. (The SbRegion rung tail DOES carry its config on the
# wire -- see acd.record.source_protection -- so it never searches.)


def _sp_walk(pt: bytes, max_count: int = 255) -> Optional[dict]:
    """Parse a decrypted ext-attr table ``[u32 count][(u32 id,u32 len,bytes)...]``.

    Returns the {attribute_id: bytes} dict, or None if the layout is structurally
    invalid (used to reject a wrong decryption key). ``max_count`` is the
    caller-computed capacity of the FULL table (after the 4-byte count, each
    attribute is at least an 8-byte id+length header), so the count check stays
    a wrong-key rejector without capping how many attributes a record may
    legitimately carry.
    """
    if len(pt) < 4:
        return None
    count = int.from_bytes(pt[0:4], "little")
    if not (0 < count <= max_count):
        return None
    out: dict = {}
    pos = 4
    for _ in range(count):
        if pos + 8 > len(pt):
            break  # truncated (we only decrypted up to the wanted attr)
        aid = int.from_bytes(pt[pos:pos + 4], "little")
        ln = int.from_bytes(pt[pos + 4:pos + 8], "little")
        pos += 8
        if ln > len(pt) or pos + ln > len(pt):
            break
        out[aid] = pt[pos:pos + ln]
        pos += ln
    return out


def _decrypt_value_attrs(ciphertext: bytes, full: bool = False) -> dict:
    """Decrypt a source-protected ext-attr tail to {attribute_id: bytes}.

    Picks the project's source-protection key by a cheap one-block validation
    (the table always begins ``count, attr 0x01, ...``), caching the winning
    config. By default decrypts only as far as the design value (0x66) so a large
    array backing does not pay for full decryption; pass ``full=True`` to decrypt
    the WHOLE table (needed for datatype records, whose member descriptors live in
    attrs 0x6E.. after 0x66). Returns {} when no key validates (e.g. a coincidental
    marker in a non-protected record).
    """
    nblocks_total = len(ciphertext) // 16
    if nblocks_total == 0:
        return {}
    # Table capacity: after the 4-byte count each attribute is >= 8 bytes
    # (u32 id + u32 len), so the count can't exceed this and still fit the
    # decrypted buffer. A count within it is plausible; beyond it is a wrong-key
    # signal. Predefined datatype records (AXIS_CIP_DRIVE, MMC, CC, ...)
    # legitimately carry hundreds of member-descriptor attributes, so a fixed
    # 256 ceiling would reject them.
    max_count = max(1, (nblocks_total * 16 - 4) // 8)
    order = list(_SP_KEYS)
    hint = _SP_KEY_HINT[0]
    if hint is not None:
        order.sort(key=lambda kv: 0 if kv[0] == hint else 1)
    for config, key in order:
        aes = _sp_aes(config, key)
        head = _sp_cbc(ciphertext, aes, 1)
        # Validate: a real ext-attr table starts with a sane count and attr 0x01.
        if len(head) < 8:
            continue
        count = int.from_bytes(head[0:4], "little")
        first_id = int.from_bytes(head[4:8], "little")
        if not (0 < count <= max_count) or first_id != 0x01:
            continue
        _SP_KEY_HINT[0] = config
        if full:
            # Whole-table mode: decrypt every block once, then walk once. (The
            # incremental grow-and-rewalk below is O(blocks^2) and a large datatype
            # blob has hundreds of blocks, so it must not be used here.)
            plain = _sp_cbc(ciphertext, aes, nblocks_total)
            return _sp_walk(plain, max_count) or {}
        # Value mode: grow the decrypted prefix only until 0x66 is complete (a big
        # array backing then never pays for full decryption). One expanding pass.
        plain = bytearray(head)
        nblocks = 1
        prev = ciphertext[0:16]
        while True:
            attrs = _sp_walk(bytes(plain))
            if attrs is not None and 0x66 in attrs:
                return attrs
            if nblocks >= nblocks_total:
                return attrs or {}
            blk = ciphertext[nblocks * 16:nblocks * 16 + 16]
            plain += bytes(x ^ y for x, y in zip(aes.decrypt_block(blk), prev))
            prev = blk
            nblocks += 1
    return {}


def decrypt_sp_nameless(record: bytes) -> Optional[bytes]:
    """Decrypt a source-protected AOI *nameless* metadata record in place.

    A non-protected AOI nameless record is ``header(20B) + ffffffff + body`` where
    ``body`` is ``[u16 ver=1][fffeff-strings + FILETIMEs ...]`` (created_by /
    created_date / edited_by / software_revision / revision_extension / edited_date
    -- the layout ``_parse_aoi_nameless`` walks). On a source-protected AOI that
    body is AES-256-CBC encrypted (IV=0, the project SP key) with the SAME marker
    framing the comps ext-attr tail uses: ``aa96aa0a`` replaces the ``ffffffff``
    sentinel, the plaintext byte length sits at ``marker+4`` (u16), and the
    ciphertext (PKCS7-padded, then 0xFF-filled to the record's slot size) starts at
    ``marker+18``. Strings are UTF-16-LE (the fffeff prefix), NOT UTF-8.

    Returns a reconstructed PLAINTEXT record (``header + ffffffff + decrypted
    body``) that ``_parse_aoi_nameless`` can parse byte-for-byte as if it were
    never protected, or ``None`` when there is no marker (already plaintext) or no
    SP key validates (project key unknown -> caller keeps its existing behaviour).
    """
    try:
        midx = record.find(_SP_MARKER)
        if midx < 0:
            return None
        # Plaintext length is framed at marker+4 (u16); round up to the AES block
        # so trailing 0xFF slot-fill past the padded ciphertext is excluded.
        plen = int.from_bytes(record[midx + 4:midx + 6], "little")
        ctlen = ((plen + 15) // 16) * 16
        ct = record[midx + _SP_CT_OFFSET:midx + _SP_CT_OFFSET + ctlen]
        nblk = len(ct) // 16
        if nblk == 0:
            return None
        order = list(_SP_KEYS)
        hint = _SP_KEY_HINT[0]
        if hint is not None:
            order.sort(key=lambda kv: 0 if kv[0] == hint else 1)
        for config, key in order:
            aes = _sp_aes(config, key)
            head = _sp_cbc(ct, aes, 1)
            # A real body begins u16 ver==1 then the first empty fffeff string.
            if not (head[0:2] == b"\x01\x00" and head[2:5] == b"\xff\xfe\xff"):
                continue
            _SP_KEY_HINT[0] = config
            pt = _sp_cbc(ct, aes, nblk)
            pad = pt[-1] if pt else 0
            if 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad:
                pt = pt[:-pad]
            return record[:midx] + b"\xff\xff\xff\xff" + pt
        return None
    except Exception:
        return None


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
# The layout is declared in the ShortComps grammar (the primary parse); these
# constants back the lenient fallback for records whose name window the
# grammar's strz refuses, plus body_offset().
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
        """V10..V21 FAFA/FDFD header parse via the ShortComps grammar."""
        if dat_record.identifier not in (_FAFA_IDENTIFIER, _FDFD_IDENTIFIER):
            return None
        buf = dat_record.record.record_buffer
        if len(buf) < _SH_BODY_OFF:
            return None
        try:
            r = ShortComps.from_bytes(buf)
            return (r.object_id, r.parent_id, r.record_name.value,
                    r.seq_number, r.record_type, r.record_buffer)
        except Exception:
            # The grammar's strz raises where the hand decode tolerates (a
            # name window that is truncated, unterminated within its 82
            # bytes, or not valid UTF-16); re-parse with the manual walk.
            # (The grammar is the decoder of record for well-formed names, so
            # a valid UTF-16 surrogate pair decodes to its combined astral
            # codepoint -- matching the long-header FafaComps/FdfdComps strz --
            # where the lenient walk below would emit two lone surrogates.
            # That alignment is deliberate; no pool name exercises it.)
            return CompsRecord._parse_short_lenient(dat_record)

    @staticmethod
    def _parse_short_lenient(dat_record: DatRecord) -> Optional[tuple]:
        """Manual short-header parse (absolute offsets above): the fallback
        for records whose name window the grammar refuses."""
        buf = dat_record.record.record_buffer
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
    def dead_oids(cur: Cursor, short_header: bool) -> frozenset:
        """object_ids of export-DEAD components: comps rows with no FAFA-family
        record (``comps_family.fafa_seen == 0``). Such an oid is a deleted relic
        Studio keeps in Comps.Dat but never exports; every component-enumeration
        and every by-value comps scan drops these so a relic is neither emitted
        nor allowed to overwrite a live component. See P6.9.

        Applies to BOTH header families since C6: FDFD-only is a deleted relic
        regardless of the body offset (the long-header realignment was the reason
        the gate was long-header-only through C2-C5; the liveness SEMANTIC holds
        on short-header too). ``short_header`` is retained for call-site symmetry
        but no longer changes the answer. Cached per cursor; empty if the
        comps_family side table is absent (older staging schema)."""
        cache = _DEAD_OIDS_CACHE.get(cur)
        if cache is None:
            try:
                cache = frozenset(
                    oid for (oid,) in cur.execute(
                        "SELECT object_id FROM comps_family WHERE fafa_seen=0"))
            except Exception:
                cache = frozenset()
            _DEAD_OIDS_CACHE[cur] = cache
        return cache

    @staticmethod
    def record_attrs(cur: Cursor, object_id: int, short_header: bool) -> dict:
        """{attribute_id: bytes} from ``read_value_attrs(full=True,
        body_mode=True)`` on the ``comps.record`` body for ``object_id``; {}
        when there is no row. Since the P6.7a size-eos flip ``comps.record``
        carries the whole untruncated body, so this body-direct read is the
        single source of truth (the comps_full table and the full_record /
        full_attrs round-trip it fed were retired in P6.9 C8). Memoized per
        cursor -- treat the returned dict as read-only."""
        cache = _RECORD_ATTRS_CACHE.setdefault(cur, {})
        key = (object_id, bool(short_header))
        if key not in cache:
            row = cur.execute(
                "SELECT record FROM comps WHERE object_id=?", (object_id,)
            ).fetchone()
            rec = bytes(row[0]) if row and row[0] is not None else None
            cache[key] = ({} if rec is None else
                          CompsRecord.read_value_attrs(rec, short_header,
                                                       full=True,
                                                       body_mode=True))
        return cache[key]

    @staticmethod
    def read_ext_attrs_from_record(record: bytes, full: bool = False) -> dict:
        """Recover {attribute_id: bytes} from a source-protected component record.

        ``record`` is the RxGeneric body (the same bytes passed to
        RxGeneric.from_bytes: 14B prelude + 60B main_record + ext-attr tail). When
        the tail is source-protected its plaintext count at body+78 is replaced by
        the marker and the rest is AES-encrypted; decrypt it to the ordinary attr
        table. Returns {} when there is no marker (a plaintext record) or no key
        validates, so callers fall back to their existing behaviour. The search
        starts past the 74-byte prelude+main so a marker-like byte sequence inside
        the plaintext main_record is never matched.
        """
        try:
            midx = record.find(_SP_MARKER, 74)
            if midx < 0:
                return {}
            ct = record[midx + _SP_CT_OFFSET:]
            ct = ct[:(len(ct) // 16) * 16]
            return _decrypt_value_attrs(ct, full=full) or {}
        except Exception:
            return {}

    @staticmethod
    def read_value_attrs(full_payload: bytes, short_header: bool, full: bool = False,
                         body_mode: bool = False) -> dict:
        """Walk a cip-0x6a backing's body and return {attribute_id: bytes}.

        ``full_payload`` MUST be the untruncated stream payload WITH its
        family header (u32 record_length + header), from which the body is
        sliced at ``body_offset`` -- unless ``body_mode=True``, which declares
        the bytes ARE already the body (``comps.record`` post size-eos, the way
        every production caller reads it now) so no header slice is taken.
        Returns an empty dict on any structural problem so callers fall back to
        today's zero-placeholder behaviour.

        Body layout (from body_offset): 14B RxGeneric prelude + 60B main_record,
        then at body+74: u32 len_record, u32 count_record, then a sequence of
        (u32 attribute_id, u32 len_value, len_value bytes) attribute records.
        We walk to buffer exhaustion (NOT count_record) so 0x66 is captured.

        ``full`` forces decryption of the WHOLE source-protected table (not just
        up to 0x66); datatype records keep their member descriptors in attrs
        0x6E.. which come after 0x66.
        """
        out: dict = {}
        try:
            off = 0 if body_mode else CompsRecord.body_offset(short_header)
            body = full_payload[off:]
            # Source-protection-at-rest: the ext-attr tail is AES-encrypted, with
            # a fixed marker replacing the plaintext count at body+78. Decrypt it
            # to the ordinary attr table. (Plaintext records have no marker and
            # take the walk below, byte-for-byte unchanged.)
            midx = body.find(_SP_MARKER, 74)
            if midx >= 0:
                ct = body[midx + _SP_CT_OFFSET:]
                ct = ct[:(len(ct) // 16) * 16]
                dec = _decrypt_value_attrs(ct, full=full)
                if dec:
                    return dec
                # Fall through to the plaintext walk on a failed decrypt so a
                # coincidental marker never blanks an otherwise-readable record.
            # prelude(14) + main_record(60) = 74, then len_record/count_record.
            pos = 74 + 8  # skip len_record(4)+count_record(4)
            n = len(body)
            while pos + 8 <= n:
                attr_id = int.from_bytes(body[pos:pos + 4], "little")
                ln = int.from_bytes(body[pos + 4:pos + 8], "little")
                pos += 8
                if ln < 0 or pos + ln > n:
                    break
                # Keep the FIRST occurrence of each attribute id. The walk runs
                # past the declared attribute table (so a trailing image attr is
                # still seen), but on a forced / relocated-value backing the bytes
                # after the real attributes (zero padding plus the 0x82/0x6b force
                # holder refs) parse as spurious (id, len) pairs and can re-emit an
                # id already captured -- e.g. a stray 4-byte 0x66 that would clobber
                # the real inline design-value image. The genuine attributes always
                # precede that region, and datatype member descriptors use unique
                # incrementing ids, so keeping the first occurrence is correct.
                if attr_id not in out:
                    out[attr_id] = body[pos:pos + ln]
                pos += ln
        except Exception:
            return {}
        return out

    @staticmethod
    def read_tag_value(full_payload: bytes, short_header: bool, body_mode: bool = False):
        """Return (value_bytes, cip_type_code) from a cip-0x6a backing, or None.

        value_bytes = ext attr 0x66 (the design value); cip_type_code = ext attr
        0x65 (u16, 0 if absent). Returns None when 0x66 is missing so callers
        keep today's zero-placeholder behaviour. ``body_mode`` as in
        ``read_value_attrs``.
        """
        attrs = CompsRecord.read_value_attrs(full_payload, short_header,
                                             body_mode=body_mode)
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
    # Proven on one project's staging db: an AOI image size 1328; a UDINT
    # param@128 = 82; a second AOI's command-code param@624 = 01 00 00 00
    # 43 00 ('C').

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
                "SELECT record FROM comps WHERE object_id=?", (dti,)
            )
            brow = cur.fetchone()
            if not brow or brow[0] is None:
                return None
            attrs = CompsRecord.read_value_attrs(bytes(brow[0]), short_header,
                                                 body_mode=True)
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
