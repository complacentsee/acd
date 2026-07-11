import argparse
import os
import re
import sqlite3
import struct
from dataclasses import dataclass
from pathlib import Path
from sqlite3 import Cursor
from typing import Dict, List, Optional, Union

from acd.database.dbextract import DbExtract
from acd.zip.unzip import Unzip
from loguru import logger as log

from acd.l5x.elements import (
    Controller,
    ControllerBuilder,
    ProjectBuilder,
    RSLogix5000Content,
)
from acd.record.comments import CommentsRecord
from acd.record.comps import CompsRecord, record_uses_short_header
from acd.record.nameless import NamelessRecord
from acd.record.sbregion import SbRegionRecord
from acd.record.source_protection import build_uid_name_map, is_v21_version


def detect_acd_version(acd_filename: os.PathLike) -> Optional[str]:
    """Read the 'Saved - VNN.../NNNN.NNN' Studio version string from an ACD.

    The version banner lives in the plaintext Version.Log at the very start of
    the ACD container, so a short read of the file head suffices.  Returns the
    last (most recent) saved version string, or None if not found.  Used to
    select the V21 source-protection rung path (see acd.record.sbregion).
    """
    try:
        with open(acd_filename, "rb") as fh:
            head = fh.read(8192).decode("latin1")
    except OSError:
        return None
    matches = re.findall(r"Saved - (V[\d.]+/[\d.]+)", head)
    return matches[-1] if matches else None


_FAFA_IDENTIFIER = 64250  # 0xFAFA stream identifier
_FDFD_IDENTIFIER = 65021  # 0xFDFD stream identifier


def _walk_comps_records(records, short_header: bool):
    """Dedup walk over the Comps.Dat stream records.

    Returns ``(comps_by_id, record_length_by_id, winner_family, fafa_seen_ids)``:
      comps_by_id        oid -> parsed tuple of the dedup winner
      record_length_by_id oid -> declared record_length (u32 @ offset 0) of the
                         LARGEST full stream payload for that oid; 0 when the
                         payload is unreadable or shorter than 4 bytes (and on
                         FDFD winners, whose @0 length is 0). This is the only
                         datum the module-builder truncation shim needs from the
                         (now-retired) comps_full table.
      winner_family      oid -> stream identifier (0xFAFA/0xFDFD) of the winner
      fafa_seen_ids      oids with >=1 FAFA-family record. A component is
                         export-live only if a FAFA primary exists for it: an
                         FDFD-only oid is a deleted relic Studio never exports
                         (measured pool-wide: FDFD wins zero dual-family dedups
                         and no FDFD-only oid appears in any OEM export).
    """
    comps_by_id = {}
    comps_len_by_id: Dict[int, int] = {}   # oid -> winning dedup length
    # Per oid, the LARGEST full stream-payload length seen and that payload's
    # declared record_length (u32 @0). Since the P6.7a size-eos flip the comps
    # `record` column already carries the whole untruncated body, so only the
    # declared length is still needed downstream (the module-builder shim
    # re-imposes it on the raw-tail scans). We no longer retain the full bytes.
    full_len_by_id: Dict[int, int] = {}
    record_length_by_id: Dict[int, int] = {}
    winner_family: Dict[int, int] = {}
    fafa_seen_ids: set = set()
    for record in records:
        # An anomalous comps record can run its name/StrzUtf16 field past the
        # buffer end (kaitai read_u2le EOF) and raise inside parse; skip the
        # bad record rather than aborting the whole export (mirrors the guarded
        # full-payload read just below).
        try:
            t = CompsRecord.parse(record, short_header)
        except Exception:  # noqa: BLE001
            continue
        if t is not None:
            oid = t[0]
            if record.identifier == _FAFA_IDENTIFIER:
                fafa_seen_ids.add(oid)
            try:
                full = bytes(record.record.record_buffer)
            except Exception:  # noqa: BLE001
                full = None
            # Dedup both maps on the FULL stream-payload length
            # (record.record.record_buffer, untruncated), NOT len(t[5]): the
            # latter is the TRUNCATED FafaComps.record_buffer today but
            # becomes the whole size-eos body after the P6.7a un-truncation,
            # so keying on it lets the kept duplicate flip once payload length
            # != record_length-148. The full payload length is what the flip
            # cannot change, and it picks the SAME winner as len(t[5]) across
            # all 14,804 duplicated oids pool-wide (verified). Declared
            # record_length@0 is NOT usable here -- it is 0 on FDFD records.
            dedup_len = len(full) if full is not None else len(t[5])
            if oid not in comps_by_id or dedup_len > comps_len_by_id[oid]:
                comps_by_id[oid] = t
                comps_len_by_id[oid] = dedup_len
                winner_family[oid] = record.identifier
            if full is not None and (
                    oid not in full_len_by_id or len(full) > full_len_by_id[oid]):
                full_len_by_id[oid] = len(full)
                record_length_by_id[oid] = (
                    int.from_bytes(full[0:4], "little") if len(full) >= 4 else 0)
    return comps_by_id, record_length_by_id, winner_family, fafa_seen_ids


@dataclass
class ExportL5x:
    input_filename: os.PathLike
    _temp_dir: str = "build"  # tempfile.mkdtemp()
    _controller: Union[Controller, None] = None
    _project: Union[RSLogix5000Content, None] = None
    # Faithful mode reproduces exactly what Studio exports (e.g. omits source-
    # protected AOIs whose source Studio withholds). Default False = recover as much
    # as possible (emit decoded plaintext for source-protected content).
    faithful: bool = False
    # Staging database location. None (the default) stages the parsed ACD tables
    # into an in-memory SQLite database; a path stages into that file instead
    # (replacing any existing one), for inspecting the tables after an export.
    db_path: Union[str, None] = None

    def __post_init__(self):
        self._init_db()
        self._extract_files()
        comps_db, name_lookup = self._load_comps()
        self.populate_region_map()
        self.populate_regn_link()
        self._load_rungs(comps_db, name_lookup)
        self._load_comments()
        self._load_nameless()
        self._load_taginfo()
        self._create_indexes()

    def close(self):
        """Close the staging database connection.

        The exporter (and any Controller still holding its cursor) is unusable
        afterwards; call once the L5X output has been produced.
        """
        self._db.close()

    def _init_db(self):
        """Create the staging SQLite database (see db_path) and its core tables."""
        if self.db_path is None:
            log.info("Creating in-memory sqllite database to store ACD database records")
            self._db = sqlite3.connect(":memory:")
        else:
            log.info(
                "Creating sqllite database to store ACD database records - "
                + str(self.db_path)
            )
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
            _parent = os.path.dirname(str(self.db_path))
            if _parent and not os.path.exists(_parent):
                os.makedirs(_parent)
            self._db = sqlite3.connect(self.db_path)
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=OFF")
        self._cur: Cursor = self._db.cursor()

        log.debug("Create Comps table in sqllite db")
        self._cur.execute(
            "CREATE TABLE comps(object_id int, parent_id int, comp_name text, seq_number int, record_type int, record BLOB NOT NULL)"
        )
        log.debug("Create Rungs table in sqllite db")
        self._cur.execute(
            "CREATE TABLE rungs(object_id int, rung text, seq_number int)"
        )
        log.debug("Create Region_map table in sqllite db")
        self._cur.execute(
            "CREATE TABLE region_map(object_id int, parent_id int, unknown int, seq_no int, record BLOB NOT NULL)"
        )
        log.debug("Create Comments table in sqllite db")
        self._cur.execute(
            "CREATE TABLE comments(seq_number int, sub_record_length int, object_id int, record_string text, record_type int, parent int, tag_reference text, rung_content int, member_ref int)"
        )

        log.debug("Create Nameless table in sqllite db")
        self._cur.execute(
            "CREATE TABLE nameless(object_id int, parent_id int, record BLOB NOT NULL)"
        )

        log.debug("Create Region Link (regn_link) table in sqllite db")
        # RegnLink.Dat is the rung<->comment link table: one 16-byte record per
        # rung that ties the rung's SbRegion object_id to its rung comment's
        # rung_content (see _populate_regn_link / RoutineBuilder).
        self._cur.execute(
            "CREATE TABLE regn_link(rung_oid int, rc_hi int, rc_lo7 int, group_id int, is_short int)"
        )

    def _extract_files(self):
        """Unzip the ACD container into _temp_dir, keeping the raw member files
        (in original order) for byte-identical write-back, and detect the Studio
        version from the container head."""
        log.info(
            "Creating temporary directory (if it doesn't exist to store ACD database files - "
            + self._temp_dir
        )
        if not os.path.exists(os.path.join(self._temp_dir)):
            os.makedirs(self._temp_dir)

        # Detect the Studio version (V21 source-protects SbRegion rungs
        # differently from V30+ — see acd.record.source_protection).
        self._acd_version: Optional[str] = detect_acd_version(self.input_filename)
        log.info("Detected ACD version: {}", self._acd_version)

        log.info("Extracting ACD database file")
        unzip = Unzip(self.input_filename)
        unzip.write_files(self._temp_dir)

        # Preserve all embedded files in original order for round-trip writing.
        # Read directly from the ACD archive (pre-decompression) so that
        # compressed files are carried as-is and write-back is byte-identical.
        self._file_order: List[str] = [r.filename for r in unzip.records]
        self._footer_unknown: int = unzip.header._unknown_two
        self._raw_files: Dict[str, bytes] = {}
        with open(self.input_filename, "rb") as acd_fh:
            for record in unzip.records:
                acd_fh.seek(record.file_offset)
                self._raw_files[record.filename] = acd_fh.read(record.file_length)

    def _load_comps(self):
        """Parse Comps.Dat into the comps table plus its side tables
        (comps_family with the liveness/record_length columns, unique_comment_key,
        project_flags), detecting the header family, and build the object_id ->
        name map used for write-back.
        Returns (comps_db, name_lookup) for the rung loader."""
        log.info("Getting records from ACD Comps file and storing in sqllite database")
        comps_db = DbExtract(os.path.join(self._temp_dir, "Comps.Dat")).read()
        # Deduplicate by object_id. When duplicate object_ids exist (e.g. a routine that
        # appears twice in Comps.Dat with different record_type values), keep the entry
        # with the largest record because the smaller/later entry is typically a truncated
        # or partial record (e.g. record_type=271 vs 259 for routines) that fails to parse
        # correctly with RxGeneric. The full record is always the largest one.
        # V10..V21 store comps with a 4-byte-SHORTER FAFA/FDFD header than V24+
        # (the shared kaitai parser uses V24+/V36 offsets). Autodetect the header
        # family STRUCTURALLY (a long-header record has a zero u32 at payload+12;
        # a short-header record has the nonzero self_lcg there) from the first
        # FAFA component record, so V10..V21 parse correctly without a version
        # table. Verified across V10..V36 pool samples.
        self._comps_short_header: bool = False
        for record in comps_db.records.record:
            if record.identifier == 64250:  # 0xFAFA
                self._comps_short_header = record_uses_short_header(
                    record.record.record_buffer
                )
                break
        log.info(
            "Comps header family: {}",
            "SHORT(<=V21)" if self._comps_short_header else "LONG(V24+)",
        )

        comps_by_id, record_length_by_id, winner_family, fafa_seen_ids = \
            _walk_comps_records(comps_db.records.record, self._comps_short_header)
        self._cur.executemany("INSERT INTO comps VALUES (?,?,?,?,?,?)", comps_by_id.values())

        # Dead-relic (FDFD-only) oids to exclude from the cross-row derived tables
        # below so those tables are FAFA-only and therefore INVARIANT to the FDFD
        # body realignment (P6.9): a dead body's realigned bytes must not shift a
        # comment key or set a project flag. Long-header only (empty on
        # short-header, matching CompsRecord.dead_oids; short-header derivation is
        # unchanged here and handled by C6). Built in-memory because comps_family
        # is not persisted until below.
        _dead_derived: frozenset = (
            frozenset() if self._comps_short_header
            else frozenset(set(comps_by_id) - fafa_seen_ids))

        # Collision-safe operand-comment keying (long-header). An operand comment
        # is keyed by parent == comment_id*0x10000 + cip_type, but that key is NOT
        # unique for every comp: cip-0x68 tags all carry a constant comment_id, and
        # some versions collide on cip-0x6b too, which would smear one tag's
        # operand comments across many. Precompute the set of comment keys owned by
        # exactly ONE comp; TagBuilder only emits long-header operand comments for
        # tags whose key is in this set (others are omitted -> missing, never
        # mis-attributed). cip_type is u2 @ record offset 10, comment_id u2 @ 12
        # (RxGeneric prelude); read directly to avoid a full parse per comp.
        self._cur.execute("CREATE TABLE unique_comment_key(k INTEGER PRIMARY KEY)")
        _key_counts: Dict[int, int] = {}
        for _oid, _t in comps_by_id.items():
            if _oid in _dead_derived:
                continue
            _rec = _t[5]
            if len(_rec) >= 14:
                _cip = int.from_bytes(_rec[10:12], "little")
                _cid = int.from_bytes(_rec[12:14], "little")
                _k = (_cid << 16) | _cip
                _key_counts[_k] = _key_counts.get(_k, 0) + 1
        self._cur.executemany(
            "INSERT OR IGNORE INTO unique_comment_key VALUES (?)",
            [(k,) for k, n in _key_counts.items() if n == 1],
        )

        # Project-level flags consumed by TagBuilder for OpcUaAccess and Class:
        #   opc_ua  : the project's OPC UA server is enabled -> every <Tag>,
        #             ConfigTag/InputTag/OutputTag carries OpcUaAccess="None".
        #             Concrete signal: V36+ AND the named controller record
        #             (cip 0x8e, parent_id 0) has extended-attribute 0x81 present
        #             (validated 20/20 on V36; gated to V36+ because the same id
        #             carries a different meaning pre-V36).
        #   is_safety: the project contains a safety memory partition -> safety
        #             controller; controller-scope Base tags then carry Class.
        #             Concrete signal: any cip-0x6b comp whose region id
        #             (u4 @ record 0x36) has hi16 == 0x00FB (the safety partition).
        _major = 0
        try:
            _m = re.match(r"V(\d+)", self._acd_version or "")
            _major = int(_m.group(1)) if _m else 0
        except Exception:
            _major = 0
        _opc = 0
        _safety = 0
        for _oid, _t in comps_by_id.items():
            if _oid in _dead_derived:
                continue
            _rec = _t[5]
            if len(_rec) < 14:
                continue
            _cip = int.from_bytes(_rec[10:12], "little")
            if _safety == 0 and _cip == 0x6B and len(_rec) >= 0x3A:
                # The safety memory partition is encoded in the region id hi16
                # (u4 @ record 0x36). The encoding is version-specific:
                #   short header (V10-V21): hi16 == 0x00FB
                #   long  header (V24+):    hi16 high byte == 0x79  (0x79xx;
                #                           standard partitions are 0x70xx)
                # Either marker present anywhere in a cip-0x6b comp => safety
                # project (validated on V20 + V36 safety projects, and emits
                # nothing on V20/V34/V36 non-safety projects).
                _phi = (int.from_bytes(_rec[0x36:0x3A], "little") >> 16) & 0xFFFF
                if _phi == 0x00FB or (_phi >> 8) == 0x79:
                    _safety = 1
            if _opc == 0 and _major >= 36 and _cip == 0x8E and _t[1] == 0:
                try:
                    from acd.generated.comps.rx_generic import RxGeneric as _RxG
                    _r = _RxG.from_bytes(_rec)
                    if any(e.attribute_id == 0x81 for e in _r.extended_records):
                        _opc = 1
                except Exception:
                    pass
        self._cur.execute("CREATE TABLE project_flags(opc_ua int, is_safety int)")
        self._cur.execute(
            "INSERT INTO project_flags VALUES (?, ?)", (_opc, _safety)
        )

        # Per-oid header-family + record-length side table. fafa_seen is the
        # liveness signal (see _walk_comps_records); winner_family is the stream
        # identifier of the deduped comps row; record_length is the declared u32
        # @0 of the winning full payload, the last datum the module-builder
        # truncation shim needed from the retired comps_full table. Since the
        # P6.7a size-eos flip the comps `record` column already carries the whole
        # untruncated body, so the full payload no longer needs its own table.
        self._cur.execute(
            "CREATE TABLE comps_family(object_id INTEGER PRIMARY KEY,"
            " winner_family INTEGER, fafa_seen INTEGER, record_length INTEGER)"
        )
        self._cur.executemany(
            "INSERT INTO comps_family VALUES (?,?,?,?)",
            [(oid, winner_family[oid], 1 if oid in fafa_seen_ids else 0,
              record_length_by_id.get(oid, 0))
             for oid in comps_by_id],
        )
        self._db.commit()

        # Build name lookup for SbRegion tag reference resolution (object_id → comp_name).
        # Store on self for use during write-back (patch_sbregion_dat needs id_to_name).
        name_lookup = {oid: t[2] for oid, t in comps_by_id.items()}
        self._id_to_name: Dict[int, str] = name_lookup
        return comps_db, name_lookup

    def _load_rungs(self, comps_db, name_lookup):
        """Resolve the rung name map (V21-corrected, __Map:-stripped) and parse
        SbRegion.Dat into the rungs table."""
        # V21 stores comps with a different FAFA layout than V30+ (the shared
        # comps parser reads object_id 4 bytes too far for V21), so the V21 rung
        # @HEX@ -> name resolution needs a V21-correct object_id -> name map.
        # Build it from Comps.Dat with V21 offsets and use it ONLY for the rung
        # path; the V30+ name_lookup / _id_to_name (write-back) is untouched.
        rung_name_lookup = name_lookup
        if is_v21_version(self._acd_version):
            v21_map = build_uid_name_map(comps_db)
            if v21_map:
                # V21 map wins for the rung path; keep any V30+ entries as fallback.
                rung_name_lookup = {**name_lookup, **v21_map}
                log.info("Built V21 rung name map: {} entries", len(v21_map))

        # A device-map tag is stored under RxTagCollection with a "__Map:" prefix
        # (an internal mirror of an RxMapDeviceCollection entry). A rung references
        # such a tag by object id, but the reference renders the bare name -- the
        # "__Map:" prefix never appears in reference output -- so strip it from the
        # rung name resolution.
        rung_name_lookup = {
            oid: (nm[len("__Map:"):] if isinstance(nm, str)
                  and nm.startswith("__Map:") else nm)
            for oid, nm in rung_name_lookup.items()
        }

        log.info(
            "Getting records from ACD SbRegion file and storing in sqllite database"
        )
        sb_region_db = DbExtract(os.path.join(self._temp_dir, "SbRegion.Dat")).read()
        rung_tuples = [t for record in sb_region_db.records.record if (t := SbRegionRecord.parse(record, rung_name_lookup, self._acd_version)) is not None]
        self._cur.executemany("INSERT INTO rungs VALUES (?,?,?)", rung_tuples)
        self._db.commit()

    def _load_comments(self):
        """Parse Comments.Dat into the comments table and harvest the record
        types the comment parser drops into their side tables: GSS safety
        signatures (per-object, per-connection and named controller-level),
        <CustomProperties> provider blocks, and alarm <Message> text."""
        log.info(
            "Getting records from ACD Comments file and storing in sqllite database"
        )
        comments_db = DbExtract(os.path.join(self._temp_dir, "Comments.Dat")).read()
        comment_tuples = [t for record in comments_db.records.record if (t := CommentsRecord.parse(record, self._comps_short_header)) is not None]
        # NB: the ACD stores multi-line descriptions / rung+operand comments with
        # CRLF, and genuine Logix Designer L5X export keeps CRLF inside the CDATA
        # (its whole file is CRLF). We deliberately PRESERVE CRLF here so our
        # output is byte-faithful to Rockwell. (Some third-party OEM reference
        # converters normalize to bare LF; that is their quirk, not Rockwell's, so
        # the gauntlet comparator normalizes newlines instead of us changing the
        # output.)
        self._cur.executemany("INSERT INTO comments VALUES (?,?,?,?,?,?,?,?,?)", comment_tuples)
        self._db.commit()

        # Generated-Safety-Signature records (record_type 0x10) are dropped by the
        # comment parser; pull the per-object 256-bit signature hash and timestamp
        # straight from the raw buffers into a side table keyed by (object_type,
        # comment_id), which each signed Task/Program joins to. The two markers are
        # UTF-16-LE; the hash is eight big-endian u32 groups 14 bytes after its
        # marker, the timestamp ASCII 12 bytes after its marker.
        self._cur.execute(
            "CREATE TABLE safety_signatures(otype int, cid int, signature text, timestamp text)"
        )
        # Per-connection signatures use the same GSS records keyed additionally by a
        # discriminator (u32 @ buf[16]); a module's connections share (otype,cid) but
        # differ by disc, so the 2-key table alone would collapse them.
        self._cur.execute(
            "CREATE TABLE connection_signatures(otype int, cid int, disc int, signature text, timestamp text)"
        )
        # The five controller-level safety signatures (<SafetyInfo> children) use the
        # SAME GSS records but at controller scope (cid 0/1) and some carry an embedded
        # NAME after the "GSS" marker (0x13 + NUL-terminated UTF-16): "OverallSignature"
        # -> RootSignature, "TagMap" -> SafetyTagMapSignature; the no-name ones are
        # ControllerAttributesSignature (otype 820) and ApplicationRollupSignature
        # (otype 142). Keyed by (otype, name) so the otype-820 collision between
        # RootSignature and ControllerAttributesSignature is resolved by the name.
        self._cur.execute(
            "CREATE TABLE named_safety_signatures(otype int, name text, signature text, timestamp text)"
        )
        # Library DataTypes (Rockwell raC_*/STR* UDTs) carry a verbatim
        # <CustomProperties> <Provider> block that the comment parser drops; capture
        # each provider record (otype 108) keyed by the owning DataType's comment_id.
        self._cur.execute(
            "CREATE TABLE custom_properties(cid int, ext text, provider_id text, blob text)"
        )
        # ALARM_DIGITAL/ANALOG tag <Message> text: a Comments.Dat record marked
        # 0x0331 (u16 @ buf[8]) carries the alarm message, keyed by a u16 join key
        # (buf[10]) that equals the alarm tag's data-table backing first u16. The
        # body holds a 2-letter Type ("AM") then the UTF-16 message text.
        self._cur.execute(
            "CREATE TABLE alarm_messages(joinkey int, mtype text, text text)"
        )
        _sig_needle = "SignatureID\x11GSS\x00".encode("utf-16-le")
        _ts_needle = "Timestamp\x11GSS\x00".encode("utf-16-le")
        # Same markers without the trailing NUL, so they also match the NAMED
        # controller-level records (where a 0x13-introduced name follows "GSS").
        _sig_mark = "SignatureID\x11GSS".encode("utf-16-le")
        _ts_mark = "Timestamp\x11GSS".encode("utf-16-le")
        _ts_re = re.compile(rb"\d\d/\d\d/\d{4}, \d\d:\d\d:\d\d\.\d{3} [AP]M")

        def _gss_name(b, p):
            """Optional 0x13-introduced NUL-terminated UTF-16-LE name at b[p:]; ''
            if absent. Scan the terminator on a 2-byte boundary."""
            if b[p:p + 2] != b"\x13\x00":
                return ""
            q = i = p + 2
            while i + 1 < len(b) and b[i:i + 2] != b"\x00\x00":
                i += 2
            try:
                return b[q:i].decode("utf-16-le")
            except Exception:
                return ""

        _gss: Dict[tuple, list] = {}
        _gss3: Dict[tuple, list] = {}
        _named: Dict[tuple, list] = {}
        _cp: List[tuple] = []
        _amsg: List[tuple] = []
        for _rec in comments_db.records.record:
            _buf = bytes(_rec.record.record_buffer)
            if len(_buf) < 16:
                continue
            # ALARM_DIGITAL/ANALOG <Message> record (0x0331 at buf[8]); the join key
            # (u16 @ buf[10]) equals the alarm tag's backing value first u16. The
            # message text sits at an odd byte offset, so anchor the UTF-16 decode on
            # the 2-letter Type token rather than slicing from an even base.
            if struct.unpack_from("<H", _buf, 8)[0] == 0x0331:
                _jk = struct.unpack_from("<H", _buf, 10)[0]
                _tm = re.search(rb"[A-Z]\x00[A-Z]\x00", _buf[12:])
                if _tm:
                    _mtype = _tm.group(0).decode("utf-16-le")
                    _rest = _buf[12 + _tm.start() + 4:].decode("utf-16-le", "replace")
                    _toks = [t.strip() for t in _rest.split("\x00") if t.strip()]
                    if _toks:
                        _amsg.append((_jk, _mtype, _toks[0]))
                continue
            _otype = struct.unpack_from("<H", _buf, 10)[0]
            _cid = struct.unpack_from("<I", _buf, 12)[0]
            # <CustomProperties> provider record: otype 108, ID terminated by 0x11,
            # Ext terminated by 0x12, then the verbatim inner XML to the trailing NUL.
            if _otype == 108 and len(_buf) >= 32 and (b'<Header' in _buf or b'<Data' in _buf):
                _sep = _buf.find(b'\x11\x00', 26)
                _m12 = _buf.find(b'\x12\x00', _sep + 2) if _sep >= 0 else -1
                _lt = _buf.find(b'<', _m12) if _m12 >= 0 else -1
                if _sep >= 0 and _m12 >= 0 and _lt >= 0:
                    _cp.append((
                        _cid,
                        _buf[_sep + 2:_m12].decode("utf-16-le", "replace"),
                        _buf[30:_sep].decode("utf-16-le", "replace"),
                        _buf[_lt:].rstrip(b"\x00").decode("latin-1", "replace"),
                    ))
            _key = (_otype, _cid)
            _key3 = (_otype, _cid,
                     struct.unpack_from("<I", _buf, 16)[0] if len(_buf) >= 20 else 0)
            _si = _buf.find(_sig_needle)
            if _si >= 0:
                _h = _buf[_si + len(_sig_needle) + 14:_si + len(_sig_needle) + 46]
                if len(_h) == 32 and any(_h):
                    _sig = " - ".join(
                        "%08X" % struct.unpack_from(">I", _h, _i * 4)[0] for _i in range(8))
                    _gss.setdefault(_key, [None, None])[0] = _sig
                    _gss3.setdefault(_key3, [None, None])[0] = _sig
            _ti = _buf.find(_ts_needle)
            if _ti >= 0:
                _txt = _buf[_ti + len(_ts_needle) + 12:].split(b"\x00")[0]
                try:
                    _ts = _txt.decode("ascii")
                    _gss.setdefault(_key, [None, None])[1] = _ts
                    _gss3.setdefault(_key3, [None, None])[1] = _ts
                except UnicodeDecodeError:
                    pass
            # Controller-level (cid 0/1) signatures, keyed by (otype, name). The hash
            # is the last 32 bytes (robust whether or not an embedded name shifts the
            # body); the timestamp is the paired record's ASCII stamp.
            if _cid in (0, 1) and len(_buf) >= 33:
                _smi = _buf.find(_sig_mark)
                if _smi >= 0:
                    _nm = _gss_name(_buf, _smi + len(_sig_mark))
                    _hh = _buf[len(_buf) - 33:len(_buf) - 1]
                    if any(_hh):
                        _named.setdefault((_otype, _nm), [None, None])[0] = " - ".join(
                            "%08X" % struct.unpack_from(">I", _hh, _i * 4)[0] for _i in range(8))
                _tmi = _buf.find(_ts_mark)
                if _tmi >= 0:
                    _nm = _gss_name(_buf, _tmi + len(_ts_mark))
                    _m = _ts_re.search(_buf)
                    if _m:
                        _named.setdefault((_otype, _nm), [None, None])[1] = _m.group().decode("ascii")
        self._cur.executemany(
            "INSERT INTO safety_signatures VALUES (?,?,?,?)",
            [(k[0], k[1], v[0], v[1]) for k, v in _gss.items() if v[0]])
        self._cur.executemany(
            "INSERT INTO connection_signatures VALUES (?,?,?,?,?)",
            [(k[0], k[1], k[2], v[0], v[1]) for k, v in _gss3.items() if v[0]])
        self._cur.executemany(
            "INSERT INTO named_safety_signatures VALUES (?,?,?,?)",
            [(k[0], k[1], v[0], v[1]) for k, v in _named.items() if v[0]])
        self._cur.executemany(
            "INSERT INTO custom_properties VALUES (?,?,?,?)", _cp)
        self._cur.executemany(
            "INSERT INTO alarm_messages VALUES (?,?,?)", _amsg)
        self._db.commit()

    def _load_nameless(self):
        """Parse Nameless.Dat into the nameless table."""
        log.info(
            "Getting records from ACD Nameless file and storing in sqllite database"
        )
        nameless_db = DbExtract(os.path.join(self._temp_dir, "Nameless.Dat")).read()
        nameless_tuples = [t for record in nameless_db.records.record if (t := NamelessRecord.parse(record)) is not None]
        self._cur.executemany("INSERT INTO nameless VALUES (?,?,?)", nameless_tuples)
        self._db.commit()

    def _load_taginfo(self):
        # Step 6d: parse TagInfo.XML ONCE into a datatype -> member byte-layout
        # map used to decode tag value images into the Decorated <Data> tree.
        # Best-effort; on any failure the map is empty and the zero-generator
        # fallback in Tag.to_xml keeps today's behaviour (no regression).
        self._taginfo_layout: Dict[str, object] = {}
        try:
            self._taginfo_layout = self._parse_taginfo_layout(
                os.path.join(self._temp_dir, "TagInfo.XML")
            )
            log.info("TagInfo layout: {} datatypes", sum(
                1 for k in self._taginfo_layout if not k.startswith("@size@")))
        except Exception as exc:  # noqa: BLE001 - never block export
            log.warning("TagInfo layout parse failed, skipping value decode: {}", exc)
            self._taginfo_layout = {}

    def _create_indexes(self):
        log.info("Creating indexes for fast object graph queries")
        self._cur.execute("CREATE INDEX idx_comps_object_id ON comps(object_id)")
        self._cur.execute("CREATE INDEX idx_comps_parent_id ON comps(parent_id)")
        self._cur.execute("CREATE INDEX idx_comps_parent_name ON comps(parent_id, comp_name)")
        self._cur.execute("CREATE INDEX idx_rungs_object_id ON rungs(object_id)")
        self._cur.execute("CREATE INDEX idx_region_map_parent_id ON region_map(parent_id)")
        self._cur.execute("CREATE INDEX idx_comments_parent ON comments(parent)")
        self._db.commit()

    @staticmethod
    def _parse_taginfo_layout(taginfo_path: str) -> Dict[str, object]:
        """Build {DATATYPE_UPPER: [(name, dt, offset, bit, hidden, dims), ...]}.

        Also stores "@size@<NAME>" -> int Size for each datatype so the value
        decoder can compute per-element strides for arrays of structs. Reads the
        UTF-16 TagInfo.XML (the authoritative per-project member byte layout).
        Returns an empty dict if the file is absent / unparsable.
        """
        import xml.etree.ElementTree as ET

        if not os.path.exists(taginfo_path):
            return {}
        with open(taginfo_path, "rb") as fh:
            raw = fh.read()
        text = raw.decode("utf-16", errors="replace")
        root = ET.fromstring(text)
        dts = root.find("DataTypes")
        layout: Dict[str, object] = {}
        if dts is None:
            return layout
        for dt in dts.findall("DataType"):
            name = dt.get("Name")
            if not name:
                continue
            size = dt.get("Size")
            try:
                if size is not None:
                    layout["@size@" + name.upper()] = int(size)
            except ValueError:
                pass
            members_node = dt.find("Members")
            members: List[tuple] = []
            if members_node is not None:
                for m in members_node.findall("Member"):
                    mname = m.get("Name")
                    mdt = m.get("DataType")
                    if mname is None or mdt is None:
                        continue
                    try:
                        off = int(m.get("Offset", "0"))
                    except ValueError:
                        off = 0
                    bit_attr = m.get("Bit")
                    bit = int(bit_attr) if bit_attr is not None else None
                    hidden = m.get("Hidden") == "true"
                    dims = None
                    dim_node = m.find("Dimensions")
                    if dim_node is not None:
                        ds = []
                        for d in dim_node.findall("Dim"):
                            try:
                                ds.append(int(d.get("Size", "0")))
                            except ValueError:
                                pass
                        dims = ds or None
                    members.append((mname, mdt, off, bit, hidden, dims))
            layout[name.upper()] = members
        return layout

    @property
    def controller(self):
        if self._controller is None:
            _major = 0
            try:
                _m = re.match(r"V(\d+)", self._acd_version or "")
                _major = int(_m.group(1)) if _m else 0
            except Exception:
                _major = 0
            # Controller firmware revision (MajorRev/MinorRev) from the project's
            # QuickInfo DeviceIdentity, distinct from the Studio app SWVersion.
            _dev_major = _dev_minor = None
            try:
                import xml.etree.ElementTree as ET
                _qi = os.path.join(self._temp_dir, "QuickInfo.XML")
                if os.path.exists(_qi):
                    _di = ET.parse(_qi).find("DeviceIdentity")
                    if _di is not None:
                        _dev_major = int(_di.attrib["MajorRevision"])
                        _dev_minor = int(_di.attrib["MinorRevision"])
            except Exception:
                _dev_major = _dev_minor = None
            self._controller = ControllerBuilder(
                self._cur,
                _short_header=self._comps_short_header,
                _taginfo_layout=getattr(self, "_taginfo_layout", {}),
                _acd_major=_major,
                _device_major=_dev_major,
                _device_minor=_dev_minor,
                _faithful=self.faithful,
            ).build()
        return self._controller

    @property
    def project(self):
        if self._project is None:
            self._project = ProjectBuilder(
                Path(os.path.join(self._temp_dir, "QuickInfo.XML"))
            ).build()
            self._project.controller = self.controller
            self._project._raw_files = self._raw_files
            self._project._file_order = self._file_order
            self._project._footer_unknown = self._footer_unknown
            self._project._id_to_name = self._id_to_name
        return self._project

    def populate_region_map(self):
        log.info(
            "Getting records from ACD Region Map file and storing in sqllite database"
        )
        # The Region Map body is parsed at V24+/V36-specific absolute offsets
        # (70/78). For V10..V21 short-header projects the body layout differs, so
        # the short path uses its own empirically-derived offset.
        if getattr(self, "_comps_short_header", False):
            try:
                self._populate_region_map_short()
            except Exception as exc:  # noqa: BLE001 - never regress short-header export
                log.warning("Short-header region map parse failed, skipping: {}", exc)
            return
        self._cur.execute(
            "SELECT comp_name, object_id, parent_id, record FROM comps WHERE parent_id=0 AND comp_name='Region Map'"
        )
        results = self._cur.fetchall()

        if len(results) == 0:
            return
        record = results[0][3]

        identifier_offset = 70

        if len(record) < (identifier_offset + 8):
            return

        region_length = struct.unpack(
            "I", record[identifier_offset + 4 : identifier_offset + 8]
        )[0]

        identifier_offset = 78
        record_length_absolute = identifier_offset + region_length - 4
        c = 0
        while identifier_offset <= (record_length_absolute - 16) and (
            identifier_offset + 16 <= len(record)
        ):
            parent_id_identifier = struct.unpack(
                "I", record[identifier_offset : identifier_offset + 4]
            )[0]

            unknown_identifier = struct.unpack(
                "I", record[identifier_offset + 4 : identifier_offset + 8]
            )[0]

            seq_identifier = struct.unpack(
                "I", record[identifier_offset + 8 : identifier_offset + 12]
            )[0]

            c += 1
            object_id_identifier = struct.unpack(
                "I", record[identifier_offset + 12 : identifier_offset + 16]
            )[0]

            query: str = "INSERT INTO region_map VALUES (?, ?, ?, ?, ?)"
            enty: tuple = (
                object_id_identifier,
                parent_id_identifier,
                unknown_identifier,
                seq_identifier,
                record[identifier_offset : identifier_offset + 16],
            )
            self._cur.execute(query, enty)
            identifier_offset += 16

        self._db.commit()

    # ---- SHORT (V10..V21) region map ---------------------------------------
    # The short-header Region Map comps record (parent_id=0, comp_name='Region
    # Map') carries a flat array of 16-byte entries that link each rung object_id
    # to its owning routine. The entries begin at FULL-PAYLOAD offset 124, which
    # is body offset 30 here because the short-header comps body is already sliced
    # at payload offset 94 (see acd.record.comps._SH_BODY_OFF). Each entry is, in
    # the SAME field order as the long-header path and as RoutineBuilder's JOIN:
    #   [parent_id u32 @0][unknown u32 @4][seq u32 @8][object_id u32 @12]
    # where parent_id is the routine's comps object_id and object_id is the rung's
    # SbRegion object_id. Derived empirically on V17/V20 short-header pool files
    # (parent_id in comps set 211/229; object_id in rungs set 223/223).
    #
    # VALIDATION (cross-reference recipe): an entry is only inserted when its
    # parent_id resolves to a known comps object_id and region_length (the 16-byte
    # entry) fits inside the body. If the parsed array fails to cross-reference
    # broadly (no entries link to a real routine), we skip and preserve today's
    # behaviour (empty region map) so nothing regresses.
    _SH_REGION_ENTRY_OFF = 30  # body offset == full-payload offset 124

    def _populate_region_map_short(self):
        self._cur.execute(
            "SELECT record FROM comps WHERE parent_id=0 AND comp_name='Region Map'"
        )
        results = self._cur.fetchall()
        if not results:
            return
        record = results[0][0]

        off = self._SH_REGION_ENTRY_OFF
        if len(record) < off + 16:
            return

        # Known comps object_id set for cross-reference validation.
        self._cur.execute("SELECT object_id FROM comps")
        valid_ids = {row[0] for row in self._cur.fetchall()}

        entries: List[tuple] = []
        linked = 0
        while off + 16 <= len(record):
            parent_id_identifier = struct.unpack_from("<I", record, off)[0]
            unknown_identifier = struct.unpack_from("<I", record, off + 4)[0]
            seq_identifier = struct.unpack_from("<I", record, off + 8)[0]
            object_id_identifier = struct.unpack_from("<I", record, off + 12)[0]

            # Only keep entries whose parent (routine) is a real comps record and
            # whose rung object_id is plausible (nonzero, not the 0xFFFFFFFF
            # sentinel that prefixes the array).
            if (
                parent_id_identifier in valid_ids
                and object_id_identifier not in (0, 0xFFFFFFFF)
            ):
                entries.append(
                    (
                        object_id_identifier,
                        parent_id_identifier,
                        unknown_identifier,
                        seq_identifier,
                        record[off : off + 16],
                    )
                )
                linked += 1
            off += 16

        # Cross-reference gate: require at least one entry to link to a known
        # routine; otherwise the offset is wrong for this file -> preserve today's
        # behaviour (no region map) rather than emit garbage rung linkage.
        if linked == 0:
            log.warning(
                "Short-header region map: no entries cross-referenced; skipping"
            )
            return

        self._cur.executemany(
            "INSERT INTO region_map VALUES (?, ?, ?, ?, ?)", entries
        )
        self._db.commit()
        log.info("Short-header region map: linked {} rung entries", linked)

    # ---- Region Link (rung <-> rung-comment linkage) -----------------------
    # RegnLink.Dat is the table that links each rung to its rung-level comment.
    # It is NOT a FAFA/FDFD stream (the shared Dat parser rejects it), but a flat
    # array of 16-byte records (one per rung):
    #   [marker u32]                   record marker (LONG: 02 ?? 00 01,
    #                                                  SHORT: 02 00 00 09)
    #   [rc_hi u16][rc_lo7 u8][00]     comment rung_content, encoded
    #   [group_id u32]                 the owning routine's region group id
    #   [rung_oid u32]                 the rung's SbRegion object_id (== region_map.object_id)
    # Each record describes the rung at offset +12 (rung_oid); records form a
    # back-linked chain so the next record's marker follows immediately.
    #
    # The comment's rung_content is encoded as rc_hi = (rung_content >> 16) and
    # rc_lo7 = (rung_content & 0x7f). The link Logix Designer uses to map a rung
    # comment to its rung lives ONLY here and in Comments.Dat (the rung_content
    # value appears nowhere in the rung/SbRegion data itself).
    #
    # Header families differ in BOTH the marker and how the comment stores
    # rung_content:
    #   LONG  (V24+): marker 02 ?? 00 01; comment rung_content is the full 32-bit
    #                 value, matched by (rc>>16, rc&0x7f) == (rc_hi, rc_lo7).
    #   SHORT (V10-V21): marker 02 00 00 09; the short-header comment parser reads
    #                 a 16-bit rung_content (== the hi16), matched by rc==rc_hi.
    #
    # VALIDATED on real projects of both families against the OEM reference
    # conversion (a long-header V34 project: 897 records, all rung comments mapped
    # with exact rung Numbers; a short-header V20 project: ~99% of ground-truth
    # pairs). Best-effort: on any structural problem the table stays empty and
    # RoutineBuilder falls back to today's behaviour (no rung comments) so nothing
    # regresses.
    def populate_regn_link(self):
        log.info(
            "Getting records from ACD Region Link file and storing in sqllite database"
        )
        path = os.path.join(self._temp_dir, "RegnLink.Dat")
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError:
            return
        is_short = 1 if getattr(self, "_comps_short_header", False) else 0
        # Record marker = 02 ?? 00 TT (byte1 varies). The tail byte TT is the
        # record kind and is version-dependent, NOT a clean short/long split:
        #   01  rung region link (LONG V24+, and SHORT V11)
        #   09  rung region link (SHORT V13..V20)
        # so we accept either tail rather than gating on header family. (The
        # 16-bit vs 32-bit comment-key difference is the real short/long axis and
        # is handled in RoutineBuilder via is_short.)
        entries: List[tuple] = []
        i = 0
        n = len(data)
        while i + 16 <= n:
            if data[i] == 0x02 and data[i + 2] == 0x00 and data[i + 3] in (0x01, 0x09):
                rc_hi = struct.unpack_from("<H", data, i + 4)[0]
                rc_lo7 = data[i + 6]
                group_id = struct.unpack_from("<I", data, i + 8)[0]
                rung_oid = struct.unpack_from("<I", data, i + 12)[0]
                entries.append((rung_oid, rc_hi, rc_lo7, group_id, is_short))
                i += 16
            else:
                i += 1
        if not entries:
            log.warning("Region Link: no records parsed; rung comments unavailable")
            return
        self._cur.executemany(
            "INSERT INTO regn_link VALUES (?, ?, ?, ?, ?)", entries
        )
        self._cur.execute(
            "CREATE INDEX idx_regn_link_oid ON regn_link(rung_oid)"
        )
        self._db.commit()
        log.info(
            "Region Link: parsed {} rung linkage records ({})",
            len(entries),
            "SHORT" if is_short else "LONG",
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Read an ACD file and export the database as an L5X file"
    )
    parser.add_argument(
        "input", metavar="input", type=str, nargs="+", help="The file to be converted"
    )
    parser.add_argument(
        "output",
        metavar="output",
        type=str,
        nargs="+",
        help="Filename of the exported file",
    )

    args = parser.parse_args()
    # Import here to avoid a module-level cycle (acd.api imports this module).
    from acd.api import ConvertAcdToL5x

    ConvertAcdToL5x(args.input[0], args.output[0]).extract()
