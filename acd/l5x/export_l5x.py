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


@dataclass
class ExportL5x:
    input_filename: os.PathLike
    _temp_dir: str = "build"  # tempfile.mkdtemp()
    _controller: Union[Controller, None] = None
    _project: Union[RSLogix5000Content, None] = None

    def __post_init__(self):
        log.info(
            "Creating temporary directory (if it doesn't exist to store ACD database files - "
            + self._temp_dir
        )
        _DEFAULT_SQL_DATABASE_NAME = "acd.db"
        if os.path.exists(os.path.join(self._temp_dir, _DEFAULT_SQL_DATABASE_NAME)):
            os.remove(os.path.join(self._temp_dir, _DEFAULT_SQL_DATABASE_NAME))
        if not os.path.exists(os.path.join(self._temp_dir)):
            os.makedirs(self._temp_dir)
        log.info("Creating sqllite database to store ACD database records")
        self._db = sqlite3.connect(
            os.path.join(self._temp_dir, _DEFAULT_SQL_DATABASE_NAME)
        )
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=OFF")
        self._cur: Cursor = self._db.cursor()

        log.debug("Create Comps table in sqllite db")
        self._cur.execute(
            "CREATE TABLE comps(object_id int, parent_id int, comp_name text, seq_number int, record_type int, record BLOB NOT NULL)"
        )
        log.debug("Create pointers table in sqllite db")
        self._cur.execute(
            "CREATE TABLE pointers(object_id int, parent_id int, comp_name text, seq_number int, record_type int, record BLOB NOT NULL)"
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

        comps_by_id = {}
        for record in comps_db.records.record:
            t = CompsRecord.parse(record, self._comps_short_header)
            if t is not None:
                oid = t[0]
                if oid not in comps_by_id or len(t[5]) > len(comps_by_id[oid][5]):
                    comps_by_id[oid] = t
        self._cur.executemany("INSERT INTO comps VALUES (?,?,?,?,?,?)", comps_by_id.values())
        self._db.commit()

        # Build name lookup for SbRegion tag reference resolution (object_id → comp_name).
        # Store on self for use during write-back (patch_sbregion_dat needs id_to_name).
        name_lookup = {oid: t[2] for oid, t in comps_by_id.items()}
        self._id_to_name: Dict[int, str] = name_lookup

        log.info(
            "Getting records from ACD Region Map file and storing in sqllite database"
        )
        self.populate_region_map()

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

        log.info(
            "Getting records from ACD SbRegion file and storing in sqllite database"
        )
        sb_region_db = DbExtract(os.path.join(self._temp_dir, "SbRegion.Dat")).read()
        rung_tuples = [t for record in sb_region_db.records.record if (t := SbRegionRecord.parse(record, rung_name_lookup, self._acd_version)) is not None]
        self._cur.executemany("INSERT INTO rungs VALUES (?,?,?)", rung_tuples)
        self._db.commit()

        log.info(
            "Getting records from ACD Comments file and storing in sqllite database"
        )
        comments_db = DbExtract(os.path.join(self._temp_dir, "Comments.Dat")).read()
        comment_tuples = [t for record in comments_db.records.record if (t := CommentsRecord.parse(record, self._comps_short_header)) is not None]
        self._cur.executemany("INSERT INTO comments VALUES (?,?,?,?,?,?,?,?,?)", comment_tuples)
        self._db.commit()

        log.info(
            "Getting records from ACD Nameless file and storing in sqllite database"
        )
        nameless_db = DbExtract(os.path.join(self._temp_dir, "Nameless.Dat")).read()
        nameless_tuples = [t for record in nameless_db.records.record if (t := NamelessRecord.parse(record)) is not None]
        self._cur.executemany("INSERT INTO nameless VALUES (?,?,?)", nameless_tuples)
        self._db.commit()

        log.info("Creating indexes for fast object graph queries")
        self._cur.execute("CREATE INDEX idx_comps_object_id ON comps(object_id)")
        self._cur.execute("CREATE INDEX idx_comps_parent_id ON comps(parent_id)")
        self._cur.execute("CREATE INDEX idx_comps_parent_name ON comps(parent_id, comp_name)")
        self._cur.execute("CREATE INDEX idx_rungs_object_id ON rungs(object_id)")
        self._cur.execute("CREATE INDEX idx_region_map_parent_id ON region_map(parent_id)")
        self._cur.execute("CREATE INDEX idx_comments_parent ON comments(parent)")
        self._db.commit()

    @property
    def controller(self):
        if self._controller is None:
            self._controller = ControllerBuilder(
                self._cur, _short_header=self._comps_short_header
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
    ExportL5x(args.input[0], args.output[0])
