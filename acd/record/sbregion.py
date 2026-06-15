import re
import struct
from dataclasses import dataclass
from sqlite3 import Cursor
from typing import Dict, Optional

from acd.database.dbextract import DatRecord

from acd.generated.sbregion.fafa_sbregions import FafaSbregions
from acd.record.source_protection import (
    decode_rung as v21_decode_rung,
    is_v21_version,
    looks_like_source_protected_rung,
)


@dataclass
class SbRegionRecord:
    _cur: Cursor
    dat_record: DatRecord

    def __post_init__(self):
        if self.dat_record.identifier == 64250:
            r = FafaSbregions.from_bytes(self.dat_record.record.record_buffer)
        else:
            return

        if r.header.language_type == "Rung NT" or r.header.language_type == "REGION NT":
            if looks_like_source_protected_rung(r.record_buffer):
                # V21 source-protection (EncryptionConfig 5): the rung buffer is
                # AES-encrypted neutral text, not the V30+ plaintext UTF-16.
                # Decrypt it and resolve @HEX@ ids to names via the comps table.
                self.text = v21_decode_rung(
                    r.record_buffer,
                    name_lookup=self._db_name_lookup,
                )
            else:
                text = r.record_buffer.decode("utf-16-le").rstrip("\x00")
                self.text = self.replace_tag_references(text)
            self._cur.execute("INSERT INTO rungs VALUES (?, ?, ?)", (r.header.identifier, self.text, ""))
        elif r.header.language_type == "REGION AST":
            pass
        elif r.header.language_type == "REGION LE UID":
            uuid = struct.unpack("<I", r.record_buffer[-4:])[0]
            pass

    def _db_name_lookup(self, object_id):
        """Resolve a comps object_id to its component name via the DB cursor.

        Used by the V21 source-protection decoder to render @HEX@ tag references
        (the @HEX@ value is the operand tag's CompUId == comps object_id).
        Returns None for unknown ids so they stay as @HEX@.
        """
        self._cur.execute(
            "SELECT comp_name FROM comps WHERE object_id=?", (object_id,)
        )
        row = self._cur.fetchone()
        return row[0] if row else None

    def replace_tag_references(self, sb_rec):
        for tag in re.findall("@[A-Za-z0-9]*@", sb_rec):
            tag_id = int(tag[1:-1], 16)
            self._cur.execute(
                "SELECT object_id, comp_name FROM comps WHERE object_id=" + str(tag_id)
            )
            results = self._cur.fetchall()
            if len(results) == 0:
                return sb_rec
            sb_rec = sb_rec.replace(tag, results[0][1])
        return sb_rec

    @staticmethod
    def parse(
        dat_record: DatRecord,
        name_lookup: Dict[int, str],
        version: Optional[str] = None,
    ) -> Optional[tuple]:
        if dat_record.identifier != 64250:
            return None
        r = FafaSbregions.from_bytes(dat_record.record.record_buffer)
        if r.header.language_type not in ("Rung NT", "REGION NT"):
            return None

        # V21 stores the rung as AES-encrypted neutral text (source protection),
        # not the plaintext UTF-16 '@HEX@' text used by V30+.  Decoding it as
        # UTF-16 yields CJK garbage, so branch to the V21 decryption path.
        # Detect V21 by ACD version when known, falling back to the V21 header
        # signature (so the V30+ path is only ever taken for genuine plaintext).
        if is_v21_version(version) or looks_like_source_protected_rung(r.record_buffer):
            text = v21_decode_rung(r.record_buffer, name_lookup=name_lookup.get)
            return (r.header.identifier, text, "")

        text = r.record_buffer.decode("utf-16-le").rstrip("\x00")
        for tag in re.findall("@[A-Za-z0-9]*@", text):
            tag_id = int(tag[1:-1], 16)
            name = name_lookup.get(tag_id)
            if name is None:
                break
            text = text.replace(tag, name)
        return (r.header.identifier, text, "")
