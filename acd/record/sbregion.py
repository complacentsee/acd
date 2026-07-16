import re
import struct
from dataclasses import dataclass
from sqlite3 import Cursor
from typing import Dict, Optional

from acd.database.dbextract import DatRecord

from acd.generated.sbregion.fafa_sbregions import FafaSbregions
from acd.record.source_protection import (
    decode_rung as sp_decode_rung,
    looks_like_source_protected_rung,
)


def _rung_buffer(r: FafaSbregions) -> bytes:
    """The WHOLE rung buffer, including any bytes past ``len_record_buffer``.

    On a source-protected rung ``len_record_buffer`` records the PLAINTEXT length,
    so the grammar's ``record_buffer`` stops short of the end of the stored
    ciphertext and the remainder lands in ``trailing``. Reading only
    ``record_buffer`` truncates the ciphertext (and makes short rungs look like a
    cipher-less 14-byte NOP header). On an unprotected rung ``trailing`` is empty,
    so this is the plaintext buffer unchanged.
    """
    return r.record_buffer + r.trailing


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
            rbuf = _rung_buffer(r)
            if looks_like_source_protected_rung(rbuf):
                # Source-protected: the rung buffer is AES-encrypted neutral
                # text, not plaintext UTF-16. Decrypt it and resolve @HEX@ ids to
                # names via the comps table. Fail closed -- an undecodable rung
                # (e.g. a framing with no key material) is left out of the table
                # entirely rather than inserted as garbage text.
                text = sp_decode_rung(rbuf, name_lookup=self._db_name_lookup)
                if text is None:
                    return
                self.text = text
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
    ) -> Optional[tuple]:
        if dat_record.identifier != 64250:
            return None
        r = FafaSbregions.from_bytes(dat_record.record.record_buffer)
        if r.header.language_type not in ("Rung NT", "REGION NT"):
            return None

        # A source-protected project stores the rung as AES-encrypted neutral
        # text, not plaintext UTF-16 '@HEX@' text; decoding that as UTF-16 yields
        # CJK garbage. Protection is a per-project setting rather than a version,
        # so branch on the header signature alone -- the plaintext path is only
        # ever taken for genuine plaintext. Fail closed on an undecodable rung.
        rbuf = _rung_buffer(r)
        if looks_like_source_protected_rung(rbuf):
            text = sp_decode_rung(rbuf, name_lookup=name_lookup.get)
            if text is None:
                return None
            return (r.header.identifier, text, "")

        text = r.record_buffer.decode("utf-16-le").rstrip("\x00")
        for tag in re.findall("@[A-Za-z0-9]*@", text):
            tag_id = int(tag[1:-1], 16)
            name = name_lookup.get(tag_id)
            if name is None:
                break
            text = text.replace(tag, name)
        return (r.header.identifier, text, "")
