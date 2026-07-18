"""FBD/SFC TextBox text.

A graphical routine's TextBox carries only geometry in its nameless record; the
text is stored separately in ``Comments.Dat`` as a ``MD_<n>`` comment record,
where ``n`` is the global TextBox id the element record references at offset
0x14 (``record[20:24]``). The comment parser drops these (they are name/value
records, not plain comments), so they are parsed here directly from the stream.

Record layout (little-endian), located by the UTF-16 name at a fixed offset:
  fafa | len u32 | .. | prog_key u32@0x12 | .. | @0x24 "MD_<n>" utf16 NUL |
  zero pad | <text UTF-8> NUL

``prog_key``'s low 16 bits are the owning routine's ``comment_id`` (the same key
the SHEETSIZE records use), so the map is keyed by ``(comment_id, n)`` and the
caller resolves a routine's textboxes through its own comment_id.
"""
import struct
from typing import Dict, Tuple

_FAFA = b"\xfa\xfa"
_NAME = "MD_".encode("utf-16-le")
_NAME_OFF = 0x24


def build_textbox_text_rows(comments_dat: bytes):
    """Rows ``(cid, md_index, text)`` for the ``textbox_text`` table."""
    rows = []
    seen: Dict[Tuple[int, int], bool] = {}
    pos = 0
    marker = _NAME  # "MD_" utf-16
    while True:
        i = comments_dat.find(marker, pos)
        if i < 0:
            break
        pos = i + 1
        start = comments_dat.rfind(_FAFA, 0, i)
        if start < 0:
            continue
        rec = comments_dat[start:comments_dat.find(_FAFA, i + 2)] \
            if comments_dat.find(_FAFA, i + 2) > 0 else comments_dat[start:]
        # The name must sit at the fixed name-field offset, else this "MD_" is
        # incidental text inside some other record.
        if len(rec) < _NAME_OFF + 6 or rec[_NAME_OFF:_NAME_OFF + 6] != b"M\x00D\x00_\x00":
            continue
        j = _NAME_OFF + 6
        digits = []
        while j + 1 < len(rec) and 0x30 <= rec[j] <= 0x39 and rec[j + 1] == 0:
            digits.append(chr(rec[j]))
            j += 2
        if not digits:
            continue
        n = int("".join(digits))
        cid = struct.unpack_from("<I", rec, 0x12)[0] & 0xFFFF
        k = j
        while k < len(rec) and rec[k] == 0:
            k += 1
        end = rec.find(b"\x00", k)
        raw = rec[k:end if end >= 0 else len(rec)]
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if (cid, n) in seen:
            continue
        seen[(cid, n)] = True
        rows.append((cid, n, text))
    return rows


def textbox_texts_for(cur, comment_id: int) -> Dict[int, str]:
    """{md_index -> text} for one routine's comment_id (empty if none)."""
    return {n: t for n, t in cur.execute(
        "SELECT md, text FROM textbox_text WHERE cid=?", (comment_id & 0xFFFF,))}
