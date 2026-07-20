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

V20 (old-layout, per-record base shift d=-4) files store the same information in
a different record: named ``FO_<n>`` (UTF-16LE name at rec offset 0x21, kind 5
at 0x0c, UTF-16LE body -- not UTF-8), keyed by ``cid = low16 of u32@0x10`` (NOT
0x12). Its owning TextBox nameless record has no global ``md`` field; instead the
u32 at ``record[28:32]`` holds ``n`` (0xFFFFFFFF = no text) -- the V20 analog of
the modern global md id. See ``build_textbox_text_v20_rows`` /
``textbox_texts_v20_for`` and the ``d == -4`` branch of ``sfc_content.decode_sfc``.
"""
import struct
from typing import Dict, Tuple

_FAFA = b"\xfa\xfa"
_NAME = "MD_".encode("utf-16-le")
_NAME_OFF = 0x24

# V20 textbox-text record: name marker "FO_" (UTF-16LE) at a fixed offset,
# discriminator kind 5 at 0x0c.
_NAME_FO = b"F\x00O\x00_\x00"
_NAME_FO_OFF = 0x21
_FO_KIND = 5


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


def build_textbox_text_v20_rows(comments_dat: bytes):
    """Rows ``(cid, idx, text)`` for the ``textbox_text_v20`` table.

    Old-layout (V20) ``FO_<n>`` records: fafa | .. | kind 5 @0x0c | cid u16@0x10
    | .. | ``FO_<n>`` UTF-16LE @0x21 NUL | <text UTF-16LE> NUL. ``idx`` is the
    ``<n>`` parsed from the name; the owning TextBox references it via
    ``record[28:32]``. Fail-closed: a record whose name is not exactly ``FO_``
    at the fixed offset, is not kind 5, has no digit run, or whose body is not
    valid UTF-16LE is skipped.
    """
    rows = []
    seen: Dict[Tuple[int, int], bool] = {}
    pos = 0
    while True:
        i = comments_dat.find(_NAME_FO, pos)
        if i < 0:
            break
        pos = i + 1
        start = comments_dat.rfind(_FAFA, 0, i)
        if start < 0:
            continue
        nxt = comments_dat.find(_FAFA, i + 2)
        rec = comments_dat[start:nxt] if nxt > 0 else comments_dat[start:]
        # The name must sit at the fixed V20 name-field offset, else this "FO_"
        # is incidental text inside some other record.
        if len(rec) < _NAME_FO_OFF + 6 or \
                rec[_NAME_FO_OFF:_NAME_FO_OFF + 6] != _NAME_FO:
            continue
        # discriminator: every V20 textbox-text record is kind 5 at 0x0c (rung
        # comments / tag descriptions carry a different kind or a non-FO name).
        if len(rec) < 0x0e or struct.unpack_from("<H", rec, 0x0c)[0] != _FO_KIND:
            continue
        j = _NAME_FO_OFF + 6
        digits = []
        while j + 1 < len(rec) and 0x30 <= rec[j] <= 0x39 and rec[j + 1] == 0:
            digits.append(chr(rec[j]))
            j += 2
        if not digits:
            continue
        n = int("".join(digits))
        # name terminator, then the UTF-16LE body until the next NUL pair
        if j + 1 >= len(rec) or rec[j] != 0 or rec[j + 1] != 0:
            continue
        b = j + 2
        end = b
        while end + 1 < len(rec) and not (rec[end] == 0 and rec[end + 1] == 0):
            end += 2
        try:
            text = rec[b:end].decode("utf-16-le")
        except UnicodeDecodeError:
            continue
        cid = struct.unpack_from("<I", rec, 0x10)[0] & 0xFFFF
        if (cid, n) in seen:
            continue
        seen[(cid, n)] = True
        rows.append((cid, n, text))
    return rows


def textbox_texts_v20_for(cur, comment_id: int) -> Dict[int, str]:
    """{fo_index -> text} for one routine's comment_id (V20; empty if none)."""
    return {n: t for n, t in cur.execute(
        "SELECT idx, text FROM textbox_text_v20 WHERE cid=?",
        (comment_id & 0xFFFF,))}
