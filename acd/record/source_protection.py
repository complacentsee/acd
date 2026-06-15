"""V21 'Rung NT' source-protection (EncryptionConfig 5) READ support.

RSLogix 5000 **V21** stores ladder rung logic in ``SbRegion.Dat`` differently
from V30+.  In V30/V34/V36 the FAFA ``Rung NT`` record's ``record_buffer`` is
plaintext UTF-16LE neutral text with ``@HEX@`` object-id placeholders (e.g.
``XIC(@e2da9d52@)OTE(@bb593e67@);``), which :class:`acd.record.sbregion.
SbRegionRecord` decodes directly.

In V21 the ``record_buffer`` is a **plaintext framing header + AES-encrypted
neutral text** (the "Source Protection 5" scheme).  Decoding it as UTF-16 (the
V30+ path) yields CJK noise.  This module decrypts the buffer back to neutral
text so the existing ``@HEX@`` -> tag-name resolution and L5X export work.

WIRE FORMAT  (m = len(rbuf) - 1)
--------------------------------
* **NOP rung** (cipher-less): a 14-byte header only, no SEP / ciphertext.
  Byte-identical across the corpus: ``4eaa96aa0a050000a05d5569550d`` ("NOP();").
* **Cipher rung**: ``[14-byte header][5-byte SEP][ciphertext]``.

  HEADER (14 bytes)::

      [0]      ASCII first char of the neutral text  (N/X/S/C/A/G/L/M/...)
      [1:5]    AA 96 AA 0A                            (magic)
      [5]      0x05 | (m & 0xF0)
      [6:8]    00 00
      [8]      A0
      [9]      0x50 | (m & 0x0F)
      [10:13]  55 69 55
      [13]     m & 0xFF
  SEP (5 bytes, cipher rungs only): ``00 00 00 00 05``.
  CIPHERTEXT: ``rbuf[19:]``.

PLAINTEXT
---------
``pt = decrypt(rbuf[19:])``.  ``pt[0]`` is a 1-byte prefix (always ``0x00``);
``pt[1:]`` is the neutral text **minus its first char**, UTF-16LE.  The first
char lives in ``header[0]``::

    full_text = chr(rbuf[0]) + pt[1:].decode('utf-16-le')

CIPHER (verified ``encrypt(decrypt(ct)) == ct`` 44/44)
------------------------------------------------------
AES-256, IV = 16 zero bytes, ``key = SHA256(keymatl5)`` where ``keymatl5`` is
the Source-Protection master key material.  Full 16-byte blocks are standard
**CBC** (IV=0); any **final partial** block is **CFB-style**:
``ks = AES_ENC(prev_ciphertext_block); partial = data XOR ks[:rem]``.

OPERAND / ``@HEX@`` RULE (cracked)
----------------------------------
Operands are tag references written ``@<8hex>@`` where ``<8hex>`` is the operand
tag's CompUId (``self_lcg``, the comps record ``object_id``) as 8-digit
lowercase big-endian hex, no byte-swap (e.g. ``D1.self_lcg = 0x1f9611fa ->
@1f9611fa@``).  Bit members: ``@<tag_uid>@.@<bit_uid>@``.  Immediates are inline
decimal text.  Verified: every fully-decoded ``@hex@`` in the corpus is a real
``rtype==256`` tag ``self_lcg`` (66/66, 0 invalid).  This is exactly the comps
``object_id`` the V30+ path already resolves via the name lookup.

LOSSY TRAILING BYTES (the one residual gap)
-------------------------------------------
The stored ciphertext is the encryption of the FULL plaintext **truncated by
the last 16 plaintext bytes** (the header length field still records the full
length).  Because CBC ciphertext byte ``k`` depends only on plaintext bytes
``0..k``, the stored body decrypts cleanly up to the last *full* 16-byte block,
but the final ~8-15 UTF-16 chars (the tail of the last operand, e.g. the
destination tag of a ``MOV``/``ADD``, or a closing ``)``) are **not present** in
the body and cannot be recovered from it.  :func:`decode_rung` therefore returns
the verifiable prefix and **never fabricates** the missing tail (naively closing
parens would produce wrong text such as ``LIM(...)OTE;`` instead of
``LIM(...)OTE(F1);``).  Full recovery requires the original neutral text (e.g. a
live-PLC upload or a Studio round-trip), which is outside the on-disk body.
"""
from __future__ import annotations

import hashlib
import re
from typing import Callable, Optional

from acd.record._aes import AES

# ---------------------------------------------------------------------------
# Key material (Source-Protection master; public, from
# skdatmonster/DecryptSourceProtection) -> AES-256 key = SHA256(keymatl5).
# ---------------------------------------------------------------------------
_KEYMATL5 = bytes.fromhex(
    "5300340079005400560049005A007A00240063003E005700380026005D0078002F00"
    "3B004F00550065003F00660051006F007A003300620063005700260042007B003100"
    "5A00240068002B006F00460033005C004C003D0023004B005E006500550025005800"
    "32007300480048002B0055003D004D0063004E0037002900"
)
AES_KEY = hashlib.sha256(_KEYMATL5).digest()
# == 42b572526846f3ed853c8428dad960c7c9c6827d4818f8ff8ea9d24af0ed2b58

_HDR_MAGIC = b"\xaa\x96\xaa\x0a"
_SEP = b"\x00\x00\x00\x00\x05"
_NOP_RBUF = bytes.fromhex("4eaa96aa0a050000a05d5569550d")  # "NOP();"
_NOP_TEXT = "NOP();"
_HEADER_LEN = 14
_FRAMED_LEN = 19  # header (14) + SEP (5)
_PREFIX_BYTE = 0x00

_TOKEN_RE = re.compile(r"@([0-9a-fA-F]{8})@")
# A trailing, never-closed @<0..8 hex> token left by the lossy 16-byte tail.
_PARTIAL_TOK = re.compile(r"@[0-9a-fA-F]{0,8}$")


# ---------------------------------------------------------------------------
# AES backend (one shared instance; block ops only).  Vendored, no third-party
# dependency.  CBC full blocks + CFB-style final partial are built here.
# ---------------------------------------------------------------------------
_AES = AES(AES_KEY)


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def decrypt(ct: bytes, iv: bytes = b"\x00" * 16) -> bytes:
    """Decrypt a *whole* ciphertext: CBC full blocks + CFB-style final partial.

    Exact byte-inverse of :func:`encrypt` (so ``encrypt(decrypt(ct)) == ct``).
    Used for the framing round-trip self-test; for reading a genuine (truncated)
    body, prefer :func:`decrypt_recoverable`, which returns only the verifiably
    correct full-block plaintext.
    """
    nf, rem = divmod(len(ct), 16)
    out = bytearray()
    prev = iv
    for i in range(nf):
        blk = ct[i * 16:i * 16 + 16]
        out += _xor(_AES.decrypt_block(blk), prev)
        prev = blk
    if rem:
        ks = _AES.encrypt_block(prev)
        out += _xor(ct[nf * 16:], ks[:rem])
    return bytes(out)


def decrypt_recoverable(ct: bytes, iv: bytes = b"\x00" * 16) -> bytes:
    """Decrypt only the FULL 16-byte CBC blocks (drop any trailing partial).

    For a genuine V21 body (ciphertext truncated by the last 16 plaintext bytes)
    this returns exactly the verifiably-correct recoverable plaintext, with no
    garbled tail.
    """
    nf = len(ct) // 16
    out = bytearray()
    prev = iv
    for i in range(nf):
        blk = ct[i * 16:i * 16 + 16]
        out += _xor(_AES.decrypt_block(blk), prev)
        prev = blk
    return bytes(out)


def encrypt(pt: bytes, iv: bytes = b"\x00" * 16) -> bytes:
    """CBC full blocks + CFB-style final partial.  Inverse of :func:`decrypt`."""
    nf, rem = divmod(len(pt), 16)
    out = bytearray()
    prev = iv
    for i in range(nf):
        c = _AES.encrypt_block(_xor(pt[i * 16:i * 16 + 16], prev))
        out += c
        prev = c
    if rem:
        ks = _AES.encrypt_block(prev)
        out += _xor(pt[nf * 16:], ks[:rem])
    return bytes(out)


# ---------------------------------------------------------------------------
# framing / detection
# ---------------------------------------------------------------------------
def looks_like_source_protected_rung(rbuf: bytes) -> bool:
    """True iff the buffer carries the V21 source-protection header scaffold.

    Version-independent: matches the fixed magic that V21 rungs carry and that
    V30+ plaintext UTF-16 text never produces, so the V30+ path is never
    diverted for genuine plaintext.
    """
    return (
        len(rbuf) >= 13
        and rbuf[1:5] == _HDR_MAGIC
        and rbuf[8] == 0xA0
        and rbuf[10:13] == b"\x55\x69\x55"
    )


def is_nop(rbuf: bytes) -> bool:
    """True for the empty/NOP rung (header only, no ciphertext)."""
    return len(rbuf) == _HEADER_LEN


def is_cipher_form(rbuf: bytes) -> bool:
    """True for a bodied (encrypted) V21 rung."""
    return looks_like_source_protected_rung(rbuf) and len(rbuf) > _FRAMED_LEN


# ---------------------------------------------------------------------------
# plaintext -> neutral text
# ---------------------------------------------------------------------------
def _plaintext_to_text(first_char: str, pt: bytes) -> str:
    body = pt[1:]
    if len(body) % 2:
        body = body[:-1]  # drop a half UTF-16 unit from the lossy boundary
    return first_char + body.decode("utf-16-le", "replace")


def _strip_partial_token(text: str) -> str:
    """Drop a trailing, never-closed ``@<hex>`` token left by the lossy tail.

    A *complete* ``@dddddddd@`` token (closing ``@`` present) is never touched.
    """
    return _PARTIAL_TOK.sub("", text)


def _utf16z(buf: bytes) -> str:
    """Decode a NUL-terminated UTF-16LE string, aligned to 2-byte units.

    A plain ``buf.split(b"\\x00\\x00")`` can truncate names on an odd boundary
    (e.g. ``D1`` = ``44 00 31 00``), so walk u16 units until the 0x0000 unit.
    """
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


# V21 Comps FAFA record_buffer payload offsets (relative to record_buffer
# start, which includes the 4-byte reclen prefix):
#   reclen u4 @0, rtype u2 @10, self_lcg/CompUId u4 @12, parent u4 @16,
#   name UTF-16LE @20.  These differ from the V30+ layout the shared
#   acd.generated.comps.FafaComps parser assumes (it consumes reclen first and
#   then seeks, landing 4 bytes too far for V21), so the V21 rung path builds
#   its own object_id -> name map here rather than reusing the V30+ comps table.
_V21_COMP_TYPE_TAG = 256  # rtype for tag/component records carrying a CompUId


def build_uid_name_map(comps_db) -> dict:
    """Build the V21 ``self_lcg (CompUId/object_id) -> name`` map from Comps.Dat.

    ``comps_db`` is the object returned by ``DbExtract(comps_path).read()`` (a
    parsed Dat with ``.records.record``).  This is the @hex@ operand resolution
    table for V21 rungs: the @hex@ value equals a tag's ``self_lcg`` at payload
    offset 12.  Only ``rtype == 256`` (component/tag) records are mapped.
    """
    out = {}
    for rec in comps_db.records.record:
        buf = rec.record.record_buffer
        if len(buf) < 22:
            continue
        rtype = buf[10] | (buf[11] << 8)
        if rtype != _V21_COMP_TYPE_TAG:
            continue
        self_lcg = int.from_bytes(buf[12:16], "little")
        if self_lcg == 0:
            continue
        out[self_lcg] = _utf16z(buf[20:])
    return out


def resolve_names(neutral_text: str, name_lookup: Optional[Callable[[int], Optional[str]]]) -> str:
    """Replace every complete ``@hex@`` with its tag name via ``name_lookup``.

    ``name_lookup(object_id) -> name | None``.  Unmapped ids are left as
    ``@hex@`` (the same behaviour as the V30+ path).
    """
    if name_lookup is None:
        return neutral_text

    def rep(m: "re.Match") -> str:
        uid = int(m.group(1), 16)
        name = name_lookup(uid)
        return name if name else m.group(0)

    return _TOKEN_RE.sub(rep, neutral_text)


# ---------------------------------------------------------------------------
# top-level READ entry point
# ---------------------------------------------------------------------------
def decode_rung(
    rbuf: bytes,
    name_lookup: Optional[Callable[[int], Optional[str]]] = None,
) -> str:
    """Decode a V21 'Rung NT' ``record_buffer`` to neutral L5X rung text.

    NOP rungs decode to ``"NOP();"``.  Cipher rungs are decrypted to the
    verifiable neutral-text prefix (see the module docstring's LOSSY note: the
    last ~8-15 chars of the final operand are not present in the on-disk body and
    are not fabricated).  ``@hex@`` operands are resolved to tag names when
    ``name_lookup`` is supplied.
    """
    if is_nop(rbuf):
        return _NOP_TEXT
    if not looks_like_source_protected_rung(rbuf):
        raise ValueError("not a V21 source-protected Rung NT buffer")
    first_char = chr(rbuf[0])
    ct = rbuf[_FRAMED_LEN:]
    pt = decrypt_recoverable(ct)
    text = _plaintext_to_text(first_char, pt)
    text = _strip_partial_token(text)
    return resolve_names(text, name_lookup)


def is_v21_version(version_string: Optional[str]) -> bool:
    """Return True for a V21.xx ACD version string (e.g. 'V21.03.02/3541.000')."""
    if not version_string:
        return False
    m = re.search(r"V(\d+)", version_string)
    return bool(m) and int(m.group(1)) == 21


def _build_test_rbuf(first_char: str, ciphertext: bytes) -> bytes:
    """Assemble a V21 cipher-rung ``record_buffer`` (header + SEP + ciphertext).

    Test/diagnostic helper only — the read path never builds buffers.  ``m`` is
    derived from the final length so the header length fields are self-consistent.
    """
    rbuf_len = _FRAMED_LEN + len(ciphertext)
    m = rbuf_len - 1
    header = bytearray(_HEADER_LEN)
    header[0] = ord(first_char) & 0xFF
    header[1:5] = _HDR_MAGIC
    header[5] = 0x05 | (m & 0xF0)
    header[6] = 0x00
    header[7] = 0x00
    header[8] = 0xA0
    header[9] = 0x50 | (m & 0x0F)
    header[10:13] = b"\x55\x69\x55"
    header[13] = m & 0xFF
    return bytes(header) + _SEP + ciphertext
