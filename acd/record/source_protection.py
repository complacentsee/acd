"""Source-protection framing/crypto primitives, and 'Rung NT' rung READ support.

A source-protected project AES-encrypts several record tails at rest, always
behind the same ``aa 96 aa 0a`` marker: the comps extended-attribute tail (see
:mod:`acd.record.comps`), the comments text tail (see :mod:`acd.record.comments`)
and -- handled here -- the ``SbRegion.Dat`` ladder-rung neutral text.  This module
owns the shared marker/key/CBC primitives so every consumer decrypts the same
way; :mod:`acd.record.comps` imports them from here.

An unprotected project stores the FAFA ``Rung NT`` / ``REGION NT`` record's rung
buffer as plaintext UTF-16LE neutral text with ``@HEX@`` object-id placeholders
(e.g. ``XIC(@e2da9d52@)OTE(@bb593e67@);``), which :class:`acd.record.sbregion.
SbRegionRecord` decodes directly.  A protected project replaces that buffer with
the marker framing below.  Protection is a per-project setting, not a firmware
version: detect it by the marker, never by the version.

BUFFER EXTENT  (read this first -- ``record_buffer`` is SHORT)
-------------------------------------------------------------
Inside the FAFA record body::

    [0:4]    u32 record_length
    [4:6]    u16 sb_regions
    [6:10]   u32 identifier
    [10:51]  language_type, NUL-terminated ASCII ("Rung NT" / "REGION NT" / ...)
    [51:55]  u32 len_record_buffer
    [55:]    the rung buffer

On a protected rung ``len_record_buffer`` is **not** the length of the stored
buffer.  It tracks the *plaintext* length the buffer would have had, not the
ciphertext, so slicing the buffer at ``len_record_buffer`` truncates the
ciphertext.  The stored buffer runs to the END of the record body.  Always read
``body[55:]``; the kaitai grammar exposes the remainder as ``trailing``, so
``record_buffer + trailing`` is the true buffer.

Slicing at ``len_record_buffer`` is also what makes a short-plaintext rung look
like a "cipher-less 14-byte NOP header": its framing and 16-byte ciphertext are
simply past the cut.  **There is no cipher-less rung form** -- every protected
rung carries a ciphertext, and rungs whose text is not ``NOP();`` (e.g. ``RET();``
and ``TND();``) hide behind exactly that cut and decode to ``NOP();`` if it is
honoured.

WIRE FORMAT  (rbuf = body[55:]; the marker sits at rbuf[1])
-----------------------------------------------------------
::

    [0]      ASCII first char of the neutral text  (N/X/S/C/A/G/L/M/[/...)
    [1:5]    AA 96 AA 0A                       marker (_SP_MARKER)
    [8]      A0
    [10:13]  55 69 55
    [13:17]  u32  marker+12   PLAINTEXT BYTE LENGTH
    [17:19]  u16  marker+16   FRAMING DISCRIMINATOR
                                low byte 0 -> legacy framing: the high byte
                                    (rbuf[18], marker+17) is the EncryptionConfig
                                    and the ciphertext starts at rbuf[19]
                                    (marker + _SP_CT_OFFSET)
                                == 1     -> EncryptionConfig 9 framing:
                                    u16 @ [19:21] = 16, u32 @ [21:25] = ct length,
                                    ciphertext at rbuf[25].  No config-9 key
                                    material exists, so this fails closed.
    [19:]    CIPHERTEXT  (legacy framing), a whole number of 16-byte blocks

The redundant length nibbles at ``[5]``/``[9]`` mirror the plaintext length.  The
u16 at ``marker+4`` is NOT the plaintext byte length -- do not reuse the
AOI-nameless offsets from :mod:`acd.record.comps` here; only ``_SP_CT_OFFSET`` is
genuinely shared.  Use the u32 at ``marker+12``.

CONFIG BYTE
-----------
``config = rbuf[18]``.  It is a real wire field, not a constant -- reading it is
what lets one code path serve every project.  The AES-256 key is
``_SP_KEY_BY_CONFIG[config]``.  An unknown config is a fail-closed refusal, never
a wrong decrypt.

CIPHER
------
AES-256-**CBC**, IV = 16 zero bytes, **PKCS7** padding.  There is no CFB-style
partial final block and nothing is truncated at rest: the ciphertext is block
aligned, the PKCS7 pad is valid, and the unpadded length equals the declared
plaintext length.  The plaintext recovered here is complete.

PLAINTEXT -> TEXT
-----------------
``pt[0]`` is a 1-byte prefix; ``pt[1:]`` is the neutral text **minus its first
character**, plus the UTF-16 NUL terminator.  The first char lives in ``rbuf[0]``::

    text = chr(rbuf[0]) + pt[1:].decode("utf-16-le").rstrip("\\x00")

This is exactly the string the plaintext path produces, so the same ``@HEX@``
resolution applies.

OPERAND / ``@HEX@`` RULE
------------------------
Operands are tag references written ``@<8hex>@`` where ``<8hex>`` is the operand
tag's CompUId (the comps record ``object_id``) as 8-digit lowercase big-endian
hex, no byte-swap.  Bit members: ``@<tag_uid>@.@<bit_uid>@``.  Immediates are
inline decimal text.  This is the same comps ``object_id`` the plaintext path
resolves via the name lookup.
"""
from __future__ import annotations

import re
from typing import Callable, Optional

from acd.record._aes import AES

# ---------------------------------------------------------------------------
# Shared source-protection framing / key material.
#
# IV = 16 zero bytes; KEY = SHA256(keymatl_N) for the public Rockwell source-
# protection key material (configs from skdatmonster/DecryptSourceProtection).
# The config is project-wide, so a consumer that has to search -- the comps
# ext-attr and comments text tails carry no config byte -- caches the winning
# config in _SP_KEY_HINT and tries it first.  The rung path never searches: its
# config is on the wire.
# ---------------------------------------------------------------------------
_SP_MARKER = b"\xaa\x96\xaa\x0a"
_SP_CT_OFFSET = 18  # ciphertext starts marker_index + 18
# (config_number, AES-256 key = SHA256(keymatl_config)).
_SP_KEYS = [
    (7, bytes.fromhex("1bac9fc4fe56e90b3467ade286dc75e35e1bd7520887ebd68ca6861c4dde8966")),
    (5, bytes.fromhex("42b572526846f3ed853c8428dad960c7c9c6827d4818f8ff8ea9d24af0ed2b58")),
    (3, bytes.fromhex("a082ef440f1659d637bce1e0181a86e05b9bf7561bdc0d0f726c48b4e75c5ddc")),
    (6, bytes.fromhex("08de99aef6d12ed4b92be37f042a237add19d8d7e15ce2eae88d645288e97cb2")),
    (8, bytes.fromhex("19927a3e5b1eff2c11dd6e7cee9b0c889e3258a339a2c63c5e0b2835402588c7")),
]
# Same table keyed for the config-on-the-wire lookup (the rung path); hoisted so
# a per-rung dict() rebuild never lands in the decode loop.
_SP_KEY_BY_CONFIG = dict(_SP_KEYS)
_SP_AES_CACHE: dict = {}          # config -> AES instance (lazy key expansion)
_SP_KEY_HINT: list = [None]       # winning config for this process, tried first


def _sp_aes(config: int, key: bytes) -> AES:
    aes = _SP_AES_CACHE.get(config)
    if aes is None:
        aes = AES(key)
        _SP_AES_CACHE[config] = aes
    return aes


def _sp_cbc(ciphertext: bytes, aes: AES, nblocks: int) -> bytes:
    """Decrypt the first ``nblocks`` CBC blocks (IV=0) of ``ciphertext``."""
    out = bytearray()
    prev = b"\x00" * 16
    for i in range(nblocks):
        blk = ciphertext[i * 16:i * 16 + 16]
        out += bytes(x ^ y for x, y in zip(aes.decrypt_block(blk), prev))
        prev = blk
    return bytes(out)


def _sp_unpad(plaintext: bytes) -> Optional[bytes]:
    """Strip PKCS7 padding, or return None when the pad is not valid."""
    if not plaintext:
        return None
    pad = plaintext[-1]
    if 1 <= pad <= 16 and plaintext[-pad:] == bytes([pad]) * pad:
        return plaintext[:-pad]
    return None


def sp_decrypt_framed(buf: bytes, marker_index: int) -> Optional[bytes]:
    """Decrypt a marker-framed tail whose EncryptionConfig is on the wire.

    ``buf[marker_index:]`` must start with :data:`_SP_MARKER`.  Reads the declared
    u32 plaintext length at ``marker+12`` and the config byte at ``marker+17``,
    decrypts the ciphertext at ``marker + _SP_CT_OFFSET`` and returns the
    unpadded plaintext.

    The ciphertext length is derived from the declared length, NOT from the rest
    of the buffer: padding is PKCS7, which always appends 1..16 bytes, so the
    ciphertext is ``declared + 16 - declared % 16`` bytes.  Anything after that is
    slot filler and must not be fed to the cipher.  (Taking the ciphertext as
    "everything to the end of the buffer" works only where there is no filler;
    deriving it with ``ceil(declared/16)*16`` instead silently drops the whole pad
    block whenever ``declared`` is already block aligned.)

    Fail-closed: returns None unless the config has key material, the buffer
    actually holds the whole ciphertext, the PKCS7 pad is valid, AND the unpadded
    length equals the declared length exactly.
    """
    if len(buf) <= marker_index + 17:
        return None
    config = buf[marker_index + 17]
    key = _SP_KEY_BY_CONFIG.get(config)
    if key is None:
        return None
    declared = int.from_bytes(buf[marker_index + 12:marker_index + 16], "little")
    ct_len = declared + 16 - (declared % 16)
    ct_start = marker_index + _SP_CT_OFFSET
    ct = buf[ct_start:ct_start + ct_len]
    if len(ct) != ct_len:
        return None
    pt = _sp_unpad(_sp_cbc(ct, _sp_aes(config, key), ct_len // 16))
    if pt is None or len(pt) != declared:
        return None
    return pt


# ---------------------------------------------------------------------------
# graphical (FBD/SFC) nameless element records
# ---------------------------------------------------------------------------
# A source-protected project also encrypts each graphical routine's nameless
# element records -- the IRef/ORef/Block/wire/attachment/sheet/connector-name
# subtree the FBD (and SFC) decoders walk -- at rest behind the SAME
# config-on-the-wire framing the SbRegion rung buffer uses (NOT the AOI-nameless
# marker+4 framing).  The marker sits just past the plaintext kind word, the u32
# plaintext length is at marker+12, the EncryptionConfig is the byte at
# marker+17, and the ciphertext (PKCS7-padded, block aligned, no trailing
# slot-fill) starts at marker + _SP_CT_OFFSET.  A non-protected record has no
# marker and flows through untouched, so modern/plaintext routines are a no-op.
#
# The plaintext is the ordinary element body -- X (u32) then Y (u32) then the
# element's fffeff operand string, etc. -- that would normally follow the record
# header's 0xffffffff sentinel.  Reconstructing header + ffffffff + plaintext
# yields a record the graphical decoder parses byte-for-byte as if it were never
# protected, exactly as :func:`acd.record.comps.decrypt_sp_nameless` does for
# AOI metadata.
_ELEM_MARKER_MIN = 18             # the marker follows the plaintext kind word (u16 @ 16)
_ELEM_SCAFFOLD = b"\x55\x69\x55"  # fixed 'Ui U' framing bytes at marker+9

# Config-9 (V30+) graphical elements are recovered only on a faithful=False
# export. Faithful mode withholds a source-protected routine as <EncodedData> and
# discards its decoded FBD/SFC sheets, so trial-decrypting its (key-table-keyed)
# config-9 element records there is pure waste; the flag keeps the faithful path
# byte-identical while recovery mode reconstructs the sheets.
_ELEMENT_RECOVERY = [False]


def set_element_recovery(enabled: bool) -> None:
    """Enable/disable config-9 graphical-element recovery (see _ELEMENT_RECOVERY)."""
    _ELEMENT_RECOVERY[0] = bool(enabled)


def sp_decrypt_nameless_element(record: bytes) -> bytes:
    """Decrypt a source-protected graphical element record, or return it unchanged.

    ``record`` is a raw ``nameless`` record buffer.  When it carries the
    config-on-the-wire source-protection framing described above, return the
    reconstructed PLAINTEXT record (``header + ffffffff + decrypted body``) the
    graphical decoders can parse as if it were never protected; otherwise return
    ``record`` unchanged.

    Fail-closed -- a record with no marker, a missing framing scaffold, a
    non-legacy (config-9) discriminator, an unknown EncryptionConfig, a
    ciphertext that is not wholly present or not block aligned, an invalid PKCS7
    pad, or a recovered length that disagrees with the declared u32 length all
    return ``record`` unchanged.  A genuinely protected record whose key is
    unknown therefore stays unreadable and its routine keeps failing closed
    (element_missing) rather than emit a wrong or partial sheet; a wrong decrypt
    is never returned.
    """
    midx = record.find(_SP_MARKER, _ELEM_MARKER_MIN)
    if midx < 0 or len(record) <= midx + 17:
        return record
    scaffold = record[midx + 9:midx + 12] == _ELEM_SCAFFOLD
    # Config-9 (V30+) graphical element: same 'Ui U' scaffold, but the framing
    # discriminator low byte is 1 and the tail is wrapped-key encrypted (no on-wire
    # config, so sp_decrypt_framed cannot read it). The ffffffff sentinel is
    # RETAINED at midx-4, so the reconstruction re-appends only the recovered
    # plaintext (unlike the legacy path, which reinserts it). Recovery-only; the
    # declared-length + PKCS7 filter pins the group key uniquely for these records,
    # and a record whose key is absent stays encrypted (fail-closed).
    if scaffold and _ELEMENT_RECOVERY[0] and record[midx + 16] != 0:
        from acd.record import config9    # lazy: config9 imports this module
        if config9.is_config9(record, midx):
            pt = config9.decrypt(record, midx, config9.get_project_keytable())
            if pt is not None:
                return record[:midx] + pt
        return record
    # The 'Ui U' scaffold and a zero discriminator low byte together identify the
    # legacy config-on-wire framing; genuine plaintext element bytes never carry
    # them, and config-9 framing (low byte 1) is left encrypted in faithful mode.
    if not scaffold or record[midx + 16] != 0:
        return record
    pt = sp_decrypt_framed(record, midx)
    if pt is None:
        return record
    return record[:midx] + b"\xff\xff\xff\xff" + pt


# ---------------------------------------------------------------------------
# rung framing
# ---------------------------------------------------------------------------
_RUNG_MARKER_OFF = 1                             # marker index within rbuf
_RUNG_DISC_OFF = _RUNG_MARKER_OFF + 16           # u16 framing discriminator
_RUNG_CT_OFF = _RUNG_MARKER_OFF + _SP_CT_OFFSET  # legacy-framing ciphertext
_DISC_CONFIG9 = 1                                # newer framing; no key material

_TOKEN_RE = re.compile(r"@([0-9a-fA-F]{8})@")


def looks_like_source_protected_rung(rbuf: bytes) -> bool:
    """True iff the buffer carries the source-protection header scaffold.

    Matches the fixed marker scaffold that protected rungs carry and that
    plaintext UTF-16 neutral text never produces, so the plaintext path is never
    diverted for genuine plaintext.
    """
    return (
        len(rbuf) >= _RUNG_CT_OFF
        and rbuf[_RUNG_MARKER_OFF:_RUNG_MARKER_OFF + 4] == _SP_MARKER
        and rbuf[8] == 0xA0
        and rbuf[10:13] == b"\x55\x69\x55"
    )


def resolve_names(
    neutral_text: str,
    name_lookup: Optional[Callable[[int], Optional[str]]],
) -> str:
    """Replace every complete ``@hex@`` with its tag name via ``name_lookup``.

    ``name_lookup(object_id) -> name | None``.  Unmapped ids are left as
    ``@hex@`` (the same behaviour as the plaintext path).
    """
    if name_lookup is None:
        return neutral_text

    def rep(m: "re.Match") -> str:
        name = name_lookup(int(m.group(1), 16))
        return name if name else m.group(0)

    return _TOKEN_RE.sub(rep, neutral_text)


def decode_rung(
    rbuf: bytes,
    name_lookup: Optional[Callable[[int], Optional[str]]] = None,
) -> Optional[str]:
    """Decode a source-protected rung buffer to neutral L5X rung text.

    ``rbuf`` MUST be the whole buffer (FAFA ``body[55:]``), not the grammar's
    ``record_buffer`` field, which is cut at ``len_record_buffer`` and so
    truncates the ciphertext.

    Fail-closed -- returns None rather than a wrong or partial rung when the
    framing carries no key material (config 9), the ciphertext is not block
    aligned, the PKCS7 pad is invalid, the recovered length disagrees with the
    declared plaintext length, or the text is not valid UTF-16.  ``@hex@``
    operands are resolved to tag names when ``name_lookup`` is supplied.
    """
    if not looks_like_source_protected_rung(rbuf):
        raise ValueError("not a source-protected rung buffer")
    if int.from_bytes(rbuf[_RUNG_DISC_OFF:_RUNG_DISC_OFF + 2], "little") == _DISC_CONFIG9:
        return None
    pt = sp_decrypt_framed(rbuf, _RUNG_MARKER_OFF)
    if pt is None:
        return None
    try:
        text = chr(rbuf[0]) + pt[1:].decode("utf-16-le").rstrip("\x00")
    except UnicodeDecodeError:
        return None
    return resolve_names(text, name_lookup)


# ---------------------------------------------------------------------------
# V21 (short-header) comps name map -- unrelated to source protection
# ---------------------------------------------------------------------------
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
#   then seeks, landing 4 bytes too far for V21), so the V21 path builds its own
#   object_id -> name map here rather than reusing the V30+ comps table.
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


def is_v21_version(version_string: Optional[str]) -> bool:
    """Return True for a V21.xx ACD version string (e.g. 'V21.03.02/3541.000')."""
    if not version_string:
        return False
    m = re.search(r"V(\d+)", version_string)
    return bool(m) and int(m.group(1)) == 21
