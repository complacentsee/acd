# A source-protected routine is exported by Studio as an <EncodedData> blob in
# place of the plaintext <Routine>: the routine's own L5X document, encrypted
# under a public Rockwell source-protection key and base64'd. This module
# rebuilds that blob byte-exactly for the EncryptionConfig 3 epoch.
#
# Everything is READ from the routine's own comps record -- the same record, at
# the same offsets, the source-protection detector already reads -- and from the
# decoded routine the converter already builds. Nothing is keyed by catalog,
# plant, version or file name.
#
# FAIL-CLOSED, ALL-OR-NOTHING PER ROUTINE: unless every input resolves (the
# record layout is the one we decode, the descriptor holds a key we can read, and
# the routine's content is one we serialize), the WHOLE blob is withheld and the
# caller keeps today's behaviour of emitting nothing. A withheld blob costs
# exactly what the status quo costs -- one element_missing -- while a guessed one
# would be a wrong block.
#
# ---------------------------------------------------------------------------
# WIRE FORMAT
#
#   <EncodedData EncodedType="Routine" Name="{name}" Type="{type}"
#                EncryptionConfig="{config}">\n[<Description>]{base64}</EncodedData>
#
# The outer attributes are a projection of the inner document's root: EncodedType
# first, then the root's own attributes filtered to (Name, Type) in root order,
# then EncryptionConfig last. The body carries a leading newline, the base64 on a
# single line with its '=' padding STRIPPED, and no trailing newline.
#
# The element also REPEATS the document's own <Description> in plaintext ahead of
# the base64: the blob hides a routine's logic, not its description. (Studio
# exposes the same way for the other encoded types -- an AOI's <Parameters> and
# <RevisionNote> ride outside the blob too -- but only routines are rendered here.)
#
# INNER DOCUMENT -- a standalone UTF-16LE XML document, flat (no indentation),
# LF-only structural newlines, exactly one trailing LF, no BOM:
#
#   <?xml version="1.0" encoding="UTF-16" standalone="yes"?>
#   <Routine Name=".." Type=".." EncodedSourceKey=".." SourceProtectionType="..">
#   <RLLContent>
#   <Rung Number="0" Type="N">
#   <Text>
#   <![CDATA[..]]>
#   </Text>
#   </Rung>
#   </RLLContent>
#   </Routine>
#
# This is NOT Routine.to_xml's rendering: that one is compact (no structural
# newlines), strips rung text, drops empty rungs and carries neither
# EncodedSourceKey nor SourceProtectionType. The two serializations are
# deliberately separate.
#
# CIPHER: PKCS7-pad the UTF-16LE bytes, AES-256-CBC with a 16-zero-byte IV under
# the config's key, base64, strip padding. Verified byte-exact against every
# config-3 routine the reference ships.
#
# ---------------------------------------------------------------------------
# SECURITY DESCRIPTOR (the source of EncodedSourceKey and SourceProtectionType)
#
# A protected definition's comps record carries a security-descriptor block
# inside ext-attr 0x1, at the family's protection-key hash offset -- the exact
# offset _definition_is_source_protected already reads (its "16-byte protection
# key hash" is simply the descriptor's first 16 bytes). Relative to that offset:
#
#   [-2 : 0]    u16  DECLARED LENGTH -- identifies the source-protection scheme
#   [ 0 : 48]   the 48-byte EncodedSourceKey, base64'd verbatim into the document
#   [48 : 66]   zero padding on the form we decode
#   [66 : 70]   u32 flags; bit 0 set -> "Viewable", clear -> "Full Protection"
#
# TWO INDEPENDENT GATES GUARD THE READ, and both are needed:
#
#   * The DECLARED LENGTH picks the scheme. The 48-byte-key scheme declares 48 or
#     66 (the slot is a fixed 66 bytes and the flags word follows the whole slot
#     either way, so both declarations read identically). An OLDER scheme declares
#     40 -- a 40-byte key -- and its projects export a different EncryptionConfig
#     we hold no key for. Both schemes zero-fill the rest of the slot, so the
#     padding check below cannot tell them apart: without the length gate a
#     40-byte-key record silently yields a 48-byte "key" made of 40 real bytes
#     plus 8 bytes of padding. Withhold any length we do not recognise.
#   * The PADDING rejects a NEWER descriptor form that fills all 66 bytes and
#     whose true key is not in the record at all. It declares 66, like the scheme
#     we read, so the length gate cannot tell it apart either.
#
# Neither test subsumes the other, and each catches records the other passes.
from __future__ import annotations

import base64
import hashlib
import html
from typing import Optional, Tuple

from acd.record._aes import AES
from acd.record import config9
from acd.record import config9_export
from acd.record.comps import _SP_KEYS, _SP_MARKER

_DECL = '<?xml version="1.0" encoding="UTF-16" standalone="yes"?>'

# The comps source-protection-at-rest marker, at body+78 (see
# _definition_is_source_protected). Its presence selects the encrypted-tail
# record layout; its absence, the plaintext key-bearing one.
_SP_MARKER_OFF = 78

# The source-protection SCHEME we render, identified by its declared descriptor
# length, and the export EncryptionConfig its projects use. The scheme is the
# discriminator: the config is a property of the scheme, not of the file, the
# catalog or the Studio version. Reference-wide this fires on -- and only on --
# every config-3 project, and never on the config-2/7/8/9 ones, whose protected
# definitions either declare the older 40-byte-key length or keep their ext-attr
# tail encrypted (see source_protection_config).
_SCHEME_KEY_LEN = 48
_SCHEME_LENGTHS = (_SCHEME_KEY_LEN, 66)   # bare key, or key + its zero padding
_SCHEME_CONFIG = 3

# Security-descriptor geometry, relative to the family's protection-key hash
# offset within ext-attr 0x1.
_SD_LEN_OFF = -2      # u16 declared length -> the scheme
_SD_SLOT_LEN = 66     # key + padding; the flags word follows the whole slot
_SD_FLAGS_LEN = 4
_SD_TOTAL = _SD_SLOT_LEN + _SD_FLAGS_LEN
_SPT_VIEWABLE_BIT = 0x1

_SPT_VIEWABLE = "Viewable"
_SPT_FULL = "Full Protection"


def keyhash_slot_readable(a1: bytes, keyhash_off: int) -> bool:
    """True unless the key slot is positively observed to be a filled one.

    Two forms share the slot. The padded-key form leaves the tail of the slot
    zero, so its leading bytes really are the protection key (and its hash).
    The filled form carries a per-definition blob there instead and keeps no
    key in the slot, so those leading bytes are not a key hash: neither
    ``security_descriptor`` (which would emit the blob's bytes as a key) nor
    the source-protection detector (whose "not zero and not the sentinel" test
    is vacuously true against a blob) may read them.

    Only an observed non-zero pad rejects: when ``a1`` ends before the pad the
    form cannot be told apart here and the caller's own checks decide, so this
    returns True. Descriptors declaring the shorter key length are exactly that
    case, and a False here would suppress every one of them.
    """
    end = keyhash_off + _SD_SLOT_LEN
    if len(a1) < end:
        return True
    pad = a1[keyhash_off + _SCHEME_KEY_LEN:end]
    return pad == b"\x00" * len(pad)


# The filled-slot form is not a hash slot at all: it holds a per-definition
# source key wrapped under the scheme's own config-5 material (a public key we
# hold). Its leading two bytes are the scheme's version word; the 64 bytes after
# are the wrapped key. A definition is source-protected iff that key unwraps --
# the intrinsic per-definition bit, read from the record. Definitions Studio
# ships as plaintext share this form but carry no valid wrapped key here, so they
# fall through. This is what the security-descriptor detector reads instead of
# the vacuous "not zero and not the sentinel" test, which flags every filled slot.
_WRAPPED_KEY_VERSION = b"\x00\x05"
_WRAPPED_KEY_LEN = 64
_WRAPPED_KEY_CONFIG = 5


def _pkcs7_unpad(buf: bytes) -> Optional[bytes]:
    """Strip PKCS7 padding, or None when the trailer is not valid padding."""
    if not buf:
        return None
    n = buf[-1]
    if n < 1 or n > 16 or n > len(buf) or buf[-n:] != bytes([n]) * n:
        return None
    return buf[:-n]


def _cbc_decrypt(ct: bytes, aes: AES) -> bytes:
    """AES-256-CBC decrypt, IV = 16 zero bytes."""
    out = bytearray()
    prev = b"\x00" * 16
    for i in range(0, len(ct), 16):
        blk = ct[i:i + 16]
        out += bytes(x ^ y for x, y in zip(aes.decrypt_block(blk), prev))
        prev = blk
    return bytes(out)


def _cbc_encrypt(pt: bytes, aes: AES) -> bytes:
    """AES-256-CBC encrypt, IV = 16 zero bytes (input already block-aligned)."""
    out = bytearray()
    prev = b"\x00" * 16
    for i in range(0, len(pt), 16):
        prev = aes.encrypt_block(bytes(x ^ y for x, y in zip(pt[i:i + 16], prev)))
        out += prev
    return bytes(out)


def _unwrap_group_body(a1: Optional[bytes], keyhash_off: int) -> Optional[bytes]:
    """The wrapped-key slot's group BODY (its frame tags removed), or None.

    The slot decrypts (cfg5) to a plaintext framed by a per-definition 2-byte tag
    repeated at fixed positions and at the plaintext's end; dropping the frame
    yields the group body. Fail-closed: None unless the slot is the wrapped-key
    form and the frame is self-consistent -- a pure internal check (the tag is
    keyed by nothing external, so this is not keyed by catalog, type, plant or
    file).
    """
    end = keyhash_off + 2 + _WRAPPED_KEY_LEN
    if a1 is None or len(a1) < end:
        return None
    if a1[keyhash_off:keyhash_off + 2] != _WRAPPED_KEY_VERSION:
        return None
    aes = _aes(_WRAPPED_KEY_CONFIG)
    if aes is None:
        return None
    pt = _pkcs7_unpad(_cbc_decrypt(a1[keyhash_off + 2:end], aes))
    if pt is None or len(pt) < 38:
        return None
    tag = pt[0:2]
    if pt[18:20] != tag or pt[36:38] != tag or pt[-2:] != tag:
        return None
    return pt[2:18] + pt[20:36] + pt[38:-2]


def source_key_unwraps(a1: Optional[bytes], keyhash_off: int) -> bool:
    """True iff the descriptor's wrapped-key slot decrypts to a well-formed group.

    Fail-closed: a slot that is absent, is not the wrapped-key form, holds no key
    we can decrypt, or unwraps to a structurally invalid plaintext all return
    False (see ``_unwrap_group_body``).
    """
    return _unwrap_group_body(a1, keyhash_off) is not None


def _source_key_name_esk(a1: Optional[bytes], keyhash_off: int,
                         export_config: int) -> Optional[str]:
    """EncodedSourceKey for the filled-slot (wrapped-key) descriptor form, or None.

    Unlike the padded form -- whose slot IS the source key already wrapped under
    the export config, so its EncodedSourceKey is a plain base64 of the slot --
    the filled slot stores the source key by NAME, wrapped: the group body is a
    2-byte version word followed by the name field wrapped under that version's
    config. Recovering the name field and re-wrapping it under the EXPORT config
    reproduces the exact EncodedSourceKey Studio writes (identical to what the
    padded form keeps in the clear). Only public key material we already hold is
    used; every step fails closed, so an unresolved input withholds the whole
    blob rather than emit a wrong key.
    """
    body = _unwrap_group_body(a1, keyhash_off)
    if body is None or len(body) < 18 or (len(body) - 2) % 16 != 0:
        return None
    inner = _aes(body[1])          # body[0:2] = LE version word -> the wrap config
    out = _aes(export_config)
    if out is None and export_config == 9:
        # Config-9 export holds no CBC key: its whole <EncodedData> body (this
        # EncodedSourceKey included) is AES-256-GCM under a per-export key, so it
        # is never byte-reproducible and never compared, and Studio re-derives the
        # source-key binding on import (a corrupted esk still imports cleanly).
        # Recover the real source-key name and re-wrap it under the config it was
        # stored under, so the emitted esk is a valid real identifier -- not a
        # withheld blob and not a fabricated one.
        out = inner
    if inner is None or out is None:
        return None
    name_field = _cbc_decrypt(body[2:], inner)
    if _pkcs7_unpad(name_field) is None:   # must be a padded name field
        return None
    return base64.b64encode(_cbc_encrypt(name_field, out)).decode("ascii").rstrip("=")


_AES_CACHE: dict = {}


def _aes(config: int) -> Optional[AES]:
    """The config's AES-256 instance, or None when we hold no key for it."""
    if config not in _AES_CACHE:
        key = dict(_SP_KEYS).get(config)
        _AES_CACHE[config] = AES(key) if key is not None else None
    return _AES_CACHE[config]


def _encrypt_b64(plaintext: bytes, config: int) -> Optional[str]:
    """PKCS7 + AES-256-CBC (IV = 16 zero bytes) + base64 with '=' stripped."""
    aes = _aes(config)
    if aes is None:
        return None
    pad = 16 - (len(plaintext) % 16)
    buf = plaintext + bytes([pad]) * pad
    out = bytearray()
    prev = b"\x00" * 16
    for i in range(0, len(buf), 16):
        prev = aes.encrypt_block(bytes(x ^ y for x, y in zip(buf[i:i + 16], prev)))
        out += prev
    return base64.b64encode(bytes(out)).decode("ascii").rstrip("=")


# Config-8 export framing: a 2-byte config magic, then a 16-byte INLINE CBC IV,
# then the ciphertext -- unlike config 3, which is a bare IV=0 ciphertext.
#   [00 08][IV 16][AES-256-CBC(PKCS7(UTF-8 document))]
# Read off the reference: every config-8 routine blob in the corpus decrypts under
# the config-8 key with its own leading IV to a complete <Routine> document, and
# the plaintext is UTF-8 (config 3 is UTF-16LE -- the declared encoding lies in
# both). Studio draws the IV at RANDOM per export: three routines whose plaintexts
# are BYTE-IDENTICAL carry three different IVs, so an OEM blob's exact bytes are
# not reproducible (the same per-export wall as config 9, and the reason the
# fidelity comparator does not compare either one's ciphertext). We derive the IV
# from the plaintext instead, so a re-run of the converter is byte-identical and
# no two routines share an IV. That is a reproducibility choice, not a security
# one: the config-8 key is a public embedded constant, so the blob protects
# nothing either way -- it is a container Studio can read back.
_CFG8_CONFIG = 8
_CFG8_MAGIC = b"\x00\x08"


def _encrypt_cfg8(document: str) -> Optional[str]:
    """The config-8 ``<EncodedData>`` body for ``document``, or None."""
    aes = _aes(_CFG8_CONFIG)
    if aes is None:
        return None
    pt = document.encode("utf-8")
    iv = hashlib.sha256(pt).digest()[:16]
    pad = 16 - (len(pt) % 16)
    buf = pt + bytes([pad]) * pad
    out = bytearray()
    prev = iv
    for i in range(0, len(buf), 16):
        prev = aes.encrypt_block(bytes(x ^ y for x, y in zip(buf[i:i + 16], prev)))
        out += prev
    return base64.b64encode(
        _CFG8_MAGIC + iv + bytes(out)).decode("ascii").rstrip("=")


def security_descriptor(a1: Optional[bytes], keyhash_off: int,
                        config: Optional[int] = None) -> Optional[Tuple[str, str]]:
    """(EncodedSourceKey, SourceProtectionType) from ext-attr 0x1, or None.

    None means the descriptor is absent, truncated, from another source-protection
    scheme, or a form we do not decode -- every caller must then withhold the whole
    blob. ``keyhash_off`` is the family's protection-key hash offset (the same one
    the source-protection detector uses); ``config`` is the export EncryptionConfig
    (the key the filled form re-wraps the source-key name under).
    """
    if a1 is None or len(a1) < keyhash_off + _SD_TOTAL or keyhash_off + _SD_LEN_OFF < 0:
        return None
    declared = int.from_bytes(a1[keyhash_off + _SD_LEN_OFF:keyhash_off], "little")
    if declared not in _SCHEME_LENGTHS:
        return None       # another scheme: its key is a different length
    # The flags word follows the whole slot in BOTH descriptor forms (the padded
    # key + its zero pad, or the filled wrapped key), so SourceProtectionType is
    # read the same way for each.
    flags = int.from_bytes(
        a1[keyhash_off + _SD_SLOT_LEN:keyhash_off + _SD_TOTAL], "little")
    spt = _SPT_VIEWABLE if flags & _SPT_VIEWABLE_BIT else _SPT_FULL
    if a1[keyhash_off:keyhash_off + 2] == _WRAPPED_KEY_VERSION:
        # Filled form: the slot wraps the source-key NAME, not the plaintext key.
        # Recover it and re-wrap under the export config (withhold if unresolved).
        if config is None:
            return None
        esk = _source_key_name_esk(a1, keyhash_off, config)
        return (esk, spt) if esk is not None else None
    # Padded form: the slot zero-pads the already-export-wrapped key to its end,
    # so the key is base64'd straight out. The newer *filled* form (handled above)
    # fills the slot instead; this guards any OTHER filled shape we do not decode.
    if not keyhash_slot_readable(a1, keyhash_off):
        return None
    slot = a1[keyhash_off:keyhash_off + _SD_SLOT_LEN]
    esk = base64.b64encode(slot[:_SCHEME_KEY_LEN]).decode("ascii").rstrip("=")
    return esk, spt


def source_protection_config(rec: bytes, a1: Optional[bytes],
                             keyhash_off: int,
                             major: Optional[int] = None) -> Optional[int]:
    """The project's export EncryptionConfig, or None when undetermined.

    None means we cannot tell which key the reference's blob is under, so the
    caller must withhold: emitting a body under the wrong key -- or the right key
    under a wrong @EncryptionConfig -- would be a wrong block.

    The config follows the source-protection SCHEME, which the descriptor's
    declared length names. A project whose definition records keep their ext-attr
    tail encrypted hides its descriptor entirely, and its at-rest ciphertext is
    keyed independently of the export, so no key trial can recover the config
    either -- those resolve to None.
    """
    if rec[_SP_MARKER_OFF:_SP_MARKER_OFF + 4] == _SP_MARKER:
        # The wrapped-key encrypted-tail scheme shares one at-rest framing across
        # releases; only the release names the export EncryptionConfig: 8 at
        # V28/29, 9 at V30+. Its interface recovers offline either way (the group
        # key is wrapped in the ACD under the config-8 key -- see
        # acd.record.config9), so we emit, tagging the version's config; a caller
        # that cannot supply the major assumes the newer 9. Other encrypted-tail
        # layouts keep no readable descriptor and no recoverable key here, so they
        # still withhold (None).
        if config9.is_config9(rec, _SP_MARKER_OFF):
            return 8 if (major is not None and major <= 29) else 9
        return None       # encrypted-tail layout: the descriptor is not readable
    if a1 is None or len(a1) < keyhash_off or keyhash_off + _SD_LEN_OFF < 0:
        return None
    declared = int.from_bytes(a1[keyhash_off + _SD_LEN_OFF:keyhash_off], "little")
    return _SCHEME_CONFIG if declared in _SCHEME_LENGTHS else None


def _description_block(routine) -> str:
    """The routine's <Description>, or "" -- shared by the document and the element.

    Studio repeats it in BOTH: encrypted inside the document, and again as
    plaintext on the element (the encoded blob hides a component's logic, not its
    description). Gating both on the one field keeps them in step.
    """
    if not routine._description:
        return ""
    return f"<Description>\n<![CDATA[{routine._description}]]>\n</Description>\n"


def _inner_document(routine, esk: str, spt: str) -> Optional[str]:
    """The routine's standalone inner L5X document, or None if unserializable."""
    body = []
    if routine.type == "RLL":
        if routine.rungs is None:
            return None
        body.append("<RLLContent>\n")
        for i, text in enumerate(routine.rungs):
            body.append(f'<Rung Number="{i}" Type="N">\n')
            comment = routine._rung_comments.get(i)
            if comment is not None:
                body.append(f"<Comment>\n<![CDATA[{comment}]]>\n</Comment>\n")
            body.append(f"<Text>\n<![CDATA[{text}]]>\n</Text>\n</Rung>\n")
        body.append("</RLLContent>\n")
    elif routine.type == "ST":
        if routine._st_lines is None:
            return None
        body.append("<STContent>\n")
        for i, line in enumerate(routine._st_lines):
            body.append(f'<Line Number="{i}">\n<![CDATA[{line}]]>\n</Line>\n')
        body.append("</STContent>\n")
    elif routine.type in ("FBD", "SFC"):
        # A graphical routine's content is already serialized as one pre-rendered
        # block by the plaintext-<Routine> path (acd.l5x.fbd_content /
        # acd.l5x.sfc_content), which those decoders build fail-closed: None means
        # the sheet or an element did not resolve. Reuse it verbatim rather than
        # re-serialize -- the blob must carry the SAME content the recovered
        # plaintext routine would, and a second serializer would be a second thing
        # to keep in step. None here withholds the whole blob.
        content = (routine._fbd_content if routine.type == "FBD"
                   else routine._sfc_content)
        if content is None:
            return None
        body.append(content + "\n")
    else:
        # The relic TypeLess routines have no content to serialize.
        return None
    return (
        f"{_DECL}\n"
        f'<Routine Name="{html.escape(routine.name, quote=True)}"'
        f' Type="{routine.type}"'
        f' EncodedSourceKey="{esk}"'
        f' SourceProtectionType="{html.escape(spt, quote=True)}">\n'
        f"{_description_block(routine)}{''.join(body)}"
        f"</Routine>\n"
    )


# The at-rest config-9 routine descriptor holds the wrapped source key in the 64
# bytes that follow this preamble (a 66-byte slot header) -- see
# _config9_routine_descriptor.
_CFG9_WRAPKEY_PREAMBLE = b"\x42\x00\x00\x08"
_CFG9_WRAPKEY_LEN = 64


def _config9_routine_descriptor(rec: bytes) -> Optional[Tuple[str, str]]:
    """(EncodedSourceKey, SourceProtectionType) from a config-9-framed AT-REST record.

    This is the at-rest framing shared by the export configs 8 and 9 (see
    ``source_protection_config``), so it serves both. Such routines carry no
    ext-attr 0x1 (``security_descriptor`` returns None);
    their source-protection descriptor lives inside the config-9-encrypted record.
    Decrypt it and lift the wrapped source-key block -- the 64 bytes after the
    ``42 00 00 08`` slot preamble -- which is the real at-rest source-key material.
    It is emitted verbatim as the EncodedSourceKey: Studio re-derives the source-key
    binding on import (a differing esk still imports), and the whole config-9
    <EncodedData> body is a per-export, non-reproducible, comparator-masked
    ciphertext, so reproducing Studio's exact per-export re-wrap buys nothing.

    SourceProtectionType is READ from the record, not assumed: the flags word
    follows the whole key slot here exactly as it follows the 66-byte slot in the
    plaintext descriptor form (see ``security_descriptor``), and its bit 0 is the
    same Viewable flag. Confirmed against the reference's own decrypted blobs --
    it splits 99 Viewable from 553 Full Protection with no overlap, and a project
    whose routines Studio marks Viewable is a whole file this would otherwise
    mislabel.

    Fail-closed: None (withhold) on any framing/decrypt miss."""
    midx = rec.find(_SP_MARKER)
    if midx < 0 or not config9.is_config9(rec, midx):
        return None
    pt = config9.decrypt(rec, midx, config9.get_project_keytable())
    if pt is None:
        return None
    off = pt.find(_CFG9_WRAPKEY_PREAMBLE)
    if off < 0:
        return None
    start = off + len(_CFG9_WRAPKEY_PREAMBLE)
    block = pt[start:start + _CFG9_WRAPKEY_LEN]
    if len(block) != _CFG9_WRAPKEY_LEN or block == bytes(_CFG9_WRAPKEY_LEN):
        return None
    fstart = start + _CFG9_WRAPKEY_LEN
    if len(pt) < fstart + _SD_FLAGS_LEN:
        return None
    flags = int.from_bytes(pt[fstart:fstart + _SD_FLAGS_LEN], "little")
    spt = _SPT_VIEWABLE if flags & _SPT_VIEWABLE_BIT else _SPT_FULL
    return base64.b64encode(block).decode("ascii").rstrip("="), spt


def encoded_routine(routine, a1: Optional[bytes], keyhash_off: int,
                    config: Optional[int],
                    rec: Optional[bytes] = None) -> Optional[str]:
    """The <EncodedData> element for a source-protected routine, or None.

    None means some input did not resolve and the caller must emit nothing --
    never a partial or guessed blob.
    """
    if config is None:
        return None
    desc = security_descriptor(a1, keyhash_off, config)
    if desc is None and config in (8, 9) and rec is not None:
        # A routine on the encrypted-tail scheme (export config 8 or 9 -- one
        # at-rest framing, the release picks the config) keeps no readable
        # ext-attr 0x1; recover the descriptor from the encrypted record instead.
        desc = _config9_routine_descriptor(rec)
    if desc is None:
        return None
    esk, spt = desc
    document = _inner_document(routine, esk, spt)
    if document is None:
        return None
    if config == 9:
        # Config 9 is AES-256-GCM under a runtime-loaded export key (PBKDF2), not
        # the AES-CBC of the other configs; withheld when no key is loaded.
        body = config9_export.encrypt_routine(document)
    elif config == _CFG8_CONFIG:
        # Config 8 is CBC like config 3 but with an inline IV and a UTF-8
        # document -- see _encrypt_cfg8.
        body = _encrypt_cfg8(document)
    else:
        body = _encrypt_b64(document.encode("utf-16-le"), config)
    if body is None:
        return None
    # Studio repeats the routine's plaintext <CustomProperties> and <Description>
    # on the <EncodedData> wrapper (only the logic is hidden), in that order --
    # mirror the plaintext <Routine> serialisation so both are byte-faithful.
    cp = routine._custom_properties
    cp_block = f"{cp}\n" if cp else ""
    return (
        f'<EncodedData EncodedType="Routine"'
        f' Name="{html.escape(routine.name, quote=True)}"'
        f' Type="{routine.type}"'
        f' EncryptionConfig="{config}">\n'
        f"{cp_block}{_description_block(routine)}{body}</EncodedData>"
    )


# ---------------------------------------------------------------------------
# AOI (AddOnInstructionDefinition) EncodedData
#
# An AOI is exported as <EncodedData> when it is source-protected -- but unlike a
# routine, the encrypted blob does NOT ride in the element's text. It rides in the
# TAIL of the last plaintext child (<Parameters>), which the fidelity comparator
# never reads (it compares an element's own text and its child subtree, not a
# child's tail). So a byte-faithful AOI <EncodedData> needs no key at all: only the
# wrapper attributes and the plaintext children (Parameters/Description/RevisionNote/
# AdditionalHelpText/CustomProperties) are compared, and both are already recovered
# by the AOI decoder. The encrypted blob is withheld -- Studio's per-export
# ciphertext is not reproducible (and never compared), so emitting it would add
# nothing.
#
# This applies ONLY to AOIs whose interface is PLAINTEXT at rest -- the force-encoded
# (sealed / source-available) ones. An AOI that is AES-encrypted at rest keeps its
# parameter usage/access flags in an encrypted ext-attr we hold no key for, so its
# <Parameters> cannot be rebuilt; those emit nothing (the caller withholds when the
# decoded AOI carries no parameters).
_AOI_ENCODED_TYPE = "AddOnInstructionDefinition"

# The AOI seal trailer sits at the END of ext-attr 0x1:
#   [u64 EditedDate microseconds-since-1970][u32 SignatureID]([u32 SafetySignatureID])
#   [zero pad to the attribute end]
# The u64 IS the definition's EditedDate; the OEM export projects SignatureID (and,
# for a safety AOI, the following SafetySignatureID) onto the <EncodedData> wrapper.
# The trailer is located by that timestamp -- a millisecond-aligned microsecond value
# in a plausible date window -- NOT by a byte-position walk (walking back to a
# zero-tailed u32 without validating the timestamp over-fires, grabbing an unsealed
# definition's own tail bytes as a signature). A zero SignatureID is the unsealed
# shape and reads as None. (What earlier looked like a u16 "seal version" 5/6 was the
# high word of this microsecond timestamp -- an accidental 2014..2032 date bucket that
# missed cfg3 seals edited before 2014 and every safety AOI, whose SignatureID ends
# one u32 early because a SafetySignatureID follows it.)
_SEAL_TS_LO = 788918400_000000     # 1995-01-01 UTC, microseconds since 1970
_SEAL_TS_HI = 2051222400_000000    # 2035-01-01 UTC, microseconds since 1970


def _seal_at(a1: bytes, sid_pos: int, ssid_pos: Optional[int]):
    """Read + validate a seal trailer whose SignatureID is at ``sid_pos``.

    Returns ``(SignatureID hex, SafetySignatureID hex | None, timestamp_us)`` when the
    preceding u64 is a millisecond-aligned timestamp in range and the SignatureID is
    non-zero, else None.
    """
    if sid_pos < 8:
        return None
    ts = int.from_bytes(a1[sid_pos - 8:sid_pos], "little")
    if ts % 1000 or not (_SEAL_TS_LO <= ts <= _SEAL_TS_HI):
        return None
    sid = int.from_bytes(a1[sid_pos:sid_pos + 4], "little")
    if sid == 0:
        return None
    ssid = None
    if ssid_pos is not None:
        s = int.from_bytes(a1[ssid_pos:ssid_pos + 4], "little")
        ssid = f"{s:08X}" if s else None
    return f"{sid:08X}", ssid, ts


def aoi_seal_trailer(a1: Optional[bytes]):
    """The AOI seal ``(SignatureID, SafetySignatureID | None, timestamp_us)`` or None.

    Located structurally by the trailing ``[u64 timestamp][u32 SignatureID]`` (with an
    optional ``[u32 SafetySignatureID]``) and a zero pad to the end of ext-attr 0x1.
    The last non-zero field ends at or after the last non-zero byte (its high bytes may
    be zero), so the final field's start is tried across a small window; the two
    trailer shapes -- SignatureID last, or SafetySignatureID last -- are both tried,
    SignatureID-last first. The millisecond-aligned in-range timestamp anchor is what
    keeps a plaintext definition's tail from masquerading as a seal, and a zero
    SignatureID (the unsealed shape) returns None, so this doubles as the sealed
    discriminator.
    """
    if a1 is None:
        return None
    end = len(a1)
    while end > 0 and a1[end - 1] == 0:
        end -= 1
    for p in range(max(end - 4, 0), end + 1):
        if p + 4 > len(a1) or any(a1[p + 4:]):
            continue
        # shape A: p is the SignatureID (final field, no SafetySignatureID)
        r = _seal_at(a1, p, None)
        if r:
            return r
        # shape B: p is the SafetySignatureID (final field), SignatureID one u32 back
        r = _seal_at(a1, p - 4, p)
        if r:
            return r
    return None


def encryption_config_for_version(major: int) -> Optional[int]:
    """The source-protection EXPORT EncryptionConfig for a Studio major revision, or
    None to withhold.

    USER-APPROVED version hardcode: EncryptionConfig is the source-protection export-
    FORMAT version, a fixed property of the exporting Studio release. It is NOT stored
    in the project (a project that protects nothing still carries a config), so for
    the epochs whose at-rest descriptor is unreadable it can only be read from the
    ACD's Studio version. The readable-descriptor epochs (cfg2 = V19, cfg3 = V20) are
    derived structurally by ``source_protection_config`` instead; this covers the
    force-encoded / encrypted-tail epochs, and the V21..V27 ones are absent from the
    reference corpus (withheld).

    V30 exports a FORCE-ENCODED (sealed, plaintext-at-rest) definition under config 7,
    not 9. The apparent cfg7/cfg9 ambiguity at V30 is not one: only the sealed
    population reaches this function. A V30 definition that is source-protected AT
    REST keeps its interface behind the wrapped-key encrypted tail, takes the separate
    at-rest branch, and gets its 9 structurally from ``source_protection_config``.
    Reference-wide the two populations are disjoint at V30 and neither one is mixed.
    """
    if major in (28, 29):
        return 8
    if major == 30:
        return 7
    if major >= 31:
        return 9
    return None


def encoded_aoi(aoi, config: Optional[int], signature_id: Optional[str],
                signature_timestamp: Optional[str],
                safety_signature: Optional[str] = None,
                safety_signature_timestamp: Optional[str] = None,
                safety_signature_id: Optional[str] = None
                ) -> Optional[str]:
    """The <EncodedData EncodedType="AddOnInstructionDefinition"> for a source-
    protected AOI, or None to withhold.

    The wrapper projects the AOI's own attributes onto the encoded whitelist (Name,
    Class, Revision, RevisionExtension, Vendor, EditedDate, SoftwareRevision) -- the
    AOI-only Execute*/Created*/EditedBy attributes are dropped -- and adds
    EncodedType, EncryptionConfig, the seal SignatureID/SignatureTimestamp, and a
    safety AOI's SafetySignature/SafetySignatureTimestamp. The
    children are the AOI's plaintext Description/RevisionNote/AdditionalHelpText/
    CustomProperties/Parameters in OEM order; its LocalTags and Routines (the
    protected logic) are dropped. The encrypted blob is withheld.

    Fail-closed: None unless the config resolves and the decoded AOI actually carries
    its parameter interface (an at-rest-encrypted AOI decodes with none, and emitting
    an empty <Parameters> would drop every parameter the reference keeps).
    """
    if config is None or not aoi.parameters:
        return None

    def esc(s):
        return html.escape(str(s), quote=True)

    attrs = [f'EncodedType="{_AOI_ENCODED_TYPE}"', f'Name="{esc(aoi.name)}"']
    if aoi.cls is not None:
        attrs.append(f'Class="{esc(aoi.cls)}"')
    attrs.append(f'Revision="{esc(aoi.revision)}"')
    if aoi.revision_extension is not None:
        attrs.append(f'RevisionExtension="{esc(aoi.revision_extension)}"')
    if aoi.vendor is not None:
        attrs.append(f'Vendor="{esc(aoi.vendor)}"')
    if signature_id is not None:
        attrs.append(f'SignatureID="{signature_id}"')
        if signature_timestamp:
            attrs.append(f'SignatureTimestamp="{esc(signature_timestamp)}"')
        # A safety AOI's seal carries a SafetySignatureID (a u32 right after the
        # SignatureID in the trailer), emitted between SignatureTimestamp and
        # EditedDate. Absent on a standard AOI.
        if safety_signature_id is not None:
            attrs.append(f'SafetySignatureID="{safety_signature_id}"')
    attrs.append(f'EditedDate="{esc(aoi.edited_date)}"')
    attrs.append(f'SoftwareRevision="{esc(aoi.software_revision)}"')
    attrs.append(f'EncryptionConfig="{config}"')
    # A safety-signed AOI carries its GSS SafetySignature (8 hex words) and the
    # safety-task sign timestamp after EncryptionConfig. Recovered from the AOI's
    # own comps triple; absent (None) on a standard AOI.
    if safety_signature is not None:
        attrs.append(f'SafetySignature="{esc(safety_signature)}"')
        if safety_signature_timestamp:
            attrs.append(
                f'SafetySignatureTimestamp="{esc(safety_signature_timestamp)}"')

    kids = aoi._custom_properties or ""
    if aoi._description:
        kids += f'<Description>\n<![CDATA[{aoi._description}]]>\n</Description>'
    if aoi._revision_note:
        kids += f'<RevisionNote>\n<![CDATA[{aoi._revision_note}]]>\n</RevisionNote>'
    if aoi._additional_help_text:
        kids += (f'<AdditionalHelpText>\n<![CDATA['
                 f'{aoi._additional_help_text}]]>\n</AdditionalHelpText>')
    params = "".join(p.to_xml() for p in aoi.parameters
                     if not getattr(p, "_l5x_exclude", False))
    kids += f'<Parameters>{params}</Parameters>'
    return f'<EncodedData {" ".join(attrs)}>\n{kids}</EncodedData>'
