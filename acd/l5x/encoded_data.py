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
import html
from typing import Optional, Tuple

from acd.record._aes import AES
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


def source_key_unwraps(a1: Optional[bytes], keyhash_off: int) -> bool:
    """True iff the descriptor's wrapped-key slot decrypts to a well-formed key.

    Fail-closed: a slot that is absent, is not the wrapped-key form, holds no
    key we can decrypt, or unwraps to a structurally invalid plaintext all
    return False. The structural check is pure internal self-consistency -- a
    2-byte item tag repeated at fixed positions and at the plaintext's end -- so
    nothing here is keyed by catalog, type, plant or file.
    """
    end = keyhash_off + 2 + _WRAPPED_KEY_LEN
    if a1 is None or len(a1) < end:
        return False
    if a1[keyhash_off:keyhash_off + 2] != _WRAPPED_KEY_VERSION:
        return False
    aes = _aes(_WRAPPED_KEY_CONFIG)
    if aes is None:
        return False
    ct = a1[keyhash_off + 2:end]
    out = bytearray()
    prev = b"\x00" * 16
    for i in range(0, len(ct), 16):
        blk = ct[i:i + 16]
        out += bytes(x ^ y for x, y in zip(aes.decrypt_block(blk), prev))
        prev = blk
    pt = _pkcs7_unpad(bytes(out))
    if pt is None or len(pt) < 38:
        return False
    tag = pt[0:2]
    return pt[18:20] == tag and pt[36:38] == tag and pt[-2:] == tag


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


def security_descriptor(a1: Optional[bytes], keyhash_off: int) -> Optional[Tuple[str, str]]:
    """(EncodedSourceKey, SourceProtectionType) from ext-attr 0x1, or None.

    None means the descriptor is absent, truncated, from another source-protection
    scheme, or a form we do not decode -- every caller must then withhold the whole
    blob. ``keyhash_off`` is the family's protection-key hash offset (the same one
    the source-protection detector uses).
    """
    if a1 is None or len(a1) < keyhash_off + _SD_TOTAL or keyhash_off + _SD_LEN_OFF < 0:
        return None
    declared = int.from_bytes(a1[keyhash_off + _SD_LEN_OFF:keyhash_off], "little")
    if declared not in _SCHEME_LENGTHS:
        return None       # another scheme: its key is a different length
    slot = a1[keyhash_off:keyhash_off + _SD_SLOT_LEN]
    # Our scheme zero-pads its key out to the slot; the newer form fills the slot
    # and keeps its real key elsewhere, so reading one would emit a wrong key.
    if not keyhash_slot_readable(a1, keyhash_off):
        return None
    flags = int.from_bytes(
        a1[keyhash_off + _SD_SLOT_LEN:keyhash_off + _SD_TOTAL], "little")
    esk = base64.b64encode(slot[:_SCHEME_KEY_LEN]).decode("ascii").rstrip("=")
    spt = _SPT_VIEWABLE if flags & _SPT_VIEWABLE_BIT else _SPT_FULL
    return esk, spt


def source_protection_config(rec: bytes, a1: Optional[bytes],
                             keyhash_off: int) -> Optional[int]:
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
    else:
        # FBD/SFC and the relic TypeLess routines have no serializer here.
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


def encoded_routine(routine, a1: Optional[bytes], keyhash_off: int,
                    config: Optional[int]) -> Optional[str]:
    """The <EncodedData> element for a source-protected routine, or None.

    None means some input did not resolve and the caller must emit nothing --
    never a partial or guessed blob.
    """
    if config is None:
        return None
    desc = security_descriptor(a1, keyhash_off)
    if desc is None:
        return None
    esk, spt = desc
    document = _inner_document(routine, esk, spt)
    if document is None:
        return None
    body = _encrypt_b64(document.encode("utf-16-le"), config)
    if body is None:
        return None
    return (
        f'<EncodedData EncodedType="Routine"'
        f' Name="{html.escape(routine.name, quote=True)}"'
        f' Type="{routine.type}"'
        f' EncryptionConfig="{config}">\n'
        f"{_description_block(routine)}{body}</EncodedData>"
    )
