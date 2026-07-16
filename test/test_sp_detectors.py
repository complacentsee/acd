"""Unit tests for the structural source-protection detectors
(_aoi_is_source_protected / _routine_is_source_protected in acd.l5x.elements).

These decide whether a recovered AOI/routine definition must be suppressed in
faithful mode (Studio emits it as <EncodedData>). P6.7a(1) re-keyed them off
STRUCTURE -- the marker+14 flag (encrypted-tail layout) and the protection-key
hash inside ext-attr 0x1 (plaintext key-bearing layout) -- instead of buffer
length, so the verdict survives the P6.7a size-eos un-truncation (which only
appends bytes past the record tail). These fixtures pin each structural branch
and the truncation-independence; the pool-wide 0-FP/0-FN equivalence to the old
length-keyed detectors is proven separately by differential execution.
"""

import struct

from acd.l5x import elements as E
from acd.l5x.elements import (
    _aoi_is_source_protected,
    _routine_is_source_protected,
    _AOI_NO_PROTECTION_HASH,
    _SP_MARKER,
)
from acd.l5x.encoded_data import (
    source_key_unwraps,
    _aes,
    _WRAPPED_KEY_CONFIG,
    _WRAPPED_KEY_LEN,
    _WRAPPED_KEY_VERSION,
)

AOI_OFF = 272   # _AOI_KEYHASH_OFF
RT_OFF = 202    # _RT_KEYHASH_OFF
SENT = _AOI_NO_PROTECTION_HASH
REAL = bytes.fromhex("dee93b79cec617a15d306f6e165f1abc")   # a real per-license hash


def _keybearing_body(keyhash_off, key_hash, a1_extra=32, lead_attrs=()):
    """A plaintext no-marker body whose ext-attr 0x1 carries a 16-byte hash at
    ``keyhash_off``. Attr 0x1 is sized to reach the hash plus a little tail.

    ``lead_attrs`` is an optional sequence of (attr_id, value) records emitted
    BEFORE attr 0x1, so attr 0x1 does not start at the fixed body offset 90 --
    this is what forces the detector to WALK the attr table rather than read a
    fixed record offset."""
    a1 = bytearray(keyhash_off + 16 + a1_extra)
    a1[keyhash_off:keyhash_off + 16] = key_hash
    tail = b"".join(struct.pack("<II", aid, len(v)) + v for aid, v in lead_attrs)
    tail += struct.pack("<II", 1, len(a1)) + bytes(a1)
    return b"\x00" * 74 + struct.pack("<II", len(tail), 1 + len(lead_attrs)) + tail


def _short_body(a1_len):
    """A no-marker body whose attr 0x1 is too short to carry any hash field."""
    a1 = b"\x00" * a1_len
    tail = struct.pack("<II", 1, len(a1)) + a1
    return b"\x00" * 74 + struct.pack("<II", len(tail), 1) + tail


def _marker_body(flag6):
    """An encrypted-tail body: _SP_MARKER at body+78, ``flag6`` at marker+14."""
    b = bytearray(120)
    b[78:82] = _SP_MARKER
    b[92:98] = flag6            # 78 + 14
    return bytes(b)


PROTECTED_FLAG = bytes.fromhex("000001001000")
PLAINTEXT_FLAG = bytes.fromhex("000000075d03")   # 00 00 00 07 .. (Studio re-decrypts)


# --------------------------------------------------------------------------- #
# Encrypted-tail (marker) layout
# --------------------------------------------------------------------------- #
def test_marker_protected_flag():
    assert _aoi_is_source_protected(_marker_body(PROTECTED_FLAG)) is True
    assert _routine_is_source_protected(_marker_body(PROTECTED_FLAG)) is True


def test_marker_plaintext_at_rest_kept():
    # 00 00 00 07 .. -> Studio re-decrypts and exports plaintext; never suppress.
    assert _aoi_is_source_protected(_marker_body(PLAINTEXT_FLAG)) is False
    assert _routine_is_source_protected(_marker_body(PLAINTEXT_FLAG)) is False


def test_marker_is_anchored_at_78_not_searched():
    # A stray marker elsewhere must NOT be treated as the SP-at-rest framing:
    # a genuinely protected key-bearing record with the marker bytes appearing
    # deep in its (plaintext) body stays classified via the hash branch.
    body = bytearray(_keybearing_body(AOI_OFF, REAL))
    body += _SP_MARKER + b"\x00" * 40      # stray marker far past offset 78
    assert _aoi_is_source_protected(bytes(body)) is True


# --------------------------------------------------------------------------- #
# Plaintext key-bearing layout
# --------------------------------------------------------------------------- #
def test_keybearing_real_hash_protected():
    assert _aoi_is_source_protected(_keybearing_body(AOI_OFF, REAL)) is True
    assert _routine_is_source_protected(_keybearing_body(RT_OFF, REAL)) is True


def test_keybearing_sentinel_unprotected():
    assert _aoi_is_source_protected(_keybearing_body(AOI_OFF, SENT)) is False
    assert _routine_is_source_protected(_keybearing_body(RT_OFF, SENT)) is False


def test_keybearing_zero_hash_unprotected():
    # A non-SP layout (e.g. the 429-byte routine) leaves the block all-zero.
    assert _aoi_is_source_protected(_keybearing_body(AOI_OFF, b"\x00" * 16)) is False
    assert _routine_is_source_protected(_keybearing_body(RT_OFF, b"\x00" * 16)) is False


def test_short_attr01_unprotected():
    # attr 0x1 too short to reach the hash field -> not source-protectable.
    assert _aoi_is_source_protected(_short_body(AOI_OFF)) is False       # 272 < 288
    assert _routine_is_source_protected(_short_body(RT_OFF)) is False    # 202 < 218


def test_no_attr01_unprotected():
    body = b"\x00" * 74 + struct.pack("<II", 0, 0)   # empty attr table
    assert _aoi_is_source_protected(body) is False
    assert _routine_is_source_protected(body) is False


def test_hash_located_by_walk_not_fixed_offset():
    # attr 0x1 preceded by a leading attr shifts its value off the fixed body
    # offset 90; a fixed-offset reader would look 24 bytes too early and misread
    # the hash. Both detectors must still find it via the attr-table walk.
    lead = ((0x65, b"\xaa" * 16),)   # 8B header + 16B value shifts attr 0x1 +24
    assert _aoi_is_source_protected(
        _keybearing_body(AOI_OFF, REAL, lead_attrs=lead)) is True
    assert _aoi_is_source_protected(
        _keybearing_body(AOI_OFF, SENT, lead_attrs=lead)) is False
    assert _routine_is_source_protected(
        _keybearing_body(RT_OFF, REAL, lead_attrs=lead)) is True
    assert _routine_is_source_protected(
        _keybearing_body(RT_OFF, SENT, lead_attrs=lead)) is False


def test_no_attr01_stays_unprotected_under_appended_tail():
    # A no-marker body whose real attr table has NO attr 0x1 must stay
    # unprotected even after the size-eos un-truncation appends bytes -- as long
    # as the appended bytes do not themselves frame a fake (id=1, len) attr, the
    # walk over real pool records never forges one (verified pool-wide on the
    # full comps_full body).
    real_attrs = struct.pack("<II", 0x65, 4) + b"\x01\x02\x03\x04"
    body = b"\x00" * 74 + struct.pack("<II", len(real_attrs), 1) + real_attrs
    assert _aoi_is_source_protected(body) is False
    assert _routine_is_source_protected(body) is False
    appended = body + b"\x99" * 400        # sub-blob bytes exposed by the flip
    assert _aoi_is_source_protected(appended) is False
    assert _routine_is_source_protected(appended) is False


def test_wrong_family_offset_does_not_leak():
    # A routine-layout hash (rel 202) must not read as protected under the AOI
    # offset (272) unless attr 0x1 is long enough AND non-sentinel there.
    rt_rec = _keybearing_body(RT_OFF, REAL)         # protected routine
    assert _routine_is_source_protected(rt_rec) is True
    # Same bytes fed to the AOI detector: attr 0x1 here is 202+16+32 = 250 < 288.
    assert _aoi_is_source_protected(rt_rec) is False


# --------------------------------------------------------------------------- #
# Truncation independence (the P6.7a invariant)
# --------------------------------------------------------------------------- #
def test_verdict_survives_appended_tail():
    for off, fn in ((AOI_OFF, _aoi_is_source_protected), (RT_OFF, _routine_is_source_protected)):
        for key_hash, want in ((REAL, True), (SENT, False), (b"\x00" * 16, False)):
            trunc = _keybearing_body(off, key_hash)
            appended = trunc + b"\xab" * 200          # size-eos un-truncation
            assert fn(trunc) is want
            assert fn(appended) is want               # same verdict either way


def test_ext_attr01_walk():
    a1 = b"\x11" * 40
    body = b"\x00" * 74 + struct.pack("<II", 0, 0) + struct.pack("<II", 1, len(a1)) + a1
    assert E._ext_attr01(body) == a1
    assert E._ext_attr01(b"\x00" * 74) is None


# --------------------------------------------------------------------------- #
# Filled-slot (wrapped-key) layout
# --------------------------------------------------------------------------- #
def _wrapped_slot_ct(tag=b"\xab\xcd"):
    """A config-5 wrapped-key ciphertext whose plaintext passes the structural
    self-check: a 2-byte tag repeated at 0/18/36 and at the plaintext's end."""
    pt = bytearray(58)
    pt[0:2] = tag
    pt[18:20] = tag
    pt[36:38] = tag
    pt[56:58] = tag
    pad = _WRAPPED_KEY_LEN - len(pt)
    buf = bytes(pt) + bytes([pad]) * pad
    aes = _aes(_WRAPPED_KEY_CONFIG)
    out = bytearray()
    prev = b"\x00" * 16
    for i in range(0, len(buf), 16):
        prev = aes.encrypt_block(bytes(x ^ y for x, y in zip(buf[i:i + 16], prev)))
        out += prev
    return bytes(out)


def _filled_body(keyhash_off, slot_ct):
    """A no-marker body whose ext-attr 0x1 is the filled (wrapped-key) form:
    the version word 0x0005 then the 64-byte wrapped key at ``keyhash_off``."""
    a1 = bytearray(keyhash_off + 2 + _WRAPPED_KEY_LEN + 4)
    a1[keyhash_off:keyhash_off + 2] = _WRAPPED_KEY_VERSION
    a1[keyhash_off + 2:keyhash_off + 2 + _WRAPPED_KEY_LEN] = slot_ct
    tail = struct.pack("<II", 1, len(a1)) + bytes(a1)
    return b"\x00" * 74 + struct.pack("<II", len(tail), 1) + tail


def test_wrapped_key_unwraps_is_protected():
    ct = _wrapped_slot_ct()
    assert _routine_is_source_protected(_filled_body(RT_OFF, ct)) is True
    assert _aoi_is_source_protected(_filled_body(AOI_OFF, ct)) is True


def test_wrapped_key_that_does_not_unwrap_is_plaintext():
    # The filled slot of a definition Studio ships as plaintext: same form, but
    # its bytes are not a wrapped key we can unwrap (here a one-bit corruption of
    # a valid one), so the definition is NOT suppressed.
    ct = bytearray(_wrapped_slot_ct())
    ct[-1] ^= 1
    assert _routine_is_source_protected(_filled_body(RT_OFF, bytes(ct))) is False
    assert _aoi_is_source_protected(_filled_body(AOI_OFF, bytes(ct))) is False


def test_wrapped_key_structural_check_rejects_wrong_tag():
    # Unwraps cleanly (valid PKCS7) but the repeated-tag self-check fails.
    aes = _aes(_WRAPPED_KEY_CONFIG)
    pt = bytes(58)                      # all-zero tags at 0/18/36 but not at end
    buf = bytearray(pt) + bytes([6]) * 6
    buf[56:58] = b"\x01\x02"            # break the trailing-tag equality
    out = bytearray()
    prev = b"\x00" * 16
    for i in range(0, len(buf), 16):
        prev = aes.encrypt_block(bytes(x ^ y for x, y in zip(buf[i:i + 16], prev)))
        out += prev
    assert source_key_unwraps(_ext01(_filled_body(RT_OFF, bytes(out))), RT_OFF) is False


def _ext01(body):
    return E._ext_attr01(body)


def test_source_key_unwraps_fail_closed():
    assert source_key_unwraps(None, RT_OFF) is False
    assert source_key_unwraps(b"\x00" * 10, RT_OFF) is False          # too short
    # right length, wrong version word -> not the wrapped-key form
    a1 = bytearray(RT_OFF + 2 + _WRAPPED_KEY_LEN)
    a1[RT_OFF:RT_OFF + 2] = b"\x4d\x53"
    assert source_key_unwraps(bytes(a1), RT_OFF) is False
