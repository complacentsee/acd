"""Self-contained tests for EncryptionConfig 9 (wrapped-key) decryption.

No customer data and no new secret: the config-9 key-encryption key is the
existing config-8 entry in ``_SP_KEY_BY_CONFIG``.  These tests build a synthetic
key-table and protected record with the repo AES primitive, exercising the
two-level unwrap, the trial-key selection, and the fail-closed refusals.  The
whole-corpus validation against a real V31+ project is run out of tree; here the
codec is pinned structurally.
"""
import struct

import pytest

from acd.record._aes import AES
from acd.record import source_protection as sp
from acd.record import config9


CFG8_KEY = sp._SP_KEY_BY_CONFIG[8]


@pytest.fixture(autouse=True)
def _reset_key_hint():
    """Isolate the module-level group-key hint + element-recovery flag between tests."""
    config9._KEY_HINT[0] = None
    sp.set_element_recovery(False)
    yield
    config9._KEY_HINT[0] = None
    sp.set_element_recovery(False)
    config9.set_project_keytable([])


def _cbc_encrypt_iv_pkcs7(pt: bytes, aes: AES, iv: bytes) -> bytes:
    pad = 16 - (len(pt) % 16)
    pt = pt + bytes([pad]) * pad
    out = bytearray()
    prev = iv
    for i in range(0, len(pt), 16):
        blk = bytes(x ^ y for x, y in zip(pt[i:i + 16], prev))
        prev = aes.encrypt_block(blk)
        out += prev
    return bytes(out)


def _wrap_slot(group_key: bytes, wrap_iv: bytes) -> bytes:
    # [16-byte IV][48-byte ct]; ct = CBC(cfg8, wrap_iv, key) -> key + 0x10*16 pad.
    return wrap_iv + _cbc_encrypt_iv_pkcs7(group_key, AES(CFG8_KEY), wrap_iv)


def _build_keytable(keys):
    # 89-byte header (matches the observed layout) then 64-byte slots on a
    # 127-byte stride with filler in the gaps.
    rec = bytearray(b"\x11" * 89)
    for i, k in enumerate(keys):
        iv = bytes([(i + 1) & 0xFF]) * 16
        slot = _wrap_slot(k, iv)
        assert len(slot) == 64
        rec += slot + b"\xAB" * (config9._WRAP_STRIDE - 64)
    return bytes(rec)


def _build_record(group_key, plaintext, content_iv, disc=1, ct_override=None,
                  declared_override=None):
    ct = ct_override
    if ct is None:
        ct = _cbc_encrypt_iv_pkcs7(plaintext, AES(group_key), content_iv)
    m = 78
    rec = bytearray(m + 40 + len(ct))
    rec[m:m + 4] = sp._SP_MARKER
    struct.pack_into(
        "<H", rec, m + 12,
        len(plaintext) if declared_override is None else declared_override)
    struct.pack_into("<H", rec, m + 16, disc)
    struct.pack_into("<I", rec, m + 20, len(ct))
    rec[m + 24:m + 40] = content_iv
    rec[m + 40:m + 40 + len(ct)] = ct
    return bytes(rec)


GK = [bytes(range(i, i + 32)) for i in (0, 40, 90)]


def test_unwrap_keytable_recovers_all_keys():
    keys = config9.unwrap_keytable(_build_keytable(GK))
    assert keys == GK


def test_find_keytable_picks_richest_record():
    noise = b"\x00" * 300
    keys = config9.find_keytable([noise, _build_keytable(GK), b"\x01" * 64])
    assert keys == GK


def test_decrypt_roundtrip():
    pt = b"the quick brown fox jumps over the lazy source protection" * 3
    iv = bytes(range(16))
    rec = _build_record(GK[1], pt, iv)
    keys = config9.unwrap_keytable(_build_keytable(GK))
    assert config9.is_config9(rec, 78)
    assert config9.decrypt(rec, 78, keys) == pt


def test_decrypt_selects_correct_key_among_many():
    pt = b"exactly one of these keys fits" * 2
    iv = bytes([7]) * 16
    rec = _build_record(GK[2], pt, iv)
    keys = config9.unwrap_keytable(_build_keytable(GK))
    assert config9.decrypt(rec, 78, keys) == pt  # GK[2], not GK[0]/GK[1]


def test_reject_non_config9_discriminator():
    pt = b"not protected framing"
    rec = _build_record(GK[0], pt, bytes(16), disc=0)
    assert not config9.is_config9(rec, 78)
    assert config9.decrypt(rec, 78, config9.unwrap_keytable(_build_keytable(GK))) is None


def test_reject_when_no_key_fits():
    pt = b"key not in table"
    rec = _build_record(bytes(range(200, 232)), pt, bytes(16))  # key absent
    assert config9.decrypt(rec, 78, config9.unwrap_keytable(_build_keytable(GK))) is None


def test_reject_declared_length_mismatch():
    pt = b"length lies here" * 2
    rec = _build_record(GK[0], pt, bytes(16), declared_override=len(pt) + 1)
    assert config9.decrypt(rec, 78, config9.unwrap_keytable(_build_keytable(GK))) is None


def test_reject_truncated_ciphertext():
    pt = b"truncated tail" * 4
    iv = bytes(16)
    ct = _cbc_encrypt_iv_pkcs7(pt, AES(GK[0]), iv)
    rec = bytearray(_build_record(GK[0], pt, iv, ct_override=ct))
    rec = bytes(rec[:-16])  # drop a ciphertext block; declared ctlen no longer present
    assert config9.decrypt(rec, 78, config9.unwrap_keytable(_build_keytable(GK))) is None


def test_reject_bad_ciphertext_length_field():
    pt = b"aligned"
    iv = bytes(16)
    ct = _cbc_encrypt_iv_pkcs7(pt, AES(GK[0]), iv)
    m = 78
    rec = bytearray(m + 40 + len(ct))
    rec[m:m + 4] = sp._SP_MARKER
    struct.pack_into("<H", rec, m + 16, 1)
    struct.pack_into("<I", rec, m + 20, 15)  # not a multiple of 16
    rec[m + 40:m + 40 + len(ct)] = ct
    assert config9.decrypt(bytes(rec), 78,
                           config9.unwrap_keytable(_build_keytable(GK))) is None


def test_framed_reads_declared_iv_ct():
    pt = b"framed body content" * 2
    iv = bytes(range(100, 116))
    rec = _build_record(GK[0], pt, iv)
    declared, got_iv, ct = config9._framed(rec, 78)
    assert declared == len(pt)
    assert got_iv == iv
    assert len(ct) % 16 == 0 and len(ct) >= len(pt)
    assert config9._framed(rec, 0) is None  # no marker there -> not config-9


def test_decrypt_candidates_yields_matching_key():
    pt = b"candidate plaintext body that is comfortably long" * 2
    rec = _build_record(GK[1], pt, bytes([9]) * 16)
    keys = config9.unwrap_keytable(_build_keytable(GK))
    assert list(config9.decrypt_candidates(rec, 78, keys)) == [pt]


def test_decrypt_candidates_head_ok_prefilter():
    # A body whose first block starts 01 00 ff fe ff (the AOI-metadata signature).
    pt = b"\x01\x00\xff\xfe\xff\x00" + b"metadata-ish tail bytes for length" * 2
    rec = _build_record(GK[2], pt, bytes([3]) * 16)
    keys = config9.unwrap_keytable(_build_keytable(GK))

    def head_ok(b, declared):
        return b[0:2] == b"\x01\x00" and b[2:5] == b"\xff\xfe\xff"

    assert list(config9.decrypt_candidates(rec, 78, keys, head_ok=head_ok)) == [pt]

    def head_never(b, declared):
        return False

    assert list(config9.decrypt_candidates(rec, 78, keys, head_ok=head_never)) == []


def test_decrypt_candidates_empty_keytable():
    rec = _build_record(GK[0], b"body" * 8, bytes(16))
    assert list(config9.decrypt_candidates(rec, 78, [])) == []


# --- sp_decrypt_nameless_element config-9 graphical-element recovery ----------
def _build_element(group_key, plaintext, content_iv, disc=1):
    """A config-9 graphical element record: marker at 78 with the 'Ui U' scaffold
    at +9 and the ffffffff sentinel RETAINED at marker-4."""
    ct = _cbc_encrypt_iv_pkcs7(plaintext, AES(group_key), content_iv)
    m = 78
    rec = bytearray(m + 40 + len(ct))
    rec[m - 4:m] = b"\xff\xff\xff\xff"
    rec[m:m + 4] = sp._SP_MARKER
    rec[m + 9:m + 12] = sp._ELEM_SCAFFOLD
    struct.pack_into("<H", rec, m + 12, len(plaintext))
    struct.pack_into("<H", rec, m + 16, disc)
    struct.pack_into("<I", rec, m + 20, len(ct))
    rec[m + 24:m + 40] = content_iv
    rec[m + 40:m + 40 + len(ct)] = ct
    return bytes(rec)


def test_sp_element_config9_recovered_when_enabled():
    config9.set_project_keytable([GK[1]])
    sp.set_element_recovery(True)
    body = b"graphical element body content" * 2
    rec = _build_element(GK[1], body, bytes(range(16)))
    # reconstruction re-appends only the plaintext (sentinel retained at midx-4).
    assert sp.sp_decrypt_nameless_element(rec) == rec[:78] + body


def test_sp_element_config9_untouched_in_faithful_mode():
    # Recovery flag off (faithful): the config-9 element stays encrypted, so the
    # faithful/gauntlet path is byte-identical to before element recovery existed.
    config9.set_project_keytable([GK[1]])
    sp.set_element_recovery(False)
    rec = _build_element(GK[1], b"body" * 8, bytes(range(16)))
    assert sp.sp_decrypt_nameless_element(rec) == rec


def test_sp_element_config9_fail_closed_without_key():
    # Recovery on but the group key absent -> stays encrypted (never a wrong block).
    config9.set_project_keytable([GK[0]])
    sp.set_element_recovery(True)
    rec = _build_element(GK[1], b"body" * 8, bytes(range(16)))
    assert sp.sp_decrypt_nameless_element(rec) == rec
