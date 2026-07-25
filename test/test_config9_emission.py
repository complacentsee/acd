"""Config-9 (V31+) faithful-emission wiring: the AOI EncodedData surface.

Synthetic and self-contained (repo AES, no customer data, no new secret -- the
key-encryption key is the shipped config-8 entry). Exercises the three wire-in
points the faithful AOI <EncodedData> parity needs:

  * encoded_data.source_protection_config -> 9 on the config-9 encrypted-tail marker
  * comps.decrypt_sp_nameless             -> AOI metadata recovered (rec[:midx]+pt)
  * elements._sp_list_candidates          -> AOI parameter-order list recovered

Config-9 nameless records RETAIN the ffffffff sentinel at marker-4 (the legacy
configs-1..8 framing overwrites it), so the reconstruction is rec[:midx] + pt.
"""
import struct

import pytest

from acd.record._aes import AES
from acd.record import source_protection as sp
from acd.record import config9
from acd.record.comps import decrypt_sp_nameless
from acd.l5x.encoded_data import source_protection_config, encoded_aoi
from acd.l5x.elements import _sp_list_candidates, _decode_oid_list


CFG8_KEY = sp._SP_KEY_BY_CONFIG[8]
GK = [bytes(range(i, i + 32)) for i in (0, 40, 90)]


def _cbc_encrypt_iv_pkcs7(pt, aes, iv):
    pad = 16 - (len(pt) % 16)
    pt = pt + bytes([pad]) * pad
    out = bytearray()
    prev = iv
    for i in range(0, len(pt), 16):
        prev = aes.encrypt_block(bytes(x ^ y for x, y in zip(pt[i:i + 16], prev)))
        out += prev
    return bytes(out)


def _wrap_slot(group_key, wrap_iv):
    return wrap_iv + _cbc_encrypt_iv_pkcs7(group_key, AES(CFG8_KEY), wrap_iv)


def _keytable(keys):
    rec = bytearray(b"\x11" * 89)
    for i, k in enumerate(keys):
        rec += _wrap_slot(k, bytes([(i + 1) & 0xFF]) * 16)
        rec += b"\xAB" * (config9._WRAP_STRIDE - 64)
    return bytes(rec)


def _comps_cfg9(group_key, plaintext, content_iv, disc=1):
    """A config-9 comps-style record: marker at body+78 (the source_protection_config
    call site), declared len at marker+12, disc at marker+16, ct at marker+40."""
    ct = _cbc_encrypt_iv_pkcs7(plaintext, AES(group_key), content_iv)
    m = 78
    rec = bytearray(m + 40 + len(ct))
    rec[m:m + 4] = sp._SP_MARKER
    struct.pack_into("<H", rec, m + 12, len(plaintext))
    struct.pack_into("<H", rec, m + 16, disc)
    struct.pack_into("<I", rec, m + 20, len(ct))
    rec[m + 24:m + 40] = content_iv
    rec[m + 40:m + 40 + len(ct)] = ct
    return bytes(rec)


def _nameless_cfg9(group_key, plaintext, midx, content_iv):
    """A config-9 nameless record: retained ffffffff at midx-4, marker at midx."""
    ct = _cbc_encrypt_iv_pkcs7(plaintext, AES(group_key), content_iv)
    rec = bytearray(midx + 40 + len(ct))
    rec[midx - 4:midx] = b"\xff\xff\xff\xff"
    rec[midx:midx + 4] = sp._SP_MARKER
    struct.pack_into("<H", rec, midx + 12, len(plaintext))
    struct.pack_into("<H", rec, midx + 16, 1)
    struct.pack_into("<I", rec, midx + 20, len(ct))
    rec[midx + 24:midx + 40] = content_iv
    rec[midx + 40:midx + 40 + len(ct)] = ct
    return bytes(rec)


@pytest.fixture
def keytable():
    keys = config9.unwrap_keytable(_keytable(GK))
    config9.set_project_keytable(keys)
    try:
        yield keys
    finally:
        config9.set_project_keytable([])


# --- source_protection_config ------------------------------------------------
def test_source_protection_config_returns_9_for_config9():
    rec = _comps_cfg9(GK[0], b"encrypted interface tail body" * 2, bytes(16))
    assert config9.is_config9(rec, 78)
    assert source_protection_config(rec, None, 272) == 9


def test_source_protection_config_version_keyed():
    # The wrapped-key at-rest framing is identical across releases; the export
    # EncryptionConfig follows the version -- 8 at V28/29, 9 at V30+.
    rec = _comps_cfg9(GK[0], b"encrypted interface tail body" * 2, bytes(16))
    assert source_protection_config(rec, None, 272, 29) == 8
    assert source_protection_config(rec, None, 272, 28) == 8
    assert source_protection_config(rec, None, 272, 30) == 9
    assert source_protection_config(rec, None, 272, 36) == 9
    # Major unknown -> assume the newer 9 (back-compat with the 3-arg callers).
    assert source_protection_config(rec, None, 272) == 9


def test_source_protection_config_none_for_other_encrypted_tail():
    # An encrypted-tail marker that is NOT config-9 (disc != 1) stays withheld.
    rec = _comps_cfg9(GK[0], b"legacy encrypted tail body here" * 2, bytes(16), disc=0)
    assert not config9.is_config9(rec, 78)
    assert source_protection_config(rec, None, 272) is None


# --- decrypt_sp_nameless (AOI metadata) --------------------------------------
def test_decrypt_sp_nameless_config9_metadata(keytable):
    # Metadata body head: u16 ver=1 then an empty fffeff string.
    body = b"\x01\x00\xff\xfe\xff\x00" + b"AOI metadata trailing bytes here" * 2
    rec = _nameless_cfg9(GK[1], body, 24, bytes([5]) * 16)
    out = decrypt_sp_nameless(rec)
    assert out == rec[:24] + body


def test_decrypt_sp_nameless_config9_fail_closed_without_keytable():
    body = b"\x01\x00\xff\xfe\xff\x00" + b"no key-table loaded" * 2
    rec = _nameless_cfg9(GK[1], body, 24, bytes([5]) * 16)
    config9.set_project_keytable([])
    assert decrypt_sp_nameless(rec) is None


# --- _sp_list_candidates (AOI parameter order) -------------------------------
def test_sp_list_candidates_config9_recovers_oid_list(keytable):
    oids = [0x11223344, 0x55667788, 0x0A0B0C0D, 0x99887766]
    body = struct.pack("<H", len(oids)) + b"".join(
        struct.pack("<I", o) for o in oids)
    rec = _nameless_cfg9(GK[2], body, 24, bytes([2]) * 16)
    cands = list(_sp_list_candidates(rec))
    assert rec[:24] + body in cands
    # The reconstruction decodes back to the authored oid order.
    decoded = next((_decode_oid_list(c) for c in cands if _decode_oid_list(c)), None)
    assert decoded == oids


def test_sp_list_candidates_passthrough_when_unprotected():
    rec = b"\x00" * 40  # no marker -> yielded unchanged
    assert list(_sp_list_candidates(rec)) == [rec]


# --- encoded_aoi safety-signature emission ------------------------------------
class _Param:
    _l5x_exclude = False

    def to_xml(self):
        return "<Parameter/>"


class _FakeAoi:
    name = "SynthSafetyAoi"
    cls = "Safety"
    revision = "2.1"
    revision_extension = None
    vendor = None
    edited_date = "2024-12-06T15:51:41.572Z"
    software_revision = "v36.00"
    parameters = [_Param()]
    _custom_properties = ""
    _description = None
    _revision_note = None
    _additional_help_text = None


_SIG = " - ".join(["DEADBEEF"] * 8)
_TS = "01/02/2020, 12:00:00.000 PM"


def test_encoded_aoi_emits_safety_signature():
    xml = encoded_aoi(_FakeAoi(), 9, None, None, _SIG, _TS)
    assert f'EncryptionConfig="9" SafetySignature="{_SIG}"' in xml
    assert f'SafetySignatureTimestamp="{_TS}"' in xml
    # SafetySignature follows EncryptionConfig (OEM attribute order).
    assert xml.index("EncryptionConfig") < xml.index("SafetySignature")


def test_encoded_aoi_omits_safety_signature_when_absent():
    xml = encoded_aoi(_FakeAoi(), 9, None, None)
    assert "SafetySignature" not in xml


def test_encoded_aoi_safety_timestamp_optional():
    xml = encoded_aoi(_FakeAoi(), 9, None, None, _SIG, None)
    assert f'SafetySignature="{_SIG}"' in xml
    assert "SafetySignatureTimestamp" not in xml
