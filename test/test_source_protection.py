"""Tests for source-protected 'Rung NT' rung READ support.

The headline validation against the v21_gm_FuncGen corpus (94 rungs) is run by
``scripts/validate_source_protection.py``.  Its ACD/L5X fixtures are embedded in
``resources/`` so ``test_v21_gm_corpus_read`` exercises the real fork read path
end-to-end here.  The remaining unit tests are self-contained: they pin the AES
primitive (FIPS-197 KAT), the SP key table, the cipher mode (zero-IV CBC), the
framing model, and -- crucially -- the fail-closed refusals, so the codec is
covered even without the corpus.
"""
import os
import struct
import sys

from acd.record._aes import AES
from acd.record import source_protection as sp

# scripts/ is not a package; add it to the path to reuse the validation driver.
sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
)
import validate_source_protection as spval  # noqa: E402


# --- test-only rung builder --------------------------------------------------
# The READ path never builds buffers, so the encryptor lives here rather than in
# the module. Mirrors the documented wire format exactly.
def _cbc_encrypt_pkcs7(pt: bytes, aes: AES) -> bytes:
    pad = 16 - (len(pt) % 16)
    pt = pt + bytes([pad]) * pad
    out = bytearray()
    prev = b"\x00" * 16
    for i in range(0, len(pt), 16):
        blk = bytes(x ^ y for x, y in zip(pt[i:i + 16], prev))
        prev = aes.encrypt_block(blk)
        out += prev
    return bytes(out)


def _build_rung(text: str, config: int = 7, trailer: bytes = b"") -> bytes:
    """Assemble a protected rung buffer (rbuf) carrying ``text``.

    ``trailer`` appends slot filler past the ciphertext, which the reader must
    ignore.
    """
    pt = b"\x00" + text[1:].encode("utf-16-le") + b"\x00\x00"
    key = dict(sp._SP_KEYS)[config]
    ct = _cbc_encrypt_pkcs7(pt, AES(key))
    rbuf = bytearray(19)
    rbuf[0] = ord(text[0])
    rbuf[1:5] = sp._SP_MARKER
    rbuf[8] = 0xA0
    rbuf[10:13] = b"\x55\x69\x55"
    struct.pack_into("<I", rbuf, 13, len(pt))   # marker+12: plaintext length
    rbuf[17] = 0x00                             # legacy framing discriminator
    rbuf[18] = config                           # marker+17: EncryptionConfig
    return bytes(rbuf) + ct + trailer


# --- test-only graphical-element builder -------------------------------------
# The READ path never builds buffers; this mirrors the config-on-the-wire framing
# a source-protected FBD/SFC nameless element record carries (marker just past the
# plaintext kind word @16, u32 plaintext length @marker+12, config @marker+17).
def _build_element(body: bytes, kind: int = 0x0e, config: int = 7) -> bytes:
    key = dict(sp._SP_KEYS)[config]
    ct = _cbc_encrypt_pkcs7(body, AES(key))
    header = bytearray(range(20))            # arbitrary 20-byte record header
    struct.pack_into("<H", header, 16, kind)  # kind word stays plaintext
    frame = bytearray(18)                    # marker .. ciphertext start
    frame[0:4] = sp._SP_MARKER
    frame[6:8] = b"\x00\xa0"                 # cosmetic framing bytes
    frame[9:12] = b"\x55\x69\x55"            # 'Ui U' scaffold at marker+9
    struct.pack_into("<I", frame, 12, len(body))  # marker+12: plaintext length
    frame[16] = 0x00                         # legacy framing discriminator
    frame[17] = config                       # marker+17: EncryptionConfig
    return bytes(header) + bytes(frame) + ct


# --- vendored AES primitive --------------------------------------------------
def test_aes256_fips197_kat():
    key = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    )
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
    a = AES(key)
    assert a.encrypt_block(pt) == ct
    assert a.decrypt_block(ct) == pt


def test_aes128_fips197_kat():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    assert AES(key).encrypt_block(pt) == ct
    assert AES(key).decrypt_block(ct) == pt


# --- SP key table ------------------------------------------------------------
def test_sp_key_table_pins_known_configs():
    keys = dict(sp._SP_KEYS)
    assert keys[5].hex() == (
        "42b572526846f3ed853c8428dad960c7c9c6827d4818f8ff8ea9d24af0ed2b58"
    )
    assert keys[7].hex() == (
        "1bac9fc4fe56e90b3467ade286dc75e35e1bd7520887ebd68ca6861c4dde8966"
    )
    # Config 9 has no key material -- its absence is what makes the config-9
    # framing fail closed rather than decrypt to garbage.
    assert 9 not in keys
    assert sp._SP_KEY_BY_CONFIG == keys


# --- cipher mode (zero-IV CBC) -----------------------------------------------
def test_sp_cbc_is_zero_iv_cbc():
    aes = AES(dict(sp._SP_KEYS)[7])
    pt = b"0123456789abcdef" * 3
    ct = _cbc_encrypt_pkcs7(pt, aes)
    # _sp_cbc decrypts whole blocks; the 4th block is the pure-pad block.
    assert sp._sp_cbc(ct, aes, 3) == pt


def test_sp_unpad_rejects_invalid_padding():
    assert sp._sp_unpad(b"abc" + bytes([3]) * 3) == b"abc"
    assert sp._sp_unpad(b"abc" + bytes([9]) * 3) is None
    assert sp._sp_unpad(b"") is None


# --- framing / detection -----------------------------------------------------
def test_looks_like_sp_rung_rejects_plaintext_utf16():
    # Plaintext UTF-16 'XIC(' never matches the SP scaffold.
    plain = "XIC(@e2da9d52@)OTE(@bb593e67@);".encode("utf-16-le")
    assert not sp.looks_like_source_protected_rung(plain)


def test_is_v21_version():
    assert sp.is_v21_version("V21.03.02/3541.000")
    assert not sp.is_v21_version("V36.00.00/1234.000")
    assert not sp.is_v21_version(None)


# --- round-trip: build a cipher rung, decode it back -------------------------
def test_decode_recovers_full_text_exactly():
    # Nothing is lossy at rest: the whole text comes back, including the final
    # operand and the closing paren.
    text = "XIO(@1f9611fa@)OTE(@9db369e9@);"
    rbuf = _build_rung(text)
    assert sp.looks_like_source_protected_rung(rbuf)
    assert sp.decode_rung(rbuf) == text


def test_decode_ignores_slot_filler_past_the_ciphertext():
    # The ciphertext length is derived from the declared plaintext length, so
    # trailing filler must not reach the cipher.
    text = "XIO(@1f9611fa@)OTE(@9db369e9@);"
    assert sp.decode_rung(_build_rung(text, trailer=b"\xff" * 32)) == text


def test_decode_short_rung_is_not_assumed_to_be_nop():
    # A short rung ("RET();") has a 13-byte plaintext and a single 16-byte
    # ciphertext block. Treating such a buffer as a cipher-less NOP header
    # renders every one of these as "NOP();" -- silently wrong output.
    for text in ("NOP();", "RET();", "TND();"):
        assert sp.decode_rung(_build_rung(text)) == text


def test_name_resolution_on_decoded_operands():
    text = "XIO(@1f9611fa@)OTE(@9db369e9@);"
    out = sp.decode_rung(
        _build_rung(text), name_lookup={0x1f9611fa: "D1", 0x9db369e9: "D3"}.get
    )
    assert out == "XIO(D1)OTE(D3);"


def test_config_is_read_from_the_wire_not_hardcoded():
    # The same text under two different configs must both decode -- the config
    # byte at marker+17 selects the key.
    text = "XIO(@1f9611fa@)OTE(@9db369e9@);"
    assert sp.decode_rung(_build_rung(text, config=5)) == text
    assert sp.decode_rung(_build_rung(text, config=7)) == text


# --- fail-closed refusals ----------------------------------------------------
def test_config9_framing_fails_closed():
    # rbuf[17:19] == 0x0001 selects the config-9 framing; no key material exists
    # for it, so the reader must return None rather than emit a wrong rung.
    rbuf = bytearray(_build_rung("XIO(@1f9611fa@);"))
    struct.pack_into("<H", rbuf, 17, 1)
    assert sp.decode_rung(bytes(rbuf)) is None


def test_unknown_config_fails_closed():
    rbuf = bytearray(_build_rung("XIO(@1f9611fa@);"))
    rbuf[18] = 0x0B  # no key material for this config
    assert sp.decode_rung(bytes(rbuf)) is None


def test_truncated_ciphertext_fails_closed():
    rbuf = _build_rung("XIO(@1f9611fa@)OTE(@9db369e9@);")
    assert sp.decode_rung(rbuf[:-16]) is None


def test_declared_length_mismatch_fails_closed():
    rbuf = bytearray(_build_rung("XIO(@1f9611fa@)OTE(@9db369e9@);"))
    struct.pack_into("<I", rbuf, 13, 4)  # lie about the plaintext length
    assert sp.decode_rung(bytes(rbuf)) is None


# --- graphical (FBD/SFC) nameless element decrypt ----------------------------
def test_element_decrypts_and_reconstructs_plaintext():
    # An IRef body: X=100, Y=160 then the operand tail. The decrypt reconstructs
    # header + ffffffff + body so the graphical decoder parses it as plaintext,
    # landing X/Y at the long-header base (24/28) and preserving the kind word.
    body = struct.pack("<II", 100, 160) + b"\xff\xfe\xff\x0a@3f73155b@"
    rec = _build_element(body, kind=0x0e, config=7)
    out = sp.sp_decrypt_nameless_element(rec)
    assert out == rec[:20] + b"\xff\xff\xff\xff" + body
    assert struct.unpack_from("<H", out, 16)[0] == 0x0e
    assert struct.unpack_from("<I", out, 24)[0] == 100
    assert struct.unpack_from("<I", out, 28)[0] == 160


def test_element_config_is_read_from_the_wire():
    # Two configs, same body: the marker+17 byte selects the key both times.
    body = struct.pack("<II", 7, 9)
    for config in (5, 7):
        rec = _build_element(body, config=config)
        assert sp.sp_decrypt_nameless_element(rec) == rec[:20] + b"\xff\xff\xff\xff" + body


def test_element_plaintext_record_passes_through_unchanged():
    # A modern/unprotected record carries no marker -> byte-for-byte no-op.
    rec = bytes(range(20)) + b"\x64\x00\x00\x00\xa0\x00\x00\x00" + b"\xff\xfe\xff\x00"
    assert sp.sp_decrypt_nameless_element(rec) == rec
    assert sp._SP_MARKER not in rec  # guard: the fixture really is marker-free


def test_element_unknown_config_fails_closed():
    rec = bytearray(_build_element(struct.pack("<II", 1, 2), config=7))
    rec[37] = 0x0B  # marker+17: no key material for this config
    assert sp.sp_decrypt_nameless_element(bytes(rec)) == bytes(rec)


def test_element_declared_length_mismatch_fails_closed():
    rec = bytearray(_build_element(struct.pack("<II", 100, 160), config=7))
    struct.pack_into("<I", rec, 32, 999)  # lie about the plaintext length (marker+12)
    assert sp.sp_decrypt_nameless_element(bytes(rec)) == bytes(rec)


def test_element_missing_scaffold_fails_closed():
    # A stray marker without the 'Ui U' scaffold (e.g. a coincidental byte run in
    # plaintext content) must not be treated as protected.
    rec = bytearray(_build_element(struct.pack("<II", 1, 2), config=7))
    rec[29] = 0x00  # corrupt the marker+9 scaffold byte
    assert sp.sp_decrypt_nameless_element(bytes(rec)) == bytes(rec)


def test_element_config9_discriminator_fails_closed():
    rec = bytearray(_build_element(struct.pack("<II", 1, 2), config=7))
    rec[36] = 0x01  # marker+16 low byte 1 -> config-9 framing, no key material
    assert sp.sp_decrypt_nameless_element(bytes(rec)) == bytes(rec)


# --- end-to-end against the embedded v21_gm_FuncGen corpus -------------------
def test_v21_gm_corpus_read():
    """Drive the real fork read path over the embedded V21 corpus.

    Asserts the no-fabrication invariant (every decoded rung is a true prefix of
    the Studio L5X ground truth) and exact full-text recovery for every rung,
    cipher rungs included: nothing is lost at rest.
    """
    r = spval.run_validation()  # defaults point at resources/v21_gm_FuncGen.*
    assert sp.is_v21_version(r["version"])
    assert r["n"] == 94
    # Nothing fabricated: decoded text is always a true prefix of the L5X text.
    assert r["prefix_ok"] == r["n"]
    # Exact full-text recovery for every rung -- the ciphertext is complete at
    # rest, so the cipher rungs come back byte-exact too.
    assert r["exact"] == 94
    assert r["nop_exact"] == 50
    assert r["cipher_exact"] == 44
