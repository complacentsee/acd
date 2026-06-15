"""Tests for V21 'Rung NT' source-protection (EncryptionConfig 5) READ support.

The headline validation against the v21_gm_FuncGen corpus (94 rungs) is run by
``scripts/validate_v21_source_protection.py``.  Its ACD/L5X fixtures are now
embedded in ``resources/`` so ``test_v21_gm_corpus_read`` exercises the real
fork read path end-to-end here.  The remaining unit tests are self-contained:
they pin the AES primitive (FIPS-197 KAT + V21 key), the cipher mode
(encrypt/decrypt inverse), the framing/header model, and the documented NOP-rung
wire bytes, so the codec is covered even without the corpus.
"""
import hashlib
import os
import sys

from acd.record._aes import AES
from acd.record import v21_source_protection as v21

# scripts/ is not a package; add it to the path to reuse the validation driver.
sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
)
import validate_v21_source_protection as v21val  # noqa: E402


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


# --- V21 key derivation ------------------------------------------------------
def test_v21_key_is_sha256_of_keymatl5():
    assert v21.AES_KEY == hashlib.sha256(v21._KEYMATL5).digest()
    assert v21.AES_KEY.hex() == (
        "42b572526846f3ed853c8428dad960c7c9c6827d4818f8ff8ea9d24af0ed2b58"
    )


# --- cipher mode (CBC full blocks + CFB final partial) -----------------------
def test_encrypt_decrypt_inverse_full_blocks():
    pt = b"A" * 48
    assert v21.decrypt(v21.encrypt(pt)) == pt


def test_encrypt_decrypt_inverse_partial_tail():
    pt = b"hello world this is a partial tail test!!"  # 41 bytes (not /16)
    assert v21.decrypt(v21.encrypt(pt)) == pt


def test_decrypt_recoverable_matches_full_blocks():
    pt = b"X" * 40  # 2 full blocks + 8 byte partial
    ct = v21.encrypt(pt)
    # recoverable == first 32 bytes (the two whole CBC blocks)
    assert v21.decrypt_recoverable(ct) == pt[:32]


# --- framing / detection -----------------------------------------------------
def test_nop_rung_wire_bytes_and_decode():
    nop = bytes.fromhex("4eaa96aa0a050000a05d5569550d")
    assert v21.is_nop(nop)
    assert v21.looks_like_v21_rung(nop)
    assert not v21.is_cipher_form(nop)
    assert v21.decode_rung(nop) == "NOP();"


def test_looks_like_v21_rejects_plaintext_utf16():
    # V30+ plaintext UTF-16 'XIC(' never matches the V21 scaffold.
    plain = "XIC(@e2da9d52@)OTE(@bb593e67@);".encode("utf-16-le")
    assert not v21.looks_like_v21_rung(plain)


def test_is_v21_version():
    assert v21.is_v21_version("V21.03.02/3541.000")
    assert not v21.is_v21_version("V36.00.00/1234.000")
    assert not v21.is_v21_version(None)


# --- round-trip: build a cipher rung, decode it back -------------------------
def test_decode_recovers_verifiable_prefix():
    # The on-disk body is lossy by the final ~8 chars (see module docstring): the
    # plaintext is always odd-length (1 prefix + 2*chars), so the last UTF-16
    # unit is never block-aligned and is never fabricated.  decode_rung returns a
    # true prefix of the full text, with each *complete* @hex@ operand intact.
    text = "XIO(@1f9611fa@)OTE(@9db369e9@);"
    pt = bytes([v21._PREFIX_BYTE]) + text[1:].encode("utf-16-le")
    rbuf = v21._build_test_rbuf(text[0], v21.encrypt(pt))
    assert v21.looks_like_v21_rung(rbuf)
    dec = v21.decode_rung(rbuf)
    assert text.startswith(dec)            # never fabricates beyond the body
    assert dec == "XIO(@1f9611fa@)OTE("    # first complete operand recovered


def test_name_resolution_on_recovered_operands():
    text = "XIO(@1f9611fa@)OTE(@9db369e9@);"
    pt = bytes([v21._PREFIX_BYTE]) + text[1:].encode("utf-16-le")
    rbuf = v21._build_test_rbuf(text[0], v21.encrypt(pt))
    out = v21.decode_rung(rbuf, name_lookup={0x1f9611fa: "D1", 0x9db369e9: "D3"}.get)
    # complete @hex@ operands resolve to names; the lossy tail is not fabricated.
    assert out == "XIO(D1)OTE("


# --- end-to-end against the embedded v21_gm_FuncGen corpus -------------------
def test_v21_gm_corpus_read():
    """Drive the real fork read path over the embedded V21 corpus.

    Asserts the no-fabrication invariant (every decoded rung is a true prefix of
    the Studio L5X ground truth) plus the exact-recovery floor for the rungs
    that fit in the recoverable prefix (all 50 NOPs).
    """
    r = v21val.run_validation()  # defaults point at resources/v21_gm_FuncGen.*
    assert v21.is_v21_version(r["version"])
    assert r["n"] == 94
    # Nothing fabricated: decoded text is always a true prefix of the L5X text.
    assert r["prefix_ok"] == r["n"]
    # Exact full-text recovery for the 50 NOP rungs; no cipher rung is faked.
    assert r["exact"] == 50
    assert r["nop_exact"] == 50
    assert r["cipher_exact"] == 0
