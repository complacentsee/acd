"""AES-128/192/256 ECB block primitive with an optional native backend.

Used by V21 source-protection rung decryption (see
``acd.record.source_protection``) and the V24 source-protected-at-rest
ext-attribute tail decryptor (see ``acd.record.comps``).

Only the two raw 16-byte block operations are exposed:

    aes = AES(key_bytes)            # key len 16/24/32 -> AES-128/192/256
    ct_block = aes.encrypt_block(pt_block16)
    pt_block = aes.decrypt_block(ct_block16)

Block chaining (CBC / the V21 CFB-style final partial) is implemented by the
callers in :mod:`acd.record.source_protection` and :mod:`acd.record.comps`.

Backend selection (transparent to callers):

* If the ``cryptography`` package is importable, block ops run through its
  OpenSSL-backed AES-ECB primitive. On source-protected V24 projects the
  ext-attribute tail is several hundred KB of ciphertext decrypted block by
  block; the native backend is ~60x faster there than the textbook path
  (a full-pool export drops from minutes-per-SP-file to seconds).
* Otherwise it falls back to the vendored, dependency-free textbook
  implementation below, so the package still works with no third-party crypto.

The native backend is verified byte-for-byte against the textbook
implementation and the FIPS-197 known-answer vectors at import time; on ANY
mismatch (or import failure) it is disabled and the textbook path is used, so
the emitted L5X is identical regardless of which backend is active.
"""
from __future__ import annotations

import os
from typing import List

# --- AES S-box and inverse S-box --------------------------------------------
_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16,
]
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i

_RCON = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a,
]


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11b
    return a & 0xff


def _mul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        b >>= 1
        a = _xtime(a)
    return p & 0xff


class _PurePythonAES:
    """Textbook AES block cipher (ECB block ops only); no dependencies."""

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24 or 32 bytes")
        self._nk = len(key) // 4
        self._nr = {4: 10, 6: 12, 8: 14}[self._nk]
        self._round_keys = self._expand_key(key)

    # -- key schedule --------------------------------------------------------
    def _expand_key(self, key: bytes) -> List[List[int]]:
        nk, nr = self._nk, self._nr
        words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
        for i in range(nk, 4 * (nr + 1)):
            temp = list(words[i - 1])
            if i % nk == 0:
                temp = temp[1:] + temp[:1]                  # RotWord
                temp = [_SBOX[b] for b in temp]             # SubWord
                temp[0] ^= _RCON[i // nk - 1]
            elif nk > 6 and i % nk == 4:
                temp = [_SBOX[b] for b in temp]
            words.append([words[i - nk][j] ^ temp[j] for j in range(4)])
        # group into per-round 16-byte keys (column-major state layout)
        round_keys = []
        for r in range(nr + 1):
            rk = []
            for c in range(4):
                rk.extend(words[r * 4 + c])
            round_keys.append(rk)
        return round_keys

    # -- state helpers (column-major: state[r + 4*c]) ------------------------
    @staticmethod
    def _add_round_key(state: List[int], rk: List[int]) -> None:
        for i in range(16):
            state[i] ^= rk[i]

    @staticmethod
    def _sub_bytes(state: List[int], box: List[int]) -> None:
        for i in range(16):
            state[i] = box[state[i]]

    @staticmethod
    def _shift_rows(state: List[int]) -> None:
        for r in range(1, 4):
            row = [state[r + 4 * c] for c in range(4)]
            row = row[r:] + row[:r]
            for c in range(4):
                state[r + 4 * c] = row[c]

    @staticmethod
    def _inv_shift_rows(state: List[int]) -> None:
        for r in range(1, 4):
            row = [state[r + 4 * c] for c in range(4)]
            row = row[-r:] + row[:-r]
            for c in range(4):
                state[r + 4 * c] = row[c]

    @staticmethod
    def _mix_columns(state: List[int]) -> None:
        for c in range(4):
            i = 4 * c
            a0, a1, a2, a3 = state[i], state[i + 1], state[i + 2], state[i + 3]
            state[i] = _xtime(a0) ^ (_xtime(a1) ^ a1) ^ a2 ^ a3
            state[i + 1] = a0 ^ _xtime(a1) ^ (_xtime(a2) ^ a2) ^ a3
            state[i + 2] = a0 ^ a1 ^ _xtime(a2) ^ (_xtime(a3) ^ a3)
            state[i + 3] = (_xtime(a0) ^ a0) ^ a1 ^ a2 ^ _xtime(a3)

    @staticmethod
    def _inv_mix_columns(state: List[int]) -> None:
        for c in range(4):
            i = 4 * c
            a0, a1, a2, a3 = state[i], state[i + 1], state[i + 2], state[i + 3]
            state[i] = _mul(a0, 14) ^ _mul(a1, 11) ^ _mul(a2, 13) ^ _mul(a3, 9)
            state[i + 1] = _mul(a0, 9) ^ _mul(a1, 14) ^ _mul(a2, 11) ^ _mul(a3, 13)
            state[i + 2] = _mul(a0, 13) ^ _mul(a1, 9) ^ _mul(a2, 14) ^ _mul(a3, 11)
            state[i + 3] = _mul(a0, 11) ^ _mul(a1, 13) ^ _mul(a2, 9) ^ _mul(a3, 14)

    # -- public block ops ----------------------------------------------------
    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("AES block must be 16 bytes")
        state = list(block)
        self._add_round_key(state, self._round_keys[0])
        for r in range(1, self._nr):
            self._sub_bytes(state, _SBOX)
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, self._round_keys[r])
        self._sub_bytes(state, _SBOX)
        self._shift_rows(state)
        self._add_round_key(state, self._round_keys[self._nr])
        return bytes(state)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("AES block must be 16 bytes")
        state = list(block)
        self._add_round_key(state, self._round_keys[self._nr])
        for r in range(self._nr - 1, 0, -1):
            self._inv_shift_rows(state)
            self._sub_bytes(state, _INV_SBOX)
            self._add_round_key(state, self._round_keys[r])
            self._inv_mix_columns(state)
        self._inv_shift_rows(state)
        self._sub_bytes(state, _INV_SBOX)
        self._add_round_key(state, self._round_keys[0])
        return bytes(state)


# --- optional native (OpenSSL) backend --------------------------------------
try:
    from cryptography.hazmat.primitives.ciphers import (
        Cipher as _Cipher, algorithms as _algorithms, modes as _modes,
    )
    _HAVE_CRYPTOGRAPHY = True
except Exception:  # pragma: no cover - exercised only when cryptography absent
    _HAVE_CRYPTOGRAPHY = False


class _OpenSSLAES:
    """OpenSSL-backed AES (ECB block ops only) via the ``cryptography`` package.

    ECB has no chaining state, so a single encryptor/decryptor is reused across
    every 16-byte block. The CBC / CFB-partial chaining the callers do on top is
    unaffected.
    """

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24 or 32 bytes")
        self._cipher = _Cipher(_algorithms.AES(key), _modes.ECB())
        self._enc = None
        self._dec = None

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("AES block must be 16 bytes")
        if self._enc is None:
            self._enc = self._cipher.encryptor()
        return self._enc.update(block)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("AES block must be 16 bytes")
        if self._dec is None:
            self._dec = self._cipher.decryptor()
        return self._dec.update(block)


def _native_matches_reference() -> bool:
    """Verify the native backend byte-for-byte vs the textbook impl + FIPS-197.

    Run once at import. Any mismatch disables the native path so the emitted
    output can never differ from the dependency-free reference.
    """
    if not _HAVE_CRYPTOGRAPHY:
        return False
    try:
        # FIPS-197 C.3 AES-256 known-answer vector.
        kat_key = bytes(range(0x00, 0x20))
        kat_pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        kat_ct = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
        if _OpenSSLAES(kat_key).encrypt_block(kat_pt) != kat_ct:
            return False
        if _OpenSSLAES(kat_key).decrypt_block(kat_ct) != kat_pt:
            return False
        # Cross-check every key size against the textbook implementation on a
        # fixed, non-trivial block (deterministic; no RNG needed).
        probe = bytes((i * 37 + 11) & 0xFF for i in range(16))
        for klen in (16, 24, 32):
            key = bytes((i * 19 + 7) & 0xFF for i in range(klen))
            ref, nat = _PurePythonAES(key), _OpenSSLAES(key)
            ct_ref = ref.encrypt_block(probe)
            if nat.encrypt_block(probe) != ct_ref:
                return False
            if nat.decrypt_block(ct_ref) != probe:
                return False
        return True
    except Exception:
        return False


# Escape hatch: set ACD_DISABLE_NATIVE_AES=1 to force the textbook backend
# (e.g. for A/B validation that the two paths are byte-identical, or if a host's
# OpenSSL is ever suspect). Empty/0/false/no leave the native path enabled.
_FORCE_PYTHON = os.environ.get("ACD_DISABLE_NATIVE_AES", "").strip().lower() not in ("", "0", "false", "no")
_NATIVE_OK = (not _FORCE_PYTHON) and _native_matches_reference()


class AES:
    """AES block cipher (ECB block ops only).

    Public API unchanged: ``AES(key).encrypt_block(b16)`` / ``.decrypt_block``.
    Delegates to the OpenSSL backend when available and verified, else to the
    vendored textbook implementation. ``AES.backend`` reports which is active.
    """

    backend = "openssl" if _NATIVE_OK else "python"

    def __init__(self, key: bytes):
        if _NATIVE_OK:
            self._impl = _OpenSSLAES(key)
        else:
            self._impl = _PurePythonAES(key)

    def encrypt_block(self, block: bytes) -> bytes:
        return self._impl.encrypt_block(block)

    def decrypt_block(self, block: bytes) -> bytes:
        return self._impl.decrypt_block(block)
