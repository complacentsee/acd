"""Config-9 export cipher -- emit a Studio-importable ``<EncodedData>`` blob.

Studio's config-9 export scheme wraps a source-protected routine's plaintext as::

    [00 09][flag][IV 16][GCM tag 16][ciphertext]           (then base64)

    key  = PBKDF2-HMAC-SHA256(master, salt, iterations, 32)
    salt = salt_table[offset : offset + 16]
    flag = salt_table[offset - 1]          (the byte just before the salt slice)
    IV   = 16 arbitrary bytes (non-96-bit -> GHASH'd to J0; free to choose)
    GCM tag is placed BEFORE the ciphertext, not after.

On import Studio brute-searches the salt table for the offset whose slice yields a
valid GCM tag, then validates ``flag == salt_table[offset - 1]``.  It only searches
*producible* offsets (the export selector emits a fixed subset, not every byte
position), so we must pick ``offset`` from that set -- an arbitrary offset with the
right flag is still rejected.

The master, salt table and producible-offset set are the export secret; they are
NEVER embedded here.  They load at runtime from a key-bundle file (``--sp-export-key``
or the ``ACD_CFG9_EXPORT_KEY`` environment variable) -- a JSON object with hex fields::

    {"master_hex": "..", "salt_table_hex": "..",
     "producible_offsets": [<int>, <int>, ...], "iterations": <n>, "dklen": 32}

With no key loaded every entry point returns None and the caller withholds the blob,
exactly as before this module existed.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import List, Optional

from acd.record._aes import AES

_ENV_VAR = "ACD_CFG9_EXPORT_KEY"


class _Key:
    __slots__ = ("master", "table", "offsets", "iters", "dklen")

    def __init__(self, master: bytes, table: bytes,
                 offsets: List[int], iters: int, dklen: int) -> None:
        self.master = master
        self.table = table
        self.offsets = offsets
        self.iters = iters
        self.dklen = dklen


_KEY: Optional[_Key] = None
_TRIED_ENV = False


def set_key_file(path: str) -> None:
    """Load the export key bundle from ``path`` (raises if it cannot be read)."""
    global _KEY
    with open(path, "r", encoding="ascii") as fh:
        d = json.load(fh)
    master = bytes.fromhex(d["master_hex"])
    table = bytes.fromhex(d["salt_table_hex"])
    offsets = [int(o) for o in d.get("producible_offsets", [])]
    offsets = sorted({o for o in offsets if 1 <= o <= len(table) - 16})
    iters = int(d.get("iterations", 0))
    dklen = int(d.get("dklen", 32))
    if not (master and table and offsets and iters > 0):
        raise ValueError("config-9 export key bundle is incomplete")
    _KEY = _Key(master, table, offsets, iters, dklen)


def _key() -> Optional[_Key]:
    """The loaded key bundle, falling back once to the environment variable."""
    global _TRIED_ENV
    if _KEY is None and not _TRIED_ENV:
        _TRIED_ENV = True
        path = os.environ.get(_ENV_VAR)
        if path:
            set_key_file(path)
    return _KEY


def is_loaded() -> bool:
    """True when an export key is available (so emission is possible)."""
    return _key() is not None


# --- AES-GCM over acd's own AES block cipher (no third-party dependency) ------
def _gmul(x: int, h: int) -> int:
    """Carry-less GF(2^128) multiply x*h (GCM's bit-reflected polynomial)."""
    z = 0
    v = x
    for i in range(127, -1, -1):
        if (h >> i) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ (0xe1 << 120)
        else:
            v >>= 1
    return z


def _ghash2(h: int, data: bytes) -> bytes:
    y = 0
    for i in range(0, len(data), 16):
        y = _gmul(y ^ int.from_bytes(data[i:i + 16], "big"), h)
    return y.to_bytes(16, "big")


def _gcm_encrypt(aes: AES, iv: bytes, pt: bytes):
    h = int.from_bytes(aes.encrypt_block(b"\x00" * 16), "big")
    j0 = _ghash2(h, iv + b"\x00" * 8 + (len(iv) * 8).to_bytes(8, "big"))
    base = j0[:12]
    ctr = int.from_bytes(j0[12:16], "big")
    ks = bytearray()
    for i in range((len(pt) + 15) // 16):
        ks += aes.encrypt_block(base + ((ctr + 1 + i) & 0xffffffff).to_bytes(4, "big"))
    ct = bytes(a ^ b for a, b in zip(pt, ks))
    padded = ct + b"\x00" * ((16 - len(ct) % 16) % 16)
    s = _ghash2(h, padded + b"\x00" * 8 + (len(ct) * 8).to_bytes(8, "big"))
    tag = bytes(a ^ b for a, b in zip(s, aes.encrypt_block(j0)))
    return ct, tag


def encrypt_routine(document: str) -> Optional[str]:
    """Base64 ``<EncodedData>`` body for ``document``, or None if no key is loaded.

    ``document`` is the recovered ``<Routine>`` plaintext; config-9 encodes it as
    UTF-8 (the export blob's declared UTF-16 is not honoured by the byte content).
    The salt offset and IV are derived deterministically from the plaintext so a
    re-run is byte-identical (the fidelity harness requires reproducible output);
    distinct routines get distinct (key, IV) pairs, so GCM nonces never repeat.
    """
    k = _key()
    if k is None:
        return None
    pt = document.encode("utf-8")
    idx = int.from_bytes(hashlib.sha256(pt + b"\x00off").digest()[:8], "big")
    off = k.offsets[idx % len(k.offsets)]
    salt = k.table[off:off + 16]
    flag = k.table[off - 1]
    key = hashlib.pbkdf2_hmac("sha256", k.master, salt, k.iters, k.dklen)
    iv = hashlib.sha256(pt + b"\x01iv").digest()[:16]
    ct, tag = _gcm_encrypt(AES(key), iv, pt)
    blob = bytes([0x00, 0x09, flag]) + iv + tag + ct
    return base64.b64encode(blob).decode("ascii").rstrip("=")
