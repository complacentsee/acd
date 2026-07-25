"""Config-9 (V31+) source-protected COMMENT decryption: AOI Description,
RevisionNote (UDI_HISTORY), AdditionalHelpText (UDI_EXT_HELP), operand comments.

Synthetic and self-contained (repo AES, config-8 key-encryption key, no customer
data). A config-9 comment frames its text tail with the wrapped-key layout
(IV@marker+24, ct@marker+40, per-group key) instead of the config-1..8 on-wire
config byte; the decrypted body is otherwise identical, so the existing
reconstruction/validation recovers the text.
"""
import struct

import pytest

from acd.record._aes import AES
from acd.record import source_protection as sp
from acd.record import config9
from acd.record import comments as CM
from acd.record.comments import CommentsRecord


CFG8_KEY = sp._SP_KEY_BY_CONFIG[8]
GK = [bytes(range(i, i + 32)) for i in (0, 40, 90)]


def _cbc_enc(pt, aes, iv):
    pad = 16 - len(pt) % 16
    pt = pt + bytes([pad]) * pad
    out = bytearray()
    prev = iv
    for i in range(0, len(pt), 16):
        prev = aes.encrypt_block(bytes(x ^ y for x, y in zip(pt[i:i + 16], prev)))
        out += prev
    return bytes(out)


def _keytable(keys):
    rec = bytearray(b"\x11" * 89)
    for i, k in enumerate(keys):
        iv = bytes([(i + 1) & 0xFF]) * 16
        rec += iv + _cbc_enc(k, AES(CFG8_KEY), iv)
        rec += b"\xAB" * (config9._WRAP_STRIDE - 64)
    return bytes(rec)


def _c9_comment(group_key, body, mi, iv, header=b""):
    """A config-9 comment record: plaintext header/prefix, marker@mi, config-9
    framing (declared@mi+12, disc@mi+16=1, ctlen@mi+20, IV@mi+24, ct@mi+40)."""
    ct = _cbc_enc(body, AES(group_key), iv)
    rec = bytearray(mi + 40 + len(ct))
    rec[:len(header)] = header
    rec[mi:mi + 4] = sp._SP_MARKER
    struct.pack_into("<H", rec, mi + 12, len(body))
    struct.pack_into("<H", rec, mi + 16, 1)
    struct.pack_into("<I", rec, mi + 20, len(ct))
    rec[mi + 24:mi + 40] = iv
    rec[mi + 40:mi + 40 + len(ct)] = ct
    return bytes(rec)


@pytest.fixture
def keytable():
    keys = config9.unwrap_keytable(_keytable(GK))
    config9.set_project_keytable(keys)
    try:
        yield keys
    finally:
        config9.set_project_keytable([])


def test_config9_comment_pts_yields_plaintext(keytable):
    body = struct.pack("<III", 7, 0, 42) + b"hello\x00"
    rec = _c9_comment(GK[0], body, 60, bytes([1]) * 16)
    assert list(CM._config9_comment_pts(rec)) == [body]


def test_is_config9_comment():
    body = struct.pack("<III", 1, 2, 3) + b"x\x00"
    rec = _c9_comment(GK[0], body, 60, bytes(16))
    assert CM._is_config9_comment(rec)
    assert not CM._is_config9_comment(b"\x00" * 80)


# --- Description ------------------------------------------------------------
def test_decrypt_sp_comment_text_config9(keytable):
    body = struct.pack("<III", 7, 0, 42) + b"A protected description\x00"
    rec = _c9_comment(GK[1], body, 60, bytes([3]) * 16)
    assert CM._decrypt_sp_comment_text(rec) == "A protected description"


def test_decrypt_sp_comment_text_config9_fail_closed_no_keytable():
    body = struct.pack("<III", 7, 0, 42) + b"desc\x00"
    rec = _c9_comment(GK[1], body, 60, bytes([3]) * 16)
    config9.set_project_keytable([])
    assert CM._decrypt_sp_comment_text(rec) is None


def test_decrypt_sp_comment_text_config9_rejects_non_utf8(keytable):
    # A key-less body: no group key yields printable UTF-8 at offset 12.
    body = struct.pack("<III", 1, 2, 3) + b"\xff\xfe\x80\x81\x00"
    rec = _c9_comment(GK[2], body, 60, bytes(16))
    assert CM._decrypt_sp_comment_text(rec) is None


# --- UDI RevisionNote / AdditionalHelpText ----------------------------------
def test_parse_sp_udi_text_config9_revision_note(keytable):
    body = CommentsRecord._UDI_HISTORY_MARKER + b"V1.0, 111114, JAG, creation\x00"
    rec = _c9_comment(GK[0], body, 30, bytes([4]) * 16)
    row = CommentsRecord._parse_sp_udi_text(rec)
    assert row is not None
    assert row[6] == "__REVISION_NOTE__"
    assert row[3] == "V1.0, 111114, JAG, creation"


def test_parse_sp_udi_text_config9_ext_help(keytable):
    body = CommentsRecord._UDI_EXT_HELP_MARKER + b"Some help text\x00"
    rec = _c9_comment(GK[1], body, 30, bytes([9]) * 16)
    row = CommentsRecord._parse_sp_udi_text(rec)
    assert row is not None
    assert row[6] == "__EXT_HELP__"
    assert row[3] == "Some help text"


def test_parse_sp_udi_text_config9_not_udi_returns_none(keytable):
    body = b"NOT_A_UDI_MARKER_AT_ALL\x00padding\x00"
    rec = _c9_comment(GK[0], body, 30, bytes(16))
    assert CommentsRecord._parse_sp_udi_text(rec) is None


# --- Operand comment (parameter description with an operand) -----------------
def test_parse_sp_operand_body_config9(keytable):
    # Body layout per _parse_sp_operand_body: the operand starts at body+16
    # (== raw[30]); its leading '.' stays plaintext in the prefix raw[30:mi], the
    # rest rides in the decrypted tail (operand remainder + NUL + 12-byte pad +
    # UTF-8 text). header: owner_ref@14, object_id@22, kind@27; marker at raw[32].
    header = bytearray(32)
    struct.pack_into("<H", header, 4, 5)          # seq_number
    struct.pack_into("<H", header, 6, 13)         # record_type (operand family)
    struct.pack_into("<H", header, 8, 40)         # sub_record_length
    struct.pack_into("<I", header, 10, 999)       # parent
    struct.pack_into("<I", header, 14, 111)       # owner_ref (body+0)
    struct.pack_into("<I", header, 22, 222)       # object_id (body+8)
    header[27] = 0x00                             # kind (body+13): comment
    header[30:32] = ".".encode("utf-16-le")       # operand start (raw[30]), prefix
    # decrypted tail: operand remainder "Value" + NUL terminator + 12-byte pad + text
    body = ("Value".encode("utf-16-le") + b"\x00\x00"
            + b"\x00" * 12 + b"Param description\x00")
    rec = _c9_comment(GK[2], bytes(body), 32, bytes([6]) * 16, header=bytes(header))
    row = CommentsRecord._parse_sp_operand_body(rec)
    assert row is not None
    assert row[6] == ".Value"
    assert row[3] == "Param description"
