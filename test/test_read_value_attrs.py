"""Unit tests for the hand-rolled ext-attr walker in acd.record.comps.

``read_value_attrs`` underpins most of the fidelity campaign's decode logic:
it walks a cip-0x6a value backing's body past the (unreliable) declared
attribute count to reach the design-value image at attr 0x66, keeping the
first occurrence of each id, and transparently decrypts a source-protected
tail.  These behaviours are load-bearing and NOT expressible in the kaitai
grammar, so this suite pins them with synthetic byte fixtures (no ACD pool
needed) ahead of the P3 kaitai work that formalizes the plaintext path.

Body layout produced by the builders below, from ``CompsRecord.body_offset``:
    [14B prelude + 60B main_record = 74B][u32 len_record][u32 count_record]
    then a sequence of (u32 attribute_id, u32 len_value, len_value bytes).
"""

import struct

from acd.record import comps as C
from acd.record._aes import AES
from acd.record.comps import CompsRecord

LONG_OFF = 148   # CompsRecord._LONG_BODY_OFF
SHORT_OFF = 94   # _SH_BODY_OFF


def _attr(attr_id: int, value: bytes) -> bytes:
    return struct.pack("<II", attr_id, len(value)) + value


def _body(attrs: list, declared_count: int = None) -> bytes:
    """Assemble a plaintext RxGeneric body from (id, value) pairs."""
    tail = b"".join(_attr(aid, val) for aid, val in attrs)
    count = len(attrs) if declared_count is None else declared_count
    # 74B prelude+main (content irrelevant to the walk), then len/count words.
    return b"\x00" * 74 + struct.pack("<II", len(tail), count) + tail


def _payload(attrs, short_header=False, declared_count=None) -> bytes:
    off = SHORT_OFF if short_header else LONG_OFF
    return b"\x00" * off + _body(attrs, declared_count)


# --------------------------------------------------------------------------- #
# Plaintext walk
# --------------------------------------------------------------------------- #


def test_happy_path_long_header():
    attrs = [
        (0x01, b"\x3e\x00" + b"\x11" * 8),
        (0x64, b"\x00" * 16),          # runtime cache (all-zero on disk)
        (0x65, b"\xc4\x00"),           # cip type code (DINT)
        (0x66, b"\x2a\x00\x00\x00"),   # design value = 42
    ]
    out = CompsRecord.read_value_attrs(_payload(attrs), short_header=False)
    assert set(out) == {0x01, 0x64, 0x65, 0x66}
    assert out[0x66] == b"\x2a\x00\x00\x00"
    assert out[0x65] == b"\xc4\x00"


def test_happy_path_short_header():
    attrs = [(0x01, b"\x3e\x00"), (0x66, b"\x07\x00\x00\x00")]
    out = CompsRecord.read_value_attrs(_payload(attrs, short_header=True),
                                       short_header=True)
    assert out[0x66] == b"\x07\x00\x00\x00"


def test_walk_ignores_declared_count():
    """The whole point of the hand walker: 0x66 sits *past* count_record, so a
    truthful walk must not stop at the declared count."""
    attrs = [(0x01, b"\x3e\x00"), (0x65, b"\xc4\x00"), (0x66, b"\x99\x00\x00\x00")]
    # Declare only 1 attribute; the walker must still reach 0x66 (the 3rd).
    out = CompsRecord.read_value_attrs(_payload(attrs, declared_count=1),
                                       short_header=False)
    assert out[0x66] == b"\x99\x00\x00\x00"


def test_keep_first_occurrence_dedup():
    """A forced/relocated backing re-emits a stray 0x66 after the real one; the
    walker must keep the FIRST (the genuine inline image). Regression pin for
    the 0ca0371 keep-first clobber fix."""
    attrs = [
        (0x01, b"\x3e\x00"),
        (0x66, b"REAL"),
        (0x82, b"\x00\x00\x00\x00"),   # force holder ref region
        (0x66, b"FAKE"),               # spurious re-parse of a later (id,len)
    ]
    out = CompsRecord.read_value_attrs(_payload(attrs), short_header=False)
    assert out[0x66] == b"REAL"


def test_truncated_tail_retains_prior_attrs():
    """An attribute whose declared length overruns the buffer stops the walk
    but keeps everything parsed before it."""
    good = _attr(0x01, b"\x3e\x00") + _attr(0x66, b"\x01\x00\x00\x00")
    # A final attr claiming a huge length that runs off the end.
    bad = struct.pack("<II", 0x6E, 0xFFFF)  # no value bytes follow
    body = b"\x00" * 74 + struct.pack("<II", len(good) + len(bad), 3) + good + bad
    out = CompsRecord.read_value_attrs(b"\x00" * LONG_OFF + body,
                                       short_header=False)
    assert out[0x66] == b"\x01\x00\x00\x00"
    assert 0x6E not in out


def test_bad_input_returns_empty_dict():
    """Any structural problem yields {} so callers fall back to today's
    zero-placeholder behaviour (comps.py:416-417)."""
    assert CompsRecord.read_value_attrs(None, short_header=False) == {}
    assert CompsRecord.read_value_attrs(b"\x00" * 10, short_header=False) == {}


def test_read_tag_value_pulls_design_value_and_type():
    attrs = [(0x01, b"\x3e\x00"), (0x65, b"\xc4\x00"), (0x66, b"\x2a\x00\x00\x00")]
    result = CompsRecord.read_tag_value(_payload(attrs), short_header=False)
    assert result is not None
    value, cip_type = result
    assert value == b"\x2a\x00\x00\x00"
    assert cip_type == 0xC4


def test_read_tag_value_none_without_0x66():
    attrs = [(0x01, b"\x3e\x00"), (0x65, b"\xc4\x00")]
    assert CompsRecord.read_tag_value(_payload(attrs), short_header=False) is None


# --------------------------------------------------------------------------- #
# Source-protection-at-rest decrypt
# --------------------------------------------------------------------------- #


def _cbc_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES-256-CBC encrypt (IV=0) using the library's own block cipher, so the
    round-trip exercises exactly the primitive the decrypt path uses."""
    assert len(plaintext) % 16 == 0
    aes = AES(key)
    prev = b"\x00" * 16
    out = bytearray()
    for i in range(0, len(plaintext), 16):
        block = bytes(x ^ y for x, y in zip(plaintext[i:i + 16], prev))
        prev = aes.encrypt_block(block)
        out += prev
    return bytes(out)


def _sp_table(attrs: list) -> bytes:
    """A decrypted ext-attr table: [u32 count][(u32 id,u32 len,bytes)...],
    zero-padded to a 16-byte boundary. First id MUST be 0x01 (the validator)."""
    body = struct.pack("<I", len(attrs))
    body += b"".join(_attr(aid, val) for aid, val in attrs)
    pad = (-len(body)) % 16
    return body + b"\x00" * pad


def _sp_body(ciphertext: bytes, prelude=74) -> bytes:
    """Embed an SP ciphertext behind the marker framing at body+prelude."""
    # marker (4B) + 14B framing == _SP_CT_OFFSET(18); ct starts at marker+18.
    return b"\x00" * prelude + C._SP_MARKER + b"\x00" * 14 + ciphertext


# A real public source-protection key (config 7) so the validator accepts it.
_SP_CONFIG, _SP_KEY = C._SP_KEYS[0]


def test_sp_decrypt_roundtrip():
    attrs = [(0x01, b"\x3e\x00\x11\x11"), (0x65, b"\xc4\x00\x00\x00"),
             (0x66, b"\x39\x05\x00\x00")]
    ct = _cbc_encrypt(_sp_table(attrs), _SP_KEY)
    payload = b"\x00" * LONG_OFF + _sp_body(ct)
    out = CompsRecord.read_value_attrs(payload, short_header=False)
    assert out.get(0x66) == b"\x39\x05\x00\x00"
    assert out.get(0x65) == b"\xc4\x00\x00\x00"


def test_sp_decrypt_via_record_body_api():
    attrs = [(0x01, b"\x3e\x00\x22\x22"), (0x66, b"\xde\xad\xbe\xef")]
    ct = _cbc_encrypt(_sp_table(attrs), _SP_KEY)
    record = _sp_body(ct)  # read_ext_attrs_from_record takes the body directly
    out = CompsRecord.read_ext_attrs_from_record(record, full=True)
    assert out.get(0x66) == b"\xde\xad\xbe\xef"


def test_sp_wrong_key_rejected():
    """A tail encrypted under a non-public key must NOT decode; the direct
    decrypt returns {} (callers then fall through to the plaintext walk)."""
    attrs = [(0x01, b"\x3e\x00"), (0x66, b"\x2a\x00\x00\x00")]
    bogus_key = bytes(range(32))
    ct = _cbc_encrypt(_sp_table(attrs), bogus_key)
    assert C._decrypt_value_attrs(ct, full=True) == {}
    # And through the record API: no valid decode, so 0x66 is not the plaintext.
    out = CompsRecord.read_ext_attrs_from_record(_sp_body(ct), full=True)
    assert out.get(0x66) != b"\x2a\x00\x00\x00"


def test_sp_decrypt_large_table_over_256_attrs():
    """A predefined-datatype record (AXIS_CIP_DRIVE-class) carries hundreds of
    member-descriptor attributes; the wrong-key count check must scale with the
    buffer, not cap at 256, or the whole table fails to decode."""
    attrs = [(0x01, b"\x3e\x00\x11\x11")]
    attrs += [(0x6E + i, struct.pack("<I", i)) for i in range(400)]
    assert len(attrs) > 256
    ct = _cbc_encrypt(_sp_table(attrs), _SP_KEY)
    out = C._decrypt_value_attrs(ct, full=True)
    assert out.get(0x01) == b"\x3e\x00\x11\x11"
    assert out.get(0x6E + 399) == struct.pack("<I", 399)
    assert len(out) == len(attrs)


def test_sp_impossible_count_rejected():
    """A count larger than the decrypted buffer could hold (each attr >= 8 bytes)
    is still a wrong-key signal: the one-block validator rejects it."""
    # A single 16-byte block holds at most (16-4)//8 = 1 attribute; claim 99.
    head = struct.pack("<I", 99) + _attr(0x01, b"\x00\x00\x00\x00")[:12]
    block = head[:16]
    ct = _cbc_encrypt(block, _SP_KEY)
    assert C._decrypt_value_attrs(ct, full=True) == {}


def test_read_ext_attrs_no_marker_returns_empty():
    """A plaintext record (no marker) yields {} from the SP-only entry point,
    so its caller keeps the plaintext fallback."""
    plain = b"\x00" * 74 + struct.pack("<II", 8, 1) + _attr(0x66, b"\x01\x02")
    assert CompsRecord.read_ext_attrs_from_record(plain) == {}


# --------------------------------------------------------------------------- #
# body_mode / record_attrs (body-direct comps.record readers, P6.7)
# --------------------------------------------------------------------------- #
# Post size-eos flip, comps.record == comps_full.record[body_offset:] for every
# FAFA/short record, so consumers can read the body directly with body_mode=True
# (offset 0) instead of round-tripping through comps_full.


def test_body_mode_equals_header_sliced_walk():
    """body_mode=True on the bare body must decode exactly what the header-
    sliced path decodes from the full payload -- for both header families."""
    attrs = [(0x01, b"\x3e\x00" + b"\x11" * 8), (0x65, b"\xc4\x00"),
             (0x66, b"\x2a\x00\x00\x00")]
    for short in (False, True):
        payload = _payload(attrs, short_header=short)
        body = payload[SHORT_OFF if short else LONG_OFF:]
        via_full = CompsRecord.read_value_attrs(payload, short)
        via_body = CompsRecord.read_value_attrs(body, short, body_mode=True)
        assert via_body == via_full
        assert via_body[0x66] == b"\x2a\x00\x00\x00"


def test_body_mode_sp_decrypt():
    """The SP marker gate and decrypt are body-relative already; body_mode must
    reach them unchanged."""
    attrs = [(0x01, b"\x3e\x00\x11\x11"), (0x66, b"\x39\x05\x00\x00")]
    ct = _cbc_encrypt(_sp_table(attrs), _SP_KEY)
    body = _sp_body(ct)
    out = CompsRecord.read_value_attrs(body, False, body_mode=True)
    assert out.get(0x66) == b"\x39\x05\x00\x00"


def test_read_tag_value_body_mode():
    attrs = [(0x01, b"\x3e\x00"), (0x65, b"\xc4\x00"), (0x66, b"\x2a\x00\x00\x00")]
    body = _body(attrs)
    result = CompsRecord.read_tag_value(body, False, body_mode=True)
    assert result == (b"\x2a\x00\x00\x00", 0xC4)


def _comps_cursor(rows):
    import sqlite3

    cur = sqlite3.connect(":memory:").cursor()
    cur.execute("CREATE TABLE comps(object_id INTEGER PRIMARY KEY, record BLOB)")
    cur.executemany("INSERT INTO comps VALUES (?, ?)", rows)
    return cur


def test_record_attrs_reads_comps_body():
    body = _body([(0x01, b"\x3e\x00"), (0x66, b"\x2a\x00\x00\x00")])
    cur = _comps_cursor([(7, body)])
    out = CompsRecord.record_attrs(cur, 7, False)
    assert out[0x66] == b"\x2a\x00\x00\x00"


def test_record_attrs_matches_header_included_read():
    """The migration invariant that let comps_full retire (P6.9 C8):
    record_attrs on the body == the full header-included read on the untruncated
    payload (what full_attrs did before comps_full was removed)."""
    attrs = [(0x01, b"\x3e\x00"), (0x65, b"\xc4\x00"), (0x66, b"\x99\x00\x00\x00"),
             (0x6E, b"member-descriptor-bytes")]
    payload = _payload(attrs)
    cur = _comps_cursor([(7, payload[LONG_OFF:])])
    assert (CompsRecord.record_attrs(cur, 7, False)
            == CompsRecord.read_value_attrs(payload, False, full=True))


def test_record_attrs_missing_row_yields_empty():
    cur = _comps_cursor([])
    assert CompsRecord.record_attrs(cur, 42, False) == {}


def test_record_attrs_memoizes_per_cursor():
    body = _body([(0x66, b"\x07\x00\x00\x00")])
    cur = _comps_cursor([(7, body)])
    first = CompsRecord.record_attrs(cur, 7, False)
    cur.execute("DELETE FROM comps")
    assert CompsRecord.record_attrs(cur, 7, False) is first
    cur2 = cur.connection.cursor()
    cur2.execute("SELECT 1").fetchone()
    assert CompsRecord.record_attrs(cur2, 7, False) == {}
