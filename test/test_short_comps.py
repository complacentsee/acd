"""Unit tests for the ShortComps grammar + CompsRecord._parse_short flow.

Pins the P6.6 formalization: the V10..V21 short header (identical for FAFA
and FDFD) is declared in the ShortComps grammar, whose record_buffer reads
from offset 94 to END OF STREAM -- deliberately NOT the u32 length at
payload offset 0, which undercounts records carrying appended sub-blobs
(the truncation bug the long-header grammars still carry). The manual walk
stays as the lenient fallback: kaitai's strz raises on a name window that
is truncated, unterminated, or not valid UTF-16 where _decode_utf16z
tolerates all three.
"""

import struct
from types import SimpleNamespace

from acd.generated.comps.short_comps import ShortComps
from acd.record.comps import CompsRecord

FAFA = 64250   # 0xFAFA
FDFD = 65021   # 0xFDFD

BODY_OFF = 94    # _SH_BODY_OFF
NAME_OFF = 20    # _SH_NAME_OFF
NAME_END = 102   # _SH_NAME_END


def _payload(object_id=0x5678, parent_id=0x42, name="MyComp", seq=3,
             record_type=256, body=b"\x69" * 20, declared=None) -> bytes:
    """Assemble a short-header stream payload (header + body @94).

    ``declared`` overrides the u32 primary-record length at offset 0 (it is
    deliberately ignored by the body read).
    """
    buf = bytearray(BODY_OFF)
    length = len(buf) + len(body) if declared is None else declared
    buf[0:4] = struct.pack("<I", length)
    buf[8:10] = struct.pack("<H", seq)
    buf[10:12] = struct.pack("<H", record_type)
    buf[12:16] = struct.pack("<I", object_id)
    buf[16:20] = struct.pack("<I", parent_id)
    nb = name.encode("utf-16-le") + b"\x00\x00"
    assert NAME_OFF + len(nb) <= BODY_OFF, "test name must fit before the body"
    buf[NAME_OFF:NAME_OFF + len(nb)] = nb
    return bytes(buf) + body


def _dat(raw, identifier=FAFA):
    return SimpleNamespace(identifier=identifier,
                           record=SimpleNamespace(record_buffer=raw))


def test_grammar_reads_the_short_offsets():
    r = ShortComps.from_bytes(_payload())
    assert (r.object_id, r.parent_id, r.record_name.value,
            r.seq_number, r.record_type) == (0x5678, 0x42, "MyComp", 3, 256)
    assert r.record_buffer == b"\x69" * 20


def test_parse_short_tuple_both_families():
    raw = _payload(name="Prog_A", body=b"\xaa" * 7)
    want = (0x5678, 0x42, "Prog_A", 3, 256, b"\xaa" * 7)
    assert CompsRecord.parse(_dat(raw), short_header=True) == want
    assert CompsRecord.parse(_dat(raw, FDFD), short_header=True) == want
    assert CompsRecord.parse(_dat(raw, 0x1234), short_header=True) is None


def test_body_reads_to_eos_not_declared_length():
    """A record with appended sub-blobs declares a SHORTER length at offset
    0 than the payload holds; the body must still run to end-of-stream."""
    body = b"\x11" * 40 + b"\xfe" * 200        # 200B "sub-blob" past declared
    raw = _payload(body=body, declared=BODY_OFF + 40)
    t = CompsRecord.parse(_dat(raw), short_header=True)
    assert t[5] == body


def test_too_short_payload_returns_none():
    assert CompsRecord.parse(_dat(b"\x00" * (BODY_OFF - 1)),
                             short_header=True) is None


def test_unterminated_name_falls_back_to_lenient_decode():
    """No NUL anywhere in the 82-byte window: strz raises, the fallback
    yields the full 41-unit name (and the same body slice)."""
    raw = bytearray(_payload())
    raw[NAME_OFF:NAME_END] = b"\x41\x00" * 40 + b"\x42\x00"  # 'A'*40 + 'B', no NUL
    raw = bytes(raw)
    t = CompsRecord.parse(_dat(raw), short_header=True)
    assert t[2] == "A" * 40 + "B"
    assert t[0] == 0x5678 and t[5] == raw[BODY_OFF:]


def test_name_window_truncated_by_short_payload_falls_back():
    """Payload >= 94 but < 102 bytes: the grammar's sized name window read
    raises EOF; the fallback decodes what is there."""
    raw = _payload(name="Zx", body=b"")[:BODY_OFF]     # exactly 94 bytes
    t = CompsRecord.parse(_dat(raw), short_header=True)
    assert t == (0x5678, 0x42, "Zx", 3, 256, b"")


def test_invalid_utf16_name_falls_back():
    """A lone surrogate makes the grammar's UTF-16 decode raise; the
    fallback's chr() walk tolerates it."""
    raw = bytearray(_payload())
    raw[NAME_OFF:NAME_OFF + 4] = b"\x00\xd8\x00\x00"   # lone high surrogate, NUL
    t = CompsRecord.parse(_dat(bytes(raw)), short_header=True)
    assert t[2] == "\ud800"


def test_grammar_and_fallback_agree_on_well_formed_records():
    """Differential pin: for well-formed (non-astral) records the grammar
    path and the manual walk return identical 6-tuples. The grammar side is
    built directly from ShortComps -- NOT via _parse_short, which would fall
    back to the walk on any raise and make this trivially walk-vs-walk."""
    # Bodies are >= 8 bytes so the payload reaches the 82-byte name window's
    # end (offset 102); a shorter body is the truncated-window fallback case,
    # pinned separately, and does not occur in the real pool.
    for name, body in (("T", b"\x11" * 8), ("A_Long_Component_Name_123", b"\x00" * 8),
                       ("", b"\x99" * 500)):
        raw = _payload(name=name, body=body)
        r = ShortComps.from_bytes(raw)
        grammar = (r.object_id, r.parent_id, r.record_name.value,
                   r.seq_number, r.record_type, r.record_buffer)
        assert grammar == CompsRecord._parse_short_lenient(_dat(raw))


def test_parse_short_takes_the_grammar_path_not_the_fallback():
    """Prove _parse_short actually runs the grammar (regression pin for the
    wiring): a name with a VALID UTF-16 surrogate pair is the only input
    where the two paths' *successful* outputs differ -- kaitai's strict
    decode combines it to the astral codepoint, the lenient chr()-per-unit
    walk yields two lone surrogates. If the grammar were unwired, _parse_short
    would return the lone-surrogate form and this assertion would fail."""
    raw = bytearray(_payload())
    raw[NAME_OFF:NAME_OFF + 6] = b"\x3d\xd8\x00\xde\x00\x00"  # U+1F600 then NUL
    raw = bytes(raw)
    via_parse = CompsRecord.parse(_dat(raw), short_header=True)[2]
    via_walk = CompsRecord._parse_short_lenient(_dat(raw))[2]
    assert via_parse == "\U0001f600" and len(via_parse) == 1     # grammar: 1 astral
    assert via_walk == chr(0xD83D) + chr(0xDE00) and len(via_walk) == 2  # 2 lone
    assert via_parse != via_walk
