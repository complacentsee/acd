"""Unit tests for the <EncodedData> renderer (acd.l5x.encoded_data).

A source-protected routine is exported by Studio as an <EncodedData> blob in
place of the plaintext <Routine>. These fixtures pin the two derivations the
renderer reads out of the routine's comps record -- the EncodedSourceKey and the
SourceProtectionType flag bit, both inside ext-attr 0x1's security descriptor --
plus the cipher/framing and every fail-closed branch.

The renderer is all-or-nothing per routine: anything it cannot resolve must yield
None so the caller emits nothing, because a wrong blob is worse than a missing
one. Byte-exactness against the reference's own blobs is proven separately by
whole-corpus differential execution.
"""

import base64
import struct

from acd.l5x.encoded_data import (
    encoded_routine,
    security_descriptor,
    source_protection_config,
    _encrypt_b64,
)
from acd.l5x.elements import Routine, _RT_KEYHASH_OFF
from acd.record.comps import _SP_MARKER, _SP_KEYS, _sp_aes, _sp_cbc

RT_OFF = _RT_KEYHASH_OFF        # 202
KEY = bytes(range(48))          # a stand-in 48-byte EncodedSourceKey
ESK = base64.b64encode(KEY).decode().rstrip("=")


def _attr01(key=KEY, pad=b"\x00" * 18, flags=0, off=RT_OFF, tail=16, declared=None):
    """ext-attr 0x1 carrying a security descriptor at ``off``."""
    a1 = bytearray(off + 70 + tail)
    a1[off - 2:off] = struct.pack(
        "<H", len(key) + len(pad) if declared is None else declared)
    a1[off:off + len(key)] = key
    a1[off + 48:off + 48 + len(pad)] = pad
    a1[off + 66:off + 70] = struct.pack("<I", flags)
    return bytes(a1)


def _cbc_e(pt, key):
    from acd.record._aes import AES
    aes = AES(key)
    out = bytearray()
    prev = b"\x00" * 16
    for i in range(0, len(pt), 16):
        prev = aes.encrypt_block(bytes(x ^ y for x, y in zip(pt[i:i + 16], prev)))
        out += prev
    return bytes(out)


def _name_field(name):
    """The source key's 40-byte NUL-padded name field, PKCS7-padded to 48."""
    return name.ljust(40, b"\x00") + bytes([8]) * 8


def _filled_attr01(name=b"sample_srckey", tag=b"\xab\xcd", off=RT_OFF, tail=16):
    """ext-attr 0x1 carrying the FILLED (wrapped-key) descriptor form: the source
    key stored by NAME, wrapped under cfg5 with a per-definition frame tag, as the
    newer Studio writes it (its EncodedSourceKey is the name re-wrapped under the
    export config, NOT the slot bytes)."""
    k5 = dict(_SP_KEYS)[5]
    group_body = b"\x00\x05" + _cbc_e(_name_field(name), k5)   # version + wrapped
    framed = (tag + group_body[0:16] + tag + group_body[16:32]
              + tag + group_body[32:50] + tag)                 # 58 bytes
    framed += bytes([6]) * 6                                   # PKCS7 pad to 64
    slot = b"\x00\x05" + _cbc_e(framed, k5)                    # 66 bytes
    a1 = bytearray(off + 70 + tail)
    a1[off - 2:off] = struct.pack("<H", 66)
    a1[off:off + 66] = slot
    a1[off + 66:off + 70] = struct.pack("<I", 0)
    return bytes(a1)


def _body(marker=False):
    """A comps record body, with or without the source-protection-at-rest marker."""
    rec = bytearray(120)
    if marker:
        rec[78:82] = _SP_MARKER
    return bytes(rec)


def _routine(rtype="RLL", rungs=("XIC(a)OTE(b);",), **kw):
    return Routine(_name="Routine", name="R1", type=rtype, rungs=list(rungs), **kw)


# --- security descriptor ----------------------------------------------------
def test_reads_key_and_full_protection():
    assert security_descriptor(_attr01(flags=0), RT_OFF) == (ESK, "Full Protection")


def test_both_declared_lengths_of_our_scheme_read_identically():
    # The slot is a fixed 66 bytes either way, so a bare-key declaration and a
    # key-plus-padding one must yield the same key.
    assert (security_descriptor(_attr01(declared=48), RT_OFF)
            == security_descriptor(_attr01(declared=66), RT_OFF) == (ESK, "Full Protection"))


def test_viewable_is_flag_bit0():
    assert security_descriptor(_attr01(flags=1), RT_OFF)[1] == "Viewable"


def test_unrelated_flag_bits_do_not_change_protection_type():
    # bit 9 rides alongside bit 0 on real records and means something else.
    assert security_descriptor(_attr01(flags=0x200), RT_OFF)[1] == "Full Protection"
    assert security_descriptor(_attr01(flags=0x201), RT_OFF)[1] == "Viewable"


def test_key_is_read_at_the_offset_not_the_slot_start():
    a1 = _attr01(key=KEY)
    esk, _ = security_descriptor(a1, RT_OFF)
    assert base64.b64decode(esk + "==") == KEY


# --- filled (wrapped-key) form ----------------------------------------------
def test_filled_form_recovers_name_and_rewraps_under_export_config():
    # The filled slot stores the source key by NAME, wrapped; its EncodedSourceKey
    # is that name re-wrapped under the EXPORT config -- byte-identical to the
    # base64 the padded form keeps in the clear. Only public key material is used.
    esk, spt = security_descriptor(_filled_attr01(b"sample_srckey"), RT_OFF, 3)
    expected = base64.b64encode(
        _cbc_e(_name_field(b"sample_srckey"), dict(_SP_KEYS)[3])).decode().rstrip("=")
    assert esk == expected and spt == "Full Protection"


def test_filled_form_withheld_without_export_config():
    # No export config -> we cannot pick the re-wrap key -> withhold the blob.
    assert security_descriptor(_filled_attr01(), RT_OFF, None) is None


# --- fail-closed branches ---------------------------------------------------
def test_unknown_filled_shape_is_withheld():
    # A slot filled to all 66 bytes that is NOT the wrapped-key form (its lead
    # word is not the cfg5 version) is a shape we do not decode; reading the
    # first 48 would emit a WRONG key, so the non-zero padding withholds it.
    assert security_descriptor(_attr01(pad=bytes(range(1, 19))), RT_OFF) is None


def test_older_40_byte_key_scheme_is_withheld():
    # The 40-byte-key scheme zero-fills the rest of the slot exactly as ours
    # does, so the padding check passes and ONLY the declared length catches it.
    # Reading 48 bytes here would splice 8 padding bytes onto a 40-byte key and
    # emit that under the wrong @EncryptionConfig.
    a1 = _attr01(key=bytes(range(40)), pad=b"\x00" * 26, declared=40)
    assert a1[RT_OFF + 48:RT_OFF + 66] == b"\x00" * 18   # padding gate passes
    assert security_descriptor(a1, RT_OFF) is None       # length gate catches it


def test_older_scheme_has_no_derivable_config():
    a1 = _attr01(key=bytes(range(40)), pad=b"\x00" * 26, declared=40)
    assert source_protection_config(_body(), a1, RT_OFF) is None


def test_unknown_declared_length_is_withheld():
    assert security_descriptor(_attr01(declared=64), RT_OFF) is None
    assert source_protection_config(_body(), _attr01(declared=64), RT_OFF) is None


def test_missing_attr01_is_withheld():
    assert security_descriptor(None, RT_OFF) is None


def test_truncated_attr01_is_withheld():
    assert security_descriptor(_attr01()[:RT_OFF + 60], RT_OFF) is None


def test_encrypted_tail_layout_has_no_derivable_config():
    assert source_protection_config(_body(marker=True), _attr01(), RT_OFF) is None


def test_plaintext_keybearing_layout_is_config_3():
    assert source_protection_config(_body(), _attr01(), RT_OFF) == 3


def test_config_none_withholds_the_blob():
    assert encoded_routine(_routine(), _attr01(), RT_OFF, None) is None


def test_unserializable_routine_type_is_withheld():
    assert encoded_routine(_routine(rtype="FBD"), _attr01(), RT_OFF, 3) is None


def test_st_routine_without_lines_is_withheld():
    assert encoded_routine(_routine(rtype="ST"), _attr01(), RT_OFF, 3) is None


def test_config_without_a_key_is_withheld():
    assert encoded_routine(_routine(), _attr01(), RT_OFF, 9) is None


# --- element / document -----------------------------------------------------
def _decrypt(body, config=3):
    raw = base64.b64decode(body + "=" * (-len(body) % 4))
    aes = _sp_aes(config, dict(_SP_KEYS)[config])
    pt = _sp_cbc(raw, aes, len(raw) // 16)
    return pt[:-pt[-1]].decode("utf-16-le")


def test_element_shape_and_attribute_order():
    xml = encoded_routine(_routine(), _attr01(), RT_OFF, 3)
    assert xml.startswith('<EncodedData EncodedType="Routine" Name="R1"'
                          ' Type="RLL" EncryptionConfig="3">\n')
    assert xml.endswith("</EncodedData>")


def test_body_is_single_line_base64_with_padding_stripped():
    xml = encoded_routine(_routine(), _attr01(), RT_OFF, 3)
    body = xml.split(">\n", 1)[1][: -len("</EncodedData>")]
    assert "=" not in body and "\n" not in body


def test_body_decrypts_to_the_inner_document():
    xml = encoded_routine(_routine(), _attr01(flags=1), RT_OFF, 3)
    body = xml.split(">\n", 1)[1][: -len("</EncodedData>")]
    doc = _decrypt(body)
    assert doc.startswith('<?xml version="1.0" encoding="UTF-16" standalone="yes"?>\n')
    assert (f'<Routine Name="R1" Type="RLL" EncodedSourceKey="{ESK}"'
            ' SourceProtectionType="Viewable">') in doc
    assert "<![CDATA[XIC(a)OTE(b);]]>" in doc
    assert doc.endswith("</Routine>\n")


def test_inner_document_keeps_empty_rungs_and_does_not_strip():
    # Unlike Routine.to_xml, the encoded document preserves rung indices verbatim.
    xml = encoded_routine(_routine(rungs=("", " A;")), _attr01(), RT_OFF, 3)
    doc = _decrypt(xml.split(">\n", 1)[1][: -len("</EncodedData>")])
    assert '<Rung Number="0" Type="N">\n<Text>\n<![CDATA[]]>' in doc
    assert '<Rung Number="1" Type="N">\n<Text>\n<![CDATA[ A;]]>' in doc


def test_rung_comment_precedes_text():
    rt = _routine()
    rt._rung_comments = {0: "hi"}
    doc = _decrypt(encoded_routine(rt, _attr01(), RT_OFF, 3)
                   .split(">\n", 1)[1][: -len("</EncodedData>")])
    assert "<Comment>\n<![CDATA[hi]]>\n</Comment>\n<Text>" in doc


def test_st_routine_emits_st_content():
    rt = _routine(rtype="ST", rungs=[])
    rt._st_lines = ["a := 1;", ""]
    doc = _decrypt(encoded_routine(rt, _attr01(), RT_OFF, 3)
                   .split(">\n", 1)[1][: -len("</EncodedData>")])
    assert '<STContent>\n<Line Number="0">\n<![CDATA[a := 1;]]>\n</Line>\n' in doc
    assert "<RLLContent>" not in doc


def test_description_precedes_content():
    rt = _routine(_description="d")
    xml = encoded_routine(rt, _attr01(), RT_OFF, 3)
    body = xml.split(">\n", 1)[1].split("</Description>\n", 1)[1][: -len("</EncodedData>")]
    assert "<Description>\n<![CDATA[d]]>\n</Description>\n<RLLContent>" in _decrypt(body)


def test_description_is_repeated_in_plaintext_on_the_element():
    # The blob hides the logic, not the description: Studio emits it BOTH inside
    # the document and as a plaintext child ahead of the base64. Omitting the
    # child costs element_missing:Description AND text_mismatch:EncodedData,
    # because the base64 then sits in .text rather than the child's tail.
    xml = encoded_routine(_routine(_description="d"), _attr01(), RT_OFF, 3)
    head, rest = xml.split(">\n", 1)
    assert rest.startswith("<Description>\n<![CDATA[d]]>\n</Description>\n")


def test_no_description_emits_no_plaintext_child():
    xml = encoded_routine(_routine(), _attr01(), RT_OFF, 3)
    assert "<Description>" not in xml
    assert xml.split(">\n", 1)[1][:4] not in ("<Des",)


def test_name_is_xml_escaped_in_both_the_element_and_the_document():
    rt = _routine()
    rt.name = 'A&B"'
    xml = encoded_routine(rt, _attr01(), RT_OFF, 3)
    assert 'Name="A&amp;B&quot;"' in xml.split(">\n", 1)[0]
    doc = _decrypt(xml.split(">\n", 1)[1][: -len("</EncodedData>")])
    assert 'Name="A&amp;B&quot;"' in doc


def test_cipher_is_cbc_iv_zero_pkcs7():
    # A whole-block plaintext still gets a full block of padding.
    body = _encrypt_b64(b"0123456789abcdef", 3)
    raw = base64.b64decode(body + "=" * (-len(body) % 4))
    assert len(raw) == 32
    aes = _sp_aes(3, dict(_SP_KEYS)[3])
    assert _sp_cbc(raw, aes, 2)[16:] == bytes([16]) * 16


def test_routine_to_xml_renders_the_blob_verbatim():
    rt = _routine()
    rt._encoded = "<EncodedData/>"
    assert rt.to_xml() == "<EncodedData/>"
