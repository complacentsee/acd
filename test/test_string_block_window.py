"""Pins the Format="String" block's element-bounded DATA window.

The <Data Format="String" Length="L"> block renders element [0] only: L is
the element's stored 32-bit LEN read UNSIGNED, and the CDATA covers the
element's DATA bytes. A malformed LEN (larger than the element's capacity)
clamps to the element's remaining image verbatim -- DATA capacity plus
trailing pad, garbage included -- and never runs into element [1]. Validated
against every OEM Format="String" block with a raw-hex image (1194 blocks,
386 arrays / 808 scalars, 0 violations); the corrupt-LEN array shape is the
uninitialised STRING[50] event-log tag family.
"""

import re

from acd.l5x import elements as E


def _string_elem(length_word: bytes, data: bytes, pad: bytes) -> bytes:
    """One padded STRING element image: LEN word + DATA[82] + 2 pad bytes."""
    assert len(length_word) == 4 and len(data) == 82 and len(pad) == 2
    return length_word + data + pad


def _render(dimensions, value_bytes, string_array_as_string):
    return E._render_value_blocks(
        "Data", "STRING", dimensions, value_bytes, {},
        taginfo_layout=None, radix=None, raw_hex_first=True,
        string_array_as_string=string_array_as_string, require_pair=True,
    )


def _string_block(out):
    m = re.search(
        r'<Data Format="String" Length="(\d+)">\n<!\[CDATA\[\'(.*)\'\]\]>'
        r'\n</Data>', out, re.S)
    assert m, out
    return int(m.group(1)), m.group(2)


def test_scalar_valid_len():
    img = _string_elem((5).to_bytes(4, "little"),
                       b"HELLO" + bytes(77), bytes(2))
    length, text = _string_block(_render(None, img, False))
    assert length == 5
    assert text == "HELLO"


def test_scalar_malformed_len_clamps_to_own_image():
    img = _string_elem(bytes.fromhex("53040080"), b"A" * 82, b"BB")
    length, text = _string_block(_render(None, img, False))
    # LEN prints as the unsigned 32-bit value; the window is the element's
    # remaining 84 bytes (DATA + pad) verbatim.
    assert length == 0x80000453
    assert text == "A" * 82 + "BB"


def test_array_malformed_len_stops_at_element_boundary():
    e0 = _string_elem(bytes.fromhex("53040080"), b"A" * 82, b"BB")
    e1 = _string_elem((4).to_bytes(4, "little"),
                      b"WXYZ" + bytes(78), bytes(2))
    length, text = _string_block(_render("2", e0 + e1, True))
    assert length == 0x80000453
    # Exactly element [0]'s 84 remaining bytes -- never element [1]'s.
    assert text == "A" * 82 + "BB"
    assert "W" not in text


def test_array_valid_len_unchanged():
    e0 = _string_elem((3).to_bytes(4, "little"),
                      b"YES" + bytes(79), bytes(2))
    e1 = _string_elem((4).to_bytes(4, "little"),
                      b"WXYZ" + bytes(78), bytes(2))
    length, text = _string_block(_render("2", e0 + e1, True))
    assert length == 3
    assert text == "YES"
