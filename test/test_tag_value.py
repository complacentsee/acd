"""Golden tests for the pure byte->string renderers in acd.l5x.tag_value.

These are the leaf formatters the two duplicated layout walkers
(render_decorated / render_l5k) share.  Pinning them here means the P4
walker-unification work can consolidate the traversal with a guard that the
actual value/format bytes never move.  Every expectation is an OEM-verified
Logix form (bit-packed BOOL arrays, Radix literals, the 1.#INF/1.#QNAN and
e+NNN float encodings, $-escapes) -- see the campaign history for the diffs
each one pins (d49ae5a BOOL bit-unpack, 48c8221 L5K BOOL, 559ee27 radix).
"""

import struct

from acd.l5x import tag_value as T


# --------------------------------------------------------------------------- #
# BOOL-array bit-unpacking -- fixed twice (render_decorated d49ae5a, render_l5k
# 48c8221) because the walkers duplicate the traversal.  Pin BOTH paths.
# --------------------------------------------------------------------------- #


def test_bool_array_decorated_is_bit_packed():
    # 10 elements packed into 2 bytes: 0b01010101, 0b00000001 -> low bit LSB-first.
    xml = T.render_decorated("BOOL", "10", bytes([0b01010101, 0x01]), {})
    assert xml.startswith('<Array DataType="BOOL" Dimensions="10" Radix="Decimal">')
    values = [c.split('Value="')[1][0] for c in xml.split("<Element")[1:]]
    assert values == ["1", "0", "1", "0", "1", "0", "1", "0", "1", "0"]


def test_bool_array_l5k_is_bit_packed():
    l5k = T.render_l5k("BOOL", "10", bytes([0b01010101, 0x01]), {})
    assert l5k == "[2#1,2#0,2#1,2#0,2#1,2#0,2#1,2#0,2#1,2#0]"


def test_bool_array_decorated_needs_ceil_div_8_bytes():
    # 32 elements require 4 bytes; 3 bytes must return None, not run off the image.
    assert T.render_decorated("BOOL", "32", b"\x00\x00\x00", {}) is None
    assert T.render_decorated("BOOL", "32", b"\x00\x00\x00\x00", {}) is not None


# --------------------------------------------------------------------------- #
# Float formatting -- Logix's non-IEEE textual forms
# --------------------------------------------------------------------------- #


def test_fmt_real_decorated_edges():
    assert T._fmt_real_decorated(0.0) == "0.0"
    assert T._fmt_real_decorated(-0.0) == "-0.0"
    assert T._fmt_real_decorated(1.5) == "1.5"
    assert T._fmt_real_decorated(-3.25) == "-3.25"
    assert T._fmt_real_decorated(float("inf")) == "1.#INF"
    assert T._fmt_real_decorated(float("-inf")) == "-1.#INF"
    assert T._fmt_real_decorated(float("nan")) == "1.#QNAN"


def test_fmt_real_l5k_uses_exponential_form():
    # L5K/raw atomic text uses the fixed 8-digit-mantissa e+NNN form.
    assert T._atomic_text("REAL", struct.pack("<f", 1.5)) == "1.50000000e+000"
    assert T._atomic_text("REAL", struct.pack("<f", 0.1)) == "1.00000000e-001"


def test_fmt_lreal_decorated_edges():
    assert T._fmt_lreal_decorated(0.0) == "0.0"
    assert T._fmt_lreal_decorated(0.1) == "0.1"
    assert T._fmt_lreal_decorated(3.141592653589793) == "3.14159265e+000"


# --------------------------------------------------------------------------- #
# Integer radix formatting
# --------------------------------------------------------------------------- #


def test_format_int_radix_hex():
    assert T._format_int_radix("DINT", 255, 4, "Hex") == "16#0000_00ff"
    assert T._format_int_radix("SINT", -1, 1, "Hex") == "16#ff"


def test_format_int_radix_binary():
    assert (T._format_int_radix("DINT", 5, 4, "Binary")
            == "2#0000_0000_0000_0000_0000_0000_0000_0101")


def test_format_int_radix_octal_decimal():
    assert T._format_int_radix("DINT", 8, 4, "Octal") == "8#10"
    assert T._format_int_radix("DINT", -5, 4, "Decimal") == "-5"
    assert T._format_int_radix("DINT", -5, 4, None) == "-5"


def test_format_int_radix_ascii_escapes():
    assert T._format_int_radix("SINT", 0x41, 1, "ASCII") == "&apos;A&apos;"
    assert T._format_int_radix("SINT", 0x24, 1, "ASCII") == "&apos;$$&apos;"
    assert T._format_int_radix("SINT", 0x00, 1, "ASCII") == "&apos;$00&apos;"


# --------------------------------------------------------------------------- #
# Char / string escaping
# --------------------------------------------------------------------------- #


def test_sint_char_escape():
    assert T._sint_char_escape(0x24) == "$$"      # '$'
    assert T._sint_char_escape(0x27) == "$'"      # "'"
    assert T._sint_char_escape(0x09) == "$t"
    assert T._sint_char_escape(0x41) == "A"
    assert T._sint_char_escape(0x00) == "$00"
    assert T._sint_char_escape(0x7F) == "$7F"


def test_ascii_string_cdata():
    assert T._ascii_string_cdata(b"Hi") == "Hi"
    assert T._ascii_string_cdata(b"a\tb") == "a$tb"
    assert T._ascii_string_cdata(b"$x") == "$$x"
    assert T._ascii_string_cdata(b"'q'") == "$'q$'"
    assert T._ascii_string_cdata(b"\x00\x01") == "$00$01"
    assert T._ascii_string_cdata(b"") == ""


# --------------------------------------------------------------------------- #
# Dimensions / index math
# --------------------------------------------------------------------------- #


def test_dims_total_accepts_space_and_comma():
    # Tag attribute form is space-separated; AOI param form is comma-separated.
    assert T._dims_total("2 3") == (6, [2, 3])
    assert T._dims_total("2,3") == (6, [2, 3])
    assert T._dims_total("4") == (4, [4])
    assert T._dims_total(None) == (0, [])
    assert T._dims_total("") == (0, [])


def test_index_str_1d_and_multidim():
    assert T._index_str(3, [10]) == "[3]"
    # dims [2,3,4] row-major, last fastest: flat 17 -> [1,1,1] (1*12 + 1*4 + 1).
    assert T._index_str(17, [2, 3, 4]) == "[1,1,1]"
    assert T._index_str(0, [2, 3, 4]) == "[0,0,0]"


# --------------------------------------------------------------------------- #
# L5K wrapping
# --------------------------------------------------------------------------- #


def test_wrap_l5k_passthrough_short():
    assert T._wrap_l5k("50", 2) == "50"            # scalar, no brackets
    assert T._wrap_l5k("[1,2,3]", 2) == "[1,2,3]"  # under budget


def test_wrap_l5k_breaks_at_budget():
    flat = "[" + ",".join(str(i % 10) for i in range(120)) + "]"
    wrapped = T._wrap_l5k(flat, 2, budget=81)
    # A break is "\n" + depth tabs, inserted before a separator once the value
    # column reaches the budget; brackets/commas cost 0 columns.
    assert "\n" + "\t" * 2 in wrapped
    # Stripping the inserted breaks recovers the original flat list.
    assert wrapped.replace("\n" + "\t" * 2, "") == flat


# --------------------------------------------------------------------------- #
# Small end-to-end renders that exercise the atomic scalar / struct paths
# --------------------------------------------------------------------------- #


def test_render_decorated_scalar_honors_radix():
    xml = T.render_decorated("DINT", None, (255).to_bytes(4, "little"), {},
                             radix="Hex")
    assert xml == '<DataValue DataType="DINT" Radix="Hex" Value="16#0000_00ff"/>'


def test_render_l5k_timer_struct_words():
    # TIMER image = status word, PRE, ACC as int32 -> "[status,PRE,ACC]".
    img = struct.pack("<iii", 0, 1000, 500)
    assert T.render_l5k("TIMER", None, img, {}) == "[0,1000,500]"
