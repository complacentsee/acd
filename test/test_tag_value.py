"""Golden tests for the pure byte->string renderers in acd.l5x.tag_value.

These are the leaf formatters the two duplicated layout walkers
(render_decorated / render_l5k) share.  Pinning them here means the P4
walker-unification work can consolidate the traversal with a guard that the
actual value/format bytes never move.  Every expectation is an OEM-verified
Logix form (bit-packed BOOL arrays, Radix literals, the 1.$/1.#QNAN and
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
    # A stored negative zero prints as plain 0.0 (the reference never emits
    # "-0.0" anywhere in either pool's exports).
    assert T._fmt_real_decorated(-0.0) == "0.0"
    assert T._fmt_real_decorated(1.5) == "1.5"
    assert T._fmt_real_decorated(-3.25) == "-3.25"
    assert T._fmt_real_decorated(float("inf")) == "1.$"
    assert T._fmt_real_decorated(float("-inf")) == "-1.$"
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


# --------------------------------------------------------------------------- #
# Layout-walker goldens (P4 C2) -- pin the L5K and Decorated LAYOUT walkers,
# including their deliberate asymmetries, so the traversal can be unified
# without moving a byte:
#   * L5K serialises STORAGE: hidden members included, scalar BOOLs whose byte
#     falls inside a wider member (bit-aliases) skipped.
#   * Decorated serialises the VIEW: hidden members skipped, bit-alias BOOLs
#     included (Radix attr only on byte-aligned BOOLs, i.e. bit is None).
#   * STRING: L5K emits the FULL DATA capacity ($00-padded); Decorated emits
#     only the active LEN characters (single-quoted when non-empty).
#   * A member that fails to decode only fails the walker that includes it.
# layout_map member tuples: (name, mdt, byte_offset, bit_or_None, hidden,
# dims_list_or_None); "@size@NAME" carries the struct stride.
# --------------------------------------------------------------------------- #


_U_LAYOUT = {
    "U": [
        ("D", "DINT", 0, None, False, None),
        ("AliasB", "BOOL", 0, 5, False, None),   # overlays D's byte 0
        ("SA", "SINT", 4, None, False, [2]),
        ("BA", "BOOL", 6, None, False, None),    # byte-aligned scalar BOOL
        ("H", "DINT", 8, None, True, None),      # hidden storage member
        ("BArr", "BOOL", 12, None, False, [10]),
    ],
    "@size@U": 16,
}

# D=120 (byte0 0x78 -> bit5 = 1), SA=[7,-2], BA=1, H=9, BArr bits 0b01010101,0x01
_U_IMAGE = bytes([0x78, 0, 0, 0, 0x07, 0xFE, 0x01, 0,
                  9, 0, 0, 0, 0x55, 0x01, 0, 0])


def test_l5k_layout_includes_hidden_skips_bit_alias():
    l5k = T.render_l5k_layout("U", None, _U_IMAGE, _U_LAYOUT, {})
    assert l5k == "[120,[7,-2],1,9,[1,0,1,0,1,0,1,0,1,0]]"


def test_decorated_layout_skips_hidden_includes_bit_alias():
    xml = T.render_decorated_layout("U", None, _U_IMAGE, _U_LAYOUT, {})
    assert xml == (
        '<Structure DataType="U">'
        '<DataValueMember Name="D" DataType="DINT" Radix="Decimal" Value="120"/>'
        '<DataValueMember Name="AliasB" DataType="BOOL" Value="1"/>'
        '<ArrayMember Name="SA" DataType="SINT" Dimensions="2" Radix="Decimal">'
        '<Element Index="[0]" Value="7"/><Element Index="[1]" Value="-2"/>'
        '</ArrayMember>'
        '<DataValueMember Name="BA" DataType="BOOL" Radix="Decimal" Value="1"/>'
        '<ArrayMember Name="BArr" DataType="BOOL" Dimensions="10" Radix="Decimal">'
        + "".join(f'<Element Index="[{i}]" Value="{v}"/>'
                  for i, v in enumerate([1, 0, 1, 0, 1, 0, 1, 0, 1, 0]))
        + '</ArrayMember>'
        '</Structure>'
    )


def test_decorated_layout_honors_member_def_radix():
    class _M:
        def __init__(self, name, radix):
            self.name, self.radix = name, radix

    class _DT:
        members = [_M("D", "Hex")]

    xml = T.render_decorated_layout("U", None, _U_IMAGE, _U_LAYOUT, {"U": _DT()})
    assert '<DataValueMember Name="D" DataType="DINT" Radix="Hex" ' \
           'Value="16#0000_0078"/>' in xml
    # L5K stays plain signed decimal regardless of the member radix.
    assert T.render_l5k_layout("U", None, _U_IMAGE, _U_LAYOUT, {"U": _DT()}
                               ).startswith("[120,")


_FAIL_LAYOUT = {
    "U2": [
        ("D", "DINT", 0, None, False, None),
        ("SA", "SINT", 4, None, False, [2]),
        ("BA", "BOOL", 6, None, False, None),
        ("H", "DINT", 8, None, True, None),   # hidden; needs bytes 8..11
    ],
    "@size@U2": 12,
}


def test_walker_failure_is_per_consumer():
    # 8-byte image: every VISIBLE member decodes, the hidden H does not.
    img = bytes([0x78, 0, 0, 0, 0x07, 0xFE, 0x01, 0])
    assert T.render_l5k_layout("U2", None, img, _FAIL_LAYOUT, {}) is None
    xml = T.render_decorated_layout("U2", None, img, _FAIL_LAYOUT, {})
    assert xml is not None and 'Name="H"' not in xml


_NEST_LAYOUT = {
    "INNER": [("X", "INT", 0, None, False, None)],
    "@size@INNER": 4,
    "OUTER": [
        ("N", "INNER", 0, None, False, None),
        ("NA", "INNER", 4, None, False, [2]),
    ],
    "@size@OUTER": 12,
}

_NEST_IMAGE = struct.pack("<hxxhxxhxx", 5, 1, 2)


def test_layout_walkers_nested_struct_and_struct_array():
    assert (T.render_l5k_layout("OUTER", None, _NEST_IMAGE, _NEST_LAYOUT, {})
            == "[[5],[[1],[2]]]")
    xml = T.render_decorated_layout("OUTER", None, _NEST_IMAGE, _NEST_LAYOUT, {})
    assert xml == (
        '<Structure DataType="OUTER">'
        '<StructureMember Name="N" DataType="INNER">'
        '<DataValueMember Name="X" DataType="INT" Radix="Decimal" Value="5"/>'
        '</StructureMember>'
        '<ArrayMember Name="NA" DataType="INNER" Dimensions="2">'
        '<Element Index="[0]"><Structure DataType="INNER">'
        '<DataValueMember Name="X" DataType="INT" Radix="Decimal" Value="1"/>'
        '</Structure></Element>'
        '<Element Index="[1]"><Structure DataType="INNER">'
        '<DataValueMember Name="X" DataType="INT" Radix="Decimal" Value="2"/>'
        '</Structure></Element>'
        '</ArrayMember>'
        '</Structure>'
    )


def test_layout_walkers_top_level_struct_array():
    img = struct.pack("<hxxhxx", 1, 2)
    assert (T.render_l5k_layout("INNER", "2", img, _NEST_LAYOUT, {})
            == "[[1],[2]]")
    xml = T.render_decorated_layout("INNER", "2", img, _NEST_LAYOUT, {})
    assert xml == (
        '<Array DataType="INNER" Dimensions="2">'
        '<Element Index="[0]"><Structure DataType="INNER">'
        '<DataValueMember Name="X" DataType="INT" Radix="Decimal" Value="1"/>'
        '</Structure></Element>'
        '<Element Index="[1]"><Structure DataType="INNER">'
        '<DataValueMember Name="X" DataType="INT" Radix="Decimal" Value="2"/>'
        '</Structure></Element>'
        '</Array>'
    )


_STR_LAYOUT = {
    "S6": [
        ("LEN", "DINT", 0, None, False, None),
        ("DATA", "SINT", 4, None, False, [6]),
    ],
    "@size@S6": 12,
}


def test_layout_walkers_string_shape():
    img = struct.pack("<i", 2) + b"Hi\x00\x00\x00\x00"
    # L5K: LEN + the FULL DATA capacity, NULs $-escaped.
    assert (T.render_l5k_layout("S6", None, img, _STR_LAYOUT, {})
            == "[2,'Hi$00$00$00$00']")
    # Decorated: only the LEN active chars, single-quoted inside the CDATA.
    xml = T.render_decorated_layout("S6", None, img, _STR_LAYOUT, {})
    assert xml == (
        '<Structure DataType="S6">'
        '<DataValueMember Name="LEN" DataType="DINT" Radix="Decimal" Value="2"/>'
        '<DataValueMember Name="DATA" DataType="S6" Radix="ASCII">\n'
        "<![CDATA['Hi']]>\n</DataValueMember>"
        '</Structure>'
    )


def test_layout_walkers_empty_string_has_no_quotes():
    img = struct.pack("<i", 0) + b"\x00" * 6
    assert (T.render_l5k_layout("S6", None, img, _STR_LAYOUT, {})
            == "[0,'$00$00$00$00$00$00']")
    xml = T.render_decorated_layout("S6", None, img, _STR_LAYOUT, {})
    assert "<![CDATA[]]>" in xml


# --------------------------------------------------------------------------- #
# Walker robustness on malformed layout_maps (never raise; degrade to None /
# render the members that DO decode). These pin the entry-point contract on
# adversarial inputs that real TagInfo extraction cannot produce -- found by
# fuzzing the unification.
# --------------------------------------------------------------------------- #


def test_decorated_zero_len_struct_array_of_unresolvable_type_is_none():
    # dims=[0] array whose element type has a stride but no member list:
    # Decorated refuses (needs the layout); L5K renders from the stride alone.
    lm = {"PARENT": [("Arr", "Elem", 0, None, False, [0])], "@size@ELEM": 8}
    assert T.render_decorated_layout("PARENT", None, b"", lm, {}) is None
    assert T.render_l5k_layout("PARENT", None, b"", lm, {}) == "[[]]"


def test_cyclic_layout_degrades_instead_of_recursing():
    # Self-referential type reachable only via a hidden member: the visible
    # members still render (Decorated); L5K includes the hidden member, cannot
    # decode it, and degrades to None. Neither entry point may raise.
    lm = {
        "PARENT": [("Vis", "DINT", 0, None, False, None),
                   ("Hid", "CYC", 4, None, True, None)],
        "CYC": [("Self", "CYC", 0, None, False, None)],
    }
    img = b"\x01\x00\x00\x00\x00\x00\x00\x00"
    assert T.render_decorated_layout("PARENT", None, img, lm, {}) == (
        '<Structure DataType="PARENT">'
        '<DataValueMember Name="Vis" DataType="DINT" Radix="Decimal" Value="1"/>'
        '</Structure>'
    )
    assert T.render_l5k_layout("PARENT", None, img, lm, {}) is None


def test_negative_offsets_never_raise():
    # A policy-skipped member with a negative offset must not blow up the
    # serialisation that skips it, and must degrade (None) the one that
    # includes it.
    lm = {"X": [("h", "DINT", -50, None, True, None),
                ("v", "DINT", 0, None, False, None)]}
    img = b"\x07\x00\x00\x00\x00\x00\x00\x00"
    assert T.render_decorated_layout("X", None, img, lm, {}) == (
        '<Structure DataType="X">'
        '<DataValueMember Name="v" DataType="DINT" Radix="Decimal" Value="7"/>'
        '</Structure>'
    )
    assert T.render_l5k_layout("X", None, img, lm, {}) is None
    # Bit-alias BOOL with a pathological negative bit index: L5K skips the
    # alias (renders the covering member), Decorated degrades to None.
    lm2 = {"P": [("BASE", "SINT", 0, None, False, None),
                 ("B", "BOOL", 0, -800, False, None)]}
    assert T.render_l5k_layout("P", None, b"\x07\x00\x00\x00", lm2, {}) == "[7]"
    assert T.render_decorated_layout("P", None, b"\x07\x00\x00\x00", lm2, {}) is None


def test_depth_capped_self_reference_terminates_quickly():
    # A self-referential array member walks to the depth cap; the walk must
    # short-circuit (not explore branching**24 elements) and keep the old
    # outputs: Decorated skips the hidden member, L5K degrades to None.
    lm = {"T1": [("B0", "T1", 0, 5, True, [2])], "@size@T1": 8}
    xml = T.render_decorated_layout("T1", "3", b"\x00" * 24, lm, {})
    assert xml == (
        '<Array DataType="T1" Dimensions="3">'
        '<Element Index="[0]"><Structure DataType="T1"></Structure></Element>'
        '<Element Index="[1]"><Structure DataType="T1"></Structure></Element>'
        '<Element Index="[2]"><Structure DataType="T1"></Structure></Element>'
        '</Array>'
    )
    assert T.render_l5k_layout("T1", "3", b"\x00" * 24, lm, {}) is None
