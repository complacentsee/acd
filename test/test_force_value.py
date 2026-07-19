"""@ForceValue rendering: the installed-force overlay on Decorated members.

Pins the three things that are easy to get wrong and expensive to get wrong:

  * the SPELLING is not the member's display radix. @ForceValue is always the
    raw bit pattern in base 2, one '.' per unforced bit, as wide as the
    datatype -- a Decimal DINT and a Hex SINT both force in 2# form. BOOL is
    the sole exception and renders bare.
  * PRESENCE is per-member and mask-driven (G2): a member with no set mask bit
    gets no attribute at all.
  * the force images are OPTIONAL, and omitting them must leave every existing
    caller's bytes untouched. The walker they thread through is shared by the
    whole corpus's tags (value images, DefaultData and the L5K storage form),
    so a slicing bug here would be corpus-wide rather than force-local.
"""

from types import SimpleNamespace as NS

from acd.l5x import tag_value as TV


def _m(name, dt, radix=None):
    return NS(name=name, data_type=dt, radix=radix)


# A struct with one member per force-relevant shape: a Decimal DINT (radix
# independence), a Hex SINT (ditto), an INT with a BOOL aliased onto one of its
# bits (one mask bit -> two attributes), and a DINT array (Element carrier).
_LAYOUT = {
    "FT": [
        ("D", "DINT", 0, None, False, None),
        ("S", "SINT", 4, None, False, None),
        ("W", "INT", 6, None, False, None),
        ("Flag", "BOOL", 6, 7, False, None),
        ("Arr", "DINT", 8, None, False, [2]),
    ],
    "@size@FT": 16,
}
_DTM = {"FT": NS(members=[_m("D", "DINT", "Decimal"), _m("S", "SINT", "Hex"),
                          _m("W", "INT", "Binary"), _m("Flag", "BOOL"),
                          _m("Arr", "DINT", "Decimal")])}

_IMAGE = bytes(16)


def _render(fmask=None, fval=None):
    return TV.render_decorated_layout("FT", None, _IMAGE, _LAYOUT, _DTM,
                                      fmask=fmask, fval=fval)


def test_force_str_is_binary_regardless_of_radix_and_width():
    # DINT (4 bytes) -> 32 bits in 8 groups of 4; little-endian, MSB..LSB, so
    # byte 2's bit 5 is bit 21 and lands 31-21=10 characters in from the left.
    # bit 0 forced to 1, bit 21 forced to 0.
    mask = bytes([0x01, 0x00, 0x20, 0x00])
    val = bytes([0x01, 0x00, 0x00, 0x00])
    assert TV._force_str(mask, val) == \
        "2#...._...._..0._...._...._...._...._...1"
    # SINT (1 byte) -> 8 bits in 2 groups of 4.
    assert TV._force_str(bytes([0x01]), bytes([0x00])) == "2#...._...0"


def test_force_str_returns_none_when_no_mask_bit_is_set():
    # G2: an all-'.' string is never written by Logix -- the attribute is
    # omitted entirely. Pool B carries ForceData blobs whose mask is all zero,
    # and they must render no @ForceValue at all.
    assert TV._force_str(bytes(4), bytes(4)) is None


def test_decimal_dint_and_hex_sint_keep_their_value_radix_but_force_binary():
    fmask = bytearray(16)
    fmask[0] = 0x01          # D bit 0, forced to 0 (fval[0] stays clear)
    fmask[4] = 0x80          # S bit 7, forced to 1
    fval = bytearray(16)
    fval[4] = 0x80
    out = _render(bytes(fmask), bytes(fval))
    assert ('<DataValueMember Name="D" DataType="DINT" Radix="Decimal" '
            'Value="0" '
            'ForceValue="2#...._...._...._...._...._...._...._...0"/>') in out
    assert ('<DataValueMember Name="S" DataType="SINT" Radix="Hex" '
            'Value="16#00" ForceValue="2#1..._...."/>') in out


def test_one_mask_bit_yields_both_the_integer_and_its_aliased_bool():
    # A BOOL overlaying bit 7 of an INT is a real Logix shape (drive status
    # words). The single mask bit legitimately produces TWO attributes: the
    # INT's bit pattern and the BOOL's bare value. This is not double-emission.
    fmask = bytearray(16)
    fmask[6] = 0x80
    fval = bytearray(16)
    out = _render(bytes(fmask), bytes(fval))
    assert ('Name="W" DataType="INT" Radix="Binary" '
            'Value="2#0000_0000_0000_0000" '
            'ForceValue="2#...._...._0..._...."/>') in out
    # BOOL forces bare -- no 2# prefix, no grouping.
    assert 'Name="Flag" DataType="BOOL" Value="0" ForceValue="0"/>' in out


def test_array_element_carries_force_only_on_the_forced_element():
    fmask = bytearray(16)
    fmask[12] = 0x02          # Arr[1] bit 1
    fval = bytearray(16)
    fval[12] = 0x02
    out = _render(bytes(fmask), bytes(fval))
    assert '<Element Index="[0]" Value="0"/>' in out          # untouched
    assert ('<Element Index="[1]" Value="0" ForceValue='
            '"2#...._...._...._...._...._...._...._..1."/>') in out


def test_omitting_the_force_images_is_byte_identical():
    # The invariant that protects the corpus: render_decorated_layout and the
    # walker beneath it are shared by every tag, so the force parameters must
    # be inert when absent.
    assert _render() == _render(None, None)
    assert "ForceValue" not in _render()
    # An all-zero mask must also be inert (G2 at every carrier).
    assert _render(bytes(16), bytes(16)) == _render()


def test_l5k_storage_form_never_carries_force():
    # Installed forces are a runtime overlay, not part of the design-value
    # image, and _emit_l5k unpacks the walker's nodes at exact arity -- this
    # pins both facts for the L5K path.
    fmask = bytearray(16)
    fmask[0] = 0x01
    fval = bytearray(16)
    fval[0] = 0x01
    plain = TV.render_l5k_layout("FT", None, _IMAGE, _LAYOUT, _DTM)
    assert plain is not None
    assert "ForceValue" not in plain
    node = TV._walk_struct("FT", _IMAGE, _LAYOUT, _DTM, 0,
                           bytes(fmask), bytes(fval))
    assert TV._emit_l5k(node) == plain


def test_strip_input_tag_inner_force_block_era_keyed():
    from acd.l5x.connections import _strip_input_tag_inner
    inner = ('<Data Format="L5K">\n<![CDATA[[1,2]]]>\n</Data>'
             '<ForceData Format="L5K">\n<![CDATA[[0,0,1,0,3,0]]]>\n'
             '</ForceData>'
             '<Data Format="Decorated"><DataValue DataType="INT" '
             'Value="1"/></Data>')
    # Raw-hex era (default): ForceData is kept in the captured inner.
    assert "ForceData" in _strip_input_tag_inner(inner)
    # L5K era: the connection InputTag never carries ForceData.
    out = _strip_input_tag_inner(inner, strip_force=True)
    assert "ForceData" not in out and 'Format="Decorated"' in out
