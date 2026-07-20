"""Pins the Decorated-block omission ceilings.

Studio omits the <Data Format="Decorated"> block for a tag whose Decorated tree
exceeds a global ELEMENT-count ceiling (_DECORATED_MAX_ELEMS = 2^15) OR whose raw
value image exceeds a global BYTE ceiling (_DECORATED_MAX_L5K_BYTES), keeping only
the compact flat first block; below both, the pair is emitted. The element metric
is the number of element start tags in the generated body (CDATA text excluded);
the byte metric catches a low-count-but-huge-image tag (e.g. a Revision UDT) the
element count misses. Both are validated 0 wrong-suppress over the OEM corpus.
"""

from acd.l5x import elements as E


def _render_bool_array(n):
    """Render a BOOL[n] tag's value blocks in the L5K-first (non-raw-hex) era."""
    nbytes = (n + 7) // 8
    return E._render_value_blocks(
        "Data", "BOOL", str(n), bytes(nbytes), {},
        taginfo_layout=None, radix=None, raw_hex_first=False,
        string_array_as_string=False, require_pair=True,
    )


def _render_dint_array(n):
    """Render a DINT[n] tag's value blocks (4n bytes, n+1 Decorated elements)."""
    return E._render_value_blocks(
        "Data", "DINT", str(n), bytes(4 * n), {},
        taginfo_layout=None, radix=None, raw_hex_first=False,
        string_array_as_string=False, require_pair=True,
    )


def test_below_ceiling_keeps_decorated():
    # 20000 elements < 32768 -> both flat L5K and Decorated blocks present.
    out = _render_bool_array(20000)
    assert 'Format="L5K"' in out
    assert 'Format="Decorated"' in out


def test_above_ceiling_omits_decorated():
    # 40000 elements > 32768 -> Decorated block suppressed, flat L5K kept.
    out = _render_bool_array(40000)
    assert 'Format="L5K"' in out
    assert 'Format="Decorated"' not in out


def test_ceiling_boundary_is_strict_greater_than():
    # Exactly at the ceiling (Array wrapper + 32767 Elements = 32768) is KEPT;
    # one more element (32769) is omitted. Confirms the '>' (not '>=') gate.
    keep = _render_bool_array(32767)   # 1 + 32767 = 32768 elements
    omit = _render_bool_array(32768)   # 1 + 32768 = 32769 elements
    assert 'Format="Decorated"' in keep
    assert 'Format="Decorated"' not in omit


def test_byte_ceiling_omits_low_count_large_image():
    # DINT[25000] = 100000 bytes >= the byte ceiling but only 25001 elements
    # (< the element ceiling): the raw value-image byte rule suppresses the
    # Decorated block that the element count alone would keep.
    out = _render_dint_array(25000)
    assert 'Format="L5K"' in out
    assert 'Format="Decorated"' not in out


def test_below_byte_ceiling_keeps_decorated():
    # DINT[20000] = 80000 bytes < the byte ceiling and 20001 elements < the
    # element ceiling: both blocks present.
    out = _render_dint_array(20000)
    assert 'Format="Decorated"' in out


def test_elem_count_helper_ignores_cdata():
    # A '<' inside a CDATA string value must not be counted as a start tag.
    body = (
        '<Structure DataType="X">'
        '<StructureMember Name="S" DataType="STRING">'
        '<DataValueMember Name="DATA" DataType="STRING" Radix="ASCII">\n'
        '<![CDATA[\'a<b<c\']]>\n</DataValueMember>'
        '</StructureMember></Structure>'
    )
    # 4 real elements: Structure, StructureMember, DataValueMember (DATA).
    # (The LEN member is omitted from this hand-written body.) The two '<' in
    # the CDATA must not inflate the count.
    assert E._decorated_elem_count(body) == 3
