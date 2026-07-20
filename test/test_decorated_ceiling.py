"""Pins the Decorated-block element-count ceiling.

Studio omits the <Data Format="Decorated"> block for a tag whose Decorated
tree exceeds a global element-count ceiling (_DECORATED_MAX_ELEMS = 2^15),
keeping only the compact flat first block. Below the ceiling both blocks are
emitted. The metric is the number of element start tags in the generated
Decorated body (CDATA string text excluded), validated 0 wrong-suppress over
the OEM corpus (max element count among OEM-kept Decorated tags is 28612).
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
