"""Unit test for the RLL <Rung> @Type derivation.

An empty routine's sole rung serializes as a bare ';' (the terminator, no
instructions), which Studio exports as Type='e'. Every rung carrying real
ladder text ends in ';' too but has instructions before it (text != ';'), so
it stays Type='N'.
"""

from acd.l5x.elements import Routine


def _rung_types(rungs):
    xml = Routine("R", "R", "RLL", rungs).to_xml()
    import re
    return re.findall(r'<Rung Number="\d+" Type="([^"]+)">', xml)


def test_bare_semicolon_rung_is_type_e():
    assert _rung_types([";"]) == ["e"]


def test_real_logic_rung_stays_type_n():
    assert _rung_types(["XIC(a)OTE(b);"]) == ["N"]


def test_mixed_routine():
    assert _rung_types(["XIC(a)OTE(b);", ";"]) == ["N", "e"]
