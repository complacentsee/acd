"""Goldens for the zero-value Decorated generator (elements._generate_decorated).

Pins the zero-placeholder <Data Format="Decorated"> fallback (emitted for a
tag with no recovered design-value image) ahead of P4 C3, which routes its
member spelling through the unified tag_value emitter. The policies pinned
here are the ones that DIFFER from the value-image walker and must survive:
members of unknown types are silently omitted (partial emission), BOOL
members carry no Radix attribute, and the empty-STRING default is the
literal two-member form with no CDATA block.
"""

from types import SimpleNamespace as NS

from acd.l5x import elements as E


def _m(name, dt, dim=0, hidden=False):
    return NS(name=name, data_type=dt, dimension=dim, hidden=hidden)


_DTM = {
    "MYUDT": NS(members=[
        _m("A", "DINT"),
        _m("B", "BOOL"),
        _m("H", "DINT", hidden=True),
        _m("Arr", "INT", dim=3),
        _m("S", "STRING"),
        _m("T", "TIMER"),
        _m("U", "UNKNOWNTYPE"),
        _m("F", "REAL"),
    ]),
}

_STRING_INNER = (
    '<DataValueMember Name="LEN" DataType="DINT" Radix="Decimal" Value="0"/>'
    '<DataValueMember Name="DATA" DataType="STRING" Radix="ASCII">\n\n'
    '</DataValueMember>'
)


def test_zero_decorated_scalar_udt_policies():
    out = E._generate_decorated("MYUDT", None, _DTM)
    assert out == (
        '<Data Format="Decorated">\n'
        '<Structure DataType="MYUDT">'
        '<DataValueMember Name="A" DataType="DINT" Radix="Decimal" Value="0"/>'
        '<DataValueMember Name="B" DataType="BOOL" Value="0"/>'
        '<ArrayMember Name="Arr" DataType="INT" Dimensions="3" Radix="Decimal">'
        '<Element Index="[0]" Value="0"/><Element Index="[1]" Value="0"/>'
        '<Element Index="[2]" Value="0"/></ArrayMember>'
        f'<StructureMember Name="S" DataType="STRING">{_STRING_INNER}'
        '</StructureMember>'
        '<StructureMember Name="T" DataType="TIMER">'
        '<DataValueMember Name="PRE" DataType="DINT" Radix="Decimal" Value="0"/>'
        '<DataValueMember Name="ACC" DataType="DINT" Radix="Decimal" Value="0"/>'
        '<DataValueMember Name="EN" DataType="BOOL" Value="0"/>'
        '<DataValueMember Name="TT" DataType="BOOL" Value="0"/>'
        '<DataValueMember Name="DN" DataType="BOOL" Value="0"/>'
        '</StructureMember>'
        '<DataValueMember Name="F" DataType="REAL" Radix="Float" Value="0.0"/>'
        '</Structure>\n'
        '</Data>'
    )


def test_zero_decorated_multidim_bool_array():
    out = E._generate_decorated("BOOL", "2,3", {})
    elems = "".join(
        f'<Element Index="[{i},{j}]" Value="0"/>'
        for i in range(2) for j in range(3)
    )
    assert out == (
        '<Data Format="Decorated">\n'
        f'<Array DataType="BOOL" Dimensions="2,3" Radix="Decimal">{elems}</Array>\n'
        '</Data>'
    )


def test_zero_decorated_real_array_uses_float_zero():
    out = E._generate_decorated("REAL", "2", {})
    assert out == (
        '<Data Format="Decorated">\n'
        '<Array DataType="REAL" Dimensions="2" Radix="Float">'
        '<Element Index="[0]" Value="0.0"/><Element Index="[1]" Value="0.0"/>'
        '</Array>\n'
        '</Data>'
    )


def test_zero_decorated_struct_array():
    dtm = {"PT": NS(members=[_m("X", "INT"), _m("Y", "INT")])}
    out = E._generate_decorated("PT", "2", dtm)
    struct = (
        '<Structure DataType="PT">'
        '<DataValueMember Name="X" DataType="INT" Radix="Decimal" Value="0"/>'
        '<DataValueMember Name="Y" DataType="INT" Radix="Decimal" Value="0"/>'
        '</Structure>'
    )
    assert out == (
        '<Data Format="Decorated">\n'
        '<Array DataType="PT" Dimensions="2">'
        f'<Element Index="[0]">{struct}</Element>'
        f'<Element Index="[1]">{struct}</Element>'
        '</Array>\n'
        '</Data>'
    )


def test_zero_decorated_unknown_and_skipped_types_return_empty():
    assert E._generate_decorated("NOSUCHTYPE", None, {}) == ""
    assert E._generate_decorated("MESSAGE", None, {}) == ""
    assert E._generate_decorated("AXIS_CIP_DRIVE", "3", {}) == ""
