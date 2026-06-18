import html
import os
import re
import shutil
import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from os import PathLike
from pathlib import Path
from sqlite3 import Cursor
from typing import List, Tuple, Dict, Union

from acd.generated.comps.rx_generic import RxGeneric
from acd.l5x.catalog_numbers import CATALOG_NUMBERS, CATALOG_NUMBERS_BY_MAJOR
from acd.l5x.port_structures import PORT_STRUCTURES
from acd.l5x import tag_value as _tag_value
from acd.record.comps import CompsRecord, _SP_MARKER


# XML 1.0 forbids the C0 control characters except TAB (0x09), LF (0x0A) and
# CR (0x0D). ``html.escape`` only rewrites markup metacharacters (& < > " '), so
# any raw control byte in a decoded field passes through verbatim and makes the
# emitted document not-well-formed (the reader then raises and the whole file is
# unparseable). Some on-disk slots land on bytes that are not real text — e.g. a
# source-protected AOI's vendor slot decodes ciphertext, and a V30 vendor read at
# a V34+ offset lands on zero bytes — so strip the illegal characters before
# emitting. Legitimate L5X attribute/text values never contain these bytes, so
# this only cleans the already-corrupt cases.
_XML_ILLEGAL_RE = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _xml_sane(s: str) -> str:
    """Drop characters XML 1.0 forbids in attribute/element content."""
    return _XML_ILLEGAL_RE.sub("", s)


@dataclass
class L5xElementBuilder:
    _cur: Cursor
    _object_id: int = -1


# Maps Python attribute names to L5X XML section wrapper tag names.
# Entries here also control which list attributes are serialized as child sections.
_LIST_SECTION_NAMES = {
    "tags": "Tags",
    "local_tags": "LocalTags",
    "parameters": "Parameters",
    "data_types": "DataTypes",
    "members": "Members",
    "modules": "Modules",
    "programs": "Programs",
    "routines": "Routines",
    "aois": "AddOnInstructionDefinitions",
    "tasks": "Tasks",
    "scheduled_programs": "ScheduledPrograms",
}


@dataclass
class L5xElement:
    _name: str

    def __post_init__(self):
        self._export_name = ""

    def to_xml(self) -> str:
        attribute_list: List[str] = []
        child_list: List[str] = []
        for attribute in self.__dict__:
            if attribute[0] != "_":
                attribute_value = self.__getattribute__(attribute)
                if attribute_value is None:
                    continue
                if isinstance(attribute_value, L5xElement):
                    child_list.append(attribute_value.to_xml())
                elif isinstance(attribute_value, list):
                    if attribute in _LIST_SECTION_NAMES:
                        section_name = _LIST_SECTION_NAMES[attribute]
                        new_child_list: List[str] = []
                        for element in attribute_value:
                            if isinstance(element, L5xElement):
                                if getattr(element, "_l5x_exclude", False):
                                    continue
                                new_child_list.append(element.to_xml())
                            else:
                                new_child_list.append(f"<{element}/>")
                        child_list.append(
                            f'<{section_name}>{"".join(new_child_list)}</{section_name}>'
                        )
                else:
                    if attribute == "cls":
                        attribute = "class"
                    if isinstance(attribute_value, bool):
                        attribute_value = str(attribute_value).lower()
                    _overrides = getattr(self, "_xml_attr_overrides", {})
                    xml_attr_name = _overrides.get(attribute, attribute.title().replace("_", ""))
                    attribute_list.append(
                        f'{xml_attr_name}="{html.escape(_xml_sane(str(attribute_value)), quote=True)}"'
                    )

        _export_name = (
            getattr(self, "_export_name", "") or self.__class__.__name__.title().replace("_", "")
        )
        return f'<{_export_name} {" ".join(attribute_list)}>{"".join(child_list)}</{_export_name}>'


@dataclass
class Member(L5xElement):
    name: str
    data_type: str
    dimension: int
    radix: str
    hidden: bool
    target: Union[str, None]      # BIT members only; None omits the attribute
    bit_number: Union[int, None]  # BIT members only; None omits the attribute
    external_access: str
    _description: Union[str, None] = field(default=None)

    def to_xml(self) -> str:
        base = super().to_xml()
        if not self._description:
            return base
        desc_xml = f'<Description>\n<![CDATA[{_xml_sane(self._description)}]]>\n</Description>'
        idx = base.index(">")
        return base[:idx + 1] + desc_xml + base[idx + 1:]


@dataclass
class DataType(L5xElement):
    name: str
    family: str
    cls: str
    members: List[Member]
    _description: Union[str, None] = field(default=None)
    # V10..V21 short-header projects store their *full* lean datatype set
    # (User + ProductDefined + IO) in Comps.Dat and the OEM L5X emits all of
    # them verbatim — so for those files we must NOT apply the V24+ exclusion
    # that drops ProductDefined / ':'-named (IO) types. Set True only by the
    # short-header DataTypeBuilder path; defaults False so the V24+/V36 long
    # path keeps its exact prior behaviour.
    _emit_predefined: bool = field(default=False)

    def __post_init__(self):
        super().__post_init__()
        self._export_name = "DataType"

    @property
    def _l5x_exclude(self) -> bool:
        if self._emit_predefined:
            return False
        return self.cls == "ProductDefined" or ":" in self.name

    def to_xml(self) -> str:
        base = super().to_xml()
        # V10..V21: atomic base types (BOOL/DINT/...) have no members and the
        # OEM emits them as self-closing DataTypes — drop the empty <Members/>
        # wrapper the generic serializer would otherwise add. Scoped to the
        # short-header emit path (_emit_predefined) so the long path is
        # untouched.
        if self._emit_predefined and not self.members:
            base = base.replace("<Members></Members>", "").replace("<Members/>", "")
        if not self._description:
            return base
        desc_xml = f'<Description>\n<![CDATA[{_xml_sane(self._description)}]]>\n</Description>'
        idx = base.index(">")
        return base[:idx + 1] + desc_xml + base[idx + 1:]


# Maps primitive DataType names to their L5K zero-default value string.
# UDT, STRING, ALARM_DIGITAL, MESSAGE, and array types are intentionally omitted —
# they require complex structured L5K encoding that is not yet implemented.
_PRIMITIVE_L5K_ZERO: Dict[str, str] = {
    "BOOL":  "0",
    "SINT":  "0",
    "INT":   "0",
    "DINT":  "0",
    "LINT":  "0",
    "USINT": "0",
    "UINT":  "0",
    "UDINT": "0",
    "ULINT": "0",
    "REAL":  "0.00000000e+000",
    "LREAL": "0.00000000e+000",
}

# Raw byte width of each atomic primitive (for the V10..V21 short-header raw-hex
# <DefaultData>/<Data> zero image: e.g. DINT -> "00 00 00 00"). BOOL stores as a
# single byte in this image (OEM emits "00").
_PRIMITIVE_BYTE_WIDTH: Dict[str, int] = {
    "BOOL":  1,
    "BIT":   1,
    "SINT":  1,
    "USINT": 1,
    "INT":   2,
    "UINT":  2,
    "DINT":  4,
    "UDINT": 4,
    "REAL":  4,
    "LINT":  8,
    "ULINT": 8,
    "LREAL": 8,
}

# Radix string used in Decorated DataValueMember for each numeric primitive.
# BOOL and BIT use no Radix attribute; REAL/LREAL use "Float"; all integers use "Decimal".
_PRIMITIVE_RADIX: Dict[str, str] = {
    "SINT":  "Decimal",
    "INT":   "Decimal",
    "DINT":  "Decimal",
    "LINT":  "Decimal",
    "USINT": "Decimal",
    "UINT":  "Decimal",
    "UDINT": "Decimal",
    "ULINT": "Decimal",
    "REAL":  "Float",
    "LREAL": "Float",
}

# Atomic data types that carry a Radix attribute on a <Tag>. Unlike the Decorated
# member rule, BOOL/BIT DO take a tag-level Radix. Logix Designer emits Radix ONLY
# for these (and arrays of them); every structured type — TIMER, COUNTER, CONTROL,
# MESSAGE, STRING, PID, UDT_*, AB:* module types, etc. — omits it.
_ATOMIC_TAG_TYPES: frozenset = frozenset({
    "BOOL", "BIT", "SINT", "INT", "DINT", "LINT",
    "USINT", "UINT", "UDINT", "ULINT", "REAL", "LREAL",
})

# Bit-width of a base symbol's element type, used to decode an internal alias's
# bit-offset (u32 @ record 0x26) into an array index + member bit. Structured
# legacy types (TIMER/COUNTER/CONTROL = 3 DINTs) are 96 bits; only base element
# types whose width is known appear here. A base whose element type is absent
# (e.g. a module connection image) is left undecoded (no AliasFor emitted).
_ALIAS_ELEM_BITS: Dict[str, int] = {
    "BOOL": 1, "BIT": 1, "SINT": 8, "USINT": 8,
    "INT": 16, "UINT": 16, "DINT": 32, "UDINT": 32, "REAL": 32,
    "LINT": 64, "ULINT": 64, "LREAL": 64,
    "TIMER": 96, "COUNTER": 96, "CONTROL": 96,
}

# Data types on which Logix NEVER writes a Constant attribute (a tag of these
# types cannot be a constant): motion axes/groups, MESSAGE, and digital alarms.
# Verified: 0 OEM tags of these types carry Constant. (Consumed tags also omit
# Constant; handled separately via tag_type.)
_NO_CONSTANT_TYPES: frozenset = frozenset({
    "MESSAGE", "AXIS_CIP_DRIVE", "AXIS_SERVO_DRIVE", "AXIS_SERVO",
    "AXIS_VIRTUAL", "AXIS_GENERIC", "AXIS_CONSUMED", "MOTION_GROUP",
    "ALARM_DIGITAL", "ALARM_ANALOG",
})

# Default zero value string for each primitive in Decorated output.
_PRIMITIVE_DECORATED_ZERO: Dict[str, str] = {
    "BOOL":  "0",
    "BIT":   "0",
    "SINT":  "0",
    "INT":   "0",
    "DINT":  "0",
    "LINT":  "0",
    "USINT": "0",
    "UINT":  "0",
    "UDINT": "0",
    "ULINT": "0",
    "REAL":  "0.0",
    "LREAL": "0.0",
}

# Built-in Logix struct types that are not in the user DataType list.
# Each entry is a list of (member_name, member_data_type) tuples.
# Only non-hidden, visible members are listed (as they appear in Decorated output).
_BUILTIN_STRUCT_MEMBERS: Dict[str, List[Tuple[str, str]]] = {
    "TIMER": [
        ("PRE", "DINT"), ("ACC", "DINT"),
        ("EN", "BOOL"), ("TT", "BOOL"), ("DN", "BOOL"),
    ],
    "COUNTER": [
        ("PRE", "DINT"), ("ACC", "DINT"),
        ("CU", "BOOL"), ("CD", "BOOL"), ("DN", "BOOL"), ("OV", "BOOL"), ("UN", "BOOL"),
    ],
    "CONTROL": [
        ("LEN", "DINT"), ("POS", "DINT"),
        ("EN", "BOOL"), ("EU", "BOOL"), ("DN", "BOOL"), ("EM", "BOOL"),
        ("ER", "BOOL"), ("UL", "BOOL"), ("IN", "BOOL"), ("FD", "BOOL"),
    ],
}

# Types for which we emit no Decorated element at all (they use other formats).
# Motion axes and motion groups are written by the reference as a dedicated
# <Data Format="Axis">/<Data Format="MotionGroup"> block (<AxisParameters>/
# <MotionGroupParameters>), never as a Decorated <Structure>, so the generic
# Decorated tree is a fabrication for them. (MOTION_INSTRUCTION is NOT a motion
# axis -- it keeps its Decorated <Structure> like any UDT.)
_SKIP_DECORATED: set = {
    "ALARM_DIGITAL", "MESSAGE", "PID_ENHANCED",
    "AXIS_SERVO", "AXIS_SERVO_DRIVE", "AXIS_CIP_DRIVE", "AXIS_VIRTUAL",
    "AXIS_GENERIC", "AXIS_CONSUMED", "MOTION_GROUP",
}

# A valid L5X tag-comment Operand is a member/bit/index path relative to the tag:
# it starts with '.' or '[' and contains only identifier/index characters. Module
# connection-point comments instead carry a raw binary key that decodes to junk
# (e.g. CJK from a UTF-16 misread); those must not leak in as tag operand comments.
_OPERAND_RE = re.compile(r"^[.\[][A-Za-z0-9_.\[\]]*$")


def _is_valid_operand(op: str) -> bool:
    return bool(op) and ".!" not in op and bool(_OPERAND_RE.match(op))


def _member_decorated_xml(member_name: str, member_dt: str, member_dim: int,
                           data_types_map: Dict[str, "DataType"]) -> str:
    """Return the Decorated XML fragment for a single UDT member.

    member_dt:  the DataType name of the member (already upper-cased by caller)
    member_dim: array dimension (0 = scalar)
    """
    if member_dim > 0:
        # Array member
        return _array_member_xml(member_name, member_dt, member_dim, data_types_map)

    if member_dt in ("BOOL", "BIT"):
        return f'<DataValueMember Name="{member_name}" DataType="BOOL" Value="0"/>'

    radix = _PRIMITIVE_RADIX.get(member_dt)
    zero = _PRIMITIVE_DECORATED_ZERO.get(member_dt)
    if radix is not None and zero is not None:
        return f'<DataValueMember Name="{member_name}" DataType="{member_dt}" Radix="{radix}" Value="{zero}"/>'

    # Struct member (nested UDT, TIMER, COUNTER, etc.)
    inner = _struct_members_xml(member_dt, data_types_map)
    if inner is None:
        return ""  # unknown / skip
    return f'<StructureMember Name="{member_name}" DataType="{member_dt}">{inner}</StructureMember>'


def _array_member_xml(member_name: str, member_dt: str, dim: int,
                      data_types_map: Dict[str, "DataType"]) -> str:
    """Generate an <ArrayMember> element for a member that is an array."""
    radix = _PRIMITIVE_RADIX.get(member_dt)
    zero = _PRIMITIVE_DECORATED_ZERO.get(member_dt)
    is_bool = member_dt in ("BOOL", "BIT")

    if is_bool:
        elems = "".join(
            f'<Element Index="[{i}]" Value="0"/>' for i in range(dim)
        )
        return (
            f'<ArrayMember Name="{member_name}" DataType="BOOL" Dimensions="{dim}" Radix="Decimal">'
            f'{elems}'
            f'</ArrayMember>'
        )

    if radix is not None and zero is not None:
        elems = "".join(
            f'<Element Index="[{i}]" Value="{zero}"/>' for i in range(dim)
        )
        return (
            f'<ArrayMember Name="{member_name}" DataType="{member_dt}" Dimensions="{dim}" Radix="{radix}">'
            f'{elems}'
            f'</ArrayMember>'
        )

    # Array of structs
    inner = _struct_members_xml(member_dt, data_types_map)
    if inner is None:
        return ""
    struct_xml = f'<Structure DataType="{member_dt}">{inner}</Structure>'
    elems = "".join(
        f'<Element Index="[{i}]">{struct_xml}</Element>' for i in range(dim)
    )
    return (
        f'<ArrayMember Name="{member_name}" DataType="{member_dt}" Dimensions="{dim}">'
        f'{elems}'
        f'</ArrayMember>'
    )


def _struct_members_xml(dt_name: str, data_types_map: Dict[str, "DataType"]) -> Union[str, None]:
    """Return the inner XML for a Structure/StructureMember of the given DataType.

    Returns None if the type is unknown or should be skipped.
    The returned string does NOT include the outer <Structure> wrapper.
    """
    if dt_name in _SKIP_DECORATED:
        return None

    # Handle STRING as a special built-in: LEN (DINT) + DATA (STRING/ASCII)
    if dt_name == "STRING":
        return (
            '<DataValueMember Name="LEN" DataType="DINT" Radix="Decimal" Value="0"/>'
            '<DataValueMember Name="DATA" DataType="STRING" Radix="ASCII">\n\n</DataValueMember>'
        )

    # Built-in struct types (TIMER, COUNTER, CONTROL)
    builtin_members = _BUILTIN_STRUCT_MEMBERS.get(dt_name)
    if builtin_members is not None:
        parts: List[str] = []
        for mname, mdt in builtin_members:
            radix = _PRIMITIVE_RADIX.get(mdt)
            zero = _PRIMITIVE_DECORATED_ZERO.get(mdt)
            if radix is not None and zero is not None:
                parts.append(
                    f'<DataValueMember Name="{mname}" DataType="{mdt}" Radix="{radix}" Value="{zero}"/>'
                )
            else:
                # BOOL member
                parts.append(f'<DataValueMember Name="{mname}" DataType="{mdt}" Value="0"/>')
        return "".join(parts)

    # User-defined type: look up in data_types_map
    dt_obj = data_types_map.get(dt_name)
    if dt_obj is None:
        return None

    parts = []
    for member in dt_obj.members:
        if member.hidden:
            continue
        mdt = member.data_type.upper()
        mname = member.name
        mdim = member.dimension

        fragment = _member_decorated_xml(mname, mdt, mdim, data_types_map)
        if fragment:
            parts.append(fragment)
    return "".join(parts)


def _generate_decorated(dt_base: str, dimensions: Union[str, None],
                        data_types_map: Dict[str, "DataType"]) -> str:
    """Generate a complete <Data Format="Decorated"> XML string for a tag.

    dt_base:    the base DataType name (uppercase, array brackets already stripped)
    dimensions: comma-separated dimension string (e.g. "100" or "4,8") or None for scalar
    Returns "" if this type should not have a Decorated element.
    """
    if dt_base in _SKIP_DECORATED:
        return ""

    if dimensions is None:
        # Scalar struct
        inner = _struct_members_xml(dt_base, data_types_map)
        if inner is None:
            return ""
        body = f'<Structure DataType="{dt_base}">{inner}</Structure>'
    else:
        # Array tag: parse dimensions (up to 3D, comma-separated)
        dim_parts = [int(d) for d in dimensions.split(",") if d.strip().isdigit()]
        if not dim_parts:
            return ""

        # For multi-dimensional arrays the total element count is the product.
        # We generate flat [0]..[N-1] indices for 1D, and nested for multi-D.
        # Logix displays multi-dim as [i][j] etc.
        total = 1
        for d in dim_parts:
            total *= d

        dim_str = ",".join(str(d) for d in dim_parts)

        radix = _PRIMITIVE_RADIX.get(dt_base)
        zero = _PRIMITIVE_DECORATED_ZERO.get(dt_base)
        is_bool = dt_base in ("BOOL", "BIT")

        if is_bool:
            # BOOL array: flat indexed elements with Radix="Decimal"
            def _bool_elems(parts: List[int], remaining: List[int]) -> str:
                if not remaining:
                    idx = "[" + "][".join(str(p) for p in parts) + "]"
                    return f'<Element Index="{idx}" Value="0"/>'
                return "".join(
                    _bool_elems(parts + [i], remaining[1:]) for i in range(remaining[0])
                )
            elems = _bool_elems([], dim_parts)
            body = f'<Array DataType="BOOL" Dimensions="{dim_str}" Radix="Decimal">{elems}</Array>'

        elif radix is not None and zero is not None:
            # Primitive array (DINT, REAL, etc.)
            def _prim_elems(parts: List[int], remaining: List[int]) -> str:
                if not remaining:
                    idx = "[" + "][".join(str(p) for p in parts) + "]"
                    return f'<Element Index="{idx}" Value="{zero}"/>'
                return "".join(
                    _prim_elems(parts + [i], remaining[1:]) for i in range(remaining[0])
                )
            elems = _prim_elems([], dim_parts)
            body = f'<Array DataType="{dt_base}" Dimensions="{dim_str}" Radix="{radix}">{elems}</Array>'

        else:
            # Struct array (UDT, TIMER, COUNTER, STRING, ...)
            inner = _struct_members_xml(dt_base, data_types_map)
            if inner is None:
                return ""
            struct_xml = f'<Structure DataType="{dt_base}">{inner}</Structure>'

            def _struct_elems(parts: List[int], remaining: List[int]) -> str:
                if not remaining:
                    idx = "[" + "][".join(str(p) for p in parts) + "]"
                    return f'<Element Index="{idx}">{struct_xml}</Element>'
                return "".join(
                    _struct_elems(parts + [i], remaining[1:]) for i in range(remaining[0])
                )
            elems = _struct_elems([], dim_parts)
            body = f'<Array DataType="{dt_base}" Dimensions="{dim_str}">{elems}</Array>'

    return f'<Data Format="Decorated">\n{body}\n</Data>'


def _build_default_data(data_type: Union[str, None],
                        dimensions: Union[str, None],
                        value_bytes: Union[bytes, None],
                        short_header: bool,
                        data_types_map: Dict[str, "DataType"],
                        taginfo_layout: Dict[str, object]) -> str:
    """Build the AOI-scoped <DefaultData> child pair for a Parameter/LocalTag.

    OEM emits, on every value-bearing AOI Parameter (Input/Output) and every
    LocalTag, two children mirroring a regular <Tag>'s value block but spelled
    <DefaultData> instead of <Data>:
        <DefaultData Format="L5K"><![CDATA[<l5k>]]></DefaultData>
        <DefaultData Format="Decorated"><tree></DefaultData>
    The Decorated body is byte-identical to a Tag's <Data Format="Decorated">.

    When value_bytes is None (no design-value image available) the type's ZERO
    image is emitted (correct for the ~88.5% of OEM defaults that are all-zero;
    a fresh-tag default). Returns "" (degrade to today's no-DefaultData
    behaviour) on any failure or for types that carry no value block.
    """
    try:
        dt_base = data_type.split("[")[0].upper() if data_type else ""
        if not dt_base or dt_base in _SKIP_DECORATED:
            return ""
        # Declared-case datatype name for the rendered <Structure DataType=...>
        # attribute (OEM keeps the author's case, e.g. DateTime not DATETIME).
        # render_decorated_layout/render_l5k_layout uppercase internally for the
        # layout lookup, so passing the original case is safe.
        dt_decorated = data_type.split("[")[0] if data_type else dt_base

        # ---- L5K (first) block ----
        # render_l5k/render_decorated reuse, exactly as Tag.to_xml: when the
        # AOI prototype value image is available it is used; otherwise the type's
        # zero default is rendered.
        decorated_inner = None
        l5k_text = None

        if value_bytes is not None:
            # STRING members render block1 as Format="String" Length=N (single-
            # quoted CDATA), NOT a Decorated <Structure>. Detect by datatype name
            # or by the resolved layout being the Logix STRING shape (LEN+DATA).
            is_string = dt_base == "STRING"
            if not is_string and dimensions is None and taginfo_layout:
                try:
                    lay = _tag_value._resolve_layout(
                        dt_base, taginfo_layout, data_types_map
                    )
                    if lay is not None and _tag_value._is_string_layout(lay):
                        is_string = True
                except Exception:
                    pass

            if is_string:
                # block1 = Format="String" Length="{LEN}" <![CDATA['text']]>
                try:
                    length = int.from_bytes(value_bytes[0:4], "little") if len(value_bytes) >= 4 else 0
                except Exception:
                    length = 0
                if length < 0 or length + 4 > len(value_bytes):
                    # Fall back to NUL-terminated scan for a malformed LEN.
                    raw = value_bytes[4:] if len(value_bytes) > 4 else b""
                    text = _tag_value._ascii_string_cdata(raw.split(b"\x00", 1)[0])
                else:
                    text = _tag_value._ascii_string_cdata(value_bytes[4:4 + length])
                decorated_inner = None  # not used for STRING
                string_block = (
                    f'<DefaultData Format="String" Length="{length}">\n'
                    f"<![CDATA['{text}']]>\n</DefaultData>"
                )
            else:
                string_block = None
                if taginfo_layout:
                    try:
                        decorated_inner = _tag_value.render_decorated_layout(
                            dt_decorated, dimensions, value_bytes,
                            taginfo_layout, data_types_map
                        )
                    except Exception:
                        decorated_inner = None
                if decorated_inner is None:
                    decorated_inner = _tag_value.render_decorated(
                        dt_base, dimensions, value_bytes, data_types_map
                    )

            if short_header:
                l5k_text = _tag_value.render_hex(value_bytes)
                first = "<DefaultData>" + l5k_text + "</DefaultData>"
                ok_first = bool(value_bytes)
            else:
                l5k_text = None
                if taginfo_layout:
                    try:
                        l5k_text = _tag_value.render_l5k_layout(
                            dt_decorated, dimensions, value_bytes,
                            taginfo_layout, data_types_map
                        )
                    except Exception:
                        l5k_text = None
                if l5k_text is None:
                    l5k_text = _tag_value.render_l5k(
                        dt_base, dimensions, value_bytes, data_types_map
                    )
                first = f'<DefaultData Format="L5K">\n<![CDATA[{l5k_text}]]>\n</DefaultData>'
                ok_first = l5k_text is not None

            if string_block is not None:
                # STRING: emit block0 (hex/L5K) + the String block1, in OEM order.
                return (first if ok_first else "") + (string_block if ok_first else "")
        else:
            # No value image -> zero default for this data type.
            if dimensions is None and dt_base in _PRIMITIVE_L5K_ZERO:
                # Scalar primitive first block. The first <DefaultData> mirrors a
                # Tag's first <Data> block and is version-styled:
                #   LONG (V24+):  <DefaultData Format="L5K"><![CDATA[0]]>...
                #   SHORT(V10-21): <DefaultData>00 00 00 00</DefaultData> (raw hex)
                if short_header:
                    width = _PRIMITIVE_BYTE_WIDTH.get(dt_base, 0)
                    if width <= 0:
                        return ""
                    first = "<DefaultData>" + _tag_value.render_hex(b"\x00" * width) + "</DefaultData>"
                else:
                    l5k_zero = _PRIMITIVE_L5K_ZERO[dt_base]
                    first = f'<DefaultData Format="L5K">\n<![CDATA[{l5k_zero}]]>\n</DefaultData>'
                ok_first = True
                # Scalar primitives: build the matching single DataValue.
                radix = _PRIMITIVE_RADIX.get(dt_base)
                zero = _PRIMITIVE_DECORATED_ZERO.get(dt_base)
                if dt_base in ("BOOL", "BIT"):
                    decorated_inner = '<DataValue DataType="BOOL" Radix="Decimal" Value="0"/>'
                elif radix is not None and zero is not None:
                    decorated_inner = (
                        f'<DataValue DataType="{dt_base}" Radix="{radix}" Value="{zero}"/>'
                    )
                else:
                    decorated_inner = None
            else:
                # Array / struct with NO value image: OEM emits the pair
                #   <DefaultData Format="L5K"><![CDATA[[0,0,0]]]> + <Decorated>...
                # but the L5K bracketed-tree body cannot be synthesised reliably
                # without a value image (it needs the per-member layout + bytes).
                # Emitting only the Decorated half mis-aligns the comparator's
                # occurrence matching (it would pair our lone Decorated against
                # OEM's first L5K block, manufacturing spurious @Format / text
                # diffs). So suppress entirely -> no block rather than a skewed
                # one. AOI params/localtags avoid this by feeding the real image.
                return ""

        decorated_block = (
            f'<DefaultData Format="Decorated">\n{decorated_inner}\n</DefaultData>'
            if decorated_inner is not None else ""
        )
        return (first if ok_first else "") + decorated_block
    except Exception:
        return ""


@dataclass
class Tag(L5xElement):
    name: str
    tag_type: str
    data_type: str
    radix: Union[str, None]
    external_access: str
    constant: Union[str, None]  # "true" for constants; None omits the attribute
    dimensions: Union[str, None]
    _data_table_instance: int
    _comments: List[Tuple[str, str]]
    _data_types_map: Dict[str, "DataType"] = field(default_factory=dict)
    # Operand-keyed member/bit/array comments: list of (operand, text) pairs,
    # e.g. ("[3]", "Hydraulic Pump\r\nStart"). Empty by default (long-header
    # path leaves these untouched).
    _operand_comments: List[Tuple[str, str]] = field(default_factory=list)
    # Alias target (e.g. "Local:1:I.Data.10"); None for non-alias tags. When set,
    # tag_type is "Alias", data_type is None (omitted), and NO <Data> child is
    # emitted. This is populated only by the V10..V21 short-header TagBuilder
    # path; defaults None so the long-header (V24+) path is unaffected.
    alias_for: Union[str, None] = None
    # Step 6c — raw design-value image (ext attr 0x66 of the cip-0x6a backing)
    # and its CIP type code (ext attr 0x65). Populated only when the value reader
    # succeeds; None leaves today's zero-placeholder <Data> behaviour untouched
    # (so both header families fall back identically on any failure).
    _value_bytes: Union[bytes, None] = None
    _value_type_code: int = 0
    # True for V10..V21 short-header projects. Selects the raw-hex <Data> first
    # block (the older Studio style: <Data>1D 00 00 00</Data>) instead of the
    # V24+ L5K CDATA block. Defaults False so the long (V24+) path is unchanged.
    _short_header: bool = False
    # True when the FIRST <Data> block is the raw-hex image (<Data>XX XX..</Data>)
    # rather than <Data Format="L5K">. This is a Studio-VERSION distinction, not a
    # header-family one: V10-V24 write raw hex, V28+ write L5K. Set by TagBuilder
    # from the detected major version (short-header V10-V21 always implies it).
    _raw_hex_data: bool = False
    # Step 6d: TagInfo.XML byte-layout map {DATATYPE_UPPER: [members...]} used to
    # decode the value image into a full Decorated tree. Empty -> the existing
    # render_decorated/zero path is used (no behaviour change).
    _taginfo_layout: Dict[str, object] = field(default_factory=dict)
    # True for module I/O tags (Local:1:C, Local:8:O, ...). When set, the tag is
    # NOT excluded for its ':' name, the OEM IO="true" attribute is emitted, and
    # Radix/Constant/Dimensions are suppressed (OEM never emits them on IO tags).
    # Defaults False so every non-IO tag (both header families) is unchanged.
    _io: bool = False
    # OpcUaAccess="None" is emitted on every <Tag> when the project's OPC UA
    # server is enabled (V36+; see ExportL5x.project_flags). Default False.
    _opc_ua: bool = False
    # Class="Standard"/"Safety" for controller-scope Base tags in a safety
    # project; None omits the attribute. Default None.
    _class_attr: Union[str, None] = None
    # Suppress ALL <Data> emission (value image AND the zero-placeholder fallback).
    # Set for a recognised alias whose AliasFor target we cannot yet build, so it
    # is emitted as Base but carries no <Data> (OEM emits none on an alias).
    _no_data: bool = False

    def _inject_tag_attrs(self, base: str) -> str:
        """Insert OpcUaAccess / Class attributes into the opening <Tag ...> of base.

        Inserted right before the first '>' of the element (attribute order is not
        significant to consumers/the comparator). No-op when neither applies.
        """
        extra = ""
        if self._class_attr:
            extra += f' Class="{self._class_attr}"'
        if self._opc_ua:
            extra += ' OpcUaAccess="None"'
        if not extra:
            return base
        i = base.find(">")
        if i < 0:
            return base
        # handle self-closing "/>"
        if i > 0 and base[i - 1] == "/":
            return base[: i - 1] + extra + base[i - 1:]
        return base[:i] + extra + base[i:]

    @property
    def _l5x_exclude(self) -> bool:
        """Exclude tags with empty or non-identifier names plus ACD-internal scratch
        tags the reference never exports: SFC/ST step-temporaries (``__SL<n>``),
        hex-address placeholders (``__l<hex>``) and import scratch (``__CLONE``).
        All carry a double underscore, so genuine single-underscore user tags
        (``_Foo``) are untouched."""
        # Module I/O tags carry a ':' in their name (Local:1:C) but are valid and
        # MUST be emitted; only their ':' would otherwise trip the filter below.
        if self._io:
            return not self.name
        return (
            not self.name
            or not (self.name[0].isalpha() or self.name[0] == "_")
            or ":" in self.name
            or self.name.startswith("__SL")
            or self.name.startswith("__l")
            or self.name.startswith("__CLONE")
        )

    @staticmethod
    def _sanitize_xml_text(text: str) -> str:
        """Encode characters illegal in XML 1.0 as XML character references (&#xNN;).

        XML 1.0 allows only #x9, #xA, #xD, and #x20–#xD7FF, #xE000–#xFFFD.
        Control characters outside that range (e.g. #x02 STX) are emitted as
        character references rather than stripped, matching Logix Designer output.
        """
        parts = []
        for ch in text:
            cp = ord(ch)
            if ch in ("\t", "\n", "\r") or (0x20 <= cp <= 0xD7FF) or (0xE000 <= cp <= 0xFFFD):
                parts.append(ch)
            else:
                parts.append(f"&#x{cp:04X};")
        return "".join(parts)

    def _build_comments_xml(self) -> str:
        """Build the <Comments> block of operand-keyed member/bit/array comments.

        Each entry becomes <Comment Operand="...">text</Comment>; the block is
        emitted only when there is at least one operand comment. Operand strings
        are de-duplicated (first occurrence wins) and sorted to give stable,
        Logix-like ordering.
        """
        if not self._operand_comments:
            return ""
        seen = set()
        items: List[Tuple[str, str]] = []
        for operand, text in self._operand_comments:
            if not operand or operand in seen:
                continue
            seen.add(operand)
            items.append((operand, text))
        if not items:
            return ""
        parts = ["<Comments>"]
        for operand, text in items:
            op_attr = html.escape(operand, quote=True)
            body = self._sanitize_xml_text(text) if text else ""
            parts.append(f'<Comment Operand="{op_attr}">\n<![CDATA[{body}]]>\n</Comment>')
        parts.append("</Comments>")
        return "".join(parts)

    def to_xml(self) -> str:
        if self._io and (self.tag_type == "Alias" or self.alias_for):
            # Per-point module I/O ALIAS tag — OEM emits a self-closing tag:
            #   Name TagType="Alias" Radix="Binary" AliasFor=... ExternalAccess IO="true"
            # No DataType, no <Data> (the value lives on the alias target). The
            # whole element is returned here; the Data/Description machinery below
            # is skipped (an alias carries none of it).
            return self._inject_tag_attrs(
                f'<Tag Name="{html.escape(self.name, quote=True)}"'
                f' TagType="Alias" Radix="Binary"'
                f' AliasFor="{html.escape(self.alias_for, quote=True)}"'
                f' ExternalAccess="{self.external_access}" IO="true"/>'
            )
        if self._io:
            # Module I/O tag — emit the exact OEM attribute set and order:
            #   Name TagType DataType ExternalAccess IO="true"
            # (no Radix/Constant/Dimensions, which OEM never writes on IO tags).
            dt_attr = f' DataType="{html.escape(self.data_type, quote=True)}"' if self.data_type else ""
            base = self._inject_tag_attrs(
                f'<Tag Name="{html.escape(self.name, quote=True)}"'
                f' TagType="{self.tag_type}"{dt_attr}'
                f' ExternalAccess="{self.external_access}" IO="true"></Tag>'
            )
        else:
            # OEM emits Radix only for atomic-typed tags (and atomic arrays);
            # suppress it on structured/UDT/STRING/module-defined types (TIMER,
            # COUNTER, CONTROL, UDT_*, AB:*, ...), which Logix never writes Radix
            # on. data_type may be an array ("DINT[10]") -> test the base type.
            # Only suppress when the type is KNOWN and non-atomic. If data_type is
            # empty (an unresolved short-header tag), leave radix as-is — those are
            # predominantly atomic (OEM still writes their Radix) and suppressing
            # would under-emit.
            _dtb = self.data_type.split("[")[0].upper() if self.data_type else ""
            if self.radix is not None and _dtb and _dtb not in _ATOMIC_TAG_TYPES:
                self.radix = None
            base = self._inject_tag_attrs(super().to_xml())

        # --- Comments child element (operand-keyed member/bit/array comments) ---
        comments_xml = self._build_comments_xml()

        # --- Description child element ---
        # _comments now carries at most the tag's OWN description (member_ref==0),
        # already filtered in TagBuilder.build. Take the first non-empty entry.
        desc_raw = next((text for _ref, text in self._comments if text), None)
        desc = self._sanitize_xml_text(desc_raw) if desc_raw else None
        desc_xml = f'<Description>\n<![CDATA[{desc}]]>\n</Description>' if desc else ""

        # --- Data child element(s) ---
        # Scalar primitives get Format="L5K" only.
        # Scalar STRING gets Format="L5K" (the L5K encoder handles it separately; we emit
        # nothing here — Decorated is not used for scalar STRING tags).
        # Everything else (UDTs, arrays, TIMER, COUNTER, etc.) gets Format="Decorated".
        # Alias tags carry no <Data> child at all (the value lives on the alias
        # target). Suppress all data emission when this is an alias.
        is_alias = self.tag_type == "Alias" or self.alias_for is not None
        dt_base = self.data_type.split("[")[0].upper() if self.data_type else ""
        # The rendered <Structure DataType=...> attribute keeps the datatype's
        # DECLARED case (OEM writes UDT_MixedCase / AB:Embedded_IQ16F:C:0, not the
        # uppercased form). render_decorated_layout/render_l5k_layout uppercase
        # internally for the layout lookup, so passing the original-case name is
        # safe and keeps the Structure attribute byte-faithful for ALL struct tags
        # (predefined/built-in types are declared all-caps, so they are unchanged).
        # dt_base (uppercased) is still the lookup key for the _SKIP_DECORATED /
        # STRING tests and the non-layout fallback paths below.
        dt_decorated = self.data_type.split("[")[0] if self.data_type else dt_base

        # --- Step 6c: real value <Data> from the design-value image (0x66) ---
        # When the value reader returned an image, emit BOTH the OEM blocks Logix
        # writes for a Base non-IO tag, then <Data Format="Decorated"> (structured
        # Value=...). The FIRST block is version-styled:
        #   LONG (V24+):  <Data Format="L5K"><![CDATA[50]]></Data>
        #   SHORT(V10-21): <Data>1D 00 00 00</Data>  (raw image, space-sep hex)
        # Both styles carry the same value; the Decorated block is identical.
        # Wrapped so any failure degrades to today's zero-placeholder behaviour
        # below — no regression.
        data_xml = ""
        # The Format="String" block is only emitted on long-header (V24+) projects:
        # there the recovered STRING value image is the verified LEN+DATA shape. The
        # short-header STRING value image is not reliably decoded yet, so keep the
        # prior behaviour there (no <Data> for dt_base=="STRING"), avoiding wrong
        # empty/array output.
        if not is_alias and self._value_bytes is not None and dt_base not in _SKIP_DECORATED \
                and not (self._short_header and dt_base == "STRING"):
            try:
                # A SCALAR STRING tag emits a Format="String" Length=N block in
                # place of the Decorated <Structure> (Logix renders STRING specially).
                # Detect by datatype name OR by the resolved TagInfo layout being the
                # Logix STRING shape (LEN u32 + DATA SINT[]) -- the latter catches
                # custom string types (String50, PF525FaultDesc, ...). STRING ARRAYS
                # keep the Decorated path (render_decorated_layout -> <Array>).
                # Long header only (see above): short-header detection mislabels some
                # atomics and yields empty text.
                is_string = False
                if not self._short_header:
                    is_string = (dt_base == "STRING") and self.dimensions is None
                    if not is_string and self.dimensions is None and self._taginfo_layout:
                        try:
                            _lay = _tag_value._resolve_layout(
                                dt_base, self._taginfo_layout, self._data_types_map
                            )
                            if _lay is not None and _tag_value._is_string_layout(_lay):
                                is_string = True
                        except Exception:
                            pass
                # Step 6d: layout-driven decode (full member fidelity) first;
                # fall back to the simpler render_decorated on None/any failure.
                decorated_inner = None
                string_block = None
                if is_string:
                    try:
                        length = (int.from_bytes(self._value_bytes[0:4], "little")
                                  if len(self._value_bytes) >= 4 else 0)
                    except Exception:
                        length = 0
                    if length < 0 or length + 4 > len(self._value_bytes):
                        raw = self._value_bytes[4:] if len(self._value_bytes) > 4 else b""
                        text = _tag_value._ascii_string_cdata(raw.split(b"\x00", 1)[0])
                    else:
                        text = _tag_value._ascii_string_cdata(self._value_bytes[4:4 + length])
                    string_block = (
                        f'<Data Format="String" Length="{length}">\n'
                        f"<![CDATA['{text}']]>\n</Data>"
                    )
                elif self._taginfo_layout:
                    try:
                        decorated_inner = _tag_value.render_decorated_layout(
                            dt_decorated, self.dimensions, self._value_bytes,
                            self._taginfo_layout, self._data_types_map,
                            radix=self.radix
                        )
                    except Exception:
                        decorated_inner = None
                if not is_string and decorated_inner is None:
                    decorated_inner = _tag_value.render_decorated(
                        dt_base, self.dimensions, self._value_bytes,
                        self._data_types_map, radix=self.radix
                    )
                if self._raw_hex_data:
                    first = "<Data>" + _tag_value.render_hex(self._value_bytes) + "</Data>"
                    ok_first = bool(self._value_bytes)
                else:
                    # Struct/UDT/built-in-struct (and module I/O) types need the
                    # layout-driven L5K bracket tree (the datatype's MEMBER tree,
                    # with mixed-width members, nested sub-structs and STRING
                    # members rendered properly); the flat int32-word render_l5k is
                    # wrong for them.  Try the layout form first whenever a TagInfo
                    # layout exists for this datatype, and fall back to the flat
                    # form only when the layout path returns None (unknown shape).
                    # Wrapped: any failure -> no L5K (ok_first stays False -> the
                    # <Data> blocks are suppressed, which is today's behaviour for
                    # the long path).
                    l5k_text = None
                    if self._taginfo_layout:
                        try:
                            l5k_text = _tag_value.render_l5k_layout(
                                dt_decorated, self.dimensions, self._value_bytes,
                                self._taginfo_layout, self._data_types_map
                            )
                        except Exception:
                            l5k_text = None
                    if l5k_text is None:
                        l5k_text = _tag_value.render_l5k(
                            dt_base, self.dimensions, self._value_bytes, self._data_types_map
                        )
                    first = f'<Data Format="L5K">\n<![CDATA[{l5k_text}]]>\n</Data>'
                    ok_first = l5k_text is not None
                if string_block is not None:
                    # Scalar STRING: first block (raw hex / L5K) then the String block.
                    if ok_first:
                        data_xml = first + string_block
                elif ok_first and decorated_inner is not None:
                    data_xml = first + f'<Data Format="Decorated">\n{decorated_inner}\n</Data>'
            except Exception:
                data_xml = ""

        if not data_xml and not self._no_data:
            # Fallback: today's exact zero-placeholder behaviour. Skipped entirely
            # when _no_data is set (a recognised alias we emit as Base because its
            # AliasFor target is uncracked -- OEM emits no <Data> on an alias, so a
            # zero placeholder here would be element_extra:Data).
            l5k_zero = (
                _PRIMITIVE_L5K_ZERO.get(dt_base)
                if (not is_alias and not self.dimensions)
                else None
            )
            data_xml = f'<Data Format="L5K">\n{l5k_zero}\n</Data>' if l5k_zero is not None else ""

            if not is_alias and not data_xml and dt_base not in _SKIP_DECORATED and dt_base != "STRING":
                # Generate Decorated data for non-primitive / array types
                decorated = _generate_decorated(dt_base, self.dimensions, self._data_types_map)
                if decorated:
                    data_xml = decorated

        if not comments_xml and not desc_xml and not data_xml:
            return base

        # Insert Comments (if any), then Description, then Data, immediately after
        # the opening tag. Logix emits <Comments> before <Description>/<Data>.
        idx = base.index(">")
        return base[:idx + 1] + comments_xml + desc_xml + data_xml + base[idx + 1:]


@dataclass
class LocalTag(L5xElement):
    """Represents a local (non-public) tag inside an AOI (<LocalTag> in L5X)."""
    name: str
    data_type: str
    dimensions: Union[str, None]  # array size; None for scalars (omitted from XML)
    radix: Union[str, None]   # None for complex/UDT types (omitted from XML)
    external_access: str
    _description: Union[str, None] = field(default=None)
    # AOI-scoped value image (mirrors Tag): populated by the builder so the
    # <DefaultData> block can be emitted. All default to the no-value state so
    # existing LocalTag() constructions are unaffected.
    _data_types_map: Dict[str, "DataType"] = field(default_factory=dict)
    _taginfo_layout: Dict[str, object] = field(default_factory=dict)
    _value_bytes: Union[bytes, None] = None
    _value_type_code: int = 0
    _short_header: bool = False

    def __post_init__(self):
        super().__post_init__()
        self._export_name = "LocalTag"

    @property
    def _l5x_exclude(self) -> bool:
        """Exclude hex-address placeholders, empty names, and ACD-internal runtime tags."""
        return (
            not self.name
            or not (self.name[0].isalpha() or self.name[0] == "_")
            or ":" in self.name
            or self.name.startswith("__l0")
            or self.name.startswith("__CLONE")
        )

    def to_xml(self) -> str:
        base = super().to_xml()
        desc_xml = (
            f'<Description>\n<![CDATA[{self._description}]]>\n</Description>'
            if self._description else ""
        )
        # DefaultData: OEM emits it on EVERY LocalTag (after Description). Degrade
        # to "" on any failure (still an element_missing, never malformed).
        dd_xml = _build_default_data(
            self.data_type, self.dimensions, self._value_bytes,
            self._short_header, self._data_types_map, self._taginfo_layout,
        )
        if not desc_xml and not dd_xml:
            return base
        idx = base.index(">")
        return base[:idx + 1] + desc_xml + dd_xml + base[idx + 1:]


@dataclass
class Parameter(L5xElement):
    """Represents a public parameter of an AOI (<Parameter> in L5X)."""
    name: str
    tag_type: str       # always "Base"
    data_type: str
    usage: str          # "Input", "Output", or "InOut"
    radix: Union[str, None]   # None for complex types (omitted from XML)
    required: str       # "true" or "false"
    visible: str        # "true" or "false"
    external_access: Union[str, None]  # None for InOut (omitted, replaced by Constant)
    constant: Union[str, None]  # "false" for non-MESSAGE InOut, None otherwise (omitted)
    dimensions: Union[str, None]  # array size; None for scalars (omitted from XML)
    _description: Union[str, None] = field(default=None)
    # AOI-scoped value image (mirrors Tag); defaults to the no-value state so
    # existing Parameter() constructions are unaffected.
    _data_types_map: Dict[str, "DataType"] = field(default_factory=dict)
    _taginfo_layout: Dict[str, object] = field(default_factory=dict)
    _value_bytes: Union[bytes, None] = None
    _value_type_code: int = 0
    _short_header: bool = False

    def __post_init__(self):
        super().__post_init__()
        self._export_name = "Parameter"

    @property
    def _l5x_exclude(self) -> bool:
        return (
            not self.name
            or not (self.name[0].isalpha() or self.name[0] == "_")
        )

    def to_xml(self) -> str:
        base = super().to_xml()
        desc_xml = (
            f'<Description>\n<![CDATA[{self._description}]]>\n</Description>'
            if self._description else ""
        )
        # DefaultData (validated gating on the full OEM pool):
        #   - emitted on Input/Output params, NOT on InOut (933/933 had none);
        #   - SUPPRESSED for the system params EnableIn/EnableOut (no DefaultData);
        #   - suppressed for unknown / SKIP_DECORATED types (handled inside helper).
        dd_xml = ""
        if self.usage != "InOut" and self.name not in ("EnableIn", "EnableOut"):
            dd_xml = _build_default_data(
                self.data_type, self.dimensions, self._value_bytes,
                self._short_header, self._data_types_map, self._taginfo_layout,
            )
        if not desc_xml and not dd_xml:
            return base
        idx = base.index(">")
        return base[:idx + 1] + desc_xml + dd_xml + base[idx + 1:]


@dataclass
class Module(L5xElement):
    """Represents a Logix hardware module (<Module> in L5X)."""
    name: str
    catalog_number: str
    vendor: int
    product_type: int
    product_code: int
    major: int
    minor: int
    parent_module: str
    parent_mod_port_id: int
    inhibited: str
    major_fault: str
    # Private fields (not serialised as XML attributes)
    # True for the root controller module (parent resolves to itself). Used to
    # special-case the root in port/slot logic; decoupled from major_fault, which
    # is now a real per-module flag and no longer a root proxy.
    _is_root: bool = field(default=False)
    _ekey_state: str = field(default="CompatibleModule")
    _slot: int = field(default=0)
    _ip_address: str = field(default="")
    _backplane_slot: Union[int, None] = field(default=None)
    _chassis_size: Union[int, None] = field(default=None)
    _port_child_counts: Dict[int, int] = field(default_factory=dict)
    # Pre-rendered <Ports> XML decoded from the module's RxDataCollection topology
    # blob (see ModuleBuilder._ports_from_data_collection). When set it replaces
    # the static PORT_STRUCTURES path; None falls back to that path.
    _ports_override: Union[str, None] = field(default=None)
    # Communications / ExtendedProperties / Description (optional)
    _description: str = field(default="")
    _comm_method: Union[str, None] = field(default=None)
    # Each entry: (name, rpi_str, conn_type_str)
    _connections: List[Tuple[str, str, str]] = field(default_factory=list)
    _extended_properties: str = field(default="")
    # True when the project's OPC UA server is enabled; module IO tag stubs then
    # carry OpcUaAccess="None" (see ExportL5x.project_flags).
    _opc_ua: bool = field(default=False)

    def __post_init__(self):
        super().__post_init__()
        self._export_name = "Module"

    def to_xml(self) -> str:
        # Hash-named drive peripherals have no Name attribute in Logix-exported L5X.
        name_attr = "" if self.name == "?" else f'Name="{self.name}" '
        attrs = (
            f'{name_attr}'
            f'CatalogNumber="{self.catalog_number}" '
            f'Vendor="{self.vendor}" '
            f'ProductType="{self.product_type}" '
            f'ProductCode="{self.product_code}" '
            f'Major="{self.major}" '
            f'Minor="{self.minor}" '
            f'ParentModule="{self.parent_module}" '
            f'ParentModPortId="{self.parent_mod_port_id}" '
            f'Inhibited="{self.inhibited}" '
            f'MajorFault="{self.major_fault}"'
        )

        # Optional <Description>
        desc_xml = ""
        if self._description:
            desc_xml = f'<Description>\n<![CDATA[{self._description}]]>\n</Description>'

        ekey = f'<EKey State="{self._ekey_state}"/>'
        ports = self._build_ports_xml()

        # <Communications> section — only emitted when a CommMethod is known.
        comm_xml = ""
        if self._comm_method is not None:
            # When the project OPC UA server is on, every module ConfigTag/InputTag/
            # OutputTag carries OpcUaAccess="None". Inject it after ExternalAccess so
            # all stubs share one rule.
            def _stub(tag: str, ext_access: str) -> str:
                opc = ' OpcUaAccess="None"' if self._opc_ua else ''
                # The reference writes <Comments> on a module InputTag/OutputTag
                # only when there is at least one operand <Comment> (always beside
                # <Data>); it never emits a bare empty <Comments/>. We carry no
                # per-operand module-IO comments, so emit a self-closing stub.
                return f'<{tag} ExternalAccess="{ext_access}"{opc}/>'

            conn_parts: List[str] = []
            for (conn_name, rpi_str, conn_type) in self._connections:
                safe_name = html.escape(conn_name, quote=True)
                # Derive InputTag / OutputTag stubs based on connection type.
                if conn_type == "Output":
                    tag_stubs = _stub("OutputTag", "Read/Write")
                else:
                    # Input or InputOutput: include both stubs.
                    tag_stubs = (
                        _stub("InputTag", "Read Only")
                        + _stub("OutputTag", "Read/Write")
                    )
                conn_parts.append(
                    f'<Connection Name="{safe_name}" RPI="{rpi_str}" Type="{conn_type}"'
                    f' EventID="0" ProgrammaticallySendEventTrigger="false" Unicast="false">'
                    f'{tag_stubs}'
                    f'</Connection>'
                )
            joined = "".join(conn_parts)
            connections_xml = f'<Connections>{joined}</Connections>' if joined else '<Connections/>'
            comm_xml = (
                f'<Communications CommMethod="{self._comm_method}">'
                f'{connections_xml}'
                f'</Communications>'
            )

        # <ExtendedProperties> section — only emitted when public data is known.
        ext_xml = ""
        if self._extended_properties:
            ext_xml = f'<ExtendedProperties><public>{self._extended_properties}</public></ExtendedProperties>'

        return f'<Module {attrs}>{desc_xml}{ekey}{ports}{comm_xml}{ext_xml}</Module>'

    def _build_ports_xml(self) -> str:
        """Build the <Ports>...</Ports> XML section for this module.

        Looks up the port structure from PORT_STRUCTURES by (vendor, product_type,
        product_code). Falls back to <Ports/> if the catalog number is not in the table.
        """
        # Prefer the real per-module topology decoded from RxDataCollection when
        # available; the static catalog covers only CPUs/EN bridges.
        if self._ports_override is not None:
            return self._ports_override
        key = (self.vendor, self.product_type, self.product_code)
        port_defs = PORT_STRUCTURES.get(key)
        if port_defs is None:
            return '<Ports/>'

        is_root = self._is_root
        port_parts: List[str] = []

        for pd in port_defs:
            # --- Upstream direction ---
            # Root modules (self-parenting CPU) have all ports downstream.
            # For other modules: if upstream_fixed=True, use the static upstream_port value.
            # If upstream_fixed=False, determine from parent_mod_port_id (the port on the
            # parent module that this module connects through — when that matches port_id,
            # this port faces upstream).
            if is_root:
                upstream_str = "false"
            elif pd.upstream_fixed:
                upstream_str = "true" if pd.upstream_port else "false"
            else:
                upstream_str = "true" if pd.port_id == self.parent_mod_port_id else "false"

            # --- Address attribute ---
            if pd.address_mode == "omit":
                addr_attr = ""
            elif pd.address_mode == "slot":
                # Non-upstream ICP ports (remote chassis owner): use _backplane_slot if known.
                if upstream_str == "false" and self._backplane_slot is not None:
                    addr_attr = f' Address="{self._backplane_slot}"'
                else:
                    addr_attr = f' Address="{self._slot if self._slot != 0xFFFFFFFF else 0}"'
            elif pd.address_mode == "zero":
                addr_attr = ' Address="0"'
            else:  # "empty" — use IP from binary if present, else omit value
                addr_attr = f' Address="{self._ip_address}"'

            # --- Bus element ---
            # Bus is only emitted on downstream (Upstream="false") ports.
            # upstream ports never carry a Bus element.
            is_upstream = (upstream_str == "true")
            bus_xml = self._bus_xml(pd, is_upstream)

            if bus_xml:
                port_parts.append(
                    f'<Port Id="{pd.port_id}"{addr_attr} Type="{pd.port_type}" Upstream="{upstream_str}">\n'
                    f'{bus_xml}\n'
                    f'</Port>\n'
                )
            else:
                port_parts.append(
                    f'<Port Id="{pd.port_id}"{addr_attr} Type="{pd.port_type}" Upstream="{upstream_str}"/>\n'
                )

        return f'<Ports>\n{"".join(port_parts)}</Ports>\n'

    def _bus_xml(self, pd, is_upstream: bool) -> str:
        """Return the Bus XML string for a port, or '' if no Bus element should be emitted.

        Bus elements are only present on downstream (Upstream=false) ports.
        """
        if is_upstream:
            return ""
        mode = pd.bus_mode
        if mode == "none":
            return ""
        if mode == "always":
            return "<Bus/>"
        if mode.startswith("fixed:"):
            # Use binary chassis size when available (read from RxDataCollection);
            # fall back to the hardcoded port_structures value.
            if self._chassis_size is not None:
                return f'<Bus Size="{self._chassis_size}"/>'
            size = mode.split(":")[1]
            return f'<Bus Size="{size}"/>'
        if mode == "children_or_none":
            child_count = self._port_child_counts.get(pd.port_id, 0)
            if self._chassis_size is not None:
                child_count = max(child_count, self._chassis_size)
            if child_count == 0:
                return ""
            return f'<Bus Size="{child_count}"/>'
        # "children" mode: child count, but never less than _chassis_size when known
        # (handles remote chassis with empty slots not represented as child modules).
        child_count = self._port_child_counts.get(pd.port_id, 0)
        if self._chassis_size is not None:
            child_count = max(child_count, self._chassis_size)
        return f'<Bus Size="{child_count}"/>'


@dataclass
class Routine(L5xElement):
    name: str
    type: str
    rungs: List[str]
    _rung_ids: List[int] = field(default_factory=list)
    _rung_comments: Dict[int, str] = field(default_factory=dict)

    def to_xml(self) -> str:
        rll_content = ""
        if self.type == "RLL" and self.rungs:
            rung_xmls = []
            for i, rung_text in enumerate(self.rungs):
                text = (rung_text or "").strip()
                if not text:
                    continue
                comment_xml = ""
                if i in self._rung_comments:
                    comment_text = self._rung_comments[i]
                    comment_xml = f'<Comment><![CDATA[{comment_text}]]></Comment>'
                rung_xmls.append(
                    f'<Rung Number="{i}" Type="N">'
                    f'{comment_xml}'
                    f'<Text><![CDATA[{text}]]></Text>'
                    f'</Rung>'
                )
            if rung_xmls:
                rll_content = f'<RLLContent>{"".join(rung_xmls)}</RLLContent>'
        return f'<Routine Name="{html.escape(self.name, quote=True)}" Type="{self.type}">{rll_content}</Routine>'


@dataclass
class AOI(L5xElement):
    name: str
    revision: str
    revision_extension: Union[str, None]  # None if absent (omitted from XML)
    vendor: Union[str, None]  # None if absent (omitted from XML)
    execute_prescan: str
    execute_postscan: str
    execute_enable_in_false: str
    created_date: str
    created_by: str
    edited_date: str
    edited_by: str
    software_revision: str
    parameters: List[Parameter]
    local_tags: List[LocalTag]
    routines: List[Routine]
    _description: Union[str, None] = field(default=None)
    _revision_note: str = field(default="")

    def __post_init__(self):
        super().__post_init__()
        self._export_name = "AddOnInstructionDefinition"

    def to_xml(self) -> str:
        base = super().to_xml()
        idx = base.index(">")
        inject = ""
        if self._description:
            inject += f'<Description>\n<![CDATA[{self._description}]]>\n</Description>'
        if self._revision_note:
            inject += f'<RevisionNote>\n<![CDATA[{self._revision_note}]]>\n</RevisionNote>'
        return base[:idx + 1] + inject + base[idx + 1:]


@dataclass
class Program(L5xElement):
    name: str
    test_edits: str
    main_routine_name: Union[str, None]  # None if absent (omitted from XML)
    fault_routine_name: Union[str, None]  # None if absent (omitted from XML)
    disabled: str
    synchronize_redundancy_data_after_execution: Union[str, None]  # None → omit attr
    use_as_folder: Union[str, None]  # None -> omit attr (V10..V20 projects)
    tags: List[Tag]        # Tags section before Routines (matches L5X export order)
    routines: List[Routine]


@dataclass
class ScheduledProgram(L5xElement):
    name: str

    def __post_init__(self):
        super().__post_init__()
        self._export_name = "ScheduledProgram"


@dataclass
class EventInfo(L5xElement):
    event_trigger: str
    enable_timeout: str

    def __post_init__(self):
        super().__post_init__()
        self._export_name = "EventInfo"


@dataclass
class Task(L5xElement):
    name: str
    type: str
    rate: Union[str, None]  # None for CONTINUOUS tasks (omitted from XML)
    priority: str
    watchdog: str
    disable_update_outputs: str
    inhibit_task: str
    event_info: Union[EventInfo, None]  # None for non-EVENT tasks
    scheduled_programs: List[ScheduledProgram]


@dataclass
class Controller(L5xElement):
    use: str
    name: str
    processor_type: Union[str, None]  # None if unknown (omitted from XML)
    major_rev: str
    minor_rev: str
    major_fault_program: Union[str, None]  # None if not set (omitted from XML)
    project_creation_date: str
    last_modified_date: str
    sfc_execution_control: str
    sfc_restart_position: str
    sfc_last_scan: str
    comm_path: Union[str, None]  # None if not set (omitted from XML)
    project_sn: str
    match_project_to_controller: str
    can_use_rpi_from_producer: str
    inhibit_automatic_firmware_update: str
    pass_through_configuration: str
    download_project_documentation_and_extended_properties: str
    download_project_custom_properties: str
    report_minor_overflow: str
    auto_diags_enabled: str
    web_server_enabled: str
    data_types: List[DataType]
    modules: List[Module]
    tags: List[Tag]
    programs: List[Program]
    tasks: List[Task]
    aois: List[AOI]
    # _redundancy_enabled is NOT serialised as a regular XML attribute (underscore prefix
    # skips it in the base to_xml()); it is used only to build the <RedundancyInfo> element.
    _redundancy_enabled: bool = field(default=False)
    # The reference emits a <DataLogs> element only for v24+ / 5x80 controllers
    # (the DataLog feature ships in v24); older controllers omit it entirely.
    # Set by the builder; default True keeps any other caller's prior output.
    _emit_data_logs: bool = field(default=True)

    def __post_init__(self):
        super().__post_init__()
        self._xml_attr_overrides = {
            "sfc_execution_control": "SFCExecutionControl",
            "sfc_restart_position": "SFCRestartPosition",
            "sfc_last_scan": "SFCLastScan",
            "project_sn": "ProjectSN",
            "can_use_rpi_from_producer": "CanUseRPIFromProducer",
        }

    def to_xml(self) -> str:
        base = super().to_xml()
        # Split at the end of the opening <Controller ...> tag so we can inject
        # structural stubs before the data sections and post-sections after them.
        idx = base.index(">")
        open_tag = base[: idx + 1]
        inner = base[idx + 1 : -len("</Controller>")]
        # RedundancyInfo: Enabled comes from binary; no pad attributes in golden.
        redundancy_enabled_str = "true" if self._redundancy_enabled else "false"
        redundancy_info = (
            f'<RedundancyInfo Enabled="{redundancy_enabled_str}" KeepTestEditsOnSwitchOver="false"/>'
        )
        return (
            open_tag
            + inner
            + redundancy_info
            + '<Security Code="0" ChangesToDetect="16#ffff_ffff_ffff_ffff"/>'
            + '<SafetyInfo/>'
            + '<CST MasterID="0"/>'
            + '<WallClockTime LocalTimeAdjustment="0" TimeZone="0"/>'
            + '<Trends/>'
            + ('<DataLogs/>' if self._emit_data_logs else '')
            + '<TimeSynchronize Priority1="128" Priority2="128" PTPEnable="true"/>'
            + '</Controller>'
        )


# Matches an emitted tag-value Format="L5K" <Data> block: group 1 = the open tag
# through "<![CDATA[", group 2 = the (single-line) bracket-list body, group 3 =
# the "]]>" terminator. Used to re-wrap the body at export time. Only <Data> is
# wrapped: the reference wraps tag-value L5K lists (4216 blocks) but never wraps
# AOI <DefaultData Format="L5K"> (5841 blocks, 0 wrapped), so those stay single-line.
_L5K_CDATA_RE = re.compile(
    r'(<Data\b[^>]*\bFormat="L5K"[^>]*>\s*<!\[CDATA\[)(.*?)(\]\]>)',
    re.S,
)


@dataclass
class RSLogix5000Content(L5xElement):
    """Controller Project"""

    controller: Union[Controller, None]
    schema_revision: str
    software_revision: str
    target_name: str
    target_type: str
    contains_context: str
    export_date: str
    export_options: str

    def __post_init__(self):
        super().__post_init__()
        self._export_name = "RSLogix5000Content"

    def to_xml(self) -> str:
        xml = super().to_xml()
        # Reproduce Logix Designer's L5K bracket-list line wrap. The writer wraps
        # long Format="L5K" <Data>/<DefaultData> CDATA at an 81 value-character
        # budget with a per-format-version tab indent (SoftwareRevision >= 32 -> 2
        # tabs, else 5). Done as a single post-pass over the assembled document so
        # the indent is resolved once from the controller revision. Best-effort:
        # if the revision can't be parsed, leave the single-line form.
        try:
            major = int(str(self.software_revision).split(".")[0])
        except (ValueError, AttributeError, IndexError):
            return xml
        depth = 2 if major >= 32 else 5

        def _rewrap(m: "re.Match") -> str:
            return m.group(1) + _tag_value._wrap_l5k(m.group(2), depth) + m.group(3)

        return _L5K_CDATA_RE.sub(_rewrap, xml)


# Atomic/primitive Logix base types: emitted as empty self-closing DataTypes
# (no <Members>) by the OEM L5X even though Comps stores a self-member for them.
_ATOMIC_TYPES = {"BOOL", "SINT", "USINT", "INT", "UINT", "DINT", "UDINT",
                 "LINT", "ULINT", "REAL", "LREAL", "BYTE", "WORD", "DWORD",
                 "LWORD"}


def _decode_utf16z(buf: bytes) -> str:
    """Decode a NUL-terminated UTF-16LE string (walk u16 units to 0x0000).

    Used for V10..V21 short-header inline member names (stored at offset 0 of
    each datatype extended record).
    """
    units = []
    for i in range(0, len(buf) - 1, 2):
        u = buf[i] | (buf[i + 1] << 8)
        if u == 0:
            break
        units.append(u)
    try:
        return "".join(chr(u) for u in units)
    except ValueError:
        return ""


def radix_enum(i: int) -> str:
    if i == 0:
        return "NullType"
    if i == 1:
        return "General"
    if i == 2:
        return "Binary"
    if i == 3:
        return "Octal"
    if i == 4:
        return "Decimal"
    if i == 5:
        return "Hex"
    if i == 6:
        return "Exponential"
    if i == 7:
        return "Float"
    if i == 8:
        return "ASCII"
    if i == 9:
        return "Unicode"
    if i == 10:
        return "Date/Time"
    if i == 11:
        return "Date/Time (ns)"
    if i == 12:
        return "UseTypeStyle"
    return "General"


def external_access_enum(i: int) -> str:
    default = "Read/Write"
    if i == 0:
        return default
    if i == 2:
        return "Read Only"
    if i == 3:
        return "None"
    return default


@dataclass
class MemberBuilder(L5xElementBuilder):
    record: bytes = field(default_factory=bytes)
    # Map from offset-0x60 value to backing member name, used to resolve BIT Target.
    # Built by DataTypeBuilder before iterating children and passed in here.
    _offset60_to_name: Dict[int, str] = field(default_factory=dict)
    # Fallback target name for Pattern-2 BIT members (0x68==0, 0x6c==0xFFFFFFFF).
    # Set by DataTypeBuilder to the most recent preceding hidden SINT/INT in member order.
    _fallback_target: Union[str, None] = field(default=None)
    # V10..V21 short-header members are NOT separate Comps records: their name +
    # field layout live inside the owning datatype's extended record (the same
    # 168-byte blob passed in via `record`, with the UTF-16LE member name at
    # offset 0). When `_short_name` is set we skip the by-object_id Comps lookup
    # (there is none) and decode straight from `record`. Defaults None so the
    # V24+/V36 long path is unaffected.
    _short_name: Union[str, None] = field(default=None)
    # Owning datatype's class ("User"/"ProductDefined"/"IO"), passed down by
    # DataTypeBuilder so BIT-overlay host resolution can branch: User keeps the
    # preceding-hidden-integer rule; ProductDefined/IO use the offset-0 member
    # (0x68==0) or the most-recent preceding non-BIT member (0x68 nonzero).
    _owner_cls: str = field(default="User")
    # Member-ordinal -> name list of the owning datatype (seq order). For
    # ProductDefined/IO BIT members whose 0x6c==FFFFFFFF, the 0x68 field is the
    # member-collection index of the host word (1-based effectively, but stored
    # as the host's 0-based ordinal), so Target = _members_by_index[0x68].
    _members_by_index: List[str] = field(default_factory=list)
    # Owning datatype's comment_id (short-header only). A member description is
    # stored in the comments table keyed by this comment_id (bare, not shifted)
    # with the member NAME in tag_reference; short-header members have no per-
    # member comps record, so the name is the only discriminator. 0 -> skip.
    _owner_comment_id: int = field(default=0)

    def build(self) -> Member:
        if self._short_name is not None:
            return self._build_short()

        self._cur.execute(
            "SELECT comp_name, object_id, parent_id, record FROM comps WHERE object_id="
            + str(self._object_id)
        )
        results = self._cur.fetchall()

        name = results[0][0]
        sp_member = False
        try:
            r = RxGeneric.from_bytes(results[0][3])
        except Exception as e:
            # Source-protected member record: its own ext-attr tail is encrypted,
            # but every field this builder needs comes from ``self.record`` (the
            # member descriptor blob, passed in already-decrypted by the datatype
            # builder). Recover comment_id/cip_type from the plaintext main_record.
            # The member-description comment key does NOT resolve for source-
            # protected members (it matches stray 1-byte rows), so descriptions are
            # left off here (member descriptions are rare anyway). Fall back to a
            # plain member only when even the main_record is unreadable.
            r = _rxgeneric_plaintext_main(results[0][3])
            if r is None:
                return Member(name, name, "", 0, "Decimal", False, None, None, "Read/Write")
            sp_member = True

        extended_records: Dict[int, List[int]] = {}
        for extended_record in getattr(r, "extended_records", []):
            extended_records[extended_record.attribute_id] = extended_record.value

        cip_data_typoe = struct.unpack_from("<I", self.record, 0x78)[0]
        dimension = struct.unpack_from("<I", self.record, 0x5C)[0]
        # A bogus dimension (e.g. 0x20000) appears in the 0x5C slot for some
        # non-array scalar members of predefined types; clamp implausible values
        # to 0 so we don't emit a garbage Dimension attribute. (BIT members
        # override dimension to 0 below regardless.)
        if dimension > 0x10000:
            dimension = 0
        radix = radix_enum(struct.unpack_from("<I", self.record, 0x54)[0])
        data_type_id = struct.unpack_from("<I", self.record, 0x58)[0]
        hidden = bool(struct.unpack_from("<I", self.record, 0x70)[0])
        # ExternalAccess is the single byte at 0xA0 of the member-descriptor
        # ext-record (0=Read/Write, 2=Read Only, 3=None), NOT the u32 at 0x74
        # (which is uniformly 1 and is not ExternalAccess). Fall back to the old
        # 0x74 enum path only when the record is too short to hold 0xA0.
        if len(self.record) > 0xA0:
            external_access = external_access_enum(self.record[0xA0])
        else:
            external_access = external_access_enum(
                struct.unpack_from("<I", self.record, 0x74)[0]
            )

        self._cur.execute(
            "SELECT comp_name, object_id, parent_id, record FROM comps WHERE object_id="
            + str(data_type_id)
        )
        data_type_results = self._cur.fetchall()
        data_type = data_type_results[0][0]

        # BIT members: data_type resolves to BOOL but the encoding varies by sub-type.
        #
        # Pattern 1 (0x6c != 0xFFFFFFFF): 0x6c holds the 0x60 byte-offset of the backing
        #   field.  Resolve target via offset60_to_name.
        #
        # Pattern 2 (0x6c == 0xFFFFFFFF and 0x68 == 0): BIT member where the backing field
        #   pointer is absent.  Use _fallback_target (the most-recent preceding hidden SINT).
        #
        # Pattern 3 (0x6c == 0xFFFFFFFF and 0x68 == 1): BIT member where 0x60 directly
        #   matches the backing field's 0x60 value.  Resolve target via offset60_to_name
        #   using the member's own 0x60 value as the lookup key.
        #
        # Plain BOOL (0x6c == 0xFFFFFFFF and 0x68 == 0x800): not a BIT member; leave as BOOL.
        target: Union[str, None] = None
        bit_number: Union[int, None] = None
        if data_type == "BOOL":
            target_key = struct.unpack_from("<I", self.record, 0x6C)[0]
            val_68 = struct.unpack_from("<I", self.record, 0x68)[0]
            # A BOOL member is a BIT overlay unless it is a real standalone BOOL
            # (0x6c == FFFFFFFF and 0x68 == 0x800).
            is_plain_bool = (target_key == 0xFFFFFFFF and val_68 == 0x800)
            if not is_plain_bool:
                # offset 0x5C holds a bit-offset into the host register, not an
                # array size — force dimension to 0 so _member_decorated_xml
                # treats this as a scalar rather than emitting many <Element>s.
                data_type = "BIT"
                dimension = 0
                bit_number = struct.unpack_from("<I", self.record, 0x64)[0]
                if target_key != 0xFFFFFFFF:
                    # Pattern 1: explicit backing-field byte offset via 0x6c.
                    target = self._offset60_to_name.get(target_key)
                elif self._owner_cls in ("ProductDefined", "IO"):
                    # Predefined / IO type: 0x68 is the member-collection ordinal
                    # of the host word (0 -> the offset-0 member, e.g.
                    # CONTROL/TIMER 'Control', PID 'CTL'; nonzero -> the host at
                    # that member index, e.g. ulBoolInput2/AlarmControlFlags).
                    if 0 <= val_68 < len(self._members_by_index):
                        target = self._members_by_index[val_68]
                    if target is None:
                        target = self._offset60_to_name.get(0)
                else:
                    # User datatype: preceding hidden integer backing member.
                    if val_68 == 1:
                        val_60 = struct.unpack_from("<I", self.record, 0x60)[0]
                        target = self._offset60_to_name.get(val_60)
                    else:
                        target = self._fallback_target

        # --- Description ---
        # The member's description is identified in the comments table by a
        # member_ref value extracted from bytes [14:18] of the comps record.
        # This value is non-zero for sub-elements (members) and zero for the
        # owning object's own description.
        description: Union[str, None] = None
        raw_comps = bytes(results[0][3])
        if not sp_member and len(raw_comps) >= 18:
            member_ref = struct.unpack_from("<I", raw_comps, 14)[0]
            if member_ref:
                self._cur.execute(
                    "SELECT record_string FROM comments WHERE parent=? AND member_ref=? LIMIT 1",
                    ((r.comment_id * 0x10000) + r.cip_type, member_ref),
                )
                desc_row = self._cur.fetchone()
                if desc_row and desc_row[0]:
                    description = desc_row[0]

        return Member(name, name, data_type, dimension, radix, hidden, target, bit_number, external_access, description)

    def _build_short(self) -> Member:
        """Build a Member for a V10..V21 short-header datatype.

        The member's name (`_short_name`) and its 168-byte field record
        (`self.record`) come from the owning datatype's extended record — there
        is no per-member Comps record to query. Field offsets are IDENTICAL to
        the long path (0x54 radix .. 0x78 cip); only the name source and the
        description lookup differ. Wrapped so a malformed short record degrades
        to a plain BOOL/empty member instead of crashing the whole datatype.
        """
        name = self._short_name
        try:
            dimension = struct.unpack_from("<I", self.record, 0x5C)[0]
            radix = radix_enum(struct.unpack_from("<I", self.record, 0x54)[0])
            data_type_id = struct.unpack_from("<I", self.record, 0x58)[0]
            hidden = bool(struct.unpack_from("<I", self.record, 0x70)[0])
            # ExternalAccess = byte at 0xA0 (0=Read/Write, 2=Read Only, 3=None),
            # not the u32 at 0x74. Fall back to 0x74 only for short records.
            if len(self.record) > 0xA0:
                external_access = external_access_enum(self.record[0xA0])
            else:
                external_access = external_access_enum(
                    struct.unpack_from("<I", self.record, 0x74)[0]
                )

            self._cur.execute(
                "SELECT comp_name FROM comps WHERE object_id=" + str(data_type_id)
            )
            dt_row = self._cur.fetchone()
            data_type = dt_row[0] if dt_row else ""

            target: Union[str, None] = None
            bit_number: Union[int, None] = None
            if data_type == "BOOL":
                # V10..V21 BIT rule (validated 5735/5735 on PROJ_D): a BOOL
                # member is a BIT alias UNLESS 0x68 == 0x800 (a real standalone
                # BOOL). The bit index is 0x64; the backing field is the
                # non-BIT member whose byte range covers 0x6c (or 0x60 when
                # 0x6c == 0xFFFFFFFF) -> resolved via the byte-range
                # offset60_to_name map (target+bit 2832/2832 correct).
                val_68 = struct.unpack_from("<I", self.record, 0x68)[0]
                if val_68 != 0x800:
                    data_type = "BIT"
                    dimension = 0
                    bit_number = struct.unpack_from("<I", self.record, 0x64)[0]
                    target_key = struct.unpack_from("<I", self.record, 0x6C)[0]
                    if target_key != 0xFFFFFFFF:
                        # Pattern 1: explicit backing-field byte offset.
                        target = self._offset60_to_name.get(target_key)
                    elif self._owner_cls in ("ProductDefined", "IO"):
                        # Predefined / IO type: 0x68 is the member-collection
                        # ordinal of the host word the bit overlays (e.g. ALARM
                        # EnableIn -> ulBoolInput1 @ index 0, the alarm bits ->
                        # ulBoolOutput1 @ index 11). Mirrors the long-header path;
                        # the prior short path fell through to the offset-60 map and
                        # mis-resolved these to an unrelated member (verified V11
                        # ALARM/PID: members_by_index[0x68] == OEM Target).
                        if 0 <= val_68 < len(self._members_by_index):
                            target = self._members_by_index[val_68]
                        if target is None:
                            target = self._offset60_to_name.get(0)
                    else:
                        val_60 = struct.unpack_from("<I", self.record, 0x60)[0]
                        target = self._offset60_to_name.get(val_60)
                    if target is None:
                        target = self._fallback_target
            else:
                # A bogus dimension (e.g. 0xFFFC0000) sometimes appears in the
                # 0x5C slot for non-array scalar members; clamp implausible
                # values to 0 so we don't emit a garbage Dimension attribute.
                if dimension > 0x10000:
                    dimension = 0
            # Member description: a short-header member has no per-member comps
            # record, so its description is stored in the comments table keyed by
            # the owning datatype's bare comment_id with the member NAME in
            # tag_reference. The comment_id is unique per datatype, so (comment_id,
            # name) identifies one member. record_type is NOT filtered: it is an
            # ordinal (3..36), so the member descriptions live across the whole
            # range (verified V16: 179/179 found by (cid,name), but only 82 fall in
            # the old 3..11 window -- 97 at record_type 8/12..22 were dropped). A
            # bare member name in tag_reference never matches an operand comment
            # (those carry a '.'/'['-prefixed operand) or an own-description (empty
            # tag_reference), so dropping the record_type window adds no false hits.
            description: Union[str, None] = None
            if self._owner_comment_id:
                self._cur.execute(
                    "SELECT record_string FROM comments "
                    "WHERE parent=? "
                    "AND tag_reference=? AND record_string!='' LIMIT 1",
                    (self._owner_comment_id, name),
                )
                d_row = self._cur.fetchone()
                if d_row and d_row[0]:
                    description = d_row[0]
            return Member(name, name, data_type, dimension, radix, hidden,
                          target, bit_number, external_access, description)
        except Exception:
            return Member(name, name, "", 0, "Decimal", False, None, None, "Read/Write")


@dataclass
class DataTypeBuilder(L5xElementBuilder):
    # V10..V21 short-header datatypes carry their members inline (extended
    # records 0x6E+) instead of as child Comps records, and the OEM L5X emits
    # the full lean set (User + ProductDefined + IO). Set True by the
    # short-header ControllerBuilder path; defaults False -> identical V24+
    # behaviour.
    _short_header: bool = field(default=False)

    def build(self) -> DataType:
        self._cur.execute(
            "SELECT comp_name, object_id, parent_id, record FROM comps WHERE object_id="
            + str(self._object_id)
        )
        results = self._cur.fetchall()

        name = results[0][0]

        extended_records: Dict[int, bytes] = {}
        try:
            r = RxGeneric.from_bytes(results[0][3])
            for extended_record in r.extended_records:
                extended_records[extended_record.attribute_id] = bytes(
                    extended_record.value
                )
        except Exception as e:
            # Source-protected datatype: the ext-attr tail (member descriptors at
            # 0x6E.., the member_count at 0x64, class flags at 0x67/0x69/0x6C) is
            # AES-encrypted, so the kaitai parser throws. Recover the WHOLE attr
            # table by decrypting the untruncated payload, and take comment_id /
            # cip_type from the plaintext main_record, so members (and their radix /
            # data type / dimensions) are still built. Returns the no-members stub
            # only when the record is too short or no key validates.
            r = _rxgeneric_plaintext_main(results[0][3])
            full_payload = None
            try:
                self._cur.execute(
                    "SELECT record FROM comps_full WHERE object_id=" + str(self._object_id)
                )
                _row = self._cur.fetchone()
                if _row and _row[0] is not None:
                    full_payload = bytes(_row[0])
            except Exception:
                full_payload = None
            if r is not None and full_payload is not None:
                extended_records = CompsRecord.read_value_attrs(
                    full_payload, self._short_header, full=True
                )
            if r is None or not extended_records:
                dt = DataType(name, name, "NoFamily", "User", [])
                dt._emit_predefined = self._short_header
                return dt

        def _ext_u32(key, default=0):
            v = extended_records.get(key)
            return struct.unpack("<I", v)[0] if v is not None and len(v) >= 4 else default

        string_family_int = _ext_u32(0x6C)
        string_family = "StringFamily" if string_family_int == 1 else "NoFamily"

        built_in = _ext_u32(0x67)
        module_defined = _ext_u32(0x69)

        class_type = "User"
        if self._short_header:
            # V10..V21: module-defined (IO) types ALSO have built_in&3 set, so IO
            # must take precedence (verified 142/142 vs OEM on PROJ_D). The long
            # path keeps its original precedence below, untouched.
            if module_defined > 0:
                class_type = "IO"
            elif built_in & 0x03:
                class_type = "ProductDefined"
        else:
            # IO precedence (module-defined types also carry built_in&3, so IO
            # must win) to match the OEM class assignment.
            if module_defined > 0:
                class_type = "IO"
            elif built_in & 0x03:
                class_type = "ProductDefined"
        if 0x64 in extended_records and len(extended_records[0x64]) == 0x04:
            member_count = struct.unpack("<I", extended_records[0x64])[0]
        else:
            member_count = 0

        self._cur.execute(
            "SELECT comp_name, object_id, parent_id, record FROM comps WHERE parent_id="
            + str(self._object_id)
        )
        member_results = self._cur.fetchall()
        children: List[Member] = []
        if len(member_results) == 1:
            member_collection_id = member_results[0][1]

            self._cur.execute(
                f"SELECT comp_name, object_id, parent_id, seq_number, record FROM comps WHERE parent_id={member_collection_id} ORDER BY seq_number"
            )
            children_results = self._cur.fetchall()

            # Build offset60→name map so BIT members can resolve their Target name.
            # Each member's extended record stores the byte offset of that member's data
            # within the UDT at [0x60]; BIT members reference their backing field's
            # offset via [0x6c].  Non-BIT members have [0x6c]=0xFFFFFFFF and 0x68=0x800.
            # Only include non-BIT members (0x68==0x800) so that BIT members sharing the
            # same 0x60 value as their backing field do not overwrite the backing entry.
            _BACKING_SIZE = {"SINT": 1, "USINT": 1, "BYTE": 1, "BOOL": 1,
                             "INT": 2, "UINT": 2, "WORD": 2,
                             "DINT": 4, "UDINT": 4, "DWORD": 4,
                             "LINT": 8, "ULINT": 8, "LWORD": 8}
            offset60_to_name: Dict[int, str] = {}
            for idx2, child2 in enumerate(children_results):
                key2 = 0x6E + idx2
                if key2 not in extended_records:
                    break
                rec2 = bytes(extended_records[key2])
                if len(rec2) >= 0x70:
                    target_key2 = struct.unpack_from("<I", rec2, 0x6C)[0]
                    val_68_2 = struct.unpack_from("<I", rec2, 0x68)[0]
                    if target_key2 == 0xFFFFFFFF and val_68_2 == 0x800:
                        val_60 = struct.unpack_from("<I", rec2, 0x60)[0]
                        offset60_to_name[val_60] = child2[0]
                        # A BIT member's 0x6c is a BYTE offset that can land in
                        # the high byte of a multi-byte backing word (e.g. an INT
                        # at 0x0e covering bytes 0x0e..0x0f). Map every byte the
                        # backing field covers to its name so Pattern-1 lookups by
                        # the exact byte resolve. setdefault keeps the first (the
                        # word's own 0x60) authoritative for collisions.
                        dt_id_2 = struct.unpack_from("<I", rec2, 0x58)[0]
                        self._cur.execute(
                            "SELECT comp_name FROM comps WHERE object_id="
                            + str(dt_id_2)
                        )
                        _row2 = self._cur.fetchone()
                        _base2 = _row2[0] if _row2 else ""
                        for _b in range(val_60, val_60 + _BACKING_SIZE.get(_base2, 1)):
                            offset60_to_name.setdefault(_b, child2[0])

            # Member-ordinal -> name list (seq order). For ProductDefined/IO BIT
            # members whose 0x6c==FFFFFFFF, 0x68 is the member-collection ordinal
            # of the host word (e.g. CONTROL idx0 host, ALARM_ANALOG bits ->
            # AlarmControlFlags at idx10, MMC bits -> ulBoolInput2/3CV* hosts).
            members_by_index: List[str] = [c[0] for c in children_results]

            # Some ACD files have mismatched member_count vs children list — iterate what we have.
            # Track the most recent preceding hidden SINT (fallback target for Pattern-2 BIT members).
            last_hidden_backing: Union[str, None] = None
            for idx, child in enumerate(children_results):
                key = 0x6E + idx
                if key not in extended_records:
                    break
                rec = bytes(extended_records[key])
                # Update last_hidden_backing when we see a hidden member
                if len(rec) >= 0x74:
                    is_hidden = bool(struct.unpack_from("<I", rec, 0x70)[0])
                    if is_hidden:
                        last_hidden_backing = child[0]
                try:
                    children.append(
                        MemberBuilder(
                            self._cur, child[1], bytes(extended_records[key]),
                            offset60_to_name,
                            last_hidden_backing,
                            _owner_cls=class_type,
                            _members_by_index=members_by_index,
                        ).build()
                    )
                except Exception:
                    pass
        elif (
            self._short_header
            and member_count > 0
            and name.upper() not in _ATOMIC_TYPES
        ):
            # V10..V21 short-header: members live inline as extended records
            # 0x6E, 0x6E+1, ... (one 168-byte blob each, member name at offset 0
            # as UTF-16LE). There is no child member-collection record, so build
            # each Member straight from its ext blob. Best-effort: a malformed
            # blob is skipped, leaving today's empty-members fallback for the
            # rest of the type. Atomic base types (BOOL/SINT/.../REAL) carry a
            # single self-referential member in Comps but the OEM L5X emits them
            # as empty self-closing DataTypes, so skip member emission for them.
            short_recs: List[tuple] = []  # (name, blob)
            for idx2 in range(member_count):
                key2 = 0x6E + idx2
                if key2 not in extended_records:
                    break
                blob = bytes(extended_records[key2])
                # The inline member name is NUL-terminated UTF-16LE starting at
                # byte 0; the next member field (radix u32) begins at 0x54, so the
                # name field spans 0..0x53. Decode up to that boundary (0x40 cut
                # names longer than 32 chars). _decode_utf16z stops at the first
                # NUL, so shorter names are unaffected.
                mname = _decode_utf16z(blob[0:0x54]) if len(blob) >= 2 else ""
                short_recs.append((mname, blob))

            # The kaitai RxGeneric parser only counts (count_record - 1)
            # extended records; the FINAL member is carried in the trailing
            # LastAttributeRecord (same layout the controller CommPath uses).
            # Recover it so datatypes don't lose their last member.
            if len(short_recs) < member_count:
                try:
                    raw_rec = bytes(results[0][3])
                    rec_offset = 82
                    for _er in r.extended_records:
                        rec_offset += 4 + 4 + len(bytes(_er.value))
                    tail = raw_rec[rec_offset:]
                    if len(tail) >= 8:
                        last_len = struct.unpack_from("<I", tail, 4)[0]
                        actual = last_len - 4
                        if actual > 0 and len(tail) >= 8 + actual:
                            tail_blob = tail[8: 8 + actual]
                            # Same name-field boundary as the inline path (0x54).
                            tail_name = _decode_utf16z(tail_blob[0:0x54])
                            if tail_name:
                                short_recs.append((tail_name, tail_blob))
                except Exception:
                    pass

            # offset60 -> backing-field name map (non-BIT members only), so BIT
            # members can resolve their Target, mirroring the long path. A BIT
            # member's 0x6c is the BYTE offset of the bit it occupies; for a
            # multi-byte backing field (INT/DINT) that byte offset can land
            # past the backing field's own 0x60 (e.g. the high byte of an INT),
            # so we map EVERY byte the backing field covers to its name (sizes
            # below). _build_short still tries the exact 0x60 first.
            _BACKING_SIZE = {"SINT": 1, "USINT": 1, "BYTE": 1, "BOOL": 1,
                             "INT": 2, "UINT": 2, "WORD": 2,
                             "DINT": 4, "UDINT": 4, "DWORD": 4,
                             "LINT": 8, "ULINT": 8, "LWORD": 8}
            offset60_to_name = {}
            for mname, blob in short_recs:
                if len(blob) < 0x78:
                    continue
                dt_id_b = struct.unpack_from("<I", blob, 0x58)[0]
                self._cur.execute(
                    "SELECT comp_name FROM comps WHERE object_id=" + str(dt_id_b)
                )
                _row = self._cur.fetchone()
                base = _row[0] if _row else ""
                val_68_2 = struct.unpack_from("<I", blob, 0x68)[0]
                # A BIT alias (BOOL with 0x68 != 0x800) is NOT a backing field;
                # every other member (atomic scalar, or a real BOOL with
                # 0x68==0x800) backs the bits that overlay its byte range.
                if base == "BOOL" and val_68_2 != 0x800:
                    continue
                val_60 = struct.unpack_from("<I", blob, 0x60)[0]
                sz = _BACKING_SIZE.get(base, 1)
                offset60_to_name[val_60] = mname
                for b_off in range(val_60, val_60 + sz):
                    offset60_to_name.setdefault(b_off, mname)

            # Member-ordinal -> name list (seq order), so ProductDefined/IO BIT
            # members can resolve their host word by 0x68 index (mirrors the long
            # path's members_by_index).
            members_by_index_s: List[str] = [n for n, _ in short_recs]
            last_hidden_backing = None
            for mname, blob in short_recs:
                if not mname:
                    continue
                if len(blob) >= 0x74:
                    is_hidden = bool(struct.unpack_from("<I", blob, 0x70)[0])
                    if is_hidden:
                        last_hidden_backing = mname
                try:
                    children.append(
                        MemberBuilder(
                            self._cur, -1, blob,
                            offset60_to_name,
                            last_hidden_backing,
                            _short_name=mname,
                            _owner_cls=class_type,
                            _members_by_index=members_by_index_s,
                            _owner_comment_id=r.comment_id,
                        ).build()
                    )
                except Exception:
                    pass

        # --- Description ---
        # The datatype's own description carries object_id == 1; operand/scratch
        # rows that share the (parent, member_ref=0) key carry a nonzero object_id
        # and their record_string is a name-fragment, so requiring object_id == 1
        # drops those fabricated Descriptions while keeping the real one.
        description: Union[str, None] = None
        self._cur.execute(
            "SELECT record_string FROM comments "
            "WHERE parent=? AND member_ref=0 AND object_id=1 LIMIT 1",
            ((r.comment_id * 0x10000) + r.cip_type,),
        )
        desc_row = self._cur.fetchone()
        if desc_row and desc_row[0]:
            description = desc_row[0]

        dt = DataType(name, name, string_family, class_type, children, description)
        dt._emit_predefined = self._short_header
        return dt


@dataclass
class ModuleBuilder(L5xElementBuilder):
    # Map from modid (u32) → module name, built by ControllerBuilder and passed in.
    _modid_to_name: Dict[int, str] = field(default_factory=dict)

    def _ip_from_data_collection(self, icp_slot: int) -> str:
        """Look up the Ethernet IP for a local backplane module via RxDataCollection.

        Local bridge modules (e.g. EN2T in the main chassis) store their IP as XML
        in hash-named children of RxDataCollection. The record for a given module
        contains its ICP slot as Type="ICP" Addr="{slot}", which uniquely identifies it.
        """
        import re as _re
        needle = f'Type="ICP" Addr="{icp_slot}"'.encode()
        # Find RxDataCollection — it is a direct child of the controller object.
        self._cur.execute(
            "SELECT object_id FROM comps WHERE comp_name='RxDataCollection' LIMIT 1"
        )
        row = self._cur.fetchone()
        if not row:
            return ""
        coll_oid = row[0]
        # Fetch all children in batches and filter in Python (SQLite LIKE on BLOBs is unreliable).
        self._cur.execute(
            "SELECT record FROM comps WHERE parent_id=?", (coll_oid,)
        )
        for (raw,) in self._cur.fetchall():
            raw = bytes(raw)
            if needle not in raw:
                continue
            m = _re.search(rb'Type="EN" Addr="([^"]+)"', raw)
            return m.group(1).decode("ascii", errors="replace") if m else ""
        return ""

    def _comms_from_data_collection(
        self, icp_slot: int, ip_address: str = ""
    ) -> "Tuple[Union[str, None], str]":
        """Extract CommMethod and ExtendedProperties public data for a module.

        Searches RxDataCollection for the hash-named child whose <in> block contains
        a Port with Type="ICP" Addr="{icp_slot}".  For Ethernet-connected modules
        (icp_slot == 0 or not found by ICP slot) a second pass matches by the
        module's IP address instead.

        Returns a 2-tuple:
          (comm_method_str_or_None, public_content_str)

        comm_method_str: the numeric string from <CF>...</CF>, or None if absent.
        public_content_str: inner content of <public>...</public>, or "" if absent.

        The record XML is often stored without the closing </public> tag (it is
        truncated in the ACD binary). We reconstruct the content by extracting
        everything after <public>.
        """
        import re as _re

        def _extract(raw: bytes) -> "Tuple[Union[str, None], str]":
            xml_start = raw.find(b'<')
            if xml_start < 0:
                return (None, "")
            xml_text = raw[xml_start:].decode("latin-1", errors="replace")
            comm_method: Union[str, None] = None
            cf_m = _re.search(r'<CF>(\d+)</CF>', xml_text)
            if cf_m:
                comm_method = cf_m.group(1)
            pub_content = ""
            pub_start = xml_text.find("<public>")
            if pub_start >= 0:
                after_pub = xml_text[pub_start + len("<public>"):]
                end_tag_m = _re.search(r'</pub', after_pub)
                if end_tag_m:
                    pub_content = after_pub[:end_tag_m.start()]
                else:
                    pub_content = after_pub.rstrip("\x00 \r\n")
            return (comm_method, pub_content)

        self._cur.execute(
            "SELECT object_id FROM comps WHERE comp_name='RxDataCollection' LIMIT 1"
        )
        row = self._cur.fetchone()
        if not row:
            return (None, "")
        coll_oid = row[0]
        self._cur.execute(
            "SELECT record FROM comps WHERE parent_id=?", (coll_oid,)
        )
        all_recs = [(bytes(raw),) for (raw,) in self._cur.fetchall()]

        # First pass: match by ICP slot.
        if icp_slot:
            needle = f'Type="ICP" Addr="{icp_slot}"'.encode()
            for (raw,) in all_recs:
                if needle in raw:
                    result = _extract(raw)
                    if result[0] is not None or result[1]:
                        return result

        # Second pass: match by IP address (for EN-connected modules).
        if ip_address:
            ip_needle = f'Addr="{ip_address}"'.encode()
            for (raw,) in all_recs:
                if ip_needle in raw:
                    result = _extract(raw)
                    if result[0] is not None or result[1]:
                        return result

        return (None, "")

    def _ports_from_data_collection(self, data_link: int) -> "Union[str, None]":
        """Build the <Ports> block from the module's RxDataCollection topology blob.

        Every module stores, at e1[0x24] (u32), the comment_id of its backing
        RxDataCollection child; that child's record carries a plaintext
        ``<in><Port .../>...</in>`` blob with the real port topology (which the
        static PORT_STRUCTURES catalog does not cover). comment_id is unique among
        the blob-bearing children, so this is an exact 1:1 link -- it works for
        every module type (Ethernet drives, drive peripherals, PointIO adapters,
        backplane bridges), unlike an IP/slot heuristic which mislinks name-less
        peripherals that share a bus address across different parents.

        ``data_link`` is e1[0x24]. Modules whose link resolves to a child with no
        ``<in>`` blob (the controller and local-chassis cards, whose single ICP
        port is implied by slot and not stored) fall back to the static catalog.
        Returns the rendered ``<Ports>...</Ports>`` string, or None to fall back.
        """
        if not data_link:
            return None
        # Blob children of every RxDataCollection, keyed by comment_id (u16 @ rec[12]).
        self._cur.execute("SELECT object_id FROM comps WHERE comp_name='RxDataCollection'")
        coll_oids = [r[0] for r in self._cur.fetchall()]
        if not coll_oids:
            return None
        for coll_oid in coll_oids:
            self._cur.execute("SELECT record FROM comps WHERE parent_id=?", (coll_oid,))
            for (raw,) in self._cur.fetchall():
                raw = bytes(raw)
                if len(raw) < 14:
                    continue
                if int.from_bytes(raw[12:14], "little") != (data_link & 0xFFFF):
                    continue
                i = raw.find(b"<in")
                if i < 0:
                    continue
                j = raw.find(b"</in>", i)
                if j < 0:
                    continue
                return self._decode_ports_blob(raw[i:j + 5].decode("latin-1", errors="replace"))
        return None

    @staticmethod
    def _decode_ports_blob(blob: str) -> "Union[str, None]":
        """Render an ``<in>`` topology blob into an L5X ``<Ports>`` block.

        Rules (validated byte-for-byte against the reference): Type EN->Ethernet,
        others verbatim (ICP/DSI/SERCOS/5069); Upstream is false only when the
        blob port carries ``Ups="False"`` (absent => upstream true); Address is the
        ``Addr`` attribute (omitted when absent, e.g. a SERCOS motion port); a
        port followed by ``<Bus Size="N"/>`` emits ``<Bus Size="N"/>`` (the Max
        attribute is dropped); a Bus without a Size, and a downstream Ethernet
        bridge port with no Bus, emit an empty ``<Bus/>``; the ``<CF>`` element is
        dropped. Returns None when the blob has no ports.
        """
        import re as _re
        type_map = {"EN": "Ethernet"}
        ports = []
        for m in _re.finditer(r'<Port\b([^>]*?)(/?)>', blob):
            a = dict(_re.findall(r'(\w+)="([^"]*)"', m.group(1)))
            pid = a.get("Id")
            # A real port always has an Id. Blobs without one (seen on some V10/V11
            # controller/CPU records) use a structure this decoder does not model;
            # bail out so the caller falls back to the static catalog rather than
            # emit an Id="None" port the reference never has.
            if pid is None:
                return None
            ptype = type_map.get(a.get("Type"), a.get("Type"))
            addr = a.get("Addr")
            upstream = "false" if a.get("Ups") == "False" else "true"
            bus = None
            if m.group(2) != "/":
                rest = blob[m.end():]
                nxt = _re.search(r'<Port\b|</in>', rest)
                seg = rest[:nxt.start()] if nxt else rest
                bm = _re.search(r'<Bus\b([^>]*)>', seg)
                if bm:
                    ba = dict(_re.findall(r'(\w+)="([^"]*)"', bm.group(1)))
                    bus = ba.get("Size") if ba.get("Size") is not None else ""
            if bus is None and upstream == "false" and ptype == "Ethernet":
                bus = ""
            addr_attr = f' Address="{addr}"' if addr is not None else ""
            head = f'<Port Id="{pid}"{addr_attr} Type="{ptype}" Upstream="{upstream}"'
            if bus is None:
                ports.append(f"{head}/>\n")
            elif bus == "":
                ports.append(f"{head}>\n<Bus/>\n</Port>\n")
            else:
                ports.append(f'{head}>\n<Bus Size="{bus}"/>\n</Port>\n')
        if not ports:
            return None
        return f'<Ports>\n{"".join(ports)}</Ports>\n'

    def _chassis_size_from_data_collection(self) -> "Union[int, None]":
        """Read the local backplane Bus Size from the RxDataCollection record for the CPU.

        The root controller (Local) module stores its backplane configuration as XML in a
        hash-named child of RxDataCollection.  The record contains:
          <Port Id="1" Type="ICP" Addr="0" Ups="False"><Bus Max="17" Size="7"/></Port>
        We extract the Size attribute from the Bus element on the ICP port at Addr="0".
        """
        import re as _re
        self._cur.execute(
            "SELECT object_id FROM comps WHERE comp_name='RxDataCollection' LIMIT 1"
        )
        row = self._cur.fetchone()
        if not row:
            return None
        coll_oid = row[0]
        self._cur.execute(
            "SELECT record FROM comps WHERE parent_id=?", (coll_oid,)
        )
        needle = b'Type="ICP" Addr="0"'
        for (raw,) in self._cur.fetchall():
            raw = bytes(raw)
            if needle not in raw:
                continue
            text_start = raw.find(b"<")
            if text_start < 0:
                continue
            text = raw[text_start:].decode("latin-1", errors="replace")
            m = _re.search(r'<Bus\b[^>]*\bSize="(\d+)"', text)
            if m:
                return int(m.group(1))
        return None

    def build(self) -> Module:
        self._cur.execute(
            "SELECT comp_name, object_id, record FROM comps WHERE object_id=" + str(self._object_id)
        )
        row = self._cur.fetchone()
        db_name = row[0]
        raw_rec = bytes(row[2])

        # Hex-encoded names like $02cc5e9d$ are unnamed peripheral modules (drive expansion
        # cards, etc.).  Logix Designer exports these with Name="?".
        name = "?" if (db_name.startswith("$") and db_name.endswith("$")) else db_name

        try:
            r = RxGeneric.from_bytes(raw_rec)
        except Exception:
            return Module(name, name, "", 0, 0, 0, 0, 0, "Local", 1, "false", "false")

        if r.cip_type != 0x69:
            return Module(name, name, "", 0, 0, 0, 0, 0, "Local", 1, "false", "false")

        exts: Dict[int, bytes] = {er.attribute_id: bytes(er.value) for er in r.extended_records}
        e1 = exts.get(0x001, b"")
        if len(e1) < 0x30:
            # Some module records (seen on V10..V20 projects) do not surface the
            # identity as extended record 0x001; the same identity block sits
            # inline behind the marker 44 02 00 00 (the u32 length 0x244 of the
            # identity TLV). The bytes after that length prefix are byte-identical
            # to the 0x001 attribute, so alias e1 to them and the existing field
            # offsets below decode unchanged. Only used when 0x001 is absent, so
            # records that do carry 0x001 (incl. long-header) are untouched.
            marker = raw_rec.find(b"\x44\x02\x00\x00")
            if marker >= 0 and len(raw_rec) - (marker + 4) >= 0x30:
                e1 = raw_rec[marker + 4:]
        if len(e1) < 0x30:
            major_fault = "true" if name == "Local" else "false"
            return Module(name, name, "", 0, 0, 0, 0, 0, "Local", 1, "false", major_fault,
                          _is_root=(name == "Local"))

        vendor        = struct.unpack("<H", e1[0x02:0x04])[0]
        product_type  = struct.unpack("<H", e1[0x04:0x06])[0]
        product_code  = struct.unpack("<H", e1[0x06:0x08])[0]
        # bit 7 of the major byte is a flag; strip it to get the firmware revision.
        major         = e1[0x08] & 0x7F
        minor         = e1[0x09]
        parent_modid  = struct.unpack("<I", e1[0x16:0x1A])[0]
        parent_port   = struct.unpack("<H", e1[0x1A:0x1C])[0]
        slot          = struct.unpack("<I", e1[0x1C:0x20])[0]

        # Genuine drive-peripheral expansion cards are hash-named ("?") AND carry a
        # PowerFlex drive product_type: 142/143 (PF753/755) export as ProductType=0
        # ProductCode=28 (RHINOBP-DRIVE-PERIPHERAL-MODULE); 150/127 (PF525 and its
        # DSI-port variant) export as ProductCode=29 (DSI-DRIVE-PERIPHERAL-MODULE).
        # CATALOG_NUMBERS maps (vendor,0,28)/(vendor,0,29) so the lookup below
        # resolves. Across the pool these four product_types account for every
        # reference drive peripheral (99 RHINOBP + 36 DSI) with no false positives.
        # Ordinary hash-named modules (unresolved 1756/1769 I/O cards, PT 7/10) keep
        # their genuine PT/PC and real catalog -- the previous unconditional rewrite
        # corrupted those into RHINOBP-DRIVE-PERIPHERAL-MODULE.
        if name == "?" and vendor == 1 and product_type in (142, 143, 150, 127):
            product_code = 29 if product_type in (150, 127) else 28
            product_type = 0

        # Resolve parent module name from the modid→name map built by ControllerBuilder.
        parent_name = self._modid_to_name.get(parent_modid, "Local")

        # MajorFault (ConfiguredAsMajorFault): bit 0 of e1[0x14]. Set on the root
        # CPU and on any module the user configured so a connection fault halts the
        # controller -- NOT root-only. (The prior parent==self rule only ever
        # flagged the root; validated e1[0x14]&1 on V20/V28/V32/V33/V35 vs OEM,
        # 164/164.) Root detection for ProcessorType/MajorRev now uses
        # parent_module==name directly (see ControllerBuilder), so it no longer
        # piggy-backs on this attribute.
        major_fault = "true" if (len(e1) > 0x14 and (e1[0x14] & 0x01)) else "false"
        # EKey state from the keying mask at e1[0x0a]: 0 = no keying (Disabled),
        # nonzero (0x1f = all identity fields keyed) = a keyed module. Both
        # ExactMatch and CompatibleModule carry the full 0x1f mask, so the mask
        # alone classifies Disabled vs keyed; we emit CompatibleModule for keyed
        # modules (ExactMatch -- almost exclusively the root CPU -- needs a further
        # discriminator and is left as a follow-on). Validated on V20/V36 vs OEM;
        # the prior e1[0]&0x04 rule mis-keyed Disabled modules as CompatibleModule.
        ekey_state  = "Disabled" if (len(e1) > 0x0a and e1[0x0a] == 0) else "CompatibleModule"

        # IP address: stored at e1[0x30] as a u16 length-prefixed ASCII string for modules
        # that connect via Ethernet upstream (parent_port == 2). Local backplane bridge
        # modules (parent_port == 1, e.g. local EN2T) leave e1[0x32] zero — their IP is
        # stored as XML in a child of RxDataCollection, keyed by ICP slot number.
        own_ip = ""
        if len(e1) > 0x32:
            ip_len = struct.unpack("<H", e1[0x30:0x32])[0]
            if ip_len:
                own_ip = e1[0x32:0x32 + ip_len].rstrip(b"\x00").decode("ascii", errors="replace")
        ip_address = own_ip
        if not ip_address and slot:
            ip_address = self._ip_from_data_collection(slot)

        # For modules that own a remote backplane (e.g. remote chassis EN2T), the Output
        # connection record under RxMapConnectionCollection stores the chassis size at [0x4e]
        # and the module's own slot in that chassis at [0x6e].
        backplane_slot = None
        chassis_size = None
        self._cur.execute(
            "SELECT o.record FROM comps coll "
            "JOIN comps o ON o.parent_id = coll.object_id AND o.comp_name = 'Output' "
            "WHERE coll.parent_id = ? AND coll.comp_name = 'RxMapConnectionCollection'",
            (self._object_id,),
        )
        out_row = self._cur.fetchone()
        if out_row:
            out_rec = bytes(out_row[0])
            if len(out_rec) > 0x70:
                backplane_slot = struct.unpack("<H", out_rec[0x6e:0x70])[0]
                chassis_size   = struct.unpack("<H", out_rec[0x4e:0x50])[0]

        # For the root (Local) CPU module (slot=0xFFFFFFFF, self-parenting), the Output
        # connection record is absent.  The backplane chassis size is stored in the
        # RxDataCollection hash child that carries the Local module's ICP port at Addr="0".
        # Example: <Port Id="1" Type="ICP" Addr="0" Ups="False"><Bus Max="17" Size="7"/></Port>
        if chassis_size is None and slot == 0xFFFFFFFF:
            chassis_size = self._chassis_size_from_data_collection()

        # --- Description ---
        # Module descriptions are stored in the comments table keyed by
        # (comment_id * 0x10000 + cip_type), same as for tags. The module's own
        # description carries object_id == 1; rows sharing the key with a nonzero
        # object_id are scratch values (e.g. export timestamps) whose record_string
        # would otherwise leak in as a fabricated Description, so require object_id == 1.
        description = ""
        self._cur.execute(
            "SELECT record_string FROM comments "
            "WHERE parent=? AND member_ref=0 AND object_id=1 LIMIT 1",
            ((r.comment_id * 0x10000) + r.cip_type,),
        )
        desc_row = self._cur.fetchone()
        if desc_row:
            description = desc_row[0] or ""

        # --- Communications and ExtendedProperties ---
        # Both are extracted from the hash-named child of RxDataCollection that
        # corresponds to this module's ICP backplane slot (primary) or its IP
        # address (secondary, for EN-connected modules).
        comm_method: Union[str, None] = None
        connections: List[Tuple[str, str, str]] = []
        extended_properties = ""
        if slot or ip_address:
            comm_method, extended_properties = self._comms_from_data_collection(
                slot, ip_address
            )

        # Read individual connection records from RxMapConnectionCollection children.
        # Each child's comp_name is the connection Name in the L5X output.
        # Connection Type is inferred from the name (heuristic):
        #   names containing "output" or equal to "config" -> "Output"
        #   all others -> "Input"
        # RPI: we do not have a reliable binary decoder for the short connection
        # records seen in the test data, so we default to "0.0" (acceptable for import).
        self._cur.execute(
            "SELECT c2.comp_name FROM comps c1 "
            "JOIN comps c2 ON c2.parent_id = c1.object_id "
            "WHERE c1.parent_id = ? AND c1.comp_name = 'RxMapConnectionCollection' "
            "AND c2.comp_name NOT IN ('Output') "
            "ORDER BY c2.seq_number",
            (self._object_id,),
        )
        for (conn_name,) in self._cur.fetchall():
            name_lower = conn_name.lower()
            if "output" in name_lower or name_lower == "config":
                conn_type = "Output"
            else:
                conn_type = "Input"
            connections.append((conn_name, "0.0", conn_type))

        # CatalogNumber: prefer the (V,PT,PC,Major) override for hardware-revision
        # ambiguous keys, then the (V,PT,PC) base table; finally fall back to any
        # <CatNum> carried in the harvested ExtendedProperties XML.
        catalog_number = CATALOG_NUMBERS_BY_MAJOR.get(
            (vendor, product_type, product_code, major)
        )
        if not catalog_number:
            catalog_number = CATALOG_NUMBERS.get(
                (vendor, product_type, product_code), ""
            )
        if not catalog_number and extended_properties:
            try:
                _cm = re.search(r"<CatNum>([^<]+)</CatNum>", extended_properties)
                if _cm:
                    catalog_number = _cm.group(1)
            except Exception:
                pass

        # Project-level OPC UA flag (see ExportL5x.project_flags); same pattern as
        # TagBuilder. When the project's OPC UA server is on, module IO tag stubs
        # carry OpcUaAccess="None".
        try:
            self._cur.execute("SELECT opc_ua FROM project_flags")
            _pf = self._cur.fetchone()
            _opc_ua = bool(_pf[0]) if _pf else False
        except Exception:
            _opc_ua = False

        # Real port topology from the RxDataCollection blob (preferred over the
        # static catalog). e1[0x24] is the comment_id of the module's backing
        # RxDataCollection child (a 1:1 link); None when it has no <in> blob.
        # The root controller is left to the static-catalog path: its blob uses
        # abbreviated CompactLogix port types (Cpt35E, Cpt32EN, ...) and a chassis
        # bus this decoder does not model, and PORT_STRUCTURES already covers CPUs.
        is_root = (parent_name == name)
        ports_override = None
        if not is_root:
            data_link = struct.unpack("<I", e1[0x24:0x28])[0] if len(e1) >= 0x28 else 0
            ports_override = self._ports_from_data_collection(data_link)

        return Module(
            name,           # L5xElement._name (private)
            name,           # Module.name
            catalog_number,
            vendor,
            product_type,
            product_code,
            major,
            minor,
            parent_name,
            parent_port,
            "false",        # Inhibited: always false in practice; no known bit
            major_fault,
            _is_root=is_root,
            _ekey_state=ekey_state,
            _slot=slot,
            _ip_address=ip_address,
            _backplane_slot=backplane_slot,
            _chassis_size=chassis_size,
            _ports_override=ports_override,
            _description=description,
            _comm_method=comm_method,
            _connections=connections,
            _extended_properties=extended_properties,
            _opc_ua=_opc_ua,
        )


class _PlaintextMain:
    """Lightweight stand-in for ``RxGeneric.RxTag`` read from fixed offsets.

    Used when ``RxGeneric.from_bytes`` cannot parse a record because its extended-
    attribute tail is source-protected (AES-encrypted) — the kaitai parser reads
    the encryption marker as ``count_record`` and runs off the end. The
    main_record itself stays PLAINTEXT, so the tag's data_type / radix /
    dimensions / data_table_instance are all recoverable at their fixed offsets.
    """

    __slots__ = ("data_type", "radix", "external_access", "dimension_1",
                 "dimension_2", "dimension_3", "data_table_instance",
                 "cip_data_type")

    def __init__(self, main: bytes):
        u4 = lambda o: int.from_bytes(main[o:o + 4], "little")
        u2 = lambda o: int.from_bytes(main[o:o + 2], "little")
        self.dimension_1 = u4(12)
        self.dimension_2 = u4(16)
        self.dimension_3 = u4(20)
        self.data_type = u4(28)
        self.radix = u2(32)
        self.external_access = u2(34)
        self.data_table_instance = u4(36)
        self.cip_data_type = u2(52)


class _PlaintextRxGeneric:
    """Minimal RxGeneric view for a source-protected tag record (plaintext main).

    Exposes only the fields TagBuilder.build reads downstream: ``cip_type``,
    ``comment_id``, ``main_record`` and an empty ``extended_records`` (the real
    ext-attrs, including the name 0x01, are encrypted; the tag name is taken from
    comp_name instead, exactly as the no-0x01 branch already does).
    """

    def __init__(self, raw_rec: bytes):
        self.cip_type = int.from_bytes(raw_rec[10:12], "little")
        self.comment_id = int.from_bytes(raw_rec[12:14], "little")
        self.main_record = _PlaintextMain(raw_rec[14:74])
        self.extended_records = []


def _rxgeneric_plaintext_main(raw_rec: bytes):
    """Build a tolerant RxGeneric view from a source-protected tag record, or None.

    Returns None when the record is too short to hold the 14-byte prelude plus the
    60-byte main_record, so the caller keeps today's stub-Tag fallback.
    """
    if len(raw_rec) < 74:
        return None
    return _PlaintextRxGeneric(raw_rec)


@dataclass
class TagBuilder(L5xElementBuilder):
    _short_header: bool = field(default=False)
    # Studio major version (e.g. 24, 36); 0 when unknown. Selects the first
    # <Data> block style: V<=24 (and short-header V10-V21) write a raw-hex
    # <Data>XX XX..</Data> image, V28+ write <Data Format="L5K">.
    _acd_major: int = field(default=0)

    def _short_header_alias_for(self, raw_rec: bytes) -> Union[str, None]:
        """Decode a V10..V21 short-header alias target, or None if not an alias.

        Alias tags store their target in the record as a UTF-16 blob of the form
        ``@<8hex CompUId>@<member path>`` (the same operand encoding used by
        source-protection rungs), e.g. ``@2b09c452@.Data.10``.  The ``@hex@``
        CompUId resolves to a module-element comps record whose name is itself a
        ``&<8hex>:slot:type`` reference (e.g. ``&4d2cae27:1:I``); the ``&hex``
        prefix resolves to the module's friendly name (``Local``).  The result is
        ``Local:1:I.Data.10``.

        Returns None for non-alias tags (no ``@hex@`` blob) and on any failure so
        the caller falls back to today's Base-tag behaviour.
        """
        try:
            s = raw_rec.decode("utf-16-le", errors="replace")
            m = re.search(r"@([0-9a-fA-F]+)@(\.?[^\x00@]*)", s)
            if not m:
                return None
            self._cur.execute(
                "SELECT comp_name FROM comps WHERE object_id=" + str(int(m.group(1), 16))
            )
            row = self._cur.fetchone()
            if not row or not row[0]:
                return None
            name = row[0]
            member = m.group(2)
            mm = re.match(r"&([0-9a-fA-F]+)(:.*)$", name)
            if mm:
                self._cur.execute(
                    "SELECT comp_name FROM comps WHERE object_id="
                    + str(int(mm.group(1), 16))
                )
                prow = self._cur.fetchone()
                if prow and prow[0]:
                    name = prow[0] + mm.group(2)
            return name + member
        except Exception:
            return None

    def _raw_hex_first_block(self) -> bool:
        """True when the tag's first <Data> block is the raw-hex image, not L5K.

        Studio's reference exporter writes the value's flat first <Data> block as
        raw hex through V24 and as Format="L5K" from V28 -- but the exact choice is
        a per-export ExportOptions setting (some V24/V15 references emit L5K, others
        raw hex; it is NOT inferable from the ACD). The two are equivalent flat
        serialisations of the same value, which the comparator normalises and the
        Decorated block validates regardless; here we emit raw hex through V24
        (short header V10-V21 always), matching the dominant reference profile.
        """
        return self._short_header or (1 <= self._acd_major <= 24)

    def _read_tag_value(self, data_table_instance: int):
        """Return (value_bytes, type_code) for a tag's design value, or (None, 0).

        Resolves the cip-0x6a backing via data_table_instance, reads its FULL
        stream payload from the comps_full side table (the deduped comps `record`
        column is the TRUNCATED FafaComps buffer and cuts off ext attr 0x66), and
        decodes attr 0x66. Best-effort: any failure yields (None, 0) so the Tag
        keeps today's zero-placeholder <Data>.
        """
        try:
            if not data_table_instance:
                return None, 0
            self._cur.execute(
                "SELECT record FROM comps_full WHERE object_id=?",
                (data_table_instance,),
            )
            row = self._cur.fetchone()
            if not row or row[0] is None:
                return None, 0
            res = CompsRecord.read_tag_value(bytes(row[0]), self._short_header)
            if res is None:
                return None, 0
            return res
        except Exception:
            return None, 0

    @staticmethod
    def _parse_rec_tolerant(raw_rec: bytes):
        """Parse a tag comps record, tolerating a source-protected (encrypted) tail.

        Returns the kaitai RxGeneric when it parses, else a plaintext-main view
        (cip_type/comment_id/main_record from fixed offsets), else None. Used by the
        alias detectors so source-protected aliases are still recognised (the
        kaitai parser throws on their encrypted ext-attr tail).
        """
        try:
            return RxGeneric.from_bytes(raw_rec)
        except Exception:
            return _rxgeneric_plaintext_main(raw_rec)

    def _long_header_alias_like(self, raw_rec: bytes) -> bool:
        """True if the tag is an alias of any kind (module-I/O OR internal-tag).

        A genuine Base tag's ``data_table_instance`` points at its own ``$<hex>$``
        RxData value backing; an alias instead points at the thing it aliases (a
        module element ``&<hex>:slot:type`` or another ordinary tag whose name is a
        plain identifier). So "dti target name exists and is not ``$``-prefixed"
        recognises BOTH alias sub-cases, including ones whose AliasFor target we
        cannot yet build byte-exactly (so the tag stays Base, but its <Data>/
        Constant must still be suppressed -- OEM emits neither on an alias).

        Tolerant of source-protected records (the kaitai parser throws on their
        encrypted ext-attr tail). Returns False on any failure (treat as Base).
        """
        try:
            r = self._parse_rec_tolerant(raw_rec)
            if r is None or r.cip_type not in (0x6B, 0x68):
                return False
            dti = r.main_record.data_table_instance
            if not dti:
                return False
            row = self._cur.execute(
                "SELECT comp_name FROM comps WHERE object_id=" + str(dti)
            ).fetchone()
            if not row or not row[0]:
                return False
            return not row[0].startswith("$")
        except Exception:
            return False

    def _long_header_is_alias(self, raw_rec: bytes) -> bool:
        """Detect a V24+ long-header alias tag, best-effort.

        An alias tag's ``main_record.data_table_instance`` points at the
        module-element comps record it aliases into; that target's name is the
        synthetic ``&<8hex moduleCompUId>:<slot>:<C|I|O>`` reference (the same
        ``&hex:`` form the IO/alias resolvers consume).  A genuine Base tag's
        ``data_table_instance`` points at an ordinary RxData backing whose name
        is a plain identifier.  So an ``&hex:`` target name is a clean,
        file-independent alias discriminator (validated 48/48 aliases, 0 false
        positives on PROJ_A + PROJ_C).

        Returns False on any failure so the caller keeps today's Base-tag
        behaviour (no regression).
        """
        try:
            r = self._parse_rec_tolerant(raw_rec)
            if r is None or r.cip_type not in (0x6B, 0x68):
                return False
            dti = r.main_record.data_table_instance
            if not dti:
                return False
            self._cur.execute(
                "SELECT comp_name FROM comps WHERE object_id=" + str(dti)
            )
            row = self._cur.fetchone()
            if not row or not row[0]:
                return False
            return bool(re.match(r"^&[0-9a-fA-F]+:.*$", row[0]))
        except Exception:
            return False

    def _long_header_alias_for(self, raw_rec: bytes) -> Union[str, None]:
        """Build a V24+ long-header alias tag's @AliasFor target, byte-exact.

        An alias tag's ``main_record.data_table_instance`` points at the
        module-element comps record it aliases into, named ``&<8hex
        moduleCompUId>:<slot>:<C|I|O>``.  Resolving the ``&hex`` ref to the
        module's friendly name yields the module element (e.g. ``Local:1:I``).
        The aliased bit is in the tag record at byte ``0x26 & 0x1F``.

        Two module sub-cases are cracked byte-exact:
          * EMBEDDED-IO (module friendly name ``Local``): suffix
            ``<module>:<slot>:<type>.Data.<bit>`` with ``bit = raw_rec[0x26] & 0x1F``
            (the ``.Data.`` member is implicit). Validated 13/13 PROJ_A, 24/24 PROJ_C.
          * NETWORKED module I/O (a real module, name != ``Local``): suffix
            ``<module>:<slot>:<type>.<bit>`` (no ``.Data``) with
            ``bit = u32@raw_rec[0x26] - (64 + slot*8)``, accepted only for a slotted
            target with ``bit`` in 0..7. Validated byte-exact on the long-header pool.
        Any other target (slotless, config ``:C``, multi-byte channel-structured
        analog point, or whole-element) returns None so the caller keeps the tag as
        Base rather than emit a wrong (and schema-invalid) ``TagType="Alias"``.

        Returns the full AliasFor string when it can be built byte-exactly, or
        None on any failure / uncracked sub-case (no regression).
        """
        try:
            r = self._parse_rec_tolerant(raw_rec)
            if r is None or r.cip_type not in (0x6B, 0x68):
                return None
            dti = r.main_record.data_table_instance
            if not dti:
                return None
            self._cur.execute(
                "SELECT comp_name FROM comps WHERE object_id=" + str(dti)
            )
            row = self._cur.fetchone()
            if not row or not row[0]:
                return None
            m = re.match(r"^&([0-9a-fA-F]+)(:.*)$", row[0])
            if not m:
                return None
            self._cur.execute(
                "SELECT comp_name FROM comps WHERE object_id="
                + str(int(m.group(1), 16))
            )
            prow = self._cur.fetchone()
            if not prow or not prow[0]:
                return None
            module_name = prow[0]
            if module_name != "Local":
                # Networked module I/O alias (a remote-rack point on a real module,
                # not the embedded Local chassis). The target is &<hex>:<slot>:<I|O>
                # and the aliased bit is a u32 at raw_rec[0x26] measured from a
                # per-slot base of 64 + slot*8 bits; the suffix is a bare ".<bit>"
                # (NOT the Local branch's ".Data.<bit>"). Only a slotted target whose
                # offset lands in a single byte (bit 0..7) is a byte-exact bit alias;
                # a slotless/config target, a multi-byte channel-structured point
                # (analog .ChNData/.ChNFault), or a whole-element reference is left as
                # Base rather than emit a wrong AliasFor. Validated byte-exact vs OEM
                # on the long-header pool (PROJ_F 38, PROJ_G 34, PROJ_B 12,
                # PROJ_A 11). This branch runs only on the long-header path (build()
                # gates on `not short_header`); short-header networked aliases are
                # resolved separately by _short_header_alias_for. Extending it to the
                # short-header families would additionally need an alias-is-BOOL /
                # flat-primitive-target gate to exclude whole-element and named-member
                # points whose offset also lands in 0..7.
                ms = re.match(r"^:(\d+):([IO])$", m.group(2))
                if not ms or len(raw_rec) < 0x2A:
                    return None
                slot = int(ms.group(1))
                bit = struct.unpack_from("<I", raw_rec, 0x26)[0] - (64 + slot * 8)
                if not (0 <= bit <= 7):
                    return None
                return module_name + m.group(2) + ".%d" % bit
            if len(raw_rec) <= 0x26:
                return None
            bit = raw_rec[0x26] & 0x1F
            return module_name + m.group(2) + ".Data.%d" % bit
        except Exception:
            return None

    def _long_header_internal_alias_for(self, raw_rec: bytes) -> Union[str, None]:
        """Build a V24+ long-header alias-to-internal-tag @AliasFor, byte-exact.

        Distinct from ``_long_header_alias_for`` (which handles the module-I/O
        ``&hex:`` sub-case): here the alias targets another *ordinary* tag in the
        same scope, e.g. ``B3[0].1`` / ``F8[22]`` / ``Some_Tag.3``.

        Encoding (cracked & validated 193/193 on a V32 project and 188/188 on a
        V15 project, 0 false positives):
          * ``main_record.data_table_instance`` -> the BASE tag's comps record;
            its ``comp_name`` is the base symbol.  A genuine Base tag instead
            points at its own ``$<hex>$`` RxData backing, and a module-I/O alias
            points at an ``&hex:`` ref; both are excluded -> alias iff the target
            name is a plain identifier (not ``$``/``&``-prefixed).
          * u32 @ raw_rec[0x26] = the BIT OFFSET of the aliased element within the
            base symbol.
          * The alias's own ``data_type`` selects bit-vs-element access: BOOL ->
            a bit reference (``base[idx].bit``); otherwise a whole element
            (``base[idx]``).  ``idx``/``bit`` come from dividing the bit offset by
            the BASE element's bit width (DINT 32, INT 16, SINT 8, TIMER 96, ...).
          * A scalar base (dimension_1 == 0) drops the ``[idx]`` subscript.

        Returns the AliasFor string, or None on any failure / undecodable base
        (e.g. a module connection image whose element width we cannot read) so
        the caller keeps the tag as Base rather than emit a wrong Alias.
        """
        try:
            r = self._parse_rec_tolerant(raw_rec)
            if r is None or r.cip_type not in (0x6B, 0x68):
                return None
            dti = r.main_record.data_table_instance
            if not dti or len(raw_rec) < 0x2A:
                return None
            self._cur.execute(
                "SELECT comp_name, record FROM comps WHERE object_id=" + str(dti)
            )
            row = self._cur.fetchone()
            if not row or not row[0]:
                return None
            base = row[0]
            # Exclude module-I/O (&hex:) and a tag's own ($hex$) data backing:
            # those are NOT internal aliases.
            if base.startswith("&") or base.startswith("$"):
                return None

            # Resolve the alias's own element type (bit vs element access).
            alias_dt_name = None
            if r.main_record.data_type:
                self._cur.execute(
                    "SELECT comp_name FROM comps WHERE object_id="
                    + str(r.main_record.data_type)
                )
                drow = self._cur.fetchone()
                alias_dt_name = drow[0] if drow else None

            # Resolve the BASE symbol's element bit-width + array-ness. Only a
            # base whose element type is a known atomic/legacy-struct type is
            # decodable; anything else (module image, UDT, ...) -> bail.
            base_elem_bits = None
            base_is_array = False
            try:
                br = RxGeneric.from_bytes(bytes(row[1]))
                if br.main_record.data_type:
                    self._cur.execute(
                        "SELECT comp_name FROM comps WHERE object_id="
                        + str(br.main_record.data_type)
                    )
                    bdrow = self._cur.fetchone()
                    bdname = bdrow[0] if bdrow else None
                    base_elem_bits = _ALIAS_ELEM_BITS.get(bdname)
                    base_is_array = bool(getattr(br.main_record, "dimension_1", 0))
            except Exception:
                base_elem_bits = None
            if base_elem_bits is None:
                return None

            bit_off = struct.unpack_from("<I", raw_rec, 0x26)[0]

            if alias_dt_name in ("BOOL", "BIT"):
                idx = bit_off // base_elem_bits
                bit = bit_off % base_elem_bits
                if base_is_array:
                    return "%s[%d].%d" % (base, idx, bit)
                return "%s.%d" % (base, bit) if idx == 0 else "%s[%d].%d" % (base, idx, bit)
            else:
                idx = bit_off // base_elem_bits
                if base_is_array:
                    return "%s[%d]" % (base, idx)
                return base if idx == 0 else "%s[%d]" % (base, idx)
        except Exception:
            return None

    def _resolve_io_name(self, comp_name: str) -> Union[str, None]:
        """Resolve a module I/O tag's display name, or None if it is not one.

        I/O config/input/output tags are stored in Comps.Dat under a synthetic
        name of the form ``&<8hex moduleCompUId>:<slot>:<C|I|O>`` (e.g.
        ``&9928c4af:2:C``).  The OEM L5X emits these with the module's *friendly*
        name substituted for the ``&hex`` ref, e.g. ``Local:2:C``.  This is the
        same ``&hex`` resolution used by the alias decoder.

        Returns the resolved ``<module>:<slot>:<type>`` name, or None when the
        comp_name is not an ``&hex:`` module-tag reference (so the caller keeps
        the ordinary tag path).  Best-effort: any failure returns None.
        """
        try:
            m = re.match(r"^&([0-9a-fA-F]+)(:.*)$", comp_name)
            if not m:
                return None
            self._cur.execute(
                "SELECT comp_name FROM comps WHERE object_id="
                + str(int(m.group(1), 16))
            )
            row = self._cur.fetchone()
            if not row or not row[0]:
                return None
            return row[0] + m.group(2)
        except Exception:
            return None

    def _io_alias_for(self, io_name: str) -> Union[str, None]:
        """AliasFor target of a per-point module I/O alias tag, or None.

        A networked module exposes its connection image as a single Base tag
        (``<module>:I`` / ``<module>:O``) whose ``Data`` member is a primitive
        array, plus one ALIAS tag per point named ``<module>:<slot>:<I|O>`` that
        references a primitive (SINT/INT/...).  The OEM emits each such alias as
        ``TagType="Alias" AliasFor="<module>:<I|O>.Data[<slot>]"`` (with no
        ``<Data>``).  The whole target is derivable from the resolved I/O name
        (``<module>:<slot>:<type>``); no @hex@ blob is involved.

        Returns the AliasFor string, or None when ``io_name`` is not a
        ``<module>:<slot>:<I|O>`` per-point form (Config ``:C`` points and the
        slotless ``<module>:<I|O>`` base tag are NOT aliases).  Best-effort.
        """
        try:
            m = re.match(r"^(.+):(\d+):([IO])$", io_name)
            if not m:
                return None
            module, slot, io_type = m.group(1), m.group(2), m.group(3)
            return "%s:%s.Data[%s]" % (module, io_type, slot)
        except Exception:
            return None

    def build(self) -> Tag:
        self._cur.execute(
            "SELECT comp_name, object_id, parent_id, record FROM comps WHERE object_id="
            + str(self._object_id)
        )
        results = self._cur.fetchall()

        # Extract ExternalAccess and Constant from the raw record at fixed offsets:
        #   raw[0x278]: ExternalAccess enum (0=Read/Write, 2=Read Only, 3=None)
        #   raw[0x279]: Constant flag (0=false, 1=true)
        raw_rec = bytes(results[0][3])
        # Source-protected-at-rest record: the extended-attribute tail (which spans
        # offsets 0x278/0x279) is AES-encrypted, so ExternalAccess/Constant cannot
        # be read there -- the ciphertext bytes decode to random enum values. The
        # main_record stays plaintext, so take ExternalAccess from main+34 and let
        # the Base Constant="false" invariant (below) supply Constant.
        is_sp = _SP_MARKER in raw_rec
        if is_sp:
            external_access = external_access_enum(raw_rec[48])  # main+34, low byte
            constant = None
        elif len(raw_rec) > 0x279:
            external_access = external_access_enum(raw_rec[0x278])
            constant = "true" if raw_rec[0x279] else None
        else:
            external_access = "Read/Write"
            constant = None

        # --- Module I/O tag detection (both header families) ---
        # I/O tags are stored as ``&<hex moduleCompUId>:slot:type`` and must be
        # emitted with the module's friendly name (Local:slot:type) and IO="true".
        # io_name is None for ordinary tags, which keeps every existing path
        # unchanged. IO tags carry no Constant attribute (OEM never emits it).
        # Enabled on BOTH header families: the OEM emits genuine module-typed
        # Base IO tags (Local:n:C/I/O, <module>:n:C/<module>:I/...) in both V10..V21
        # short and V24+ long projects. The refinement at the bottom of build()
        # (drop is_io unless the resolved DataType name carries a ':', i.e. a real
        # module-defined type) keeps the slotless alias-into-module form out of the
        # Base-IO path. The Decorated/L5K <Data> image decode is wrapped in
        # try/except in the renderer so an incomplete value image degrades to
        # no-<Data> (today's behaviour) rather than a wrong Structure.
        io_name = self._resolve_io_name(results[0][0])
        is_io = io_name is not None
        if is_io:
            constant = None

        # --- V10..V21 short-header (Step 6a) ---
        # Alias detection + the Base-tag Constant="false" OEM invariant. Both are
        # gated to the short-header path so the long-header (V24+) export is
        # byte-for-byte unchanged. The long path's 0x278/0x279 offsets do not hold
        # the Constant flag for short-header records (observed 0), so we apply the
        # OEM invariant instead: Logix always emits Constant="false" on Base
        # non-IO tags. IO tags are emitted with their own attribute set below.
        alias_for: Union[str, None] = None
        if self._short_header and not is_io:
            alias_for = self._short_header_alias_for(raw_rec)
            if alias_for is None and constant is None:
                constant = "false"

        # --- V24+ long-header Constant="false" OEM invariant ---
        # Logix always emits Constant="false" on a non-IO *Base* tag; on Alias
        # tags it emits no Constant attribute (the value lives on the target).
        # The long-header record's 0x279 flag is 1 only for genuine constants
        # (handled above -> "true"); a 0 there means an ordinary Base tag, which
        # OEM still writes as Constant="false". We must NOT stamp it on alias
        # tags, so gate on the long-header alias detector (dti -> &hex: module
        # ref; validated 48/48 aliases, 0 false positives on PROJ_A+PROJ_C).
        # Wrapped/best-effort: a detector failure leaves `constant` as today.
        _lh_is_alias = False
        if not self._short_header and not is_io and constant is None:
            _lh_is_alias = self._long_header_alias_like(raw_rec)
            if not _lh_is_alias:
                constant = "false"

        # --- V24+ long-header @AliasFor / TagType="Alias" ---
        # When the alias detector fires AND we can build the AliasFor target
        # byte-exactly (the cracked embedded-IO "Local:" sub-case), emit the tag
        # as an Alias: TagType="Alias", AliasFor=<module>:<slot>:<type>.Data.<bit>,
        # no DataType, no Constant, no <Data>. We deliberately gate on
        # _long_header_alias_for succeeding (not merely on _long_header_is_alias)
        # so the uncracked alias-into-alias sub-case stays a Base tag rather than
        # emit an invalid Alias without a correct AliasFor. Wrapped/best-effort:
        # any failure leaves the tag exactly as today (no regression).
        if not self._short_header and not is_io and not alias_for:
            try:
                _laf = self._long_header_alias_for(raw_rec)
            except Exception:
                _laf = None
            if _laf:
                alias_for = _laf
                constant = None

        # --- V24+ long-header alias to another internal tag (e.g. B3[0].1) ---
        # Separate from the module-I/O "&hex:" sub-case above: the alias targets
        # an ordinary tag in the same scope. Gated on a byte-exact decode
        # succeeding so a Base tag is never mis-emitted as an Alias. Fixes both
        # the missing @AliasFor and the over-emitted Constant on these tags.
        if not self._short_header and not is_io and not alias_for:
            try:
                _iaf = self._long_header_internal_alias_for(raw_rec)
            except Exception:
                _iaf = None
            if _iaf:
                alias_for = _iaf
                constant = None

        # Alias tags export TagType="Alias", carry no Constant (it lives on the
        # target), and omit DataType (None -> attribute omitted).
        tag_type = "Alias" if alias_for else "Base"
        if alias_for:
            constant = None

        # A tag the alias detector recognised but whose AliasFor target we could
        # not build (uncracked sub-case: a remote-rack module alias) stays a Base
        # tag, but OEM emits NO <Data> on an alias. Suppress its value image so we
        # do not introduce element_extra:Data for it.
        suppress_value = _lh_is_alias and not alias_for

        # Project-level OpcUaAccess / Class flags (see ExportL5x.project_flags).
        try:
            self._cur.execute("SELECT opc_ua, is_safety FROM project_flags")
            _pf = self._cur.fetchone() or (0, 0)
        except Exception:
            _pf = (0, 0)
        _opc_ua = bool(_pf[0])

        def _cls_attr():
            # Class only on controller-scope (cip 0x6b) Base tags of a safety
            # project; Safety/Standard from the region partition hi16 @ record
            # 0x36. The safety-partition encoding is VERSION-SPECIFIC:
            #   short header (V10-V21): safety partition hi16 == 0x00FB
            #                           (standard partitions are 0x00xx/0x0cxx)
            #   long  header (V24+):    safety partition hi16 high byte == 0x79
            #                           (0x79xx; standard partitions are 0x70xx)
            # A controller-scope Base tag in the safety partition -> "Safety";
            # any other controller-scope Base tag in a safety project ->
            # "Standard". This INCLUDES genuine module I/O tags, which the OEM
            # emits as TagType="Base" IO="true" WITH a Class (e.g. a motion
            # :SI/:SO -> Safety, a module :C/:I/:O -> Standard). Only Alias tags
            # (tag_type != "Base") and program-scope tags (built by other
            # builders) get no Class.
            # Validated: tag-for-tag agreement with the OEM L5X on every
            # name-overlapping controller Base tag for both a V20 and a V36
            # safety project; emits nothing on V20/V34/V36 non-safety projects.
            if not _pf[1] or tag_type != "Base":
                return None
            if len(raw_rec) < 0x3A or int.from_bytes(raw_rec[10:12], "little") != 0x6B:
                return None
            hi = (int.from_bytes(raw_rec[0x36:0x3A], "little") >> 16) & 0xFFFF
            if self._short_header:
                is_safe_partition = hi == 0x00FB
            else:
                is_safe_partition = (hi >> 8) == 0x79
            return "Safety" if is_safe_partition else "Standard"

        try:
            r = RxGeneric.from_bytes(raw_rec)
        except Exception as e:
            # A source-protected record's encrypted ext-attr tail defeats the
            # kaitai parser; recover the (plaintext) main_record at fixed offsets
            # so the tag still emits its data_type / dimensions / design value.
            r = _rxgeneric_plaintext_main(raw_rec)
            if r is None or r.cip_type not in (0x6B, 0x68):
                _nm = io_name or results[0][0]
                return Tag(
                    _nm, _nm, tag_type, None if alias_for else "",
                    None, external_access, constant, None, 0, [],
                    alias_for=alias_for, _io=is_io,
                    _opc_ua=_opc_ua, _class_attr=_cls_attr(),
                )

        if r.cip_type != 0x6B and r.cip_type != 0x68:
            _nm = io_name or results[0][0]
            return Tag(
                _nm, _nm, tag_type, None if alias_for else "",
                None, external_access, constant, None, 0, [],
                alias_for=alias_for, _io=is_io,
                _opc_ua=_opc_ua, _class_attr=_cls_attr(),
            )
        if r.main_record.data_type == 0xFFFFFFFF:
            data_type = ""
        else:
            self._cur.execute(
                "SELECT comp_name, object_id, parent_id, record FROM comps WHERE object_id="
                + str(r.main_record.data_type)
            )
            data_type_results = self._cur.fetchall()
            data_type = data_type_results[0][0]

        # OEM omits Constant on motion/MESSAGE/alarm tags (they cannot be
        # constants) and on Consumed tags. We stamped Constant="false" above
        # before the data type was known; drop it here for those cases.
        if constant == "false":
            _dtb = data_type.split("[")[0].upper() if data_type else ""
            if _dtb in _NO_CONSTANT_TYPES or tag_type == "Consumed":
                constant = None

        # Refine IO classification: a genuine module config/input/output tag
        # (Local:N:C/I/O) references a MODULE-DEFINED data type whose own name
        # carries a ':' (e.g. AB:1756_DI:C:0). The other ':'-named module records
        # (e.g. <Module>:1:I) are ALIASES into a parent module tag and
        # reference a primitive (SINT/INT/...). The OEM emits those as
        # TagType="Alias" AliasFor="<module>:<I|O>.Data[<slot>]" with no <Data>.
        # That target is fully derivable from the resolved I/O name, so we emit
        # them as aliases; only when the alias target cannot be built do we drop
        # is_io and let the ordinary ':' filter exclude them (baseline behaviour).
        if is_io and ":" not in (data_type or ""):
            _io_alias = None
            if not alias_for:
                try:
                    _io_alias = self._io_alias_for(io_name)
                except Exception:
                    _io_alias = None
            if _io_alias:
                # Per-point module I/O alias (e.g. <Module>:1:I). Keep the
                # IO flag (emits IO="true", Radix="Binary"-styled alias) but make
                # it an Alias with no DataType / no <Data>.
                alias_for = _io_alias
                tag_type = "Alias"
                data_type = ""
                constant = None
            else:
                is_io = False

        # Tag-level Description: a tag must only carry its OWN description, which
        # the comments table identifies by member_ref==0 (sub-element/member
        # descriptions have a nonzero member_ref). The previous behaviour fetched
        # EVERY comment for the parent and stamped the longest as a Description on
        # the tag, over-emitting member descriptions as tag Descriptions.
        #
        # The exact comment is identified by the member_ref stored in bytes
        # [14:18] of the tag's OWN comps record (the same discriminator used by
        # MemberBuilder/Parameter/LocalTag): nonzero for tags whose description
        # lives under a member_ref (e.g. alias tags into a shared I/O module),
        # zero for a tag's plain own description. The member_ref@14 read is a
        # LONG-header (V24+) construct; for V10..V21 short-header records we emit
        # no tag-level Description rather than risk a wrong lookup. Wrapped so any
        # failure degrades to today's no-description behaviour.
        comment_results: List[Tuple[str, str]] = []
        if not self._short_header:
            try:
                member_ref = 0
                if len(raw_rec) >= 18:
                    member_ref = struct.unpack_from("<I", raw_rec, 14)[0]
                parent_key = (r.comment_id * 0x10000) + r.cip_type
                # The tag's own Description is the row at (parent_key, member_ref).
                # A tag's own description carries an empty tag_reference; an
                # operand comment (array element/bit member) shares the same key
                # and member_ref but has a non-empty tag_reference. Suppress the
                # latter so it does not leak in as the Description. Only inspect
                # the row the original lookup already selected (do not search for
                # a different tag_reference='' row): under a shared/sentinel key,
                # searching would surface another tag's description and
                # mis-attribute it. So this can only drop an operand leak, never
                # add a description.
                #
                # COLLISION-SAFE: cip-0x68 tags SHARE a comment_id with the rung
                # comments of their routine, and (parent_key, member_ref) there can
                # collide with a RUNG comment -> a fabricated tag description (e.g.
                # an axis tag stamped with a "Homing Sequence" rung comment). A rung
                # comment carries a nonzero rung_content (the rung id); a genuine
                # tag/own description has rung_content 0. Excluding nonzero
                # rung_content drops the rung-comment collisions while keeping the
                # real cip-0x68 descriptions (validated: PROJ_E keeps 11, drops 26
                # rung collisions; layout AX* over-emit gone).
                # A long-header own description also carries object_id == 1; the
                # scratch/operand rows that share (parent_key, member_ref) under a
                # sentinel key instead carry a nonzero object_id (e.g. 33) with an
                # empty tag_reference, so the tag_reference guard alone lets them
                # through as a fabricated name-fragment Description. Requiring
                # object_id == 1 keeps the real own description and drops those.
                self._cur.execute(
                    "SELECT record_string, tag_reference FROM comments "
                    "WHERE parent=? AND member_ref=? "
                    "AND (rung_content IS NULL OR rung_content=0) "
                    "AND object_id=1 "
                    "LIMIT 1",
                    (parent_key, member_ref),
                )
                desc_row = self._cur.fetchone()
                if desc_row and desc_row[0] and not desc_row[1]:
                    comment_results = [("", desc_row[0])]
            except Exception:
                comment_results = []
        elif r.cip_type == 0x6B:
            # V10..V21 short-header own-description lookup. These type-1/2 records
            # are keyed by parent == comment_id (the same scheme as the short
            # operand comments) and carry the tag's own Description when
            # member_ref == 0. Restricted to cip-0x6b (as the short operand path
            # is): cip-0x68 tags share a constant comment_id, so the bare-cid
            # lookup there matches another comp's description and fabricates one.
            # Wrapped so any failure degrades to today's no-description behaviour.
            try:
                self._cur.execute(
                    "SELECT record_string FROM comments "
                    "WHERE parent=? AND member_ref=0 AND record_type IN (1,2) "
                    "AND record_string!='' LIMIT 1",
                    (r.comment_id,),
                )
                desc_row = self._cur.fetchone()
                if desc_row and desc_row[0]:
                    comment_results = [("", desc_row[0])]
            except Exception:
                comment_results = []

        # Operand-keyed member/bit/array comments. Stored in the comments table
        # with the operand in tag_reference and the text in record_string.
        # Wrapped so any failure degrades to today's no-operand-comment behaviour.
        operand_comments: List[Tuple[str, str]] = []
        if self._short_header and r.cip_type == 0x6B:
            # SHORT (V10..V21): keyed by the bare comment_id; record types 3..11.
            # Restricted to cip 0x6b: cip-0x68 tags share a constant comment_id
            # (in some projects one comment_id spans dozens of cip-0x68 tags), so
            # keying operand comments by comment_id there smears one tag's comments
            # across many. cip-0x6b legit comments often share a comment_id too (so
            # bare-cid uniqueness would wrongly drop them), but restricting to 0x6b
            # removes the dominant 0x68 over-emission while keeping the bulk of
            # correct comments.
            try:
                # tag_reference!='' selects operand records (own-descriptions
                # store ''); record_type is NOT filtered because it is an ordinal,
                # not a type enum (a parent's member comments range over rt 3..36).
                # The bare comment_id is unique per cip-0x6b comp, so this join
                # never smears one tag's comments onto another. __REVISION_NOTE__
                # is AOI UDI metadata, not a tag operand comment.
                self._cur.execute(
                    "SELECT tag_reference, record_string FROM comments "
                    "WHERE parent=? AND tag_reference!='' "
                    "AND tag_reference!='__REVISION_NOTE__'",
                    (r.comment_id,),
                )
                for op_ref, op_text in self._cur.fetchall():
                    # A valid L5X tag Operand is a qualifier relative to the tag:
                    # it begins with '.' (member/bit) or '[' (array index). A bare
                    # member name is a DataType member description (emitted on the
                    # datatype, not the tag), and a '.!<hex>' operand is a module
                    # I/O connection point Studio does not surface on the tag.
                    # Both would be mis-attributed as tag comments, so skip them.
                    if op_ref and op_ref[0] in ".[" and not op_ref.startswith(".!"):
                        operand_comments.append((op_ref, op_text or ""))
            except Exception:
                operand_comments = []
        else:
            # LONG (V24+): keyed by parent == comment_id*0x10000 + cip_type. The
            # operand string ("[0]", ".5", ".Member") is in tag_reference, the text
            # in record_string. record_type is NOT filtered: it is an ordinal, and
            # the member/bit/array comments live under types beyond the kaitai's
            # 3/4/13/14 (decoded by _parse_long_operand_body). Require both fields
            # non-empty (empty record_string marks an internal multi-entry record
            # Studio does not surface). COLLISION-SAFE: only emit when the key is
            # owned by exactly one comp (unique_comment_key) -- cip-0x68 tags share
            # a constant comment_id and would smear otherwise. A '.!<hex>' operand
            # anywhere in the path is a module connection point Logix resolves to a
            # member name (a separate feature), never surfaced as a tag comment; it
            # is excluded as a substring ("[30].!0F83..." also occurs).
            try:
                parent_key = (r.comment_id * 0x10000) + r.cip_type
                self._cur.execute(
                    "SELECT c.tag_reference, c.record_string FROM comments c "
                    "WHERE c.parent=? "
                    "AND c.tag_reference!='' AND c.tag_reference!='__REVISION_NOTE__' "
                    "AND c.record_string!='' "
                    "AND EXISTS (SELECT 1 FROM unique_comment_key u WHERE u.k=c.parent)",
                    (parent_key,),
                )
                for op_ref, op_text in self._cur.fetchall():
                    if op_text and _is_valid_operand(op_ref):
                        operand_comments.append((op_ref, op_text))
            except Exception:
                operand_comments = []

        extended_records: Dict[int, bytes] = {}
        for extended_record in r.extended_records:
            extended_records[extended_record.attribute_id] = bytes(
                extended_record.value
            )

        if 0x01 not in extended_records:
            # Name comes from comp_name in the database; radix from main_record
            raw_radix = r.main_record.radix
            radix = radix_enum(raw_radix)
            dim_parts = []
            if r.main_record.dimension_1 != 0:
                dim_parts.append(str(r.main_record.dimension_1))
            if r.main_record.dimension_2 != 0:
                dim_parts.append(str(r.main_record.dimension_2))
            if r.main_record.dimension_3 != 0:
                dim_parts.append(str(r.main_record.dimension_3))
            dimensions = ",".join(dim_parts) if dim_parts else None
            value_bytes, value_type_code = (
                (None, 0) if (alias_for or suppress_value)
                else self._read_tag_value(r.main_record.data_table_instance)
            )
            _nm = io_name or results[0][0]
            return Tag(
                _nm, _nm, tag_type,
                None if alias_for else data_type, radix,
                external_access, constant, dimensions, r.main_record.data_table_instance,
                comment_results,
                _operand_comments=operand_comments,
                alias_for=alias_for,
                _value_bytes=value_bytes,
                _value_type_code=value_type_code,
                _short_header=self._short_header,
                _raw_hex_data=self._raw_hex_first_block(),
                _no_data=suppress_value,
                _io=is_io,
                _opc_ua=_opc_ua, _class_attr=_cls_attr(),
            )

        name_length = struct.unpack("<H", extended_records[0x01][0:2])[0]
        name = bytes(extended_records[0x01][2 : name_length + 2]).decode("utf-8", errors="replace")

        raw_radix = r.main_record.radix
        radix = radix_enum(raw_radix)

        dim_parts = []
        if r.main_record.dimension_1 != 0:
            dim_parts.append(str(r.main_record.dimension_1))
        if r.main_record.dimension_2 != 0:
            dim_parts.append(str(r.main_record.dimension_2))
        if r.main_record.dimension_3 != 0:
            dim_parts.append(str(r.main_record.dimension_3))
        dimensions = ",".join(dim_parts) if dim_parts else None
        value_bytes, value_type_code = (
            (None, 0) if (alias_for or suppress_value)
            else self._read_tag_value(r.main_record.data_table_instance)
        )
        _nm = io_name or name
        return Tag(
            _nm,
            _nm,
            tag_type,
            None if alias_for else data_type,
            radix,
            external_access,
            constant,
            dimensions,
            r.main_record.data_table_instance,
            comment_results,
            _operand_comments=operand_comments,
            alias_for=alias_for,
            _value_bytes=value_bytes,
            _value_type_code=value_type_code,
            _short_header=self._short_header,
            _raw_hex_data=self._raw_hex_first_block(),
            _no_data=suppress_value,
            _io=is_io,
            _opc_ua=_opc_ua, _class_attr=_cls_attr(),
        )


def _aoi_tag_usage(ext01: bytes, short_header: bool = False) -> Tuple[Union[str, None], bool, bool]:
    """Return (usage, required, visible) for an AOI tag record's ext[0x01] blob.

    ``usage`` is ``'Input'|'Output'|'InOut'|'Local'`` (or ``None`` if the blob is
    too short).  The encoding differs by header family:

    * Long header (V24+): the usage bits and the required/visible flags share one
      byte at ext01[0x20E] — 0x04=Input, 0x08=Output (both=InOut, neither=Local),
      0x20=Required, 0x40=Visible.
    * Short header (V10..V21): the direction is the LOW nibble of ext01[0x20F]
      (4=Input, 5=Output/InOut, 6=Local) — that byte's HIGH nibble is the radix.
      Nibble 5 is Output for a plain output but InOut for a by-reference
      parameter; the two are separated by the 0x80 bit of ext01[0x20E] (input
      semantics, also set for Input). Required/Visible are at ext01[0x105]
      (0x80=Required, 0x40=Visible; Required always implies Visible). In the long
      layout 0x20E&0x0C is unrelated to usage, so a short-header parameter is
      otherwise misread as a local tag.
    """
    if short_header:
        if len(ext01) <= 0x20F:
            return None, False, False
        nibble = ext01[0x20F] & 0x0F
        if nibble == 4:
            usage = "Input"
        elif nibble == 5:
            usage = "InOut" if (ext01[0x20E] & 0x80) else "Output"
        elif nibble == 6:
            usage = "Local"
        else:
            usage = None
        flags = ext01[0x105] if len(ext01) > 0x105 else 0
        return usage, bool(flags & 0x80), bool(flags & 0x40)
    if len(ext01) <= 0x20E:
        return None, False, False
    bits = ext01[0x20E]
    usage = {0x04: "Input", 0x08: "Output", 0x0C: "InOut"}.get(bits & 0x0C, "Local")
    return usage, bool(bits & 0x20), bool(bits & 0x40)


def _aoi_tag_data_type(cur, raw_rec: bytes) -> str:
    """Look up the DataType name for an AOI tag record.

    The DataType OID is stored at offset 0x2A in the raw parameter record
    as a little-endian u32.  We look it up in the comps table by object_id.
    """
    if len(raw_rec) < 0x2E:
        return ""
    dt_oid = struct.unpack_from("<I", raw_rec, 0x2A)[0]
    cur.execute("SELECT comp_name FROM comps WHERE object_id=" + str(dt_oid))
    row = cur.fetchone()
    return row[0] if row else ""


@dataclass
class ParameterBuilder(L5xElementBuilder):
    """Build a Parameter from an AOI RxTagCollection child record."""

    _short_header: bool = field(default=False)
    # Owning AOI's bare comment_id; the short-header description key.
    _owner_comment_id: int = field(default=0)

    def build(self) -> Parameter:
        self._cur.execute(
            "SELECT comp_name, record FROM comps WHERE object_id=" + str(self._object_id)
        )
        row = self._cur.fetchone()
        name = row[0]
        raw_rec = bytes(row[1])

        data_type = _aoi_tag_data_type(self._cur, raw_rec)

        # Dimensions (array size) at raw record offset 0x1A as u32; 0 means scalar.
        dimensions: Union[str, None] = None
        if len(raw_rec) >= 0x1E:
            dim_val = struct.unpack_from("<I", raw_rec, 0x1A)[0]
            if dim_val:
                dimensions = str(dim_val)

        # Source-protected AOI parameters encrypt the ext-attr tail, so
        # RxGeneric.from_bytes throws. Decrypt the tail to recover ext[0x01] and
        # read cip/comment_id from the plaintext main_record so the description
        # lookup below still resolves. The decrypted ext blob always uses the
        # LONG-header usage layout regardless of the file's header family.
        sp = False
        try:
            r = RxGeneric.from_bytes(raw_rec)
            exts: Dict[int, bytes] = {
                er.attribute_id: bytes(er.value) for er in r.extended_records
            }
        except Exception:
            exts = CompsRecord.read_ext_attrs_from_record(raw_rec)
            r = _rxgeneric_plaintext_main(raw_rec)
            if not exts or r is None:
                return Parameter(name, name, "Base", data_type, "Input", None, "false", "false", "Read/Write", None, dimensions)
            sp = True

        ext01 = exts.get(0x01, b"")
        usage, required_b, visible_b = _aoi_tag_usage(ext01, short_header=False if sp else self._short_header)
        # AoiBuilder only routes Input/Output/InOut here; guard the Local/None
        # edge to the prior InOut default so behaviour can't regress.
        if usage not in ("Input", "Output", "InOut"):
            usage = "InOut"

        required = "true" if required_b else "false"
        visible = "true" if visible_b else "false"

        # ExternalAccess (u16 at ext01[0x21E])
        # Built-in reference-type InOut parameters (MESSAGE and the motion
        # references MOTION_GROUP / AXIS_CIP_DRIVE) don't carry Constant in the
        # reference L5X; every other InOut parameter (atomic, string, and user
        # UDTs including axis-named ones like tstAxisUDT) still carries it. Match
        # by exact DataType, never a name substring.
        _no_constant_inout = ("MESSAGE", "MOTION_GROUP", "AXIS_CIP_DRIVE")
        if usage == "InOut":
            external_access = None
            constant: Union[str, None] = None if data_type in _no_constant_inout else "false"
        elif len(ext01) > 0x21F:
            ea_val = struct.unpack_from("<H", ext01, 0x21E)[0]
            external_access = external_access_enum(ea_val)
            constant = None
        else:
            external_access = "Read/Write"
            constant = None

        # Radix (high nibble of ext01[0x20F]).  InOut params for complex/UDT types
        # omit Radix; InOut params for scalar/array types (BOOL, INT, DINT, REAL, etc.)
        # still carry Radix in the golden L5X, so include it whenever the radix index
        # is non-zero regardless of Usage.
        if not data_type or len(ext01) <= 0x20F:
            radix: Union[str, None] = None
        else:
            radix_idx = ext01[0x20F] >> 4
            radix = radix_enum(radix_idx) if radix_idx != 0 else None

        # --- Description ---
        # Source-protected projects also encrypt the comment text, so for an
        # SP-recovered parameter the comments table holds undecryptable garbage
        # (e.g. a lone 0x1d control byte, which would additionally produce invalid
        # XML). Skip the lookup on the SP path rather than emit a bogus Description;
        # the real text needs a separate comment-decryption that is not yet cracked.
        description: Union[str, None] = None
        if sp:
            pass
        elif self._short_header:
            # V10-V21: the parameter description is in the comments table keyed by
            # the owning AOI's bare comment_id with the parameter NAME in
            # tag_reference (same scheme as short-header datatype members; verified
            # V16). record_type is an ordinal, so it is not filtered.
            if self._owner_comment_id:
                self._cur.execute(
                    "SELECT record_string FROM comments "
                    "WHERE parent=? AND tag_reference=? AND record_string!='' LIMIT 1",
                    (self._owner_comment_id, name),
                )
                desc_row = self._cur.fetchone()
                if desc_row and desc_row[0]:
                    description = desc_row[0]
        elif len(raw_rec) >= 18:
            # V24+ long header: bytes [14:18] are the member_ref into the comments
            # table, keyed by comment_id*0x10000 + cip.
            member_ref = struct.unpack_from("<I", raw_rec, 14)[0]
            if member_ref:
                self._cur.execute(
                    "SELECT record_string FROM comments WHERE parent=? AND member_ref=? LIMIT 1",
                    ((r.comment_id * 0x10000) + r.cip_type, member_ref),
                )
                desc_row = self._cur.fetchone()
                if desc_row and desc_row[0]:
                    description = desc_row[0]

        return Parameter(
            name,
            name,
            "Base",
            data_type,
            usage,
            radix,
            required,
            visible,
            external_access,
            constant,
            dimensions,
            description,
        )


@dataclass
class LocalTagBuilder(L5xElementBuilder):
    """Build a LocalTag from an AOI RxTagCollection child record."""

    _short_header: bool = field(default=False)
    # Owning AOI's bare comment_id; the short-header description key.
    _owner_comment_id: int = field(default=0)

    def build(self) -> LocalTag:
        self._cur.execute(
            "SELECT comp_name, record FROM comps WHERE object_id=" + str(self._object_id)
        )
        row = self._cur.fetchone()
        name = row[0]
        raw_rec = bytes(row[1])

        data_type = _aoi_tag_data_type(self._cur, raw_rec)

        # Dimensions at raw record offset 0x1A.
        dimensions: Union[str, None] = None
        if len(raw_rec) >= 0x1E:
            dim_val = struct.unpack_from("<I", raw_rec, 0x1A)[0]
            if dim_val:
                dimensions = str(dim_val)

        # Source-protected AOI local tags encrypt the ext-attr tail, so
        # RxGeneric.from_bytes throws. Decrypt it to recover ext[0x01] for the
        # correct ExternalAccess/Radix (read at fixed ext01 offsets, layout-
        # independent). The comment text is also encrypted on SP projects, so the
        # description lookup is skipped on this path (see below).
        sp = False
        try:
            r = RxGeneric.from_bytes(raw_rec)
            exts: Dict[int, bytes] = {
                er.attribute_id: bytes(er.value) for er in r.extended_records
            }
        except Exception:
            exts = CompsRecord.read_ext_attrs_from_record(raw_rec)
            r = _rxgeneric_plaintext_main(raw_rec)
            if not exts or r is None:
                return LocalTag(name, name, data_type, dimensions, None, "Read/Write")
            sp = True

        ext01 = exts.get(0x01, b"")
        if len(ext01) > 0x21F:
            ea_val = struct.unpack_from("<H", ext01, 0x21E)[0]
            external_access = external_access_enum(ea_val)
        else:
            external_access = "Read/Write"

        if len(ext01) > 0x20F:
            radix_idx = ext01[0x20F] >> 4
            radix: Union[str, None] = radix_enum(radix_idx) if radix_idx != 0 else None
        else:
            radix = None

        # --- Description ---
        # SP projects encrypt the comment text, so skip the lookup on the SP path
        # (the stored comment is undecryptable garbage that would also break XML).
        description: Union[str, None] = None
        if sp:
            pass
        elif self._short_header:
            # V10-V21: keyed by the owning AOI's bare comment_id + the local-tag
            # NAME in tag_reference (same scheme as short-header members/params).
            if self._owner_comment_id:
                self._cur.execute(
                    "SELECT record_string FROM comments "
                    "WHERE parent=? AND tag_reference=? AND record_string!='' LIMIT 1",
                    (self._owner_comment_id, name),
                )
                desc_row = self._cur.fetchone()
                if desc_row and desc_row[0]:
                    description = desc_row[0]
        elif len(raw_rec) >= 18:
            # V24+ long header: bytes [14:18] are the member_ref into the comments
            # table, keyed by comment_id*0x10000 + cip.
            member_ref = struct.unpack_from("<I", raw_rec, 14)[0]
            if member_ref:
                self._cur.execute(
                    "SELECT record_string FROM comments WHERE parent=? AND member_ref=? LIMIT 1",
                    ((r.comment_id * 0x10000) + r.cip_type, member_ref),
                )
                desc_row = self._cur.fetchone()
                if desc_row and desc_row[0]:
                    description = desc_row[0]

        return LocalTag(name, name, data_type, dimensions, radix, external_access, description)


def routine_type_enum(idx: int) -> str:
    if idx == 0:
        return "TypeLess"
    if idx == 1:
        return "RLL"
    if idx == 2:
        return "FBD"
    if idx == 3:
        return "SFC"
    if idx == 4:
        return "ST"
    if idx == 5:
        return "External"
    if idx == 6:
        return "Encrypted"
    return "Typeless"


@dataclass
class RoutineBuilder(L5xElementBuilder):
    def build(self) -> Routine:
        self._cur.execute(
            "SELECT comp_name, object_id, parent_id, record FROM comps WHERE object_id="
            + str(self._object_id)
        )
        results = self._cur.fetchall()

        try:
            r = RxGeneric.from_bytes(results[0][3])
        except Exception as e:
            return Routine(results[0][0], results[0][0], "", [])

        record = results[0][3]
        name = results[0][0]
        routine_type = routine_type_enum(
            struct.unpack_from("<H", r.record_buffer, 0x30)[0]
        )

        self._cur.execute(
            "SELECT rm.object_id, r.rung FROM region_map rm "
            "LEFT JOIN rungs r ON r.object_id = rm.object_id "
            "WHERE rm.parent_id=" + str(self._object_id) + " ORDER BY rm.unknown"
        )
        rows = [(row[0], row[1]) for row in self._cur.fetchall() if row[1] is not None]
        rung_ids = [row[0] for row in rows]
        rungs = [row[1] for row in rows]

        # Resolve &hexid: placeholders (object ID references) to comp names.
        # The ACD binary stores tag references as &XXXXXXXX: where XXXXXXXX is the
        # object_id in hex. Batch-resolve all unique IDs to avoid per-rung queries.
        import re as _re
        all_hex = set(_re.findall(r'&([0-9a-f]{8}):', " ".join(r for r in rungs if r)))
        if all_hex:
            id_to_name: Dict[int, str] = {}
            for hex_id in all_hex:
                oid = int(hex_id, 16)
                self._cur.execute("SELECT comp_name FROM comps WHERE object_id=?", (oid,))
                row2 = self._cur.fetchone()
                if row2:
                    id_to_name[hex_id] = row2[0]
            if id_to_name:
                def _resolve(rung: str) -> str:
                    return _re.sub(
                        r'&([0-9a-f]{8}):',
                        lambda m: (id_to_name[m.group(1)] + ":") if m.group(1) in id_to_name else m.group(0),
                        rung,
                    )
                rungs = [_resolve(r) if r else r for r in rungs]

        # Fetch rung-level comments and map each to its rung Number.
        #
        # A rung comment lives in Comments.Dat keyed only by its own rung_content
        # (an id that appears NOWHERE in the rung/SbRegion data). The link from a
        # rung to its comment is RegnLink.Dat (the regn_link table): each rung_oid
        # is paired with its comment's rung_content, encoded as
        #   rc_hi  = rung_content >> 16
        #   rc_lo7 = rung_content & 0x7f   (LONG header only)
        # and a per-routine group_id == the routine's comps object_id. rung_ids[i]
        # is the SbRegion object_id of the rung at Number i (region_map order), so
        # regn_link gives rung_oid -> comment, and Number = position in rung_ids.
        # (The legacy "object_id - 1" scheme was wrong: the comment object_id is
        # always 1.) Best-effort: if regn_link is empty no comments are attached.
        #
        # The (rc_hi, rc_lo7) key is only 23 bits and NOT globally unique in large
        # LONG-header projects (collisions make one comment match many rungs ->
        # 2x over-emission), so we SCOPE both sides to this routine:
        #   - rungs:    regn_link.group_id == this routine's comps object_id
        #   - comments: c.parent / c.member_ref == this routine's keys, read from
        #               the routine's own comps record (parent = comment_id*0x10000
        #               + cip_type; member_ref = u32 at body offset 14). Within one
        #               routine the key is unique. SHORT-header (V10-V21) comments
        #               encode parent/member_ref differently and don't collide in
        #               practice, so there we scope rungs by group_id and match the
        #               16-bit rung_content (== rc_hi) without the comment scope.
        rung_comments: Dict[int, str] = {}
        try:
            if rung_ids:
                oid_to_number = {oid: idx for idx, oid in enumerate(rung_ids)}
                self._cur.execute("SELECT is_short FROM regn_link LIMIT 1")
                _isr = self._cur.fetchone()
                is_short = bool(_isr[0]) if _isr else False
                if is_short:
                    # SHORT-header: scope the comment side to this routine too, to
                    # drop cross-routine 16-bit rc_hi collisions (precision). The
                    # short-header rung comment's parent column is
                    #   0x6d0000 | (routine comment_id & 0xffff)
                    # (the short comment parser stores parent == comment_id; the
                    # 0x6d high byte is the rung-comment record tag). Verified on
                    # V20 (1767 -> exact 1727) and V16 (102, unchanged).
                    short_parent_key = 0x6D0000 | (r.comment_id & 0xFFFF)
                    self._cur.execute(
                        "SELECT rl.rung_oid, c.record_string FROM regn_link rl "
                        "JOIN comments c ON c.rung_content = rl.rc_hi "
                        "WHERE c.record_type=1 AND c.rung_content!=0 "
                        "  AND rl.group_id=? AND c.parent=?",
                        (self._object_id, short_parent_key),
                    )
                else:
                    parent_key = (r.comment_id * 0x10000) + r.cip_type
                    member_ref_key = (
                        struct.unpack_from("<I", record, 14)[0]
                        if len(record) >= 18 else -1
                    )
                    self._cur.execute(
                        "SELECT rl.rung_oid, c.record_string FROM regn_link rl "
                        "JOIN comments c "
                        "  ON (c.rung_content >> 16) = rl.rc_hi "
                        " AND (c.rung_content & 127) = rl.rc_lo7 "
                        "WHERE c.record_type=1 AND c.rung_content!=0 "
                        "  AND rl.group_id=? AND c.parent=? AND c.member_ref=?",
                        (self._object_id, parent_key, member_ref_key),
                    )
                for rung_oid, rec_str in self._cur.fetchall():
                    number = oid_to_number.get(rung_oid)
                    if number is not None and rec_str and number not in rung_comments:
                        rung_comments[number] = rec_str
        except Exception:
            pass

        return Routine(name, name, routine_type, rungs, rung_ids, rung_comments)


def _parse_fffeff(data: bytes, offset: int):
    """Parse one fffeff-encoded string at offset. Returns (str, new_offset)."""
    if offset + 3 > len(data) or not (data[offset] == 0xFF and data[offset+1] == 0xFE and data[offset+2] == 0xFF):
        return "", offset
    length = data[offset+3]
    s = data[offset+4:offset+4+length*2].decode("utf-16-le", errors="replace")
    return s, offset + 4 + length * 2


def _parse_aoi_nameless(data: bytes) -> dict:
    """Extract AOI metadata from its large nameless record."""
    result: dict = {}

    offset = 0x1A
    # Three empty fffeff strings
    for _ in range(3):
        _, offset = _parse_fffeff(data, offset)

    # 8 bytes (unknown - some kind of date, skip)
    offset += 8

    # 2-byte constant (0x0002 observed)
    offset += 2

    # CreatedBy
    result["created_by"], offset = _parse_fffeff(data, offset)

    # Software revision at creation time (skip - we want the current one later)
    _, offset = _parse_fffeff(data, offset)

    # 4 zero bytes
    offset += 4

    # Empty fffeff placeholder
    _, offset = _parse_fffeff(data, offset)

    # CreatedDate FILETIME (8 bytes, Windows FILETIME in 100-ns units)
    ft = struct.unpack_from("<Q", data, offset)[0]
    if ft:
        try:
            dt = datetime(1601, 1, 1) + timedelta(microseconds=ft // 10)
            result["created_date"] = dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"
        except (OverflowError, OSError, ValueError):
            # garbage/out-of-range FILETIME in some real-world records
            result["created_date"] = ""
    else:
        result["created_date"] = ""
    offset += 8

    # EditedBy
    result["edited_by"], offset = _parse_fffeff(data, offset)

    # SoftwareRevision (current)
    result["software_revision"], offset = _parse_fffeff(data, offset)

    # 4 bytes (01 00 00 00)
    offset += 4

    # RevisionExtension
    rev_ext, offset = _parse_fffeff(data, offset)
    result["revision_extension"] = rev_ext or None

    # EditedDate FILETIME (always last 8 bytes)
    ft = struct.unpack_from("<Q", data, len(data) - 8)[0]
    if ft:
        try:
            dt = datetime(1601, 1, 1) + timedelta(microseconds=ft // 10)
            result["edited_date"] = dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"
        except (OverflowError, OSError, ValueError):
            # garbage/out-of-range FILETIME in some real-world records
            result["edited_date"] = ""
    else:
        result["edited_date"] = ""

    return result


@dataclass
class AoiBuilder(L5xElementBuilder):
    _data_types_map: Dict[str, "DataType"] = field(default_factory=dict)
    _short_header: bool = field(default=False)
    _taginfo_layout: Dict[str, object] = field(default_factory=dict)

    def build(self) -> AOI:
        self._cur.execute(
            "SELECT comp_name, object_id, parent_id, record FROM comps WHERE object_id="
            + str(self._object_id)
        )
        results = self._cur.fetchall()

        aoi_record = bytes(results[0][3])
        name = results[0][0]

        # The AOI's parameter/local-tag descriptions are keyed (short header) by
        # the comment_id of the AOI's DATATYPE comp -- the cip-0x6c struct under
        # RxDataTypeCollection that shares the AOI name -- NOT the AOI definition
        # comp (cip 0x338) this builder is invoked on. (An AOI's parameters are its
        # datatype members, so they share the datatype's comment_id, as plain UDT
        # members do.) Verified V16: descriptions resolve off this comment_id.
        aoi_comment_id = 0
        try:
            _dtrow = self._cur.execute(
                "SELECT record FROM comps WHERE comp_name=? AND parent_id="
                "(SELECT object_id FROM comps WHERE comp_name='RxDataTypeCollection')",
                (name,),
            ).fetchone()
            if _dtrow and _dtrow[0] is not None:
                aoi_comment_id = RxGeneric.from_bytes(bytes(_dtrow[0])).comment_id
        except Exception:
            aoi_comment_id = 0

        # --- AOI Parameter/LocalTag prototype DefaultData value images ---
        # Resolve the AOI's hidden __DEFVAL backing ONCE: a consolidated image of
        # the whole AOI struct. Each Parameter/LocalTag default is a slice at the
        # member's TagInfo byte offset/width. Best-effort: None on any failure ->
        # builders leave _value_bytes None -> exactly today's behaviour.
        defval_image: Union[bytes, None] = None
        defval_members: Dict[str, tuple] = {}
        try:
            img = CompsRecord.read_aoi_defval_image(
                self._cur, name, self._short_header
            )
            members = self._taginfo_layout.get(name.upper(), [])
            aoi_size = self._taginfo_layout.get("@size@" + name.upper())
            # Integrity gate: image length MUST equal @size@<AOI>, else reject.
            if (img is not None and members and aoi_size is not None
                    and len(img) == aoi_size):
                defval_image = img
                for m in members:
                    # m = (mname, mdt, off, bit, hidden, dims)
                    if m and m[0]:
                        defval_members[m[0].upper()] = m
        except Exception:
            defval_image = None
            defval_members = {}

        def _member_slice(child_name: str, child_dt: str):
            """Return the value image (bytes) for one AOI member, or None.

            Resolves the member from the AOI layout by name, then slices the
            consolidated __DEFVAL image at its byte offset/width. BOOL members
            return a synthesized 1-byte image (b'\\x01'/b'\\x00') from the bit in
            the prelude/host word (never slice a sub-byte). All guards return
            None on any mismatch so a wrong slice is never shipped (degrade to
            today's no-value behaviour).
            """
            try:
                if defval_image is None:
                    return None
                m = defval_members.get(child_name.upper())
                if m is None:
                    return None
                mname, mdt, off, bit, hidden, dims = m
                if off is None or off < 0 or off > len(defval_image):
                    return None
                mdt_base = (mdt or "").split("[")[0].upper()
                # BOOL: read the bit from the host word; emit a 1-byte image.
                if mdt_base in ("BOOL", "BIT"):
                    if bit is not None:
                        byte_off = off + (bit // 8)
                        if byte_off >= len(defval_image):
                            return None
                        b = (defval_image[byte_off] >> (bit % 8)) & 1
                    else:
                        if off >= len(defval_image):
                            return None
                        b = 1 if (defval_image[off] & 1) else 0
                    return b"\x01" if b else b"\x00"
                # Width: scalar primitives by table; STRING/UDT/array by @size@.
                total = 1
                for d in (dims or []):
                    total *= d
                if mdt_base in _PRIMITIVE_BYTE_WIDTH:
                    width = _PRIMITIVE_BYTE_WIDTH[mdt_base] * max(total, 1)
                else:
                    msize = self._taginfo_layout.get("@size@" + mdt_base)
                    if msize is None:
                        return None
                    width = msize * max(total, 1)
                if width <= 0 or off + width > len(defval_image):
                    return None
                return defval_image[off:off + width]
            except Exception:
                return None

        # --- Revision (major.minor) from ext[0x01] ---
        _r_aoi: Union[RxGeneric, None] = None
        try:
            r = RxGeneric.from_bytes(aoi_record)
            _r_aoi = r
            exts: Dict[int, bytes] = {e.attribute_id: bytes(e.value) for e in r.extended_records}
            e01 = exts.get(0x01, b"")
            rev_major = struct.unpack_from("<H", e01, 0x1A)[0] if len(e01) > 0x1B else 1
            rev_minor = struct.unpack_from("<H", e01, 0x1C)[0] if len(e01) > 0x1D else 0
        except Exception:
            rev_major, rev_minor = 1, 0
        revision = f"{rev_major}.{rev_minor}"

        # --- Vendor from comps record ---
        # The u16 length @0xA6 / UTF-8 @0xA8 layout is V34+; on older records (e.g.
        # V30) the slot lands on zero bytes, and on a source-protected AOI it lands
        # on ciphertext. Sanitize the decoded value (drop XML-illegal control bytes)
        # and treat an empty result as absent so the attribute is omitted rather
        # than emitting control bytes / an empty Vendor="".
        vlen = struct.unpack_from("<H", aoi_record, 0xA6)[0] if len(aoi_record) > 0xA8 else 0
        vendor: Union[str, None] = None
        if vlen > 0:
            _vendor = _xml_sane(aoi_record[0xA8:0xA8 + vlen].decode("utf-8", errors="replace"))
            vendor = _vendor if _vendor.strip() else None

        # --- Metadata from large nameless record ---
        self._cur.execute(
            "SELECT record FROM nameless WHERE parent_id=" + str(self._object_id)
            + " ORDER BY LENGTH(record) DESC LIMIT 1"
        )
        nameless_row = self._cur.fetchone()
        if nameless_row and len(bytes(nameless_row[0])) > 50:
            meta = _parse_aoi_nameless(bytes(nameless_row[0]))
        else:
            meta = {"created_by": "", "created_date": "", "edited_by": "", "edited_date": "",
                    "software_revision": "", "revision_extension": None}

        parameters: List[Parameter] = []
        local_tags: List[LocalTag] = []
        routines: List[Routine] = []

        # --- Extract Parameters and LocalTags from RxTagCollection ---
        self._cur.execute(
            "SELECT object_id FROM comps WHERE parent_id="
            + str(self._object_id)
            + " AND comp_name='RxTagCollection'"
        )
        tag_coll_row = self._cur.fetchone()
        if tag_coll_row:
            tag_coll_oid = tag_coll_row[0]
            self._cur.execute(
                "SELECT object_id, record FROM comps WHERE parent_id="
                + str(tag_coll_oid)
                + " AND record_type != 512"
                + " ORDER BY seq_number"
            )
            for child_oid, child_rec in self._cur.fetchall():
                child_rec = bytes(child_rec)
                # Determine whether this is a parameter or a local tag from the
                # AOI tag usage (Input/Output/InOut -> parameter; Local -> local
                # tag). The usage encoding is header-family-specific (see
                # _aoi_tag_usage); short-header projects store it in a different
                # byte, so this must be version-aware or every short-header
                # parameter is misread as a local tag.
                is_param = False
                try:
                    r_child = RxGeneric.from_bytes(child_rec)
                    exts_child: Dict[int, bytes] = {
                        er.attribute_id: bytes(er.value)
                        for er in r_child.extended_records
                    }
                    ext01 = exts_child.get(0x01, b"")
                    usage, _, _ = _aoi_tag_usage(ext01, self._short_header)
                    is_param = usage in ("Input", "Output", "InOut")
                except Exception:
                    # Source-protected AOI: the ext-attr tail is AES-encrypted, so
                    # RxGeneric.from_bytes throws. Decrypt it to recover ext[0x01]
                    # and classify on the usage byte. The decrypted blob always uses
                    # the LONG-header usage layout regardless of the file's native
                    # header family (a short-header source-protected project would
                    # otherwise misread every parameter as a local tag), so classify
                    # with short_header=False. Degrades to today's local-tag routing
                    # if no key validates.
                    try:
                        ext01 = CompsRecord.read_ext_attrs_from_record(child_rec).get(0x01, b"")
                        usage, _, _ = _aoi_tag_usage(ext01, short_header=False)
                        is_param = usage in ("Input", "Output", "InOut")
                    except Exception:
                        pass

                if is_param:
                    try:
                        p = ParameterBuilder(self._cur, child_oid, _short_header=self._short_header, _owner_comment_id=aoi_comment_id).build()
                        # Wire the value-emission maps so <DefaultData> can be
                        # built (mirrors how TagBuilder receives them). Failure
                        # to attach degrades to no-DefaultData, never crashes.
                        try:
                            p._data_types_map = self._data_types_map
                            p._taginfo_layout = self._taginfo_layout
                            p._short_header = self._short_header
                            sl = _member_slice(p.name, p.data_type)
                            if sl is not None:
                                p._value_bytes = sl
                        except Exception:
                            pass
                        parameters.append(p)
                    except Exception:
                        pass
                else:
                    try:
                        lt = LocalTagBuilder(self._cur, child_oid, _short_header=self._short_header, _owner_comment_id=aoi_comment_id).build()
                        try:
                            lt._data_types_map = self._data_types_map
                            lt._taginfo_layout = self._taginfo_layout
                            lt._short_header = self._short_header
                            sl = _member_slice(lt.name, lt.data_type)
                            if sl is not None:
                                lt._value_bytes = sl
                        except Exception:
                            pass
                        local_tags.append(lt)
                    except Exception:
                        pass

        # --- Extract Routines from RxRoutineCollection ---
        self._cur.execute(
            "SELECT object_id FROM comps WHERE parent_id="
            + str(self._object_id)
            + " AND comp_name='RxRoutineCollection'"
        )
        routine_coll_row = self._cur.fetchone()
        if routine_coll_row:
            routine_coll_oid = routine_coll_row[0]
            self._cur.execute(
                "SELECT object_id FROM comps WHERE parent_id=" + str(routine_coll_oid)
            )
            for (child_oid,) in self._cur.fetchall():
                try:
                    routines.append(RoutineBuilder(self._cur, child_oid).build())
                except Exception:
                    pass

        # --- Description + RevisionNote ---
        aoi_description: Union[str, None] = None
        revision_note = ""
        if _r_aoi is not None:
            aoi_comment_parent = (_r_aoi.comment_id * 0x10000) + _r_aoi.cip_type
            # The AOI's own description carries object_id == 1; the extended-help
            # text rows under the same key carry a nonzero object_id (with a
            # non-empty tag_reference such as UDI_EXT_HELP) and are not emitted by
            # OEM as a Description, so require object_id == 1 to exclude them.
            self._cur.execute(
                "SELECT record_string FROM comments "
                "WHERE parent=? AND member_ref=0 AND object_id=1 LIMIT 1",
                (aoi_comment_parent,),
            )
            desc_row = self._cur.fetchone()
            if desc_row and desc_row[0]:
                aoi_description = desc_row[0]
            try:
                self._cur.execute(
                    "SELECT record_string FROM comments WHERE parent=? AND tag_reference='__REVISION_NOTE__' LIMIT 1",
                    (aoi_comment_parent,),
                )
                rn_row = self._cur.fetchone()
                if rn_row:
                    revision_note = rn_row[0] or ""
            except Exception:
                pass

        return AOI(
            name, name, revision,
            meta["revision_extension"],
            vendor,
            "false", "false", "false",
            meta["created_date"], meta["created_by"],
            meta["edited_date"], meta["edited_by"],
            meta["software_revision"],
            parameters, local_tags, routines,
            aoi_description,
            revision_note,
        )


@dataclass
class ProgramBuilder(L5xElementBuilder):
    _data_types_map: Dict[str, "DataType"] = field(default_factory=dict)
    _redundancy_enabled: bool = field(default=False)
    _short_header: bool = field(default=False)
    _taginfo_layout: Dict[str, object] = field(default_factory=dict)
    _acd_major: int = field(default=0)

    def build(self) -> Program:
        self._cur.execute(
            "SELECT comp_name, object_id, parent_id, record FROM comps WHERE object_id="
            + str(self._object_id)
        )
        results = self._cur.fetchall()

        prog_record = bytes(results[0][3])
        name = results[0][0]

        # V10..V21 program bodies are source-protected/opaque -> degrade to a
        # name-only Program rather than crashing.
        try:
            r = RxGeneric.from_bytes(prog_record)
            exts: Dict[int, bytes] = {e.attribute_id: bytes(e.value) for e in r.extended_records}
            _prog_comment_parent = (r.comment_id * 0x10000) + r.cip_type
        except Exception:
            r = None
            exts = {}
            _prog_comment_parent = None

        # --- MainRoutineName and FaultRoutineName from extended records ---
        # ext[0x12D] = MainRoutine object_id, ext[0x066] = FaultRoutine object_id
        main_routine_name: Union[str, None] = None
        fault_routine_name: Union[str, None] = None
        if 0x12D in exts and len(exts[0x12D]) >= 4:
            main_oid = struct.unpack_from("<I", exts[0x12D], 0)[0]
            if main_oid:
                self._cur.execute("SELECT comp_name FROM comps WHERE object_id=" + str(main_oid))
                row = self._cur.fetchone()
                main_routine_name = row[0] if row else None
        if 0x066 in exts and len(exts[0x066]) >= 4:
            fault_oid = struct.unpack_from("<I", exts[0x066], 0)[0]
            if fault_oid:
                self._cur.execute("SELECT comp_name FROM comps WHERE object_id=" + str(fault_oid))
                row = self._cur.fetchone()
                fault_routine_name = row[0] if row else None

        # --- Disabled flag from ext[0x01] at offset 0x24 ---
        # A u32 of 0xFFFFFFFF means the program is disabled; 0x00000000 means enabled.
        ext01 = exts.get(0x01, b"")
        disabled_flag = (
            struct.unpack_from("<I", ext01, 0x24)[0] != 0
            if len(ext01) >= 0x28
            else False
        )
        disabled = "true" if disabled_flag else "false"

        self._cur.execute(
            "SELECT comp_name, object_id, parent_id, record FROM comps WHERE parent_id="
            + str(self._object_id)
            + " AND comp_name='RxRoutineCollection'"
        )
        collection_results = self._cur.fetchall()
        routine_results = []
        if collection_results:
            collection_id = collection_results[0][1]
            self._cur.execute(
                "SELECT comp_name, object_id, parent_id, record FROM comps WHERE parent_id="
                + str(collection_id)
            )
            routine_results = self._cur.fetchall()

        routines = []
        for child in routine_results:
            routines.append(RoutineBuilder(self._cur, child[1]).build())

        # Get the Program Scoped Tags
        self._cur.execute(
            "SELECT comp_name, object_id, parent_id, record_type FROM comps WHERE parent_id="
            + str(self._object_id)
            + " AND comp_name='RxTagCollection'"
        )
        results = self._cur.fetchall()
        if len(results) > 1:
            raise Exception("Contains more than one program tag collection")

        tags: List[Tag] = []
        if results:
            self._cur.execute(
                "SELECT comp_name, object_id, parent_id, record_type FROM comps WHERE parent_id="
                + str(results[0][1])
            )
            for result in self._cur.fetchall():
                tag = TagBuilder(self._cur, result[1], _short_header=self._short_header,
                                 _acd_major=self._acd_major).build()
                tag._data_types_map = self._data_types_map
                tag._taginfo_layout = self._taginfo_layout
                tags.append(tag)

        if _prog_comment_parent is not None:
            self._cur.execute(
                "SELECT tag_reference, record_string FROM comments WHERE parent="
                + str(_prog_comment_parent)
            )
            comment_results = self._cur.fetchall()
        else:
            comment_results = []

        # SynchronizeRedundancyDataAfterExecution: present only for redundant controllers.
        # The binary does not expose a per-program flag for this attribute — it is implicit
        # for all programs in a redundant controller project.
        sync_redundancy = "true" if self._redundancy_enabled else None

        # UseAsFolder: Studio 5000 only began emitting this Program attribute at
        # V21. For V10..V20 ACDs the attribute is absent from the OEM L5X (the
        # value, when present, is always "false" for non-folder programs). Gate
        # emission on the ACD save-version: emit "false" for V21+ (matches OEM),
        # omit (None) for older projects to avoid attr_extra over-emission.
        # (The handful of V15-V20 projects re-exported by a newer Studio do
        # carry it, but that depends on the *export tool* version, which is not
        # recoverable from the ACD; keying on the ACD version is the only
        # deterministic signal.)
        use_as_folder: Union[str, None] = "false" if self._acd_major >= 21 else None

        return Program(name, name, "false", main_routine_name, fault_routine_name,
                       disabled, sync_redundancy, use_as_folder, tags, routines)


_TASK_TYPE_MAP = {1: "EVENT", 2: "PERIODIC", 4: "CONTINUOUS"}


@dataclass
class TaskBuilder(L5xElementBuilder):
    def build(self, comment_id_to_program: Dict[int, str]) -> Task:
        self._cur.execute(
            "SELECT comp_name, record FROM comps WHERE object_id=" + str(self._object_id)
        )
        row = self._cur.fetchone()
        name, record = row[0], row[1]

        # All task config fields live within ext[0x01], accessed via absolute BLOB offsets.
        # These offsets were reverse-engineered from PROJ_N.ACD (V36). V10..V21
        # task bodies are shorter/source-protected, so emit a valid default PERIODIC task
        # rather than reading out-of-range -> the L5X skeleton still exports.
        record = bytes(record)
        if len(record) < 0x112F:
            return Task(name, name, "PERIODIC", "10", "10", "10", "false", "false", None, [])
        rate_us = struct.unpack_from("<I", record, 0x106C)[0]
        type_val = struct.unpack_from("<H", record, 0x10F6)[0]
        priority = struct.unpack_from("<H", record, 0x10F8)[0]
        watchdog_us = struct.unpack_from("<I", record, 0x110A)[0]
        disable_update = record[0x112E]

        task_type = _TASK_TYPE_MAP.get(type_val, "PERIODIC")
        rate_str = str(rate_us // 1000) if task_type != "CONTINUOUS" else None

        # Scheduled programs: ext[0x01] value starts at BLOB offset 0x5A.
        # Format: u16 count followed by N u32 comment_ids.
        prog_count = struct.unpack_from("<H", record, 0x5A)[0]
        scheduled_programs = []
        for i in range(prog_count):
            off = 0x5A + 2 + i * 4
            if off + 4 > len(record):  # bound by the actual buffer (real files vary)
                break
            cid = struct.unpack_from("<I", record, off)[0]
            prog_name = comment_id_to_program.get(cid)
            if prog_name:
                scheduled_programs.append(ScheduledProgram(prog_name, prog_name))

        event_info = None
        if task_type == "EVENT":
            event_info = EventInfo("EventInfo", "EVENT Instruction Only", "false")

        return Task(
            name,
            name,
            task_type,
            rate_str,
            str(priority),
            str(watchdog_us // 1000),
            "true" if disable_update else "false",
            "false",
            event_info,
            scheduled_programs,
        )


@dataclass
class ControllerBuilder(L5xElementBuilder):
    # True for V10..V21 short-header projects (set by ExportL5x). Routes the
    # datatype build through the inline-member / full-lean-set path; defaults
    # False so V24+/V36 export is byte-for-byte unchanged.
    _short_header: bool = field(default=False)
    # Step 6d: {DATATYPE_UPPER: [member layout...]} from TagInfo.XML, used to
    # decode tag value images into the Decorated <Data> tree. Empty -> the
    # zero-generator fallback is used (no behaviour change).
    _taginfo_layout: Dict[str, object] = field(default_factory=dict)
    # ACD save-version major (e.g. 21, 36). 0 if unknown. Used to gate
    # version-specific attribute emission (e.g. Program/@UseAsFolder).
    _acd_major: int = field(default=0)

    def build(self) -> Controller:
        # The root controller is the named FAFA component at parent_id=0 /
        # record_type=256. A few projects also carry an anomalous empty-named
        # FDFD sub-record that decodes to the same parent/type; exclude empty
        # names so it isn't mistaken for a second controller. The real controller
        # always carries the project name, so named-only never drops it.
        self._cur.execute(
            "SELECT comp_name, object_id, parent_id, record_type, record FROM comps "
            "WHERE parent_id=0 AND record_type=256 AND comp_name IS NOT NULL AND comp_name != ''"
        )
        results = self._cur.fetchall()
        if len(results) != 1:
            raise Exception("Does not contain exactly one root controller node")

        # V10..V21 component BODIES are source-protected/opaque to the V36
        # RxGeneric parser; degrade body-derived fields to defaults rather than
        # crashing so the L5X skeleton (names + hierarchy) still exports.
        try:
            r = RxGeneric.from_bytes(results[0][4])
            extended_records: Dict[int, bytes] = {
                er.attribute_id: bytes(er.value) for er in r.extended_records
            }
            _comment_parent = (r.comment_id * 0x10000) + r.cip_type
        except Exception:
            r = None
            extended_records = {}
            _comment_parent = None
        if _comment_parent is not None:
            self._cur.execute(
                "SELECT tag_reference, record_string FROM comments WHERE parent="
                + str(_comment_parent)
            )
            comment_results = self._cur.fetchall()
        else:
            comment_results = []

        def _decode_utf16(key):
            raw = extended_records.get(key)
            if raw is None or len(raw) < 2:
                return ""
            return bytes(raw[:-2]).decode("utf-16", errors="replace")

        sfc_execution_control = _decode_utf16(0x6F)
        sfc_restart_position = _decode_utf16(0x70)
        sfc_last_scan = _decode_utf16(0x71)

        # CommPath prefix (key 0x06A): may be in kaitai extended_records (usually empty),
        # or in the LastAttributeRecord appended after the counted records (value length
        # is stored as len_value where actual data = len_value - 4 bytes, UTF-16-LE).
        _comm_path_prefix: Union[str, None] = None
        if 0x06A in extended_records:
            _cp_raw = extended_records[0x06A]
            _cp_str = _cp_raw.decode("utf-16-le", errors="replace").rstrip("\x00")
            if _cp_str:
                _comm_path_prefix = _cp_str
        elif r is not None:
            # LastAttributeRecord tail: located after the (count_record - 1) parsed records.
            # Header layout: parent_id(4) + unique_tag_id(4) + record_format_version(2) +
            #   cip_type(2) + comment_id(2) = 14 bytes, then main_record(60), then
            #   len_record(4) + count_record(4) = 82 bytes total before first AttributeRecord.
            _raw_record = bytes(results[0][4])
            _rec_offset = 82
            for _er in r.extended_records:
                _rec_offset += 4 + 4 + len(bytes(_er.value))
            _tail = _raw_record[_rec_offset:]
            if len(_tail) >= 8:
                _last_attr_id = struct.unpack_from("<I", _tail, 0)[0]
                _last_len_value = struct.unpack_from("<I", _tail, 4)[0]
                if _last_attr_id == 0x06A and _last_len_value >= 4:
                    _actual_len = _last_len_value - 4
                    if len(_tail) >= 8 + _actual_len and _actual_len > 0:
                        _cp_val = _tail[8: 8 + _actual_len]
                        _cp_str = _cp_val.decode("utf-16-le", errors="replace").rstrip("\x00")
                        if _cp_str:
                            _comm_path_prefix = _cp_str

        if 0x75 in extended_records and len(extended_records[0x75]) >= 4:
            sn_raw = hex(struct.unpack("<I", extended_records[0x75])[0])[2:].zfill(8)
            project_sn = f"16#{sn_raw[:4]}_{sn_raw[4:]}"
        else:
            project_sn = "Unknown"

        _DEFAULT_DATE = "Mon Jan 01 00:00:00 2001"
        if 0x66 in extended_records and len(extended_records[0x66]) >= 8:
            raw_modified_date = struct.unpack("<Q", extended_records[0x66])[0] / 10000000
            last_modified_date = (
                datetime(1601, 1, 1) + timedelta(seconds=raw_modified_date)
            ).strftime("%a %b %d %H:%M:%S %Y")
        else:
            last_modified_date = _DEFAULT_DATE

        if 0x65 in extended_records and len(extended_records[0x65]) >= 8:
            raw_created_date = struct.unpack("<Q", extended_records[0x65])[0] / 10000000
            project_creation_date = (
                datetime(1601, 1, 1) + timedelta(seconds=raw_created_date)
            ).strftime("%a %b %d %H:%M:%S %Y")
        else:
            project_creation_date = _DEFAULT_DATE

        # MajorRev and MinorRev: derived later from the root controller module (see below)

        # MajorFaultProgram from ext[0x068] OID → comp_name lookup
        major_fault_program: Union[str, None] = None
        if 0x068 in extended_records and len(extended_records[0x068]) >= 4:
            mfp_oid = struct.unpack_from("<I", extended_records[0x068])[0]
            if mfp_oid and mfp_oid != 0xFFFFFFFF:
                self._cur.execute("SELECT comp_name FROM comps WHERE object_id=" + str(mfp_oid))
                mfp_row = self._cur.fetchone()
                major_fault_program = mfp_row[0] if mfp_row else None

        # RedundancyEnabled: controller extended record 0x001, byte offset 0x0E.
        # This byte is 0x01 for redundant controllers (e.g. 1756-L85E in redundancy mode)
        # and 0x00 for non-redundant controllers.
        _ctrl_ext001 = extended_records.get(0x001, b"")
        redundancy_enabled: bool = bool(_ctrl_ext001[0x0E]) if len(_ctrl_ext001) > 0x0E else False

        self._object_id = results[0][1]
        controller_name = results[0][0]

        # Get the data types
        self._cur.execute(
            "SELECT comp_name, object_id, parent_id, record_type FROM comps WHERE parent_id="
            + str(self._object_id)
            + " AND comp_name='RxDataTypeCollection'"
        )
        results = self._cur.fetchall()
        if len(results) > 1:
            raise Exception("Contains more than one controller data type collection")

        _data_type_id = results[0][1]
        self._cur.execute(
            "SELECT comp_name, object_id, parent_id, record_type FROM comps WHERE parent_id="
            + str(_data_type_id)
        )
        results = self._cur.fetchall()

        # Names of add-on-instruction definitions: these own datatype records too,
        # but the OEM L5X emits them only as AddOnInstructionDefinitions, never as
        # DataTypes. Everything else (User + ProductDefined + IO) IS emitted as a
        # DataType, matching the OEM emit-set exactly.
        aoi_names: set = set()
        self._cur.execute(
            "SELECT object_id FROM comps WHERE parent_id="
            + str(self._object_id)
            + " AND comp_name='RxUDIDefinitionCollection'"
        )
        _aoi_coll_row = self._cur.fetchone()
        if _aoi_coll_row is not None:
            self._cur.execute(
                "SELECT comp_name FROM comps WHERE parent_id="
                + str(_aoi_coll_row[0])
                + " AND record_type=256"
            )
            aoi_names = {row[0] for row in self._cur.fetchall()}

        data_types: List[DataType] = []
        # all_data_types_map includes ProductDefined types (excluded from L5X output but
        # needed for generating Decorated XML for tags that reference those types).
        all_data_types_map: Dict[str, DataType] = {}
        for result in results:
            _data_type_object_id = result[1]
            dt = DataTypeBuilder(
                self._cur, _data_type_object_id, _short_header=self._short_header
            ).build()
            all_data_types_map[dt.name.upper()] = dt
            if self._short_header:
                # V10..V21 OEM L5X emits the full lean set (User + ProductDefined
                # + IO); _l5x_exclude is disabled via _emit_predefined so the
                # serializer keeps all of them. (The long path keeps User-only.)
                # AOI definitions own a backing datatype comp too, but the
                # reference emits them only as AddOnInstructionDefinitions, never
                # as a <DataType> -- so skip AOI-named comps here as the long path
                # already does at the elif below.
                if dt.name not in aoi_names:
                    data_types.append(dt)
            elif dt.name not in aoi_names:
                # V24+/V36: emit every datatype that is not an AOI definition
                # (User + ProductDefined + IO), matching the OEM emit-set.
                # _emit_predefined disables _l5x_exclude so ProductDefined and
                # ':'-named IO types are kept.
                dt._emit_predefined = True
                data_types.append(dt)

        # data_types_map: case-insensitive name → DataType for all types (User + ProductDefined).
        # Used by Tag.to_xml() when generating Decorated XML.
        data_types_map: Dict[str, DataType] = all_data_types_map

        # Get the Controller Scoped Tags
        self._cur.execute(
            "SELECT comp_name, object_id, parent_id, record_type FROM comps WHERE parent_id="
            + str(self._object_id)
            + " AND comp_name='RxTagCollection'"
        )
        results = self._cur.fetchall()
        if len(results) > 1:
            raise Exception("Contains more than one controller tag collection")
        _tag_collection_object_id = results[0][1]
        self._cur.execute(
            "SELECT comp_name, object_id, parent_id, record_type FROM comps WHERE parent_id="
            + str(_tag_collection_object_id)
        )
        results = self._cur.fetchall()
        tags: List[Tag] = []
        for result in results:
            _tag_object_id = result[1]
            tag = TagBuilder(self._cur, _tag_object_id, _short_header=self._short_header,
                             _acd_major=self._acd_major).build()
            tag._data_types_map = data_types_map
            tag._taginfo_layout = self._taginfo_layout
            # Module I/O tags carry a ':' (Local:1:C) and are kept; the ':' filter
            # only drops other internal ':'-named records. Per-point I/O ALIAS
            # tags (<Module>:1:I) carry no DataType (the value lives on the
            # target) but a non-empty alias_for, so keep them via the IO/alias
            # path even though tag.data_type is empty.
            keep_typed = bool(tag.data_type)
            # Alias tags carry no DataType (the value lives on the target) but a
            # non-empty alias_for; keep them via the alias path. This covers both
            # per-point I/O aliases (tag._io, e.g. <Module>:1:I) and ordinary user
            # aliases into an I/O point (e.g. <UserTag> -> Local:1:I.Data.0), which
            # the long-path alias resolver builds.
            keep_alias = bool(tag.alias_for)
            if (keep_typed or keep_alias) and not tag.name.startswith("$") and (tag._io or ":" not in tag.name) and not tag.name.startswith("__"):
                tags.append(tag)

        # Get the Program Collection and get the programs
        self._cur.execute(
            "SELECT comp_name, object_id, parent_id, record_type FROM comps WHERE parent_id="
            + str(self._object_id)
            + " AND comp_name='RxProgramCollection'"
        )
        results = self._cur.fetchall()
        if len(results) > 1:
            raise Exception("Contains more than one controller program collection")

        _program_collection_object_id = results[0][1]
        self._cur.execute(
            "SELECT comp_name, object_id, parent_id, record_type FROM comps WHERE parent_id="
            + str(_program_collection_object_id)
        )
        results = self._cur.fetchall()
        programs: List[Program] = []
        for result in results:
            _program_object_id = result[1]
            programs.append(
                ProgramBuilder(self._cur, _program_object_id, data_types_map, redundancy_enabled, _short_header=self._short_header, _taginfo_layout=self._taginfo_layout, _acd_major=self._acd_major).build()
            )

        # Build comment_id → program name map for task scheduled-program resolution.
        # comment_id is a u16 at BLOB offset 0x0C in each program's RxGeneric record.
        self._cur.execute(
            "SELECT comp_name, record FROM comps WHERE parent_id=" + str(_program_collection_object_id)
        )
        comment_id_to_program: Dict[int, str] = {
            struct.unpack_from("<H", rec, 0x0C)[0]: pname
            for pname, rec in self._cur.fetchall()
        }

        # Get the Task Collection and build Tasks
        self._cur.execute(
            "SELECT comp_name, object_id FROM comps WHERE parent_id="
            + str(self._object_id)
            + " AND comp_name='RxTaskCollection'"
        )
        task_coll_results = self._cur.fetchall()
        tasks: List[Task] = []
        if task_coll_results:
            _task_collection_object_id = task_coll_results[0][1]
            self._cur.execute(
                "SELECT comp_name, object_id FROM comps WHERE parent_id="
                + str(_task_collection_object_id)
                + " AND record_type=256"
            )
            for task_result in self._cur.fetchall():
                tasks.append(TaskBuilder(self._cur, task_result[1]).build(comment_id_to_program))

        # Get the AOI Collection and get the AOIs
        self._cur.execute(
            "SELECT comp_name, object_id, parent_id, record_type FROM comps WHERE parent_id="
            + str(self._object_id)
            + " AND comp_name='RxUDIDefinitionCollection'"
        )
        results = self._cur.fetchall()
        if len(results) > 1:
            raise Exception("Contains more than one AOI collection")
        _aoi_collection_object_id = results[0][1]
        self._cur.execute(
            "SELECT comp_name, object_id, parent_id, record_type FROM comps WHERE parent_id="
            + str(_aoi_collection_object_id)
            + " AND record_type=256"
        )
        results = self._cur.fetchall()
        aois: List[AOI] = []
        for result in results:
            _aoi_object_id = result[1]
            aois.append(AoiBuilder(
                self._cur, _aoi_object_id,
                _data_types_map=data_types_map,
                _short_header=self._short_header,
                _taginfo_layout=self._taginfo_layout,
            ).build())

        # Get the Module (IO) Collection and build all Module elements.
        self._cur.execute(
            "SELECT object_id FROM comps WHERE parent_id="
            + str(self._object_id)
            + " AND comp_name='RxMapDeviceCollection'"
        )
        row = self._cur.fetchone()
        if row is None:
            modules: List[Module] = []
        else:
            coll_oid = row[0]
            self._cur.execute(
                "SELECT comp_name, object_id, record FROM comps WHERE parent_id="
                + str(coll_oid)
                + " ORDER BY seq_number"
            )
            mod_rows = self._cur.fetchall()

            # First pass: build modid→name map so child modules can resolve their parent name.
            from acd.generated.comps.rx_generic import RxGeneric as _RxG
            modid_to_name: Dict[int, str] = {}
            for db_name, mod_oid, mod_rec in mod_rows:
                display_name = "?" if (db_name.startswith("$") and db_name.endswith("$")) else db_name
                try:
                    r = _RxG.from_bytes(bytes(mod_rec))
                    if r.cip_type == 0x69:
                        exts = {er.attribute_id: bytes(er.value) for er in r.extended_records}
                        e1 = exts.get(0x001, b"")
                        if len(e1) >= 0x30:
                            modid = struct.unpack("<I", e1[0x2C:0x30])[0]
                            modid_to_name[modid] = display_name
                except Exception:
                    pass

            # Second pass: build Module objects.
            modules = []
            for _, mod_oid, _ in mod_rows:
                modules.append(
                    ModuleBuilder(self._cur, mod_oid, modid_to_name).build()
                )

            # Third pass: compute (parent_name, parent_port_id) → child count,
            # then inject the relevant sub-dict into each Module as _port_child_counts.
            child_counts: Dict[tuple, int] = {}
            for m in modules:
                k = (m.parent_module, m.parent_mod_port_id)
                child_counts[k] = child_counts.get(k, 0) + 1
            for m in modules:
                m._port_child_counts = {
                    port_id: child_counts.get((m.name, port_id), 0)
                    for port_id in range(1, 20)
                    if (m.name, port_id) in child_counts
                }

        # ProcessorType is the CatalogNumber of the root controller module (the one
        # whose parent resolves to itself). (MajorFault is no longer root-only, so
        # the root is identified by parent_module==name instead.)
        processor_type = next(
            (m.catalog_number for m in modules if m.parent_module == m.name and m.catalog_number),
            None,
        )

        # MajorRev and MinorRev come from the firmware version of the Local (backplane
        # controller) module, stored in its ext[0x01] bytes [0x08] and [0x09].
        local_module = next(
            (m for m in modules if m.name == "Local"),
            next((m for m in modules if m.parent_module == m.name), None),
        )
        if local_module is not None:
            major_rev = str(local_module.major)
            minor_rev = str(local_module.minor)
        else:
            major_rev = "0"
            minor_rev = "0"

        # CommPath: combine the stored path prefix (ends with "\") with the controller
        # module's backplane slot number (e.g. "EthernetModule\192.168.1.10\Backplane\4").
        comm_path: Union[str, None] = None
        if _comm_path_prefix is not None:
            _ctrl_slot = next(
                (m._slot for m in modules if m._is_root), None
            )
            if _ctrl_slot is not None:
                comm_path = _comm_path_prefix + str(_ctrl_slot)

        # Controller project settings that Studio only writes for certain
        # controller generations / save versions. Emitting them unconditionally
        # fabricates attributes the reference omits on older saves and on
        # controllers that never carried the feature.
        #  - AutoDiags/WebServer are written ONLY for the 5x80 generation
        #    (5069-/5094- CompactLogix 5380/5480, 1756-L8x ControlLogix 5580);
        #    every 1756-L6/L7 and 1769/1768 controller omits them regardless of
        #    firmware.
        #  - PassThrough/DownloadDocs and DownloadCustomProperties/
        #    ReportMinorOverflow are written from save-version 24 onward. The
        #    5x80 clause also covers projects whose header mis-reports an older
        #    save version than the controller they target.
        is_5x80 = bool(processor_type) and processor_type.startswith(
            ("5069-", "5094-", "1756-L8")
        )
        _v24_plus = is_5x80 or self._acd_major >= 24
        pass_through = "EnabledWithAppend" if _v24_plus else None
        download_docs = "true" if _v24_plus else None
        download_custom = "true" if _v24_plus else None
        report_minor_overflow = "false" if _v24_plus else None
        # AutoDiags/WebServer hinge on the 5x80 generation, which we read from
        # the catalog number. When the root catalog can't be resolved
        # (processor_type is None) we can't tell the generation, so fall back to
        # the save version: these features never appear below v32, so a modern
        # save with an unknown catalog is treated as 5x80 rather than dropping a
        # value the reference keeps.
        _modern_unknown_cpu = processor_type is None and self._acd_major >= 32
        auto_diags = "false" if (is_5x80 or _modern_unknown_cpu) else None
        web_server = "false" if (is_5x80 or _modern_unknown_cpu) else None

        return Controller(
            controller_name,
            "Target",
            controller_name,
            processor_type,
            major_rev,
            minor_rev,
            major_fault_program,
            project_creation_date,
            last_modified_date,
            sfc_execution_control,
            sfc_restart_position,
            sfc_last_scan,
            comm_path,
            project_sn,
            "false",        # MatchProjectToController
            "false",        # CanUseRPIFromProducer
            "0",            # InhibitAutomaticFirmwareUpdate
            pass_through,   # PassThroughConfiguration
            download_docs,  # DownloadProjectDocumentationAndExtendedProperties
            download_custom,  # DownloadProjectCustomProperties
            report_minor_overflow,  # ReportMinorOverflow
            auto_diags,     # AutoDiagsEnabled
            web_server,     # WebServerEnabled
            data_types,
            modules,
            tags,
            programs,
            tasks,
            aois,
            redundancy_enabled,
            # <DataLogs> ships with the DataLog feature in v24; gate it on the
            # same v24+/5x80 signal as the project-download settings above.
            _emit_data_logs=_v24_plus,
        )


@dataclass
class ProjectBuilder:
    quick_info_filename: PathLike

    def build(self) -> RSLogix5000Content:
        element = ET.parse(self.quick_info_filename)
        rslogix_content_element = element.find(".")
        if rslogix_content_element is not None:
            target_name = rslogix_content_element.attrib["Name"]

        schema_version_element = element.find("SchemaVersion")
        if schema_version_element is not None:
            schema_version_major = schema_version_element.attrib["Major"]
            schema_version_minor = schema_version_element.attrib["Minor"]
            schema_revision = f"{schema_version_major}.{schema_version_minor}"
        else:
            schema_revision = "1.0"

        # SWVersion reflects the Studio 5000 application version (e.g. "RSLogix 5000 v35.04"),
        # which is what RSLogix5000Content SoftwareRevision represents.  DeviceIdentity
        # MajorRevision/MinorRevision is the controller firmware version — a different value.
        sw_version_element = element.find("SWVersion")
        if sw_version_element is not None:
            sw_version_string = sw_version_element.attrib.get("String", "")
            # Extract the version number from the trailing "vXX.YY" portion.
            match = re.search(r"v(\d+\.\d+)$", sw_version_string.strip())
            if match:
                software_revision = match.group(1)
            else:
                # Unexpected format — fall back to DeviceIdentity firmware version.
                device_identity = element.find("DeviceIdentity")
                if device_identity is not None:
                    software_revision = (
                        f"{device_identity.attrib['MajorRevision']}"
                        f".{device_identity.attrib['MinorRevision']}"
                    )
                else:
                    software_revision = "33.01"
        else:
            # No SWVersion element — fall back to DeviceIdentity firmware version.
            device_identity = element.find("DeviceIdentity")
            if device_identity is not None:
                software_revision = (
                    f"{device_identity.attrib['MajorRevision']}"
                    f".{device_identity.attrib['MinorRevision']}"
                )
            else:
                software_revision = "33.01"

        target_type = "Controller"
        contains_context = "false"
        now = datetime.now()
        export_date = now.strftime("%a %b %d %H:%M:%S %Y")
        export_options = (
            "NoRawData L5KData DecoratedData ForceProtectedEncoding AllProjDocTrans"
        )
        return RSLogix5000Content(
            target_name,
            None,
            schema_revision,
            software_revision,
            target_name,
            target_type,
            contains_context,
            export_date,
            export_options,
        )


@dataclass
class DumpCompsRecords(L5xElementBuilder):
    base_directory: PathLike = Path("dump")

    def dump(self, parent_id: int = 0, log_file=None):
        self._cur.execute(
            f"SELECT comp_name, object_id, parent_id, record_type, record FROM comps WHERE parent_id={parent_id}"
        )
        results = self._cur.fetchall()

        for result in results:
            object_id = result[1]
            name = result[0]
            record = result[4]
            new_path = Path(os.path.join(self.base_directory, name))
            if os.path.exists(os.path.join(new_path)):
                shutil.rmtree(os.path.join(new_path))
            if not os.path.exists(os.path.join(new_path)):
                os.makedirs(new_path)
            with open(Path(os.path.join(new_path, name + ".dat")), "wb") as file:
                log_file.write(
                    f"Class - {struct.unpack_from('<H', result[4], 0xA)[0]} Instance {struct.unpack_from('<H', result[4], 0xC)[0]}- {str(new_path) + '/' + name}\n"
                )
                file.write(record)

            DumpCompsRecords(self._cur, object_id, new_path).dump(object_id, log_file)
