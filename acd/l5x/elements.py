import base64
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
from typing import List, Tuple, Dict, Union

from acd.generated.comps.module_identity import ModuleIdentity
from acd.generated.comps.rx_generic import RxGeneric
from acd.l5x.alarms import (
    _alarm_definitions_xml,
    _build_alarm_conditions,
    _render_alarm_digital_data,
)
from acd.l5x.alias import TagAliasResolver
from acd.l5x.base import (
    L5xElement,
    L5xElementBuilder,
    _LANG_DESC_OIDS,
    _parse_rec_and_exts,
    _parse_rec_tolerant,
    _rxgeneric_plaintext_main,
    _xml_sane,
    connection_signature_row,
    custom_properties_by_parent,
    custom_properties_by_scope_owner,
    external_access_enum,
    own_data_exchange_id,
    own_description,
    project_lang_oid,
    scope_owner_data_exchange_id,
    radix_enum,
    render_custom_properties,
    resolve_aoi_alias_target,
    resolve_hex_operand,
    safety_signature_row,
    short_own_description,
)
from acd.l5x.encoded_data import (
    _WRAPPED_KEY_VERSION,
    encoded_routine,
    keyhash_slot_readable,
    source_key_unwraps,
    source_protection_config,
)
from acd.l5x.connections import (
    _DESC_BLOCK_RE,
    _build_config_holders,
    _build_connection_map,
    _build_consume_map,
    _build_produce_map,
    _strip_input_tag_inner,
)
from acd.l5x.controller_ports import (
    build_comm_ports,
    build_ethernet_network,
    build_ethernet_ports,
    build_internet_protocol,
)
from acd.l5x.datatypes import (
    DataType,
    DataTypeBuilder,
    Member,
    MemberBuilder,
    _ATOMIC_TYPES,
    _BACKING_SIZE,
    _decode_utf16z,
)
from acd.l5x.messages import _msg_build_module_routes, _render_message_data
from acd.l5x.module_builder import (
    Module,
    ModuleBuilder,
    _build_rxdata_holders,
    _module_identity_e1,
)
from acd.l5x import tag_value as _tag_value
from acd.l5x.axis_cip import render_axis_cip_drive as _render_axis_cip_drive
from acd.l5x.axis_cip import render_motion_group as _render_motion_group
from acd.l5x.trends import build_trends
from acd.record.blobs import ControllerProps
from acd.record.comps import CompsRecord, _SP_MARKER, decrypt_sp_nameless


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

# Data types on which Logix NEVER writes a Constant attribute (a tag of these
# types cannot be a constant): motion axes/groups/coordinate systems, MESSAGE,
# and digital alarms. Verified: 0 OEM tags of these types carry Constant
# (COORDINATE_SYSTEM 0/13 pool-wide, all revs). (Consumed tags also omit
# Constant; handled separately via tag_type.)
_NO_CONSTANT_TYPES: frozenset = frozenset({
    "MESSAGE", "AXIS_CIP_DRIVE", "AXIS_SERVO_DRIVE", "AXIS_SERVO",
    "AXIS_VIRTUAL", "AXIS_GENERIC", "AXIS_CONSUMED", "MOTION_GROUP",
    "COORDINATE_SYSTEM", "ALARM_DIGITAL", "ALARM_ANALOG",
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
    "ALARM_DIGITAL", "MESSAGE",
    "AXIS_SERVO", "AXIS_SERVO_DRIVE", "AXIS_CIP_DRIVE", "AXIS_VIRTUAL",
    "AXIS_GENERIC", "AXIS_CONSUMED", "MOTION_GROUP",
}
# PID_ENHANCED is NOT skipped: OEM renders it like any predefined struct, a value
# block (L5K / raw-hex) plus a Decorated <Structure> of its members.

# Value-image size at/above which Studio's raw-hex-first export omits the
# Decorated <Data> block (emitting only the flat first block). This is a single
# global Logix export threshold -- NOT keyed by catalog/type -- validated at 0
# violations across ~27,000 pool tags (< threshold keeps Decorated, >= omits).
# Overridable via the ACD_DECORATED_MAX_BYTES env var so a future corpus that
# shifts the ceiling can be accommodated without a code change.
try:
    _DECORATED_MAX_BYTES = int(os.environ.get("ACD_DECORATED_MAX_BYTES", "16384"))
except ValueError:
    _DECORATED_MAX_BYTES = 16384

# A valid L5X tag-comment Operand is a member/bit/index path relative to the tag:
# it starts with '.' or '[' and contains only identifier/index characters (the
# comma separates a multi-dimension array index, e.g. "[4,1]"). Module
# connection-point comments instead carry a raw binary key that decodes to junk
# (e.g. CJK from a UTF-16 misread); those must not leak in as tag operand comments.
_OPERAND_RE = re.compile(r"^[.\[][A-Za-z0-9_.,\[\]]*$")


def _is_valid_operand(op: str) -> bool:
    return bool(op) and ".!" not in op and bool(_OPERAND_RE.match(op))


# ---- AXIS_VIRTUAL <Data Format="Axis"> renderer ------------------------- #
# The value image is attr 0x01 of the tag's cip-0x6a backing (body_mode). It is
# the axis CONFIG serialization, which is a flat fixed-offset struct -- and,
# unlike a UDT, it is NOT member-tagged in the datatype schema (TagInfo carries
# only the 384-byte RUNTIME AXIS_VIRTUAL struct: AxisFault/ModuleFault/...; the
# config parameter layout below is not recoverable from any parseable ACD
# record). So these offsets are the firmware motion-schema binary layout,
# reverse-engineered and validated the same way the module-identity/ForceData
# offsets elsewhere in this file are.
#
# WHAT GENERALISES: the whole header (offsets 158..1182) is IDENTICAL across
# every firmware generation -- every value is decoded from the record at these
# offsets (nothing keyed by catalog/type; even pool-constant fields like
# AverageVelocityTimebase are read, not hardcoded). The int->label tables are
# reference-invariant Logix motion-schema constants (same class as radix_enum).
# Only ONE field shifts by generation: the record grows in the middle, moving
# the tail InterpolatedPositionConfiguration (+ whether AxisUpdateSchedule is
# appended). That shift is keyed on the blob LENGTH -- an intrinsic property of
# the bytes, so it cannot disagree with the layout it selects (a MajorRev key
# could, since the two probe passes disagreed on whether firmware rev or the
# container version drives it). An unrecognised length returns None -> no
# <Data> (element_missing, today's behaviour), never a wrong render.
# Validated byte-exact vs OEM on every AXIS_VIRTUAL tag whose blob length is in
# the tail table, across two independent test pools and firmware 20/30/33/35/36/37
# (the 3654/5965 entries add the newer generations; the header offsets are
# unchanged -- only the length-keyed tail shifts). The short <=1216-byte variant
# is a different, smaller struct that does not fit the header, so it stays out of
# the table -> no <Data>, never a wrong render.
_AXIS_ENUM: Dict[str, Dict[int, str]] = {
    "RotaryAxis": {0: "Linear", 1: "Rotary"},
    "HomeMode": {0: "Passive", 1: "Active", 2: "Absolute"},
    "HomeDirection": {0: "Uni-directional Forward", 1: "Bi-directional Forward",
                      2: "Uni-directional Reverse", 3: "Bi-directional Reverse"},
    "HomeSequence": {0: "Immediate", 1: "Switch", 2: "Marker"},
    "ProgrammedStopMode": {0: "Fast Stop", 1: "Fast Disable"},
    "AxisUpdateSchedule": {0: "Base"},
}
# Fixed header attrs (name, offset, kind[, enum]); kind: f real, d u32-dec,
# h u32-hex (16#XXXX_XXXX), s u16-len-prefixed UTF-8, e u8 enum.
_AXIS_VIRTUAL_HEADER = [
    ("ConversionConstant", 196, "f"),
    ("OutputCamExecutionTargets", 1055, "d"),
    ("PositionUnits", 158, "s"),
    ("AverageVelocityTimebase", 192, "f"),
    ("RotaryAxis", 200, "e", "RotaryAxis"),
    ("PositionUnwind", 201, "d"),
    ("HomeMode", 205, "e", "HomeMode"),
    ("HomeDirection", 206, "e", "HomeDirection"),
    ("HomeSequence", 207, "e", "HomeSequence"),
    ("HomeConfigurationBits", 208, "h"),
    ("HomePosition", 212, "f"),
    ("HomeOffset", 216, "f"),
    ("MaximumSpeed", 228, "f"),
    ("MaximumAcceleration", 232, "f"),
    ("MaximumDeceleration", 236, "f"),
    ("ProgrammedStopMode", 240, "e", "ProgrammedStopMode"),
    ("MasterInputConfigurationBits", 1129, "d"),
    ("MasterPositionFilterBandwidth", 1133, "f"),
    ("MaximumAccelerationJerk", 1174, "f"),
    ("MaximumDecelerationJerk", 1178, "f"),
    ("DynamicsConfigurationBits", 1182, "d"),
]
# Blob length -> (InterpolatedPositionConfiguration offset, AxisUpdateSchedule
# present). The blob length is the firmware-generation discriminator, read
# straight from the record, so this needs no external version input; an
# unknown length falls through to today's no-<Data> behaviour (0-worse).
_AXIS_VIRTUAL_TAIL = {
    3430: (3426, False),
    3654: (3426, True),
    3666: (3426, True),
    5476: (3474, True),
    5843: (3506, True),
    5965: (3506, True),
}


def _axis_attr(blob: bytes, off: int, kind: str, enum: str = "") -> str:
    if kind == "f":
        return _tag_value._fmt_real_decorated(struct.unpack_from("<f", blob, off)[0])
    if kind == "d":
        return str(struct.unpack_from("<I", blob, off)[0])
    if kind == "h":
        return _tag_value._format_int_radix(
            "UDINT", struct.unpack_from("<I", blob, off)[0], 4, "Hex")
    if kind == "s":
        ln = struct.unpack_from("<H", blob, off)[0]
        return blob[off + 2:off + 2 + ln].decode("utf-8", errors="replace")
    if kind == "e":
        return _AXIS_ENUM[enum][blob[off]]
    raise ValueError(kind)


def _render_axis_virtual(blob: bytes, group_name: str) -> "Union[str, None]":
    """The full <Data Format="Axis"><AxisParameters .../></Data> for an
    AXIS_VIRTUAL tag, or None when the blob length is an unrecognised firmware
    generation (keep today's no-<Data>, never a wrong render)."""
    tail = _AXIS_VIRTUAL_TAIL.get(len(blob))
    if tail is None:
        return None
    ipc_off, aus = tail
    try:
        parts = [f'MotionGroup="{html.escape(group_name, quote=True)}"']
        for entry in _AXIS_VIRTUAL_HEADER:
            val = _axis_attr(blob, entry[1], entry[2],
                             entry[3] if len(entry) > 3 else "")
            parts.append(f'{entry[0]}="{html.escape(val, quote=True)}"')
        ipc = _tag_value._format_int_radix(
            "UDINT", struct.unpack_from("<I", blob, ipc_off)[0], 4, "Hex")
        parts.append(f'InterpolatedPositionConfiguration="{ipc}"')
        if aus:
            parts.append('AxisUpdateSchedule="'
                         + _AXIS_ENUM["AxisUpdateSchedule"][0] + '"')
    except Exception:
        return None
    # OEM joins attrs with a single space, breaking to a newline+space after
    # every 11th attribute.
    joined = ""
    for i, p in enumerate(parts):
        if i:
            joined += "\n " if i % 11 == 0 else " "
        joined += p
    return f'<Data Format="Axis">\n<AxisParameters {joined}/>\n</Data>'


# TODO(MOTION_GROUP <Data Format="MotionGroup">): the sibling of AXIS_VIRTUAL,
# ~36 pool diffs, HELD by decision (2026-07-12). 3 of the 7
# MotionGroupParameters attrs ARE byte-derivable from the tag's attr-0x01 blob
# (CoarseUpdatePeriod u32; blob-length-keyed: V20 @564, V30 @2212, V32+ @2210;
# Alternate1/2UpdateMultiplier). The other 4 -- GroupType, PhaseShift,
# GeneralFaultType, AutoTagUpdate -- are pool-CONSTANT with NO locatable offset
# (they map to zero bytes indistinguishable from padding), so a full render
# needs them as literal schema constants, and a partial render is net-worse
# (1 element_missing -> 3-4 attr_missing per file). Left unimplemented until the
# pool gains a project that VARIES one of those 4 attrs, exposing its offset --
# then this becomes a clean, fully-derived -36 mirroring _render_axis_virtual.
# Full offset map: scratchpad p8probes/a7c3_axis_servo_virtual + renderprobes.
#
# TODO(AXIS_CIP_DRIVE / AXIS_SERVO_DRIVE <Data Format="Axis">): same struct
# family as AXIS_VIRTUAL (shared, length-keyed blob) but with the full drive
# config. A differential analysis over two pools decodes ~231/366 fields
# byte-exact (float text included) and cracks the four non-scalar decoders, yet
# ~133 fields per length are pool-INVARIANT (no differential handle to locate an
# offset). Emitting those would be a hardcoded default with regression risk, and
# the block is all-or-nothing, so it is HELD. Unblocks when more-varied ACDs make
# those fields vary (or the CIP Motion attribute table is available). Full
# status + reproduction: docs/motion-axis-data-status.md.


def _zero_member_node(mdt: str, mdim: int,
                      data_types_map: Dict[str, "DataType"], depth: int):
    """Zero-valued tag_value node for one member (scalar or 1-D array).

    Node tuples must match the arity tag_value's walker builds, since the same
    emitters consume both. The trailing force field is always None/[None]: a
    zero default is generated in the absence of any value image, so it can
    carry no installed force and never renders an @ForceValue.
    """
    if mdim > 0:
        if mdt in ("BOOL", "BIT"):
            return ("aarr", "BOOL", [mdim], [0] * mdim, None, [None] * mdim)
        if mdt in _PRIMITIVE_RADIX:
            zero = 0.0 if mdt in ("REAL", "LREAL") else 0
            return ("aarr", mdt, [mdim], [zero] * mdim, None, [None] * mdim)
        sub = _zero_value_node(mdt, data_types_map, depth + 1)
        if sub is None:
            return None
        return ("sarr", mdt, [mdim], lambda i, _s=sub: _s, mdim, True)
    if mdt in ("BOOL", "BIT"):
        # explicit_bit=True suppresses the Radix attribute: a zero-default
        # BOOL member never carries one (unlike the value-image walker's
        # byte-aligned BOOLs).
        return ("bool", 0, True, None)
    if mdt in _PRIMITIVE_RADIX:
        val = 0.0 if mdt in ("REAL", "LREAL") else 0
        return ("atomic", mdt, val, _PRIMITIVE_BYTE_WIDTH.get(mdt, 4), None,
                None)
    return _zero_value_node(mdt, data_types_map, depth + 1)


def _zero_value_node(dt_name: str, data_types_map: Dict[str, "DataType"],
                     depth: int = 0):
    """Build a zero-valued tag_value node tree for a datatype with NO image.

    Used by _generate_decorated (the zero-placeholder <Data> fallback): the
    XML spelling comes from tag_value's shared Decorated emitter, so only the
    zero-tree POLICIES live here, encoded in the nodes:
      * members of unknown / skipped types are OMITTED (partial emission,
        never a whole-render failure);
      * BOOL members never carry a Radix attribute;
      * the empty-STRING default keeps its literal two-member form (Logix
        writes no CDATA block there), as a ("literal", ...) leaf.
    Returns a node, or None for an unknown/skipped type (or a depth cap the
    old recursion did not have -- a cyclic data_types_map now degrades
    instead of overflowing the stack).
    """
    if dt_name in _SKIP_DECORATED or depth > 24:
        return None

    # STRING as a special built-in: LEN (DINT) + DATA (STRING/ASCII)
    if dt_name == "STRING":
        return ("literal", (
            '<DataValueMember Name="LEN" DataType="DINT" Radix="Decimal" Value="0"/>'
            '<DataValueMember Name="DATA" DataType="STRING" Radix="ASCII">\n\n</DataValueMember>'
        ))

    builtin_members = _BUILTIN_STRUCT_MEMBERS.get(dt_name)
    if builtin_members is not None:
        raw_members = [(mname, mdt, 0) for mname, mdt in builtin_members]
    else:
        dt_obj = data_types_map.get(dt_name)
        if dt_obj is None:
            return None
        raw_members = [(m.name, m.data_type.upper(), m.dimension)
                       for m in dt_obj.members if not m.hidden]

    members = []
    for mname, mdt, mdim in raw_members:
        node = _zero_member_node(mdt, mdim, data_types_map, depth)
        if node is None:
            continue  # unknown member type -> omitted (partial emission)
        if mdt in ("BOOL", "BIT"):
            mdt = "BOOL"
        members.append((mname, mdt, False, False, node))
    return ("struct", dt_name, members)


def _generate_decorated(dt_base: str, dimensions: Union[str, None],
                        data_types_map: Dict[str, "DataType"]) -> str:
    """Generate a complete <Data Format="Decorated"> XML string for a tag.

    dt_base:    the base DataType name (uppercase, array brackets already stripped)
    dimensions: comma-separated dimension string (e.g. "100" or "4,8") or None for scalar
    Returns "" if this type should not have a Decorated element.

    Zero-value fallback (no design-value image): struct member trees are
    built as zero-valued tag_value nodes (_zero_value_node) and spelled by
    the shared Decorated emitter; only the tag-level <Array>/<Structure>
    wrapper is assembled here, mirroring render_decorated_layout's top level.
    """
    if dt_base in _SKIP_DECORATED:
        return ""

    def _struct_inner() -> Union[str, None]:
        node = _zero_value_node(dt_base, data_types_map)
        if node is None:
            return None
        return _tag_value._emit_decorated_inner(node)

    if dimensions is None:
        # Scalar struct
        inner = _struct_inner()
        if inner is None:
            return ""
        body = f'<Structure DataType="{dt_base}">{inner}</Structure>'
    else:
        # Array tag: parse dimensions (up to 3D). The tag-level Dimensions
        # attribute is space-separated (Logix convention) while AOI param/
        # local dims may still arrive comma-separated, so accept either
        # separator. Multi-dim element indices are row-major [i,j] via
        # _index_str (verified against OEM V17/V34 arrays).
        dim_parts = [int(d) for d in re.split(r"[,\s]+", dimensions.strip())
                     if d.strip().isdigit()]
        if not dim_parts:
            return ""
        total = 1
        for d in dim_parts:
            total *= d
        dim_str = ",".join(str(d) for d in dim_parts)

        radix = _PRIMITIVE_RADIX.get(dt_base)
        zero = _PRIMITIVE_DECORATED_ZERO.get(dt_base)

        if dt_base in ("BOOL", "BIT"):
            # BOOL array: flat indexed elements with Radix="Decimal"
            elems = "".join(
                f'<Element Index="{_tag_value._index_str(i, dim_parts)}" Value="0"/>'
                for i in range(total))
            body = f'<Array DataType="BOOL" Dimensions="{dim_str}" Radix="Decimal">{elems}</Array>'
        elif radix is not None and zero is not None:
            # Primitive array (DINT, REAL, etc.)
            elems = "".join(
                f'<Element Index="{_tag_value._index_str(i, dim_parts)}" Value="{zero}"/>'
                for i in range(total))
            body = f'<Array DataType="{dt_base}" Dimensions="{dim_str}" Radix="{radix}">{elems}</Array>'
        else:
            # Struct array (UDT, TIMER, COUNTER, STRING, ...)
            inner = _struct_inner()
            if inner is None:
                return ""
            struct_xml = f'<Structure DataType="{dt_base}">{inner}</Structure>'
            elems = "".join(
                f'<Element Index="{_tag_value._index_str(i, dim_parts)}">{struct_xml}</Element>'
                for i in range(total))
            body = f'<Array DataType="{dt_base}" Dimensions="{dim_str}">{elems}</Array>'

    return f'<Data Format="Decorated">\n{body}\n</Data>'


def _render_value_blocks(element: str,
                         data_type: Union[str, None],
                         dimensions: Union[str, None],
                         value_bytes: bytes,
                         data_types_map: Dict[str, "DataType"],
                         taginfo_layout: Dict[str, object],
                         radix: Union[str, None],
                         raw_hex_first: bool,
                         string_array_as_string: bool,
                         require_pair: bool,
                         force_xml: str = "",
                         fmask: Union[bytes, None] = None,
                         fval: Union[bytes, None] = None) -> str:
    """Render a tag's design-value image as its flat + Decorated block pair.

    Shared by Tag.to_xml (element="Data") and _build_default_data
    (element="DefaultData"): the OEM value spelling is identical for both,
    only the element name and a few policy gates differ:

      raw_hex_first           the first block is the raw space-separated hex
                              image (reference style through V24) instead of
                              Format="L5K".
      string_array_as_string  a STRING ARRAY renders as a single
                              Format="String" block of element [0] instead of
                              the Decorated <Array> tree (scalar STRING always
                              renders as a String block).
      require_pair            emit nothing unless BOTH the first block and the
                              Decorated body rendered (Tag policy); when False
                              each half is emitted independently (DefaultData
                              policy).
      force_xml               optional <ForceData> block inserted between the
                              first block and the Decorated tree (never
                              emitted for STRING, matching Logix).
      fmask / fval            the installed-force mask and value images (each
                              the same length as value_bytes), which give the
                              Decorated members their @ForceValue. Both None
                              -> no @ForceValue anywhere.

    Returns "" when nothing rendered. Exceptions propagate to the caller's
    degrade-to-"" wrapper, except where a narrower internal fallback preserves
    partial output (layout decode, LEN parse).
    """
    dt_base = data_type.split("[")[0].upper() if data_type else ""
    # The rendered <Structure DataType=...> attribute keeps the datatype's
    # DECLARED case (OEM writes UDT_MixedCase / AB:Embedded_IQ16F:C:0, not the
    # uppercased form). render_decorated_layout/render_l5k_layout uppercase
    # internally for the layout lookup, so passing the original-case name is
    # safe and keeps the Structure attribute byte-faithful for ALL struct tags
    # (predefined/built-in types are declared all-caps, so they are unchanged).
    dt_decorated = data_type.split("[")[0] if data_type else dt_base

    # A STRING tag emits a Format="String" Length=N block in place of the
    # Decorated <Structure>/<Array> (Logix renders STRING specially). Detect by
    # datatype name OR by the resolved TagInfo layout being the Logix STRING
    # shape (LEN u32 + DATA SINT[]) -- the latter catches custom string types
    # (String50, PF525FaultDesc, ...). The short-header value image
    # decodes the same LEN+DATA shape, so this runs on both header families
    # (verified byte-exact pool-wide).
    is_string = (dt_base == "STRING") and (
        dimensions is None or string_array_as_string)
    # A custom-string ARRAY (String50[16], a custom STRING UDT[]...) is rendered by
    # OEM as a single Format="String" block (element[0]) just like a scalar
    # custom string, so admit the layout-based detection for arrays too when the
    # caller opts in (string_array_as_string, the short-header raw-hex-first era).
    if not is_string and (dimensions is None or string_array_as_string) and taginfo_layout:
        try:
            lay = _tag_value._resolve_layout(dt_base, taginfo_layout,
                                             data_types_map)
            if lay is not None and _tag_value._is_string_layout(lay):
                is_string = True
        except Exception:
            pass

    decorated_inner = None
    string_block = None
    if is_string:
        try:
            length = (int.from_bytes(value_bytes[0:4], "little")
                      if len(value_bytes) >= 4 else 0)
        except Exception:
            length = 0
        if length + 4 > len(value_bytes):
            # Malformed/garbage LEN: the reference clamps to the DATA
            # capacity and emits those bytes verbatim (the garbage bytes are
            # in the stored image), so mirror min(LEN, capacity).
            text = _tag_value._ascii_string_cdata(
                value_bytes[4:] if len(value_bytes) > 4 else b"")
        else:
            text = _tag_value._ascii_string_cdata(value_bytes[4:4 + length])
        string_block = (
            f'<{element} Format="String" Length="{length}">\n'
            f"<![CDATA['{text}']]>\n</{element}>"
        )
    elif taginfo_layout:
        # Layout-driven decode (full member fidelity) first; fall back to the
        # simpler render_decorated on None/any failure.
        try:
            decorated_inner = _tag_value.render_decorated_layout(
                dt_decorated, dimensions, value_bytes,
                taginfo_layout, data_types_map, radix=radix,
                fmask=fmask, fval=fval
            )
        except Exception:
            decorated_inner = None
    if not is_string and decorated_inner is None:
        decorated_inner = _tag_value.render_decorated(
            dt_base, dimensions, value_bytes, data_types_map, radix=radix
        )

    # First block: the flat value image, version-styled:
    #   raw hex : <Data>1D 00 00 00</Data>  (space-separated image)
    #   L5K     : <Data Format="L5K"><![CDATA[29]]></Data>
    if raw_hex_first:
        first = (f"<{element}>" + _tag_value.render_hex(value_bytes)
                 + f"</{element}>")
        ok_first = bool(value_bytes)
    else:
        # Struct/UDT/built-in-struct (and module I/O) types need the
        # layout-driven L5K bracket tree (the datatype's MEMBER tree, with
        # mixed-width members, nested sub-structs and STRING members rendered
        # properly); the flat int32-word render_l5k is wrong for them. Try the
        # layout form first whenever a TagInfo layout exists for this
        # datatype, and fall back to the flat form only when the layout path
        # returns None (unknown shape).
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
        first = (f'<{element} Format="L5K">\n<![CDATA[{l5k_text}]]>\n'
                 f'</{element}>')
        ok_first = l5k_text is not None

    if string_block is not None:
        # STRING: first block (raw hex / L5K) then the String block, OEM order.
        return first + string_block if ok_first else ""

    if require_pair:
        # Studio omits the Decorated block (keeping only the flat first block)
        # for a very large value image in the raw-hex-first export era: a
        # per-export size ceiling, not an ACD field. The threshold is a single
        # global export constant (like the L5K wrap width / version gates), not
        # a per-catalog value; it is validated 0-violation over ~27k pool tags
        # and exposed as _DECORATED_MAX_BYTES so it can be tuned without a code
        # edit (env override) if a later corpus shifts it.
        if (ok_first and raw_hex_first
                and len(value_bytes) >= _DECORATED_MAX_BYTES):
            return first + force_xml
        if ok_first and decorated_inner is not None:
            return (first + force_xml
                    + f'<{element} Format="Decorated">\n{decorated_inner}\n'
                      f'</{element}>')
        return ""
    decorated_block = (
        f'<{element} Format="Decorated">\n{decorated_inner}\n</{element}>'
        if decorated_inner is not None else ""
    )
    return (first if ok_first else "") + decorated_block


def _raw_hex_first(short_header: bool, acd_major: int) -> bool:
    """True when a value's flat first <Data>/<DefaultData> block is the raw-hex
    image, not Format="L5K".

    Studio's reference exporter writes the flat first block as raw hex through
    V24 and as Format="L5K" from V28 -- but the exact choice is a per-export
    ExportOptions setting (some V24/V15 references emit L5K, others raw hex; it
    is NOT inferable from the ACD). The two are equivalent flat serialisations
    of the same value, which the comparator normalises and the Decorated block
    validates regardless; we emit raw hex through V24 (short header V10-V21
    always), matching the dominant reference profile. One policy for <Data>
    (TagBuilder) and <DefaultData> (AoiBuilder): the reference corpus styles
    both identically per file (V24 references carry raw-hex DefaultData with
    zero Format="L5K" occurrences; V28+ the reverse).
    """
    return short_header or (1 <= acd_major <= 24)


def _build_default_data(data_type: Union[str, None],
                        dimensions: Union[str, None],
                        value_bytes: Union[bytes, None],
                        short_header: bool,
                        data_types_map: Dict[str, "DataType"],
                        taginfo_layout: Dict[str, object],
                        radix: Union[str, None] = None,
                        raw_hex_first: Union[bool, None] = None) -> str:
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
        # First-block style: the Tag policy (_raw_hex_first) threaded in by
        # the AoiBuilder; raw_hex_first=None degrades to the short-header-only
        # rule for callers that do not thread it.
        raw_hex = short_header if raw_hex_first is None else raw_hex_first
        if value_bytes is not None:
            # Value image present: render exactly the pair a Tag would emit,
            # spelled <DefaultData>. Policy gates: the shared raw-hex first-
            # block rule, the Tag STRING-array rule (a long-header STRING
            # ARRAY keeps the Decorated <Array> tree, pool-proven on <Data>;
            # the corpus has no long-header STRING-array AOI member, so the
            # gate is shared rather than left divergent), and each half of
            # the pair is emitted independently of the other.
            return _render_value_blocks(
                "DefaultData", data_type, dimensions, value_bytes,
                data_types_map, taginfo_layout, radix,
                raw_hex_first=raw_hex,
                string_array_as_string=short_header,
                require_pair=False,
            )
        else:
            # No value image -> zero default for this data type.
            if dimensions is None and dt_base in _PRIMITIVE_L5K_ZERO:
                # Scalar primitive first block. The first <DefaultData> mirrors a
                # Tag's first <Data> block and is version-styled (_raw_hex_first):
                #   raw hex (through V24): <DefaultData>00 00 00 00</DefaultData>
                #   L5K (V28+):            <DefaultData Format="L5K"><![CDATA[0]]>...
                if raw_hex:
                    width = _PRIMITIVE_BYTE_WIDTH.get(dt_base, 0)
                    if width <= 0:
                        return ""
                    first = "<DefaultData>" + _tag_value.render_hex(b"\x00" * width) + "</DefaultData>"
                else:
                    l5k_zero = _PRIMITIVE_L5K_ZERO[dt_base]
                    first = f'<DefaultData Format="L5K">\n<![CDATA[{l5k_zero}]]>\n</DefaultData>'
                ok_first = True
                # Scalar primitives: build the matching single DataValue. The owner
                # Parameter/LocalTag radix (when set to a non-default) overrides the
                # per-type default, and the zero value is re-formatted to match it
                # (e.g. Hex -> 16#0000), exactly as Logix renders the DefaultData.
                # The spelling comes from _decorated_scalar; the radix POLICY here
                # deliberately differs from the value-image path: an explicit
                # "Decimal" on a non-BOOL does NOT override the type default (a
                # REAL declared Decimal keeps Radix="Float"), verified in 559ee27.
                if dt_base in ("BOOL", "BIT"):
                    eff = (radix if (radix and radix not in ("NullType", "General"))
                           else "Decimal")
                    decorated_inner = _tag_value._decorated_scalar(dt_base, "0", eff)
                else:
                    eff = (radix if (radix and radix not in
                                     (None, "Decimal", "NullType", "General"))
                           else _PRIMITIVE_RADIX.get(dt_base))
                    width = _PRIMITIVE_BYTE_WIDTH.get(dt_base, 0)
                    if eff is None or width <= 0:
                        decorated_inner = None
                    elif eff == "Float":
                        zero = _PRIMITIVE_DECORATED_ZERO.get(dt_base)
                        decorated_inner = (
                            _tag_value._decorated_scalar(dt_base, zero, "Float")
                            if zero is not None else None
                        )
                    else:
                        decorated_inner = _tag_value._decorated_scalar(
                            dt_base,
                            _tag_value._format_int_radix(dt_base, 0, width, eff),
                            eff,
                        )
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
    # e.g. ("[3]", "Some Motor\r\nStart"). Empty by default (long-header
    # path leaves these untouched).
    _operand_comments: List[Tuple[str, str]] = field(default_factory=list)
    # Operand-keyed EngineeringUnit / Max / Min entries from the same comment
    # records, routed by the record kind byte (comments.member_ref). OEM emits
    # them as standalone sibling blocks -- <EngineeringUnits>, <Maxes>, <Mins>,
    # always in that order -- between Description and Data. Empty by default.
    _eng_units: List[Tuple[str, str]] = field(default_factory=list)
    _maxes: List[Tuple[str, str]] = field(default_factory=list)
    _mins: List[Tuple[str, str]] = field(default_factory=list)
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
    # OpcUaAccess value ("None"/"Read/Write"/"Read Only") emitted on every
    # <Tag> when the project's OPC UA server is enabled (V36+; see
    # ExportL5x.project_flags); "" omits the attribute. Per-tag value from the
    # tag parameter blob's last byte (ExternalAccess enum encoding).
    _opc_ua: str = ""
    # Class="Standard"/"Safety" for controller-scope Base tags in a safety
    # project; None omits the attribute. Default None.
    _class_attr: Union[str, None] = None
    # Suppress ALL <Data> emission (value image AND the zero-placeholder fallback).
    # Set for a recognised alias whose AliasFor target we cannot yet build, so it
    # is emitted as Base but carries no <Data> (OEM emits none on an alias).
    _no_data: bool = False
    # ConsumeInfo for a Consumed tag: dict with Producer/RemoteTag/RemoteInstance/
    # RPI/Unicast. When set, tag_type is "Consumed" and a <ConsumeInfo/> child is
    # emitted as the first child (before Comments/Data). None for ordinary tags.
    _consume_info: Union[dict, None] = None
    # ProduceInfo for a Produced tag. Either the FULL form (ProduceCount,
    # ProgrammaticallySendEventTrigger, UnicastPermitted, MinimumRPI, MaximumRPI,
    # DefaultRPI) or the PLC-mapped form (a single PLCMappingFile). When set,
    # tag_type is "Produced" and a <ProduceInfo/> child is emitted as the first
    # child (before Comments/Data). None for ordinary tags.
    _produce_info: Union[dict, None] = None
    # Force image hex for an I/O tag that has installed forces: emitted as a
    # <ForceData> block between the value <Data> blocks (after the binary/L5K image,
    # before the Decorated tree). None for tags with no force holder. Set by
    # ControllerBuilder from the tag's force-holder ext-attr (0x6b).
    _force_data: Union[str, None] = None
    # Pre-rendered <AlarmConditions> block for a tag that owns configured alarm
    # conditions (V33+). Emitted as the FIRST child of <Tag> (before Comments/Data).
    # Empty for tags with no alarms. Set by Controller/ProgramBuilder from the
    # alarm map keyed by this tag's object id (see _build_alarm_conditions).
    _alarm_xml: str = field(default="")
    # Pre-rendered <Data Format="Message"> block for a MESSAGE tag, resolved by
    # ControllerBuilder once the module topology is complete. None -> no <Data>.
    _message_data_xml: Union[str, None] = field(default=None)
    # Pre-rendered <Data Format="Alarm"> block for an ALARM_DIGITAL tag, resolved
    # by ControllerBuilder from the tag's data-table backing. None -> no <Data>.
    _alarm_data_xml: Union[str, None] = field(default=None)
    # Pre-rendered <Data Format="Axis"> block for an AXIS_VIRTUAL tag, resolved by
    # ControllerBuilder once every MOTION_GROUP tag is known. None -> no <Data>.
    _axis_data_xml: Union[str, None] = field(default=None)
    # A rack chassis-image alias (structure target) carries no Radix, unlike the
    # atomic per-point alias which OEM always writes Radix="Binary" on.
    _alias_no_radix: bool = False
    # Pre-rendered <CustomProperties> ACM/library block; emitted as the FIRST
    # child of the tag (before AlarmConditions/Comments/Description/Data). "" for
    # tags with no provider block. Set by TagBuilder from the custom_properties
    # table.
    _custom_properties: str = field(default="")
    # @DataExchangeId GUID string ("{...}") for a tag that carries one; None omits
    # the attribute. Set by TagBuilder from the comments table (object_id 45).
    _data_exchange_id: Union[str, None] = None
    # @Usage ("Public"/"Input"/"Output"/"InOut") for a PROGRAM-scope tag; None
    # omits it. Set by TagBuilder from the tag's ext-attr 0x01 (ext01[0x20E]).
    _usage: Union[str, None] = None

    def _inject_tag_attrs(self, base: str) -> str:
        """Insert OpcUaAccess / Class attributes into the opening <Tag ...> of base.

        Inserted right before the first '>' of the element (attribute order is not
        significant to consumers/the comparator). No-op when neither applies.
        """
        extra = ""
        if self._class_attr:
            extra += f' Class="{self._class_attr}"'
        if self._opc_ua:
            extra += f' OpcUaAccess="{self._opc_ua}"'
        if self._data_exchange_id:
            extra += f' DataExchangeId="{self._data_exchange_id}"'
        if self._usage:
            extra += f' Usage="{self._usage}"'
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

    def _build_operand_block_xml(self, section: str, child: str,
                                 items: List[Tuple[str, str]],
                                 cdata: bool) -> str:
        """One <EngineeringUnits>/<Maxes>/<Mins> block, or "" when empty.

        Mirrors _build_comments_xml (first-occurrence dedup, insertion order).
        EngineeringUnit text is a CDATA block on its own line (the same shape
        as <Comment>); Max/Min values are plain inline element text with no
        CDATA and no newlines -- both shapes OEM-verified pool-wide.
        """
        seen = set()
        parts: List[str] = []
        for operand, text in items:
            if not operand or operand in seen:
                continue
            seen.add(operand)
            op_attr = html.escape(operand, quote=True)
            if cdata:
                body = self._sanitize_xml_text(text) if text else ""
                parts.append(
                    f'<{child} Operand="{op_attr}">\n<![CDATA[{body}]]>\n</{child}>')
            else:
                parts.append(
                    f'<{child} Operand="{op_attr}">{html.escape(text or "")}</{child}>')
        if not parts:
            return ""
        return f"<{section}>" + "".join(parts) + f"</{section}>"

    def _force_images(self) -> Tuple[Union[bytes, None], Union[bytes, None]]:
        """Split ``_force_data`` into its force MASK and force VALUE images.

        The stored blob is three equal thirds of the tag's data image:

            [0:n]    the force SNAPSHOT (the live value Logix last observed; it
                     drifts from the design value on analog/output points, so
                     it is deliberately NOT used here)
            [n:2n]   the force MASK   (1 = this bit is forced)
            [2n:3n]  the force VALUE

        Returns (None, None) unless a third is exactly as long as the design
        value image. That guard is not a tautology: the two _force_data
        producers gate on different things. The second (source-protected
        backing) path validates the blob against the HOLDER's own declared data
        size, because the tag's value there is a relocated sentinel rather than
        the real image -- so it can legitimately yield a blob whose third does
        not match len(_value_bytes). Slicing members out of such a blob with
        offsets taken from the value image would mis-read EVERY member, so this
        renderer refuses it and emits no @ForceValue at all (fail closed).
        """
        if not self._force_data or not self._value_bytes:
            return (None, None)
        try:
            blob = bytes.fromhex(self._force_data.replace(" ", ""))
        except ValueError:
            return (None, None)
        n = len(self._value_bytes)
        if len(blob) != 3 * n:
            return (None, None)
        return (blob[n:2 * n], blob[2 * n:3 * n])

    def to_xml(self) -> str:
        # Operand-comment blocks are needed by BOTH the alias-IO early return
        # below (OEM attaches the per-point <Comments> to the alias tag) and
        # the shared injection at the bottom, so build them up front.
        comments_xml = self._build_comments_xml()
        eu_xml = self._build_operand_block_xml(
            "EngineeringUnits", "EngineeringUnit", self._eng_units, cdata=True)
        maxes_xml = self._build_operand_block_xml(
            "Maxes", "Max", self._maxes, cdata=False)
        mins_xml = self._build_operand_block_xml(
            "Mins", "Min", self._mins, cdata=False)

        if self._io and (self.tag_type == "Alias" or self.alias_for):
            # Per-point module I/O ALIAS tag — OEM emits:
            #   Name TagType="Alias" Radix="Binary" AliasFor=... ExternalAccess IO="true"
            # No DataType, no <Data> (the value lives on the alias target), but
            # the point's own <Description> and operand <Comments> (and
            # EU/Maxes/Mins) DO ride on the alias tag; without them the element
            # is self-closing.
            _adesc_raw = next((t for _r, t in self._comments if t), None)
            _adesc = self._sanitize_xml_text(_adesc_raw) if _adesc_raw else None
            _adesc_xml = (f'<Description>\n<![CDATA[{_adesc}]]>\n</Description>'
                          if _adesc else "")
            inner = _adesc_xml + comments_xml + eu_xml + maxes_xml + mins_xml
            _radix_attr = "" if self._alias_no_radix else ' Radix="Binary"'
            # ExternalAccess is suppressed (None) below schema major 18 (rule A)
            # and on module IO tags below major 20 (rule B); omit the attribute
            # in that case rather than rendering ExternalAccess="None".
            _ea_attr = (f' ExternalAccess="{self.external_access}"'
                        if self.external_access is not None else "")
            head = (
                f'<Tag Name="{html.escape(self.name, quote=True)}"'
                f' TagType="Alias"{_radix_attr}'
                f' AliasFor="{html.escape(self.alias_for, quote=True)}"'
                f'{_ea_attr} IO="true"'
            )
            return self._inject_tag_attrs(
                head + (f'>{inner}</Tag>' if inner else '/>'))
        if self._io:
            # Module I/O tag — emit the exact OEM attribute set and order:
            #   Name TagType DataType ExternalAccess IO="true"
            # (no Radix/Constant/Dimensions, which OEM never writes on IO tags).
            dt_attr = f' DataType="{html.escape(self.data_type, quote=True)}"' if self.data_type else ""
            _ea_attr = (f' ExternalAccess="{self.external_access}"'
                        if self.external_access is not None else "")
            base = self._inject_tag_attrs(
                f'<Tag Name="{html.escape(self.name, quote=True)}"'
                f' TagType="{self.tag_type}"{dt_attr}'
                f'{_ea_attr} IO="true"></Tag>'
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
            # "NullType" is the no-radix sentinel (motion/axis and other non-
            # displayable types); the reference never writes Radix="NullType" on a
            # <Tag> element, so drop it. This also covers alias tags onto such types,
            # whose empty data_type slips past the type-based suppression above.
            if self.radix == "NullType":
                self.radix = None
            base = self._inject_tag_attrs(super().to_xml())

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

        # --- Step 6c: real value <Data> from the design-value image (0x66) ---
        # When the value reader returned an image, emit the OEM <Data> block
        # pair via the shared renderer (flat first block styled raw-hex or L5K
        # per _raw_hex_first_block, then <Data Format="Decorated">; a STRING
        # renders a Format="String" block instead -- see _render_value_blocks).
        # Wrapped so any failure degrades to today's zero-placeholder behaviour
        # below — no regression.
        data_xml = ""
        if not is_alias and self._value_bytes is not None and dt_base not in _SKIP_DECORATED:
            try:
                # <ForceData> for an I/O tag with installed forces sits between
                # the flat value block and the Decorated tree (the order Logix
                # uses).
                force_xml = (f'<ForceData>{self._force_data}</ForceData>'
                             if self._force_data else '')
                _fmask, _fval = self._force_images()
                data_xml = _render_value_blocks(
                    "Data", self.data_type, self.dimensions, self._value_bytes,
                    self._data_types_map, self._taginfo_layout, self.radix,
                    raw_hex_first=self._raw_hex_data,
                    string_array_as_string=self._short_header,
                    require_pair=True,
                    force_xml=force_xml,
                    fmask=_fmask, fval=_fval,
                )
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

        # --- MESSAGE tag <Data Format="Message"> block ---
        # MESSAGE keeps its dedicated <MessageParameters> block (resolved by the
        # controller builder) instead of a Decorated structure; emitted only when
        # the configuration decoded with full confidence.
        if not data_xml and not self._no_data and self._message_data_xml:
            data_xml = self._message_data_xml

        # --- ALARM_DIGITAL tag <Data Format="Alarm"> block ---
        # ALARM_DIGITAL is in _SKIP_DECORATED (it uses a dedicated Alarm format, not
        # a Decorated structure); the block is resolved by the controller builder.
        if not data_xml and not self._no_data and self._alarm_data_xml:
            data_xml = self._alarm_data_xml

        # --- AXIS_VIRTUAL tag <Data Format="Axis"> block ---
        # AXIS_VIRTUAL is in _SKIP_DECORATED; its value image is attr 0x01 (not
        # 0x66), resolved by the controller builder once MotionGroup names are
        # known. None -> keep today's no-<Data> (element_missing, never worse).
        if not data_xml and not self._no_data and self._axis_data_xml:
            data_xml = self._axis_data_xml

        # --- ConsumeInfo child (Consumed tags) ---
        # OEM emits <ConsumeInfo> as the FIRST child of a Consumed tag, before
        # Comments/Data. Attribute order matches OEM (Producer, RemoteTag,
        # RemoteInstance, RPI, Unicast).
        consume_xml = ""
        if self._consume_info:
            ci = self._consume_info
            # A safety consumed tag (fmt-30 connection) additionally carries
            # the CIP-safety timing attributes, emitted between RPI and
            # Unicast (OEM attribute order).
            _saf = ""
            if "TimeoutMultiplier" in ci:
                _saf = (
                    f' TimeoutMultiplier="{ci["TimeoutMultiplier"]}"'
                    f' NetworkDelayMultiplier="{ci["NetworkDelayMultiplier"]}"'
                    f' ReactionTimeLimit="{ci["ReactionTimeLimit"]}"'
                    f' MaxObservedNetworkDelay="{ci["MaxObservedNetworkDelay"]}"'
                )
            consume_xml = (
                f'<ConsumeInfo Producer="{html.escape(str(ci.get("Producer", "")), quote=True)}"'
                f' RemoteTag="{html.escape(str(ci.get("RemoteTag", "")), quote=True)}"'
                f' RemoteInstance="{ci.get("RemoteInstance", "0")}"'
                f' RPI="{ci.get("RPI", "")}"'
                f'{_saf}'
                f' Unicast="{ci.get("Unicast", "false")}"/>'
            )

        # --- ProduceInfo child (Produced tags) ---
        # OEM emits <ProduceInfo> as the FIRST child of a Produced tag, before
        # Comments/Data. The FULL form carries the connection parameters; the
        # PLC-mapped form carries only PLCMappingFile.
        produce_xml = ""
        if self._produce_info:
            pi = self._produce_info
            if "PLCMappingFile" in pi:
                produce_xml = f'<ProduceInfo PLCMappingFile="{pi["PLCMappingFile"]}"/>'
            else:
                # A safety produced tag (fmt-31 connection) has no RPI triple;
                # its map entry omits the keys and OEM omits the attributes.
                _rpi3 = ""
                if "MinimumRPI" in pi:
                    _rpi3 = (
                        f' MinimumRPI="{pi.get("MinimumRPI", "")}"'
                        f' MaximumRPI="{pi.get("MaximumRPI", "")}"'
                        f' DefaultRPI="{pi.get("DefaultRPI", "")}"'
                    )
                produce_xml = (
                    f'<ProduceInfo ProduceCount="{pi.get("ProduceCount", "1")}"'
                    f' ProgrammaticallySendEventTrigger="{pi.get("ProgrammaticallySendEventTrigger", "false")}"'
                    f' UnicastPermitted="{pi.get("UnicastPermitted", "false")}"'
                    f'{_rpi3}/>'
                )

        if (not self._custom_properties and not self._alarm_xml
                and not consume_xml and not produce_xml
                and not comments_xml and not desc_xml and not data_xml
                and not eu_xml and not maxes_xml and not mins_xml):
            return base

        # Insert <CustomProperties> first (the reference emits the ACM/library
        # provider block before everything else), then <AlarmConditions>,
        # ConsumeInfo/ProduceInfo (Consumed/Produced tags), Comments, Description,
        # EngineeringUnits/Maxes/Mins, Data, immediately after the opening tag.
        idx = base.index(">")
        return (base[:idx + 1] + self._custom_properties + self._alarm_xml
                + consume_xml + produce_xml
                + comments_xml + desc_xml + eu_xml + maxes_xml + mins_xml
                + data_xml + base[idx + 1:])


@dataclass
class LocalTag(L5xElement):
    """Represents a local (non-public) tag inside an AOI (<LocalTag> in L5X)."""
    name: str
    data_type: str
    dimensions: Union[str, None]  # array size; None for scalars (omitted from XML)
    radix: Union[str, None]   # None for complex/UDT types (omitted from XML)
    external_access: str
    _description: Union[str, None] = field(default=None)
    # Operand-keyed member/bit/array comments (AOI scope). Rendered as a
    # <Comments> block after <Description> and before <DefaultData>. Empty by
    # default so existing LocalTag() constructions are unaffected.
    _operand_comments: List[Tuple[str, str]] = field(default_factory=list)
    # AOI-scoped value image (mirrors Tag): populated by the builder so the
    # <DefaultData> block can be emitted. All default to the no-value state so
    # existing LocalTag() constructions are unaffected.
    _data_types_map: Dict[str, "DataType"] = field(default_factory=dict)
    _taginfo_layout: Dict[str, object] = field(default_factory=dict)
    _value_bytes: Union[bytes, None] = None
    _short_header: bool = False
    _raw_hex_data: bool = False

    def __post_init__(self):
        super().__post_init__()
        self._export_name = "LocalTag"

    @property
    def _l5x_exclude(self) -> bool:
        """Exclude hex-address placeholders, empty names, and ACD-internal runtime
        tags -- including the SFC/ST step-temporaries (``__SL<n>``) the Tag
        predicate already drops; the reference exports no ``__``-prefixed
        LocalTag anywhere in the OEM pool."""
        return (
            not self.name
            or not (self.name[0].isalpha() or self.name[0] == "_")
            or ":" in self.name
            or self.name.startswith("__SL")
            or self.name.startswith("__l0")
            or self.name.startswith("__CLONE")
        )

    def to_xml(self) -> str:
        base = super().to_xml()
        desc_xml = (
            f'<Description>\n<![CDATA[{self._description}]]>\n</Description>'
            if self._description else ""
        )
        # Operand comments render between Description and DefaultData (OEM order).
        comments_xml = _aoi_comments_xml(self._operand_comments)
        # DefaultData: OEM emits it on EVERY LocalTag (after Description). Degrade
        # to "" on any failure (still an element_missing, never malformed).
        dd_xml = _build_default_data(
            self.data_type, self.dimensions, self._value_bytes,
            self._short_header, self._data_types_map, self._taginfo_layout,
            radix=self.radix, raw_hex_first=self._raw_hex_data,
        )
        if not desc_xml and not comments_xml and not dd_xml:
            return base
        idx = base.index(">")
        return base[:idx + 1] + desc_xml + comments_xml + dd_xml + base[idx + 1:]


@dataclass
class Parameter(L5xElement):
    """Represents a public parameter of an AOI (<Parameter> in L5X)."""
    name: str
    tag_type: str       # "Base", or "Alias" for an AOI alias parameter
    data_type: str
    usage: str          # "Input", "Output", or "InOut"
    radix: Union[str, None]   # None for complex types (omitted from XML)
    # AliasFor target for an AOI alias parameter (None omits the attribute); it
    # renders between @Radix and @Required, matching OEM's attribute order.
    alias_for: Union[str, None]
    required: str       # "true" or "false"
    visible: str        # "true" or "false"
    external_access: Union[str, None]  # None for InOut (omitted, replaced by Constant)
    constant: Union[str, None]  # "false" for non-MESSAGE InOut, None otherwise (omitted)
    dimensions: Union[str, None]  # array size; None for scalars (omitted from XML)
    _description: Union[str, None] = field(default=None)
    # Operand-keyed member/bit/array comments (AOI scope). Rendered as a
    # <Comments> block after <Description> and before <DefaultData>. Empty by
    # default so existing Parameter() constructions are unaffected.
    _operand_comments: List[Tuple[str, str]] = field(default_factory=list)
    # AOI-scoped value image (mirrors Tag); defaults to the no-value state so
    # existing Parameter() constructions are unaffected.
    _data_types_map: Dict[str, "DataType"] = field(default_factory=dict)
    _taginfo_layout: Dict[str, object] = field(default_factory=dict)
    _value_bytes: Union[bytes, None] = None
    _short_header: bool = False
    _raw_hex_data: bool = False

    def __post_init__(self):
        super().__post_init__()
        self._export_name = "Parameter"

    @property
    def _l5x_exclude(self) -> bool:
        # OEM never emits a __-prefixed scratch tag (SFC/ST step-temporaries
        # __SL<n>, hex placeholders __l0, import scratch __CLONE) as a
        # Parameter; the compact-AOI ext01 recovery can hand such a tag a usage
        # byte that would otherwise route it here, so exclude them exactly as
        # LocalTag does.
        return (
            not self.name
            or not (self.name[0].isalpha() or self.name[0] == "_")
            or self.name.startswith("__SL")
            or self.name.startswith("__l0")
            or self.name.startswith("__CLONE")
        )

    def to_xml(self) -> str:
        base = super().to_xml()
        desc_xml = (
            f'<Description>\n<![CDATA[{self._description}]]>\n</Description>'
            if self._description else ""
        )
        # Operand comments render between Description and DefaultData (OEM order).
        comments_xml = _aoi_comments_xml(self._operand_comments)
        # DefaultData (validated gating on the full OEM pool):
        #   - emitted on Input/Output params, NOT on InOut (933/933 had none);
        #   - SUPPRESSED for the system params EnableIn/EnableOut (no DefaultData);
        #   - suppressed for unknown / SKIP_DECORATED types (handled inside helper).
        dd_xml = ""
        if self.usage != "InOut" and self.name not in ("EnableIn", "EnableOut"):
            dd_xml = _build_default_data(
                self.data_type, self.dimensions, self._value_bytes,
                self._short_header, self._data_types_map, self._taginfo_layout,
                radix=self.radix, raw_hex_first=self._raw_hex_data,
            )
        if not desc_xml and not comments_xml and not dd_xml:
            return base
        idx = base.index(">")
        return base[:idx + 1] + desc_xml + comments_xml + dd_xml + base[idx + 1:]


@dataclass
class Routine(L5xElement):
    name: str
    type: str
    rungs: List[str]
    _rung_ids: List[int] = field(default_factory=list)
    _rung_comments: Dict[int, str] = field(default_factory=dict)
    _description: Union[str, None] = field(default=None)
    # Safety routines carry a generated signature + timestamp; None omits them.
    _safety_signature: Union[str, None] = field(default=None)
    _safety_signature_timestamp: Union[str, None] = field(default=None)
    # ST routine source lines decoded from the nameless subtree; None emits no
    # <STContent> (fail-closed -- see _st_content_lines).
    _st_lines: Union[List[str], None] = field(default=None)
    # Pre-rendered routine-own <CustomProperties> block ("" if none) and per-rung
    # blocks keyed by rung Number ({} if none). Both from the custom_properties
    # table; the routine-own block is the first child of <Routine>, a rung block
    # the first child of its <Rung>.
    _custom_properties: str = field(default="")
    _rung_custom_properties: Dict[int, str] = field(default_factory=dict)
    # A source-protected routine Studio exports as an <EncodedData> blob rather
    # than a plaintext <Routine>; when the blob is reconstructable it is rendered
    # here and replaces the whole element. None = an ordinary plaintext routine.
    _encoded: Union[str, None] = field(default=None)

    def to_xml(self) -> str:
        if self._encoded is not None:
            return self._encoded
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
                    f'{self._rung_custom_properties.get(i, "")}'
                    f'{comment_xml}'
                    f'<Text><![CDATA[{text}]]></Text>'
                    f'</Rung>'
                )
            if rung_xmls:
                rll_content = f'<RLLContent>{"".join(rung_xmls)}</RLLContent>'
        if self.type == "ST" and self._st_lines is not None:
            rll_content = "<STContent>" + "".join(
                f'<Line Number="{i}">\n<![CDATA[{t}]]>\n</Line>'
                for i, t in enumerate(self._st_lines)) + "</STContent>"
        # A routine's own Description is the first child, before RLLContent.
        desc_xml = (
            f'<Description>\n<![CDATA[{self._description}]]>\n</Description>'
            if self._description else ""
        )
        sig_attr = ""
        if self._safety_signature is not None:
            sig_attr = f' SafetySignature="{self._safety_signature}"'
            if self._safety_signature_timestamp is not None:
                sig_attr += (' SafetySignatureTimestamp="'
                             f'{html.escape(self._safety_signature_timestamp, quote=True)}"')
        return (
            f'<Routine Name="{html.escape(self.name, quote=True)}" Type="{self.type}"{sig_attr}>'
            f'{self._custom_properties}{desc_xml}{rll_content}</Routine>'
        )


@dataclass
class AOI(L5xElement):
    name: str
    cls: Union[str, None]  # "Standard" on safety-controller AOIs; None omits @Class
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
    # AdditionalHelpText (UDI_EXT_HELP) -- emitted after RevisionNote, before
    # Parameters (the OEM child order); "" omits the element.
    _additional_help_text: str = field(default="")
    # Pre-rendered <CustomProperties> block ("" if none); the first child of the
    # AOI definition, before Description.
    _custom_properties: str = field(default="")

    def __post_init__(self):
        super().__post_init__()
        self._export_name = "AddOnInstructionDefinition"

    def to_xml(self) -> str:
        base = super().to_xml()
        idx = base.index(">")
        inject = self._custom_properties
        if self._description:
            inject += f'<Description>\n<![CDATA[{self._description}]]>\n</Description>'
        if self._revision_note:
            inject += f'<RevisionNote>\n<![CDATA[{self._revision_note}]]>\n</RevisionNote>'
        if self._additional_help_text:
            inject += (f'<AdditionalHelpText>\n<![CDATA['
                       f'{self._additional_help_text}]]>\n</AdditionalHelpText>')
        return base[:idx + 1] + inject + base[idx + 1:]


@dataclass
class Program(L5xElement):
    name: str
    cls: Union[str, None]  # "Safety"/"Standard" on safety controllers; None omits @Class
    test_edits: str
    main_routine_name: Union[str, None]  # None if absent (omitted from XML)
    fault_routine_name: Union[str, None]  # None if absent (omitted from XML)
    disabled: str
    synchronize_redundancy_data_after_execution: Union[str, None]  # None → omit attr
    use_as_folder: Union[str, None]  # None -> omit attr (V10..V20 projects)
    tags: List[Tag]        # Tags section before Routines (matches L5X export order)
    routines: List[Routine]
    # <ChildPrograms> name index after Routines (None omits the section; the
    # child programs themselves are emitted as flat sibling <Program>s).
    child_programs: Union[List["ChildProgram"], None] = field(default=None)
    # Safety program signature/timestamp (None omits the attributes).
    safety_signature: Union[str, None] = field(default=None)
    safety_signature_timestamp: Union[str, None] = field(default=None)
    _description: Union[str, None] = field(default=None)
    # Pre-rendered <CustomProperties> block ("" if none); the first child of the
    # program, before Description.
    _custom_properties: str = field(default="")

    def to_xml(self) -> str:
        base = super().to_xml()
        prefix = self._custom_properties
        if self._description:
            # The program's own Description follows CustomProperties.
            prefix += (f'<Description>\n<![CDATA[{_xml_sane(self._description)}]]>\n'
                       f'</Description>')
        if not prefix:
            return base
        idx = base.index(">")
        return base[:idx + 1] + prefix + base[idx + 1:]


@dataclass
class ChildProgram(L5xElement):
    name: str

    def __post_init__(self):
        super().__post_init__()
        self._export_name = "ChildProgram"


@dataclass
class ScheduledProgram(L5xElement):
    name: str

    def __post_init__(self):
        super().__post_init__()
        self._export_name = "ScheduledProgram"


@dataclass
class EventInfo(L5xElement):
    event_trigger: str
    event_tag: Union[str, None]  # None omits @EventTag (e.g. EVENT-instruction tasks)
    enable_timeout: str

    def __post_init__(self):
        super().__post_init__()
        self._export_name = "EventInfo"


@dataclass
class Task(L5xElement):
    name: str
    cls: Union[str, None]  # "Safety"/"Standard" on safety controllers; None omits @Class
    type: str
    rate: Union[str, None]  # None for CONTINUOUS tasks (omitted from XML)
    priority: str
    watchdog: str
    disable_update_outputs: str
    inhibit_task: str
    event_info: Union[EventInfo, None]  # None for non-EVENT tasks
    scheduled_programs: List[ScheduledProgram]
    # Safety task signature/timestamp (None omits the attributes).
    safety_signature: Union[str, None] = field(default=None)
    safety_signature_timestamp: Union[str, None] = field(default=None)
    _description: Union[str, None] = field(default=None)

    def to_xml(self) -> str:
        base = super().to_xml()
        if not self._description:
            return base
        # A task's own Description is its first child, before ScheduledPrograms.
        desc_xml = (f'<Description>\n<![CDATA[{_xml_sane(self._description)}]]>'
                    f'\n</Description>')
        idx = base.index(">")
        return base[:idx + 1] + desc_xml + base[idx + 1:]


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
    # The controller's own <Description> (first child), or None.
    _description: Union[str, None] = field(default=None)
    # Pre-rendered controller-root <CustomProperties> block ("" if none); emitted
    # as the first child, before Description.
    _custom_properties: str = field(default="")
    # @DataExchangeId GUID string for the controller root; None omits the attr.
    _data_exchange_id: Union[str, None] = None
    # A safety-signed project stamps the <AddOnInstructionDefinitions> collection
    # with these two attributes; both None on a standard/unsigned project (omitted).
    _aoi_safety_signature: Union[str, None] = field(default=None)
    _aoi_safety_signature_timestamp: Union[str, None] = field(default=None)
    # Controller-properties attributes recovered from the controller record's
    # decrypted ext-attrs (None -> attribute omitted). A classic controller carries
    # the continuous-task slice (time_slice / share_unused_time_slice) and, on the
    # pre-V21 save format, compatibility_mode; a 5x80 controller carries
    # ethernet_ip_mode instead. power_loss_program is an optional program name.
    time_slice: Union[str, None] = field(default=None)
    share_unused_time_slice: Union[str, None] = field(default=None)
    compatibility_mode: Union[str, None] = field(default=None)
    ethernet_ip_mode: Union[str, None] = field(default=None)
    power_loss_program: Union[str, None] = field(default=None)
    # Project language attributes, emitted only on a genuinely multilingual project
    # (see ControllerBuilder._project_language_attrs); all None -> all omitted.
    # ControllerLanguage is the ExtendedDevice record's locale; the current/default
    # project languages are the export language (an export-environment property,
    # like ExportDate). Placed AFTER the first defaulted field so the positional
    # redundancy_enabled argument is undisturbed; passed by keyword.
    controller_language: Union[str, None] = field(default=None)
    current_project_language: Union[str, None] = field(default=None)
    default_project_language: Union[str, None] = field(default=None)
    # RedundancyInfo pad percentages, read from the controller-properties blob
    # (ext-attr 0x001): IOMemoryPadPercentage = u16 @ offset 16, DataTablePadPercentage
    # = u16 @ offset 18. Both None on the 5x80 generation (which omits the attributes).
    # Underscore-prefixed so the base to_xml() does not serialise them as <Controller>
    # attributes; they are rendered onto the <RedundancyInfo> child instead.
    _io_memory_pad_percentage: Union[str, None] = field(default=None)
    _data_table_pad_percentage: Union[str, None] = field(default=None)
    # <TimeSynchronize> PTPEnable / Priority1 / Priority2, read from the controller's
    # TimeSynchronize config record. Default to the prior fixed true/128/128.
    _ts_ptp_enable: str = field(default="true")
    _ts_priority1: str = field(default="128")
    _ts_priority2: str = field(default="128")
    # <CST MasterID>, read from the controller's CST config record. Default "0".
    _cst_master_id: str = field(default="0")
    # Pre-rendered controller communication port elements (see
    # acd.l5x.controller_ports): <CommPorts> sits immediately before <CST>;
    # <InternetProtocol>, <EthernetPorts> and <EthernetNetwork> follow
    # <TimeSynchronize> in that order (the reference's invariant placement).
    # "" omits each.
    _comm_ports_xml: str = field(default="")
    _internet_protocol_xml: str = field(default="")
    _ethernet_ports_xml: str = field(default="")
    _ethernet_network_xml: str = field(default="")
    # The controller-level safety signatures rendered as <SafetyInfo> children, each a
    # (signature, timestamp) pair or None. Populated only on safety-signed projects;
    # all None -> <SafetyInfo/> is emitted as before.
    _root_signature: Union[tuple, None] = field(default=None)
    _ctrl_attr_signature: Union[tuple, None] = field(default=None)
    _tag_map_signature: Union[tuple, None] = field(default=None)
    _app_rollup_signature: Union[tuple, None] = field(default=None)
    # Pre-rendered attribute string for the <SafetyInfo> open tag (recovered from the
    # SafetyController record); "" on a non-safety project -> empty <SafetyInfo/>.
    _safety_info_attrs: str = field(default="")
    # <SafetyTagMap> body text (" a=b, c=d" form); None omits the child.
    _safety_tag_map: Union[str, None] = field(default=None)
    # Pre-rendered <AlarmDefinitions> element (per-datatype member alarm
    # definitions); "" when the project defines none.
    _alarm_definitions: str = field(default="")
    # Pre-rendered <Trends> section (see acd.l5x.trends). Sits between
    # <WallClockTime> and <DataLogs>. Defaults to the bare '<Trends/>' the
    # controller emitted before the renderer existed, which is also what the
    # builder passes for a project with no reconstructable trend.
    _trends_xml: str = field(default="<Trends/>")

    def __post_init__(self):
        super().__post_init__()
        self._xml_attr_overrides = {
            "sfc_execution_control": "SFCExecutionControl",
            "sfc_restart_position": "SFCRestartPosition",
            "sfc_last_scan": "SFCLastScan",
            "project_sn": "ProjectSN",
            "can_use_rpi_from_producer": "CanUseRPIFromProducer",
            "ethernet_ip_mode": "EtherNetIPMode",
        }
        self._section_attrs: Dict[str, str] = {}
        if self._aoi_safety_signature is not None:
            self._section_attrs["aois"] = (
                f' SafetySignature="{self._aoi_safety_signature}"'
                f' SafetySignatureTimestamp="'
                f'{html.escape(self._aoi_safety_signature_timestamp or "", quote=True)}"'
            )

    def to_xml(self) -> str:
        base = super().to_xml()
        # Split at the end of the opening <Controller ...> tag so we can inject
        # structural stubs before the data sections and post-sections after them.
        idx = base.index(">")
        # @DataExchangeId is an attribute of the <Controller> open tag; inject it
        # before the closing '>' when present.
        _dxid_attr = (f' DataExchangeId="{self._data_exchange_id}"'
                      if self._data_exchange_id else "")
        open_tag = base[:idx] + _dxid_attr + ">"
        inner = base[idx + 1 : -len("</Controller>")]
        # CustomProperties is the first child, then the controller's own
        # Description.
        desc_xml = (
            f'<Description>\n<![CDATA[{_xml_sane(self._description)}]]>\n</Description>'
            if self._description else ""
        )
        open_tag = open_tag + self._custom_properties + desc_xml
        # RedundancyInfo: Enabled from the binary; the pad percentages are read from
        # the controller-properties blob and emitted only for the controller
        # generations that carry them (the 5x80 family omits both).
        redundancy_enabled_str = "true" if self._redundancy_enabled else "false"
        pad_attrs = ""
        if self._io_memory_pad_percentage is not None:
            pad_attrs += f' IOMemoryPadPercentage="{self._io_memory_pad_percentage}"'
        if self._data_table_pad_percentage is not None:
            pad_attrs += f' DataTablePadPercentage="{self._data_table_pad_percentage}"'
        redundancy_info = (
            f'<RedundancyInfo Enabled="{redundancy_enabled_str}" '
            f'KeepTestEditsOnSwitchOver="false"{pad_attrs}/>'
        )
        return (
            open_tag
            + inner
            + redundancy_info
            # The reference omits @ChangesToDetect on the pre-V20 save format and
            # emits the fixed all-ones mask from V20 on. Gate on our own MajorRev;
            # strip only when it is CONFIDENTLY pre-V20, else keep the attribute
            # (fail-closed: an unknown version keeps today's output).
            + ('<Security Code="0"/>'
               if str(self.major_rev).isdigit() and int(self.major_rev) < 20
               else '<Security Code="0" ChangesToDetect="16#ffff_ffff_ffff_ffff"/>')
            + self._safety_info_xml()
            + self._alarm_definitions
            + self._comm_ports_xml
            + f'<CST MasterID="{self._cst_master_id}"/>'
            + '<WallClockTime LocalTimeAdjustment="0" TimeZone="0"/>'
            + self._trends_xml
            + ('<DataLogs/>' if self._emit_data_logs else '')
            + (f'<TimeSynchronize Priority1="{self._ts_priority1}" '
               f'Priority2="{self._ts_priority2}" PTPEnable="{self._ts_ptp_enable}"/>')
            + self._internet_protocol_xml
            + self._ethernet_ports_xml
            + self._ethernet_network_xml
            + '</Controller>'
        )

    def _safety_info_xml(self) -> str:
        """The <SafetyInfo> element. Renders the controller-level safety-signature
        children on a safety-signed project, in the reference's sibling order; an
        unsigned project keeps the empty self-closing form."""
        children = ""
        if self._safety_tag_map:
            # The tag map precedes the signature children in the reference.
            children += ("<SafetyTagMap>"
                         + html.escape(_xml_sane(self._safety_tag_map))
                         + "</SafetyTagMap>")
        for tag, pair in (
            ("RootSignature", self._root_signature),
            ("ControllerAttributesSignature", self._ctrl_attr_signature),
            ("SafetyTagMapSignature", self._tag_map_signature),
            ("ApplicationRollupSignature", self._app_rollup_signature),
        ):
            if pair and pair[0]:
                ts = (f' Timestamp="{html.escape(pair[1], quote=True)}"'
                      if pair[1] else "")
                children += f'<{tag} Signature="{pair[0]}"{ts}/>'
        attrs = self._safety_info_attrs or ""
        if children:
            return f'<SafetyInfo{attrs}>{children}</SafetyInfo>'
        if attrs:
            return f'<SafetyInfo{attrs}/>'
        return '<SafetyInfo/>'


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
    # Root display language on a multilingual project (== the controller's
    # CurrentProjectLanguage); None on a single-language project -> omitted.
    current_language: Union[str, None] = None

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


@dataclass
class TagBuilder(TagAliasResolver, L5xElementBuilder):
    _short_header: bool = field(default=False)
    # Studio major version (e.g. 24, 36); 0 when unknown. Selects the first
    # <Data> block style: V<=24 (and short-header V10-V21) write a raw-hex
    # <Data>XX XX..</Data> image, V28+ write <Data Format="L5K">.
    _acd_major: int = field(default=0)
    # Owning program's comment_id (short-header program-tag description key); 0
    # for controller-scope tags.
    _program_cid: int = field(default=0)
    # Datatype layout map (UPPER name -> member list, "@size@NAME" -> byte
    # size); build()'s alias resolver reads it, so pass it at construction.
    _taginfo_layout: Dict[str, object] = field(default_factory=dict)

    def _raw_hex_first_block(self) -> bool:
        """True when the tag's first <Data> block is the raw-hex image, not L5K
        (the shared _raw_hex_first policy — see its docstring)."""
        return _raw_hex_first(self._short_header, self._acd_major)

    def _read_tag_value(self, data_table_instance: int):
        """Return (value_bytes, type_code) for a tag's design value, or (None, 0).

        Resolves the cip-0x6a backing via data_table_instance and decodes its
        ext attr 0x66 from the size-eos comps record body. Best-effort: any
        failure yields (None, 0) so the Tag keeps today's zero-placeholder
        <Data>.
        """
        try:
            if not data_table_instance:
                return None, 0
            self._cur.execute(
                "SELECT record FROM comps WHERE object_id=?",
                (data_table_instance,),
            )
            row = self._cur.fetchone()
            if not row or row[0] is None:
                return None, 0
            res = CompsRecord.read_tag_value(bytes(row[0]), self._short_header,
                                             body_mode=True)
            if res is None:
                return None, 0
            return res
        except Exception:
            return None, 0

    # Exposed on the class for the TagAliasResolver mixin's host contract.
    _parse_rec_tolerant = staticmethod(_parse_rec_tolerant)

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
        # ref; validated 48/48 aliases, 0 false positives across two long-header
        # projects).
        # Wrapped/best-effort: a detector failure leaves `constant` as today.
        _lh_is_alias = False
        if not self._short_header and not is_io and constant is None:
            _lh_is_alias = self._long_header_alias_like(raw_rec)
            if not _lh_is_alias:
                constant = "false"

        # --- V24+ long-header @AliasFor / TagType="Alias" ---
        # The layout-driven resolver handles every long-header alias shape
        # (module-I/O channel members, internal UDT member paths, array-of-struct,
        # nested structs/bit members, whole-element) by walking the base
        # datatype's TagInfo layout. It is fail-closed (None -> keep Base), so the
        # narrower resolvers below remain as a fallback for the rare base whose
        # datatype layout is unavailable.
        if not self._short_header and not is_io and not alias_for:
            try:
                _vaf = self._layout_alias_for(raw_rec)
            except Exception:
                _vaf = None
            if _vaf:
                alias_for = _vaf
                constant = None
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

        # --- Source-protected alias: the live target sits in the encrypted main
        # record, so the resolvers above see nothing; recover it from the decrypted
        # ext-attr 0x65 alias template (validated 0-FP, target-exact pool-wide). ---
        if not alias_for:
            try:
                _spaf = self._sp_alias_for()
            except Exception:
                _spaf = None
            if _spaf:
                alias_for = _spaf
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
            self._cur.execute(
                "SELECT opc_ua, is_safety, opc_access, sw_major "
                "FROM project_flags")
            _pf = self._cur.fetchone() or (0, 0, "None", 0)
        except Exception:
            _pf = (0, 0, "None", 0)
        _sw_major = _pf[3] or 0
        # Export-schema epoch (rule A): the reference emits neither
        # @ExternalAccess nor @Constant on ANY element below schema major 18
        # (0/10302 Members, 0/331 Tags across the v17 corpus vs present at v19+).
        # File-wide and element-kind-independent. sw_major==0 (underivable) keeps
        # today's emission.
        if 1 <= _sw_major < 18:
            external_access = None
            constant = None
        _opc_ua = ""
        if _pf[0]:
            # Per-tag OPC UA access: the tag parameter blob's (ext-attr 0x1)
            # last byte, ExternalAccess enum encoding (0=Read/Write,
            # 2=Read Only, 3=None). Falls back to the project-level value for
            # a record whose blob cannot be read (e.g. source-protected).
            _opc_ua = _pf[2] or "None"
            try:
                _r8 = RxGeneric.from_bytes(raw_rec)
                _a1 = next((bytes(e.value) for e in _r8.extended_records
                            if e.attribute_id == 0x1), b"")
                if _a1 and _a1[-1] in (0, 2, 3):
                    _opc_ua = external_access_enum(_a1[-1])
            except Exception:
                pass

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
                # 0x79xx = 5069-family safety partition; 0x8100 = the
                # 1756-L8xES (GuardLogix) safety partition (same field,
                # family-specific id).
                is_safe_partition = (hi >> 8) == 0x79 or hi == 0x8100
            return "Safety" if is_safe_partition else "Standard"

        # A source-protected record's encrypted ext-attr tail defeats the
        # kaitai parser; _parse_rec_tolerant recovers the (plaintext) main_record
        # at fixed offsets so the tag still emits its data_type / dimensions /
        # design value.
        r = self._parse_rec_tolerant(raw_rec)
        if r is None or r.cip_type not in (0x6B, 0x68):
            _nm = io_name or results[0][0]
            # Rule B on the unparseable-record fallback (no is_io refinement runs
            # here): an IO-named tag still omits @ExternalAccess below major 20.
            if is_io and 1 <= _sw_major < 20:
                external_access = None
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
        # Rack chassis-image per-point alias (structure-typed IO point, e.g.
        # Rack_2:1:I of type AB:1756_ENET_17SLOT:I:0): OEM emits it as
        # TagType="Alias" AliasFor="Rack_2:I.Slot[1]" with NO DataType and NO
        # Radix (structure target). The tight presence gate (unique slotless
        # chassis sibling with one matching Slot[] member) fires only on these,
        # never a genuine ':'-typed module-IO point.
        _alias_no_radix = False
        if is_io and not alias_for and data_type and ":" in data_type:
            try:
                _raf = self._rack_slot_alias_for(results[0][0], io_name, data_type)
            except Exception:
                _raf = None
            if _raf:
                alias_for = _raf
                tag_type = "Alias"
                data_type = ""
                constant = None
                _alias_no_radix = True

        # Rule B: the reference omits @ExternalAccess on module I/O tags (IO="true")
        # below export-schema major 20 (0/1145 IO tags carry it at v19 vs present
        # at v20+), even though non-IO tags at v19 DO carry it (rule A only strips
        # below v18). Keyed on the final is_io. sw_major 0 -> today's emission.
        if is_io and 1 <= _sw_major < 20:
            external_access = None

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
                # real cip-0x68 descriptions (validated on one project: keeps 11, drops 26
                # rung collisions; layout AX* over-emit gone).
                # A long-header own description also carries object_id == 1; the
                # scratch/operand rows that share (parent_key, member_ref) under a
                # sentinel key instead carry a nonzero object_id (e.g. 33) with an
                # empty tag_reference, so the tag_reference guard alone lets them
                # through as a fabricated name-fragment Description. Requiring the
                # description object_id keeps the real own description and drops
                # those. In a language-enabled project that id is the export
                # language's (project_lang), falling back to the legacy 1.
                _lang_oid = project_lang_oid(self._cur)
                _desc_oids = (_lang_oid, 1) if _lang_oid else (1,)
                for _doid in _desc_oids:
                    self._cur.execute(
                        "SELECT record_string, tag_reference FROM comments "
                        "WHERE parent=? AND member_ref=? "
                        "AND (rung_content IS NULL OR rung_content=0) "
                        "AND object_id=? "
                        "LIMIT 1",
                        (parent_key, member_ref, _doid),
                    )
                    desc_row = self._cur.fetchone()
                    if desc_row and desc_row[0] and not desc_row[1]:
                        comment_results = [("", desc_row[0])]
                        break
            except Exception:
                comment_results = []
        elif self._program_cid and r.cip_type != 0x6B and len(raw_rec) >= 18:
            # V10-V21 PROGRAM-scoped tag own description. cip-0x68 program tags
            # share a comment_id, so the bare-cid lookup collides; instead key off
            # the tag record's bytes[14:18] = (selector << 16 | member_ref): the
            # description is at parent = (selector << 16) | the program's
            # comment_id, that member_ref, record_type 1, and sub_record_length ==
            # 0x68 (the program-tag cip, which drops a colliding row owned by a
            # different comp). Folding the selector into the parent high-word
            # disambiguates instruction-backing tags (ADD_*/SSUM_*/DIV_*) that the
            # bare member_ref alone could not -- the collision that blocked this
            # bucket before. Wrapped to degrade to no description on any failure.
            try:
                _b14 = struct.unpack_from("<I", raw_rec, 14)[0]
                _parent = ((_b14 & 0xFFFF) << 16) | self._program_cid
                self._cur.execute(
                    "SELECT record_string FROM comments "
                    "WHERE record_type=1 AND parent=? AND member_ref=? "
                    "AND sub_record_length=0x68 AND record_string!='' LIMIT 1",
                    (_parent, _b14 >> 16),
                )
                desc_row = self._cur.fetchone()
                if desc_row and desc_row[0]:
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
            # An AOI DEFINITION's own-description row shares this bare comment_id
            # but stores the AOI cip (0x6c) in sub_record_length; filtering on the
            # tag's own cip (0x6b) excludes it (the same owner-cip discriminator
            # base.short_own_description uses), so a tag never inherits an AOI's
            # description.
            try:
                self._cur.execute(
                    "SELECT record_string FROM comments "
                    "WHERE parent=? AND member_ref=0 AND record_type IN (1,2) "
                    "AND sub_record_length=? AND record_string!='' LIMIT 1",
                    (r.comment_id, r.cip_type),
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
        eng_units: List[Tuple[str, str]] = []
        maxes: List[Tuple[str, str]] = []
        mins: List[Tuple[str, str]] = []
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
            # Studio does not surface). COLLISION-SAFE, two modes:
            #   * unique parent key (unique_comment_key): the key alone owns the
            #     rows -- today's path, unchanged;
            #   * SHARED program-scope key (cip-0x68 tags share the program's
            #     comment_id): each row repeats its owner's scope-local comment
            #     key (comp record[14:18]) in owner_ref, so rows are attributed
            #     by the (parent, owner_ref) pair -- gated on this tag's own
            #     pair being owned by exactly one live comp (unique_owner_key)
            #     and rows with owner_ref==0 stay suppressed. Cross-validated
            #     537/537 vs OEM across three long-header projects.
            # A '.!<hex>' operand is a member token, (collection<<16)|member
            # into member_resolve; resolve_hex_operand rewrites it to the OEM
            # member path and is fail-closed (any unresolvable token keeps the
            # operand suppressed). Rows are routed by the record kind byte
            # (member_ref): EngineeringUnit/Min/Max rows are NOT tag comments --
            # OEM renders them as their own blocks. Kaitai-staged rows (rt
            # 3/4/13/14) carry member_ref 0 and stay on the comment path.
            try:
                parent_key = (r.comment_id * 0x10000) + r.cip_type
                own_key = (struct.unpack_from("<I", raw_rec, 14)[0]
                           if len(raw_rec) >= 18 else 0)
                if self._cur.execute(
                        "SELECT 1 FROM unique_comment_key WHERE k=?",
                        (parent_key,)).fetchone():
                    self._cur.execute(
                        "SELECT c.tag_reference, c.record_string, c.member_ref, "
                        "c.revision "
                        "FROM comments c "
                        "WHERE c.parent=? "
                        "AND c.tag_reference!='' AND c.tag_reference!='__REVISION_NOTE__' "
                        "AND c.record_string!=''",
                        (parent_key,),
                    )
                elif (own_key and (own_key & 0xFFFF) == 0x6B
                        and self._cur.execute(
                            "SELECT 1 FROM unique_owner_key WHERE scope=? AND own=?",
                            (parent_key, own_key)).fetchone()):
                    self._cur.execute(
                        "SELECT c.tag_reference, c.record_string, c.member_ref, "
                        "c.revision "
                        "FROM comments c "
                        "WHERE c.parent=? AND c.owner_ref=? "
                        "AND c.tag_reference!='' AND c.tag_reference!='__REVISION_NOTE__' "
                        "AND c.record_string!=''",
                        (parent_key, own_key),
                    )
                else:
                    self._cur.execute("SELECT 1 WHERE 0")
                # Studio keeps prior edits of an operand comment; the reference
                # emits only the LATEST. Keep the max-revision row per
                # (operand, kind), preserving first-occurrence order.
                _best: Dict[Tuple[str, int], Tuple[int, str]] = {}
                _gen_max = 0
                for op_ref, op_text, op_kind, op_rev in self._cur.fetchall():
                    if not op_text:
                        continue
                    if ".!" in op_ref:
                        op_ref = resolve_hex_operand(self._cur, op_ref)
                        if op_ref is None:
                            continue
                    if not _is_valid_operand(op_ref):
                        continue
                    _k = (op_ref, op_kind)
                    if op_kind not in (0x02, 0x03, 0x05):
                        _gen_max = max(_gen_max, op_rev or 0)
                    _prev = _best.get(_k)
                    if _prev is None or (op_rev or 0) > _prev[0]:
                        _best[_k] = (op_rev or 0, op_text)
                for (op_ref, op_kind), (_op_rev, op_text) in _best.items():
                    if op_kind == 0x05:
                        eng_units.append((op_ref, op_text))
                    elif op_kind == 0x02:
                        mins.append((op_ref, op_text))
                    elif op_kind == 0x03:
                        maxes.append((op_ref, op_text))
                    else:
                        # An edit of a tag's comments rewrites every LIVE row
                        # at the project's new edit revision; a row left at an
                        # older revision was deleted in that edit, and the
                        # reference export lists its operand with EMPTY text.
                        # Blank (don't drop) a winner older than the tag's
                        # newest comment revision. Value/EngUnit kinds keep
                        # their text (separate blocks, no observed blanking);
                        # revision is 0 across a short-header project, where
                        # this is a no-op.
                        operand_comments.append(
                            (op_ref, op_text if _op_rev >= _gen_max else ""))
            except Exception:
                operand_comments = []
                eng_units = []
                mins = []
                maxes = []

        extended_records: Dict[int, bytes] = {}
        for extended_record in r.extended_records:
            extended_records[extended_record.attribute_id] = bytes(
                extended_record.value
            )

        if 0x01 not in extended_records:
            # Name comes from comp_name in the database; radix from main_record
            name = results[0][0]
        else:
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
        # The Dimensions attribute is space-separated (Logix convention).
        dimensions = " ".join(dim_parts) if dim_parts else None
        value_bytes, _ = (
            (None, 0) if (alias_for or suppress_value)
            else self._read_tag_value(r.main_record.data_table_instance)
        )
        _nm = io_name or name
        # ACM/library <CustomProperties>: a controller-scope tag (cip 0x6B) owns
        # its block keyed by its own comment parent (owner_ref 0); a program-scope
        # tag (cip 0x68) owns it keyed by its program's scope parent
        # (comment_id<<16 | 0x68 -- a program tag shares its program's comment_id)
        # plus the tag's own key at record[14:18].
        _cp_xml = ""
        try:
            if r.cip_type == 0x6B:
                _cp_xml = custom_properties_by_parent(
                    self._cur, (r.comment_id * 0x10000) + r.cip_type) or ""
            elif r.cip_type == 0x68 and len(raw_rec) >= 18:
                _cp_xml = custom_properties_by_scope_owner(
                    self._cur, (r.comment_id * 0x10000) + 0x68,
                    struct.unpack_from("<I", raw_rec, 14)[0]) or ""
        except Exception:
            _cp_xml = ""
        # @DataExchangeId: same owner-key join as CustomProperties -- the GUID is a
        # comments-table row (object_id 45). None (no row) omits the attribute.
        _dxid = None
        try:
            if r.cip_type == 0x6B:
                _dxid = own_data_exchange_id(
                    self._cur, (r.comment_id * 0x10000) + r.cip_type)
            elif r.cip_type == 0x68 and len(raw_rec) >= 18:
                _dxid = scope_owner_data_exchange_id(
                    self._cur, (r.comment_id * 0x10000) + 0x68,
                    struct.unpack_from("<I", raw_rec, 14)[0])
        except Exception:
            _dxid = None
        # @Usage: a per-tag flag on long-header PROGRAM-scope tags (cip 0x68) in
        # ext-attr 0x01. Controller-scope tags (cip 0x6B) never carry it.
        _usage = None
        try:
            if not self._short_header and r.cip_type == 0x68:
                _, _uexts, _ = _parse_rec_and_exts(raw_rec)
                _usage = _program_tag_usage(_uexts.get(0x01, b""))
        except Exception:
            _usage = None
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
            _eng_units=eng_units,
            _maxes=maxes,
            _mins=mins,
            alias_for=alias_for,
            _value_bytes=value_bytes,
            _short_header=self._short_header,
            _raw_hex_data=self._raw_hex_first_block(),
            _no_data=suppress_value,
            _io=is_io,
            _alias_no_radix=_alias_no_radix,
            _custom_properties=_cp_xml,
            _data_exchange_id=_dxid,
            _usage=_usage,
            _opc_ua=_opc_ua, _class_attr=_cls_attr(),
        )


def _program_tag_usage(ext01: bytes) -> Union[str, None]:
    """Return the @Usage of a long-header PROGRAM-scope tag from its ext-attr 0x01
    blob, or None (no @Usage attribute). The flag shares the same byte the AOI
    parameter decoder reads (ext01[0x20E]): bit 0x10 => Public; otherwise the
    0x0C direction bits => Input(0x04)/Output(0x08)/InOut(0x0C); 0x00 => omit."""
    if len(ext01) <= 0x20E:
        return None
    b = ext01[0x20E]
    if b & 0x10:
        return "Public"
    return {0x04: "Input", 0x08: "Output", 0x0C: "InOut"}.get(b & 0x0C)


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


def _aoi_operand_comments(cur, r, raw_rec: bytes) -> List[Tuple[str, str]]:
    """Operand-keyed member/bit/array <Comment> rows for an AOI Parameter/
    LocalTag, using the SAME shared-scope-key + owner_ref join TagBuilder uses
    for program-scope tags (long header only). An AOI's parameters/local tags
    all share the AOI DEFINITION's comment_id and carry the AOI-scope cip 0x338
    in their prelude, so parent == comment_id*0x10000 + cip is the AOI's shared
    scope key (== unique_comment_key / unique_owner_key.scope) and record[14:18]
    is the tag's own key repeated in each comment row's owner_ref -- exactly the
    program-scope machinery, only the scope cip differs (0x338 vs 0x68). Gated on
    the same unique-owner-key attribution so a collision fails closed to nothing.
    AOI params/local tags never carry Min/Max/EngUnit blocks anywhere in the OEM
    pool, so only comment kinds are kept; Min/Max/EngUnit rows are dropped.
    Returns [] fail-closed on any miss (short-header handled by the caller)."""
    operand_comments: List[Tuple[str, str]] = []
    try:
        parent_key = (r.comment_id * 0x10000) + r.cip_type
        own_key = (struct.unpack_from("<I", raw_rec, 14)[0]
                   if len(raw_rec) >= 18 else 0)
        if cur.execute("SELECT 1 FROM unique_comment_key WHERE k=?",
                       (parent_key,)).fetchone():
            cur.execute(
                "SELECT c.tag_reference, c.record_string, c.member_ref, "
                "c.revision FROM comments c WHERE c.parent=? "
                "AND c.tag_reference!='' AND c.tag_reference!='__REVISION_NOTE__' "
                "AND c.record_string!=''",
                (parent_key,))
        elif (own_key and (own_key & 0xFFFF) == 0x6B
                and cur.execute(
                    "SELECT 1 FROM unique_owner_key WHERE scope=? AND own=?",
                    (parent_key, own_key)).fetchone()):
            cur.execute(
                "SELECT c.tag_reference, c.record_string, c.member_ref, "
                "c.revision FROM comments c WHERE c.parent=? AND c.owner_ref=? "
                "AND c.tag_reference!='' AND c.tag_reference!='__REVISION_NOTE__' "
                "AND c.record_string!=''",
                (parent_key, own_key))
        else:
            return operand_comments
        _best: Dict[Tuple[str, int], Tuple[int, str]] = {}
        _gen_max = 0
        for op_ref, op_text, op_kind, op_rev in cur.fetchall():
            if not op_text:
                continue
            if ".!" in op_ref:
                op_ref = resolve_hex_operand(cur, op_ref)
                if op_ref is None:
                    continue
            if not _is_valid_operand(op_ref):
                continue
            if op_kind in (0x02, 0x03, 0x05):
                continue  # Min/Max/EngUnit -- never on an AOI param/local tag
            _k = (op_ref, op_kind)
            _gen_max = max(_gen_max, op_rev or 0)
            _prev = _best.get(_k)
            if _prev is None or (op_rev or 0) > _prev[0]:
                _best[_k] = (op_rev or 0, op_text)
        for (op_ref, _op_kind), (_op_rev, op_text) in _best.items():
            operand_comments.append(
                (op_ref, op_text if _op_rev >= _gen_max else ""))
    except Exception:
        operand_comments = []
    return operand_comments


def _aoi_comments_xml(operand_comments: List[Tuple[str, str]]) -> str:
    """<Comments> block for an AOI Parameter/LocalTag, or "".

    Same shape as Tag._build_comments_xml (first-occurrence dedup, CDATA body)."""
    if not operand_comments:
        return ""
    seen = set()
    items: List[Tuple[str, str]] = []
    for operand, text in operand_comments:
        if not operand or operand in seen:
            continue
        seen.add(operand)
        items.append((operand, text))
    if not items:
        return ""
    parts = ["<Comments>"]
    for operand, text in items:
        op_attr = html.escape(operand, quote=True)
        body = Tag._sanitize_xml_text(text) if text else ""
        parts.append(
            f'<Comment Operand="{op_attr}">\n<![CDATA[{body}]]>\n</Comment>')
    parts.append("</Comments>")
    return "".join(parts)


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
    # {member_name: description} from the AOI datatype member-description join
    # (long header). Preferred over the per-tag lookup below when it has an entry.
    _member_desc: Dict[str, str] = field(default_factory=dict)
    # The AOI definition comp's comment_id (short-header parameter desc key).
    _owner_def_cid: int = field(default=0)

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
        r, exts, sp = _parse_rec_and_exts(raw_rec)
        if sp and (not exts or r is None):
            return Parameter(name, name, "Base", data_type, "Input", None, None, "false", "false", "Read/Write", None, dimensions)

        ext01 = exts.get(0x01, b"")
        usage, required_b, visible_b = _aoi_tag_usage(ext01, short_header=False if sp else self._short_header)
        # AoiBuilder only routes Input/Output/InOut here; guard the Local/None
        # edge to the prior InOut default so behaviour can't regress.
        if usage not in ("Input", "Output", "InOut"):
            usage = "InOut"

        required = "true" if required_b else "false"
        visible = "true" if visible_b else "false"

        # ExternalAccess (u16 at ext01[0x21E])
        # Built-in reference-type InOut parameters don't carry Constant in the
        # reference L5X; every other InOut parameter (atomic, string, and user
        # UDTs including axis-named ones) still carries it. Match
        # by exact DataType, never a name substring. The never-set set is the
        # corpus-proven six (0 with Constant vs 7,839/7,839 WITH on all other
        # InOut datatypes, 0 mixed): the motion references, MESSAGE, and MODULE.
        _no_constant_inout = (
            "MESSAGE", "MOTION_GROUP", "AXIS_CIP_DRIVE", "AXIS_SERVO_DRIVE",
            "AXIS_VIRTUAL", "MODULE",
        )
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

        # AOI ALIAS parameter: OEM emits TagType="Alias" AliasFor="<target>" with
        # no DataType and no <DefaultData>. The direction byte ext01[0x20E] bit
        # 0x02 marks exactly these (14/14 OEM-alias params pool-wide carry it;
        # zero Base/Local params do). Null the DataType (base to_xml omits None
        # attrs and _build_default_data suppresses the DefaultData pair) and
        # resolve the AliasFor target from ext-attr 0x65 (a @hex@.@hex@ template
        # of comps oids). Fail-closed: an unresolved template keeps the param
        # TagType="Base" with no AliasFor, i.e. today's over-emission-only fix.
        tag_type = "Base"
        alias_for: Union[str, None] = None
        if not sp and len(ext01) > 0x20E and (ext01[0x20E] & 0x02):
            data_type = None
            _tgt = resolve_aoi_alias_target(self._cur, raw_rec, self._short_header)
            if _tgt:
                tag_type = "Alias"
                alias_for = _tgt

        # --- Description ---
        # Source-protected projects also encrypt the comment text, so for an
        # SP-recovered parameter the comments table holds undecryptable garbage
        # (e.g. a lone 0x1d control byte, which would additionally produce invalid
        # XML). Skip the lookup on the SP path rather than emit a bogus Description;
        # the real text needs a separate comment-decryption that is not yet cracked.
        # Prefer the AOI datatype member-description map (long header): it keys by
        # the datatype comment_id, which is correct for both plain and
        # source-protected AOIs, where the per-tag lookup below is not.
        description: Union[str, None] = self._member_desc.get(name)
        if description is not None:
            pass
        elif self._short_header:
            # V10-V21 AOI parameter description join. The parameter record's
            # bytes[14:18] encode (selector << 16 | per-parameter member_ref); the
            # description lives at parent = (selector << 16) | the AOI definition
            # comment_id, with that member_ref, record_type 1, and
            # sub_record_length == the AOI definition cip (0x338). The cip filter
            # excludes a colliding tag/string row that shares the comment_id. This
            # runs before the sp guard: bytes[14:18] are plaintext even on
            # source-protected parameters, and the text decrypts in the comments
            # table.
            if self._owner_def_cid and len(raw_rec) >= 18:
                _b14 = struct.unpack_from("<I", raw_rec, 14)[0]
                _parent = ((_b14 & 0xFFFF) << 16) | self._owner_def_cid
                self._cur.execute(
                    "SELECT record_string FROM comments "
                    "WHERE record_type=1 AND parent=? AND member_ref=? "
                    "AND sub_record_length=? AND record_string!='' LIMIT 1",
                    (_parent, _b14 >> 16, 0x338),
                )
                desc_row = self._cur.fetchone()
                if desc_row and desc_row[0]:
                    description = desc_row[0]
        elif sp:
            pass
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

        # Operand-keyed member/bit/array comments, both header forms. Short-header
        # AOI operand records decode through the 0x338 scope branch in
        # _parse_short_operand_body; attribution stays fail-closed via unique_owner_key.
        operand_comments = _aoi_operand_comments(self._cur, r, raw_rec)

        return Parameter(
            name,
            name,
            tag_type,
            data_type,
            usage,
            radix,
            alias_for,
            required,
            visible,
            external_access,
            constant,
            dimensions,
            description,
            operand_comments,
        )


@dataclass
class LocalTagBuilder(L5xElementBuilder):
    """Build a LocalTag from an AOI RxTagCollection child record."""

    _short_header: bool = field(default=False)
    # Owning AOI's bare comment_id; the short-header description key.
    _owner_comment_id: int = field(default=0)
    # {member_name: description} from the AOI datatype member-description join
    # (long header). Preferred over the per-tag lookup below when it has an entry.
    _member_desc: Dict[str, str] = field(default_factory=dict)
    # The AOI definition comp's comment_id (short-header local-tag desc key).
    _owner_def_cid: int = field(default=0)

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
        r, exts, sp = _parse_rec_and_exts(raw_rec)
        if sp and (not exts or r is None):
            return LocalTag(name, name, data_type, dimensions, None, "Read/Write")

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
        # Prefer the AOI datatype member-description map (long header), which keys
        # by the datatype comment_id and is correct for source-protected AOIs too.
        description: Union[str, None] = self._member_desc.get(name)
        if description is not None:
            pass
        elif self._short_header:
            # V10-V21 AOI local-tag description join (same as ParameterBuilder):
            # record bytes[14:18] = (selector << 16 | member_ref); description at
            # parent = (selector << 16) | AOI-def comment_id, that member_ref,
            # record_type 1, sub_record_length == AOI def cip (0x338, which excludes
            # a colliding tag/string row). Runs before the sp guard.
            if self._owner_def_cid and len(raw_rec) >= 18:
                _b14 = struct.unpack_from("<I", raw_rec, 14)[0]
                _parent = ((_b14 & 0xFFFF) << 16) | self._owner_def_cid
                self._cur.execute(
                    "SELECT record_string FROM comments "
                    "WHERE record_type=1 AND parent=? AND member_ref=? "
                    "AND sub_record_length=? AND record_string!='' LIMIT 1",
                    (_parent, _b14 >> 16, 0x338),
                )
                desc_row = self._cur.fetchone()
                if desc_row and desc_row[0]:
                    description = desc_row[0]
        elif sp:
            pass
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

        # Operand-keyed member/bit/array comments (both header forms).
        operand_comments = _aoi_operand_comments(self._cur, r, raw_rec)

        return LocalTag(name, name, data_type, dimensions, radix,
                        external_access, description, operand_comments)


_ST_AT_TOKEN_RE = re.compile(r"@([0-9a-fA-F]+)@")
_ST_LINE_MARKER = b"\xff\xfe\xff"


def _st_content_lines(cur, routine_oid: int) -> "Union[List[str], None]":
    """Decode an ST routine's source lines from its nameless subtree, or None.

    The routine's nameless subtree contains exactly one GROUP record that ENDS
    with a contiguous little-endian u32 array listing all of its line-record
    children in source order (V20 stores a count u16 right before the array,
    V33 pads differently -- the trailing-array-of-own-children shape is the
    version-invariant signature). Each line record carries the UTF-16LE source
    text after an FF FE FF marker + a 1-byte code-unit length (length 0 = an
    empty line); ``@<hex>@`` tokens are comps object references resolved to
    comp_name, and unresolvable tokens are left in place rather than
    fabricated. V33 files also store a compiled DECOY subtree of the same
    routine (literal-operand MOVs) whose parent record is too short to carry
    the trailing child array, so the selection rule structurally rejects it.
    FAIL-CLOSED: zero or multiple candidate groups, or any array entry whose
    record does not decode as a line, returns None (routine stays empty).
    """
    try:
        candidates = []
        frontier = [routine_oid]
        seen = set()
        while frontier:
            nxt: List[int] = []
            for pid in frontier:
                for coid, crec in cur.execute(
                        "SELECT object_id, record FROM nameless "
                        "WHERE parent_id=?", (pid,)).fetchall():
                    if coid in seen:
                        continue
                    seen.add(coid)
                    nxt.append(coid)
                    crec = bytes(crec)
                    kids = [o for (o,) in cur.execute(
                        "SELECT object_id FROM nameless WHERE parent_id=?",
                        (coid,)).fetchall()]
                    k = len(kids)
                    if k == 0 or len(crec) < 4 * k:
                        continue
                    arr = [struct.unpack_from("<I", crec, len(crec) - 4 * k
                                              + 4 * i)[0] for i in range(k)]
                    if set(arr) == set(kids) and len(set(arr)) == k:
                        candidates.append((coid, arr))
            frontier = nxt
        def _deref(oid: int, depth: int = 0) -> "Union[str, None]":
            # Resolve a comps oid to its export name, following the
            # ``&<parentHex><suffix>`` module-reference convention recursively
            # (same rule the alias/rung resolvers use): '&04767ecc:2:I'
            # renders as 'Local:2:I' in OEM source text.
            if depth > 6:
                return None
            row = cur.execute(
                "SELECT comp_name FROM comps WHERE object_id=?",
                (oid,)).fetchone()
            if not row or not row[0]:
                return None
            nm = row[0]
            m = re.match(r"^&([0-9a-fA-F]+)(.*)$", nm)
            if m:
                parent = _deref(int(m.group(1), 16), depth + 1)
                return (parent + m.group(2)) if parent is not None else None
            return nm

        def _resolve(mo: "re.Match") -> str:
            nm = _deref(int(mo.group(1), 16))
            return nm if nm else mo.group(0)

        def _decode_group(order: "List[int]") -> "Union[List[str], None]":
            lines: List[str] = []
            for oid in order:
                row = cur.execute(
                    "SELECT record FROM nameless WHERE object_id=?",
                    (oid,)).fetchone()
                if not row:
                    return None
                rec = bytes(row[0])
                m = rec.find(_ST_LINE_MARKER)
                if m < 0 or len(rec) < m + 4:
                    return None
                # Code-unit count: u8, with 0xFF as the long-form sentinel
                # followed by a u16 LE count (observed on 267-unit lines).
                n = rec[m + 3]
                tpos = m + 4
                if n == 0xFF:
                    if len(rec) < m + 6:
                        return None
                    n = struct.unpack_from("<H", rec, m + 4)[0]
                    tpos = m + 6
                if len(rec) < tpos + 2 * n:
                    return None
                text = rec[tpos:tpos + 2 * n].decode("utf-16-le")
                lines.append(_ST_AT_TOKEN_RE.sub(_resolve, text))
            return lines

        # A structural candidate whose children do not ALL decode as line
        # records is an interior index node (its trailing array lists interior
        # children), not the line group -- decode success is part of the
        # selection, and only an unambiguous single survivor is emitted.
        decoded = []
        for _, order in candidates:
            lines = _decode_group(order)
            if lines is not None:
                decoded.append(lines)
        if len(decoded) != 1:
            return None
        return decoded[0]
    except Exception:
        return None


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
    _short_header: bool = field(default=False)
    # Precomputed routine object_id -> own Description for short-header files
    # (built file-wide by ControllerBuilder so the cross-routine collision gate
    # can see every routine). Empty on long-header, where the lookup is inline.
    _short_routine_desc: Dict[int, str] = field(default_factory=dict)

    def build(self) -> Routine:
        self._cur.execute(
            "SELECT comp_name, object_id, parent_id, record FROM comps WHERE object_id="
            + str(self._object_id)
        )
        results = self._cur.fetchall()

        record = results[0][3]
        name = results[0][0]

        def _typeless_routine() -> Routine:
            # The routine type index still sits at raw record offset 0x3e
            # (1=RLL, 2=FBD, 3=SFC, 4=ST). Recover @Type from it instead of
            # emitting "", and emit no rungs.
            rtype = routine_type_enum(record[0x3e]) if len(record) > 0x3e else ""
            return Routine(name, name, rtype, [])

        try:
            r = RxGeneric.from_bytes(record)
        except Exception:
            return _typeless_routine()
        try:
            # The ext-attr tail parses lazily; materialise it here so a record
            # whose tail cannot be read is handled once, up front.
            r.extended_records
        except Exception:
            # A source-protected routine keeps its prelude and main_record
            # PLAINTEXT and AES-encrypts only the ext-attr tail, replacing the
            # count_record word at body+78 with the SP marker. RxGeneric reads
            # that word as a repeat count, so materialising the tail raises --
            # but the rungs do NOT live in that tail. They come from the
            # region_map/rungs join below, which needs only object_id, and the
            # fields read here (cip_type, comment_id, main_record) are all
            # plaintext. So carry on rather than abandoning the routine's rungs.
            #
            # Scoped to records that actually carry the marker: any OTHER tail
            # failure keeps the previous behaviour exactly, so this cannot change
            # a routine that is not source-protected.
            if record[_SP_MARKER_OFF:_SP_MARKER_OFF + 4] != _SP_MARKER:
                return _typeless_routine()

        routine_type = routine_type_enum(
            struct.unpack_from("<H", r.record_buffer, 0x30)[0]
        )

        self._cur.execute(
            "SELECT rm.object_id, r.rung, rm.unknown FROM region_map rm "
            "LEFT JOIN rungs r ON r.object_id = rm.object_id "
            "WHERE rm.parent_id=" + str(self._object_id) + " ORDER BY rm.unknown"
        )
        # The region map can carry two entries for one rung object_id: an OLD one
        # (lower 'unknown') left behind when the rung was moved, and the LIVE one
        # (higher 'unknown'). The reference emits each rung once, at its live slot,
        # so keep the HIGHEST-'unknown' occurrence per object_id and order the kept
        # rungs by that 'unknown'. An exact duplicate shares its 'unknown', so
        # keep-last == keep-first there and nothing changes; a moved rung lands at
        # its live Number instead of shifting every following rung's text.
        _keep = {}
        for oid, rung, unk in self._cur.fetchall():
            if rung is not None:
                _keep[oid] = (unk, rung)
        rows = [(oid, kv[1]) for oid, kv in
                sorted(_keep.items(), key=lambda item: item[1][0])]
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

        # A tag-based-alarm condition member is stored internally as
        # ``@Alarms._CA<8 hex>_<Name>`` (the ``_CA<id>_`` prefix is the alarm
        # object's generated key); the reference export strips it to
        # ``@Alarms.<Name>``. The prefix is a fixed shape that only this
        # system-generated reference produces, so the rewrite is scoped to the
        # ``@Alarms.`` context and leaves every other operand untouched.
        if any(r and "@Alarms._CA" in r for r in rungs):
            _ALARM_CA_RE = _re.compile(r"(@Alarms\.)_CA[0-9A-Fa-f]{8}_")
            rungs = [_ALARM_CA_RE.sub(r"\1", r) if r else r for r in rungs]

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
                    # 0x6d high byte is the rung-comment record tag). But EVERY
                    # routine in a program shares the one comment_id, so the
                    # parent scope separates nothing, and rc_hi collides across
                    # routines -> a comment binds to a rung in the WRONG routine.
                    # The routine's own key is the high u16 of record[14:18];
                    # each of its rung comments repeats it in the low u16 of
                    # member_ref, so match on it to scope to the true owner.
                    # Verified pool-wide: removes exactly the 15 cross-routine
                    # over-emissions (11 + 2 + 2 across three routines), 0 regressions.
                    short_parent_key = 0x6D0000 | (r.comment_id & 0xFFFF)
                    short_mref_key = (
                        struct.unpack_from("<I", record, 14)[0] >> 16
                        if len(record) >= 18 else -1
                    )
                    self._cur.execute(
                        "SELECT rl.rung_oid, c.record_string FROM regn_link rl "
                        "JOIN comments c ON c.rung_content = rl.rc_hi "
                        "WHERE c.record_type=1 AND c.rung_content!=0 "
                        "  AND rl.group_id=? AND c.parent=? "
                        "  AND (c.member_ref & 65535)=?",
                        (self._object_id, short_parent_key, short_mref_key),
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

        # --- CustomProperties (ACM/library) ---
        # A routine owns a block keyed by its own key at record[14:18] (owner_ref,
        # rung_content 0); each of its rungs owns a block keyed by the same owner
        # with a nonzero rung_content, mapped to the rung Number through the same
        # regn_link join used for rung comments (rc_hi/rc_lo7 scoped to this
        # routine's group_id). Long-header only -- the capture is gated to V24+,
        # so a short-header routine finds no rows.
        routine_cp = ""
        rung_cp: Dict[int, str] = {}
        try:
            _mref = (struct.unpack_from("<I", record, 14)[0]
                     if len(record) >= 18 else 0)
            # Scope parent = the program's key. A routine shares its program's
            # comment_id (record[12:14]), so (comment_id<<16 | 0x68) is the parent
            # every one of the program's ACM blocks stores.
            _scope = ((struct.unpack_from("<H", record, 12)[0] * 0x10000) + 0x68
                      if len(record) >= 14 else 0)
            if _mref and _scope:
                routine_cp = custom_properties_by_scope_owner(
                    self._cur, _scope, _mref) or ""
                if rung_ids and not self._short_header:
                    _oidnum = {oid: i for i, oid in enumerate(rung_ids)}
                    _by_rc: Dict[int, list] = {}
                    for _pid, _ext, _blob, _rc in self._cur.execute(
                            "SELECT provider_id, ext, blob, rung_content "
                            "FROM custom_properties "
                            "WHERE parent=? AND owner_ref=? AND rung_content!=0",
                            (_scope, _mref)):
                        _by_rc.setdefault(_rc, []).append((_pid, _ext, _blob))
                    for _rc, _rows in _by_rc.items():
                        _rl = self._cur.execute(
                            "SELECT rung_oid FROM regn_link "
                            "WHERE rc_hi=? AND rc_lo7=? AND group_id=?",
                            (_rc >> 16, _rc & 127, self._object_id)).fetchall()
                        if len(_rl) == 1:
                            _num = _oidnum.get(_rl[0][0])
                            if _num is not None:
                                _blk = render_custom_properties(_rows)
                                if _blk:
                                    rung_cp[_num] = _blk
        except Exception:
            routine_cp = ""
            rung_cp = {}

        # --- Routine own Description ---
        # A routine's own description is stored in the comments table under the
        # same own-description key scheme used for tags/datatypes. Long-header
        # (V24+): parent == comment_id*0x10000 + cip_type, keyed by the member_ref
        # at record[14:18]; the own description carries object_id==1 (scratch /
        # operand rows that share the key carry a different object_id) and an empty
        # tag_reference. Excluding nonzero rung_content avoids any rung-comment
        # collision under a shared key. Short-header (V10-V21) own descriptions
        # come from the file-wide, collision-gated map built by ControllerBuilder
        # (_build_short_routine_descriptions): the bare-comment_id key collides
        # across a program's routines, so a routine is resolved only when its
        # (parent, member_ref) is unique in the file. Wrapped so any failure
        # degrades to no description.
        description: Union[str, None] = None
        if self._short_header:
            description = self._short_routine_desc.get(self._object_id)
        else:
            try:
                parent_key = (r.comment_id * 0x10000) + r.cip_type
                member_ref = (
                    struct.unpack_from("<I", record, 14)[0]
                    if len(record) >= 18 else 0
                )
                # Language-enabled projects key the own description by the export
                # language's object_id, falling back to the legacy 1.
                _lang_oid = project_lang_oid(self._cur)
                for _doid in ((_lang_oid, 1) if _lang_oid else (1,)):
                    self._cur.execute(
                        "SELECT record_string, tag_reference FROM comments "
                        "WHERE parent=? AND member_ref=? AND object_id=? "
                        "AND (rung_content IS NULL OR rung_content=0) LIMIT 1",
                        (parent_key, member_ref, _doid),
                    )
                    drow = self._cur.fetchone()
                    if drow and drow[0] and not drow[1]:
                        description = drow[0]
                        break
            except Exception:
                description = None

        # Safety routines carry a generated signature. The routine's comps
        # record embeds an (otype, cid, disc) triple at body+10/+12/+16;
        # the 3-key connection_signatures side table holds every GSS signature
        # (routines of one collection share (otype, cid) and differ only by disc, so
        # the 2-key safety_signatures table overwrites all but one -- use the 3-key
        # table). The lookup returns nothing for an unsigned routine (0 false-pos).
        safety_sig = safety_sig_ts = None
        try:
            # The (otype, cid, disc) triple sits at fixed body offsets, not in
            # the attr table; the size-eos comps.record IS the body (offset 0).
            _cf = self._cur.execute(
                "SELECT record FROM comps WHERE object_id=?",
                (self._object_id,)).fetchone()
            if _cf and _cf[0]:
                _rb = bytes(_cf[0])
                if len(_rb) >= 20:
                    _sr = connection_signature_row(self._cur, _rb, 0)
                    if _sr and _sr[0]:
                        safety_sig, safety_sig_ts = _sr[0], _sr[1]
        except Exception:
            pass

        st_lines = (_st_content_lines(self._cur, self._object_id)
                    if routine_type == "ST" else None)
        return Routine(name, name, routine_type, rungs, rung_ids, rung_comments,
                       description, _safety_signature=safety_sig,
                       _safety_signature_timestamp=safety_sig_ts,
                       _st_lines=st_lines,
                       _custom_properties=routine_cp,
                       _rung_custom_properties=rung_cp)


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
    _short_routine_desc: Dict[int, str] = field(default_factory=dict)
    _acd_major: int = field(default=0)

    def build(self) -> AOI:
        self._cur.execute(
            "SELECT comp_name, object_id, parent_id, record FROM comps WHERE object_id="
            + str(self._object_id)
        )
        results = self._cur.fetchall()

        aoi_record = bytes(results[0][3])
        name = results[0][0]
        # The AOI definition comp's own comment_id (u16 @ record offset 12); the
        # short-header Parameter/LocalTag description join keys off it.
        aoi_def_cid = struct.unpack_from("<H", aoi_record, 12)[0] if len(aoi_record) >= 14 else 0

        # The AOI's parameter/local-tag descriptions are keyed (short header) by
        # the comment_id of the AOI's DATATYPE comp -- the cip-0x6c struct under
        # RxDataTypeCollection that shares the AOI name -- NOT the AOI definition
        # comp (cip 0x338) this builder is invoked on. (An AOI's parameters are its
        # datatype members, so they share the datatype's comment_id, as plain UDT
        # members do.) Verified V16: descriptions resolve off this comment_id.
        aoi_comment_id = 0
        aoi_dt_oid = None
        try:
            _dtrow = self._cur.execute(
                "SELECT object_id, record FROM comps WHERE comp_name=? AND parent_id="
                "(SELECT object_id FROM comps WHERE comp_name='RxDataTypeCollection')",
                (name,),
            ).fetchone()
            if _dtrow and _dtrow[1] is not None:
                aoi_dt_oid = _dtrow[0]
                _dtrec = bytes(_dtrow[1])
                try:
                    aoi_comment_id = RxGeneric.from_bytes(_dtrec).comment_id
                except Exception:
                    # Source-protected AOI datatype: read comment_id from the
                    # plaintext main record (only the ext-attr tail is encrypted).
                    _pm = _rxgeneric_plaintext_main(_dtrec)
                    aoi_comment_id = _pm.comment_id if _pm is not None else 0
        except Exception:
            aoi_comment_id = 0
            aoi_dt_oid = None

        # Long-header AOI Parameter/LocalTag descriptions are member descriptions
        # of the AOI's backing datatype, keyed by (datatype comment_id*0x10000 +
        # 0x6c, member_ref) where member_ref is the datatype member record's
        # bytes[14:18] -- the same key the UDT member-description join uses. (The
        # ParameterBuilder's own-comment_id key finds an unrelated row; the real
        # text now also decrypts for source-protected AOIs.) Build a
        # {member_name: description} map once and pass it to the builders, which
        # prefer it over their existing per-tag lookup so nothing regresses. Short
        # header keeps the bare-comment_id + name path inside the builders.
        aoi_member_desc: Dict[str, str] = {}
        if not self._short_header and aoi_comment_id and aoi_dt_oid is not None:
            try:
                _parent = (aoi_comment_id * 0x10000) + 0x6C
                _mc = self._cur.execute(
                    "SELECT object_id FROM comps WHERE parent_id=? AND "
                    "comp_name='RxTypeMemberCollection'", (aoi_dt_oid,)).fetchone()
                if _mc:
                    for _mnm, _mrec in self._cur.execute(
                            "SELECT comp_name, record FROM comps WHERE parent_id=? "
                            "ORDER BY seq_number", (_mc[0],)).fetchall():
                        _mrec = bytes(_mrec)
                        if len(_mrec) < 18:
                            continue
                        _mref = struct.unpack_from("<I", _mrec, 14)[0]
                        _drow = self._cur.execute(
                            "SELECT record_string FROM comments WHERE parent=? AND "
                            "member_ref=? AND record_string!='' LIMIT 1",
                            (_parent, _mref)).fetchone()
                        if _drow and _drow[0]:
                            aoi_member_desc[_mnm] = _drow[0]
            except Exception:
                aoi_member_desc = {}

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
                    # A BOOL ARRAY default is packed 32 bits per DINT word (the
                    # universal Logix rule), sliced whole from the image -- not a
                    # single host bit. Fail closed if the packed words overrun.
                    if dims:
                        total = 1
                        for _d in dims:
                            total *= _d
                        width = ((total + 31) // 32) * 4
                        if width <= 0 or off + width > len(defval_image):
                            return None
                        return defval_image[off:off + width]
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
        e01 = b""
        try:
            r = RxGeneric.from_bytes(aoi_record)
            _r_aoi = r
            exts: Dict[int, bytes] = {e.attribute_id: bytes(e.value) for e in r.extended_records}
            e01 = exts.get(0x01, b"")
        except Exception:
            # Source-protected AOI: recover comment_id/cip_type from the plaintext
            # main record so the own-description lookup below still runs (the
            # description text is decrypted in the comments table), and decrypt the
            # ext tail so the revision + execute flags below are still recovered.
            _r_aoi = _rxgeneric_plaintext_main(aoi_record)
            try:
                e01 = CompsRecord.read_ext_attrs_from_record(aoi_record).get(0x01, b"")
            except Exception:
                e01 = b""

        # --- Revision (major.minor) ---
        # The major/minor u16 pair sits at a length-discriminated offset in ext[0x01]:
        # 0x9C/0x9E on the long (>= 0x160 byte) blob, 0x1A/0x1C on the shorter blobs --
        # the blob length, not the file's header family, selects the layout. The few
        # AOIs with no ext[0x01] carry the revision inline at the second "20 24"
        # marker. Never emit "0.0"; fall back to the 1.0 default.
        rev_major = rev_minor = 0
        _legacy_noe01 = False
        if e01:
            _moff, _noff = (0x9C, 0x9E) if len(e01) >= 0x160 else (0x1A, 0x1C)
            if len(e01) > _noff + 1:
                rev_major = struct.unpack_from("<H", e01, _moff)[0]
                rev_minor = struct.unpack_from("<H", e01, _noff)[0]
        elif (len(aoi_record) > 0x11D and aoi_record[0x11B] == 0
              and aoi_record[0x11D] == 0
              and (aoi_record[0x11A] or aoi_record[0x11C])):
            # Older AOI schema (no ext-attr 0x01, e.g. V16-17 imported libraries):
            # the revision is a zero-padded major u16 @ 0x11A / minor u16 @ 0x11C
            # in the definition record. The zero-high-byte guard (bytes
            # 0x11B/0x11D == 0) fences this off from OTHER no-ext01 schemas whose
            # 0x11A holds unrelated data -- such a record fails the guard and
            # drops to the legacy "20 24" scan below (today's output, 0-worse).
            rev_major = struct.unpack_from("<H", aoi_record, 0x11A)[0]
            rev_minor = struct.unpack_from("<H", aoi_record, 0x11C)[0]
            _legacy_noe01 = True
        else:
            _offs = [i for i in range(len(aoi_record) - 1)
                     if aoi_record[i] == 0x20 and aoi_record[i + 1] == 0x24]
            if len(_offs) >= 2 and _offs[1] + 26 <= len(aoi_record):
                rev_major = struct.unpack_from("<H", aoi_record, _offs[1] + 22)[0]
                rev_minor = struct.unpack_from("<H", aoi_record, _offs[1] + 24)[0]
        revision = f"{rev_major}.{rev_minor}" if (rev_major or rev_minor) else "1.0"

        # --- Execute flags from ext[0x01] byte 0x02 ---
        # bit 0 = ExecuteEnableInFalse, bit 4 = ExecutePrescan (both present in the
        # plaintext ext on normal AOIs and in the decrypted ext tail on
        # source-protected ones; 0 false-positives pool-wide). ExecutePostscan is
        # never set in the reference, so it stays "false". Fail-safe to "false" when
        # the ext is absent/too short.
        if len(e01) > 0x02:
            _flag_byte = e01[0x02]
        elif _legacy_noe01 and len(aoi_record) > 0x80:
            # The same execution-config bitfield (bit0 = EnableInFalse,
            # bit4 = Prescan), carried at record offset 0x80 in the older no-ext01
            # schema. Trusted only when the revision gate above confirmed that
            # schema (_legacy_noe01); every other no-ext01 record keeps the 0
            # default (false), i.e. today's output.
            _flag_byte = aoi_record[0x80]
        else:
            _flag_byte = 0
        execute_enable_in_false = "true" if (_flag_byte & 0x01) else "false"
        execute_prescan = "true" if (_flag_byte & 0x10) else "false"

        # --- Vendor from the decrypted ext-attr 0x01 ---
        # Vendor is a length-prefixed UTF-8 string in ext[0x01]: four zero bytes, a
        # u16 length, then the string. Locate it structurally (the only such field
        # carrying a printable ASCII value in the AOI blob) so the read is independent
        # of the blob layout/version AND works on the decrypted tail of a
        # source-protected AOI -- the previous read of the truncated record at a fixed
        # 0xA6/0xA8 slot was wrong on both counts. An AOI with no Vendor stores a zero
        # length here, so no candidate is found and the attribute is omitted (verified
        # 0 false-positives pool-wide; the structural candidate is unique and equals
        # the Vendor on every AOI that carries one).
        vendor: Union[str, None] = None
        for _p in range(6, len(e01) - 1):
            if e01[_p - 6:_p - 2] != b"\x00\x00\x00\x00":
                continue
            _vl = struct.unpack_from("<H", e01, _p - 2)[0]
            if not (0 < _vl <= 64) or _p + _vl > len(e01):
                continue
            try:
                _vendor = e01[_p:_p + _vl].decode("utf-8")
            except UnicodeDecodeError:
                continue
            if (_vendor.strip() and all(0x20 <= ord(c) < 0x7F for c in _vendor)
                    and _xml_sane(_vendor) == _vendor):
                vendor = _vendor
                break

        # --- Metadata from large nameless record ---
        self._cur.execute(
            "SELECT record FROM nameless WHERE parent_id=" + str(self._object_id)
            + " ORDER BY LENGTH(record) DESC LIMIT 1"
        )
        nameless_row = self._cur.fetchone()
        if nameless_row and len(bytes(nameless_row[0])) > 50:
            nm_rec = bytes(nameless_row[0])
            # Source-protected AOIs store the metadata body (CreatedBy/EditedBy/
            # SoftwareRevision/RevisionExtension/dates) AES-encrypted behind the
            # aa96aa0a marker. Decrypt it back to the ordinary plaintext layout so
            # the same parser recovers them; the strings are UTF-16-LE, same as a
            # non-protected record. Degrades to the raw record (-> empty/garbage,
            # i.e. today's behaviour) when no project SP key validates.
            if _SP_MARKER in nm_rec:
                _dec = decrypt_sp_nameless(nm_rec)
                if _dec is not None:
                    nm_rec = _dec
            meta = _parse_aoi_nameless(nm_rec)
        else:
            meta = {"created_by": "", "created_date": "", "edited_by": "", "edited_date": "",
                    "software_revision": "", "revision_extension": None}

        parameters: List[Parameter] = []
        local_tags: List[LocalTag] = []
        routines: List[Routine] = []
        # Dead-relic (FDFD-only) AOI children are deleted params/tags/routines
        # Studio never exports; skip them in both enums below (P6.9). Defensive
        # today (zero FDFD-only children under any live AOI subtree pool-wide).
        dead = CompsRecord.dead_oids(self._cur, self._short_header)

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
                "SELECT object_id, record, record_type, comp_name FROM comps WHERE parent_id="
                + str(tag_coll_oid)
                + " AND record_type != 512"
                + " ORDER BY seq_number"
            )
            for child_oid, child_rec, child_rt, child_name in self._cur.fetchall():
                if child_oid in dead:
                    continue
                # Hidden/internal scratch local tags (__l<hex> address placeholders)
                # carry the record_type 0x8 bit and a "__" name; Studio never
                # exports them. Both conditions guard the skip (never drop a real tag).
                if child_rt & 0x8 and (child_name or "").startswith("__"):
                    continue
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
                    # Compact AOI-tag format (rt 260/1284): the 0x01 identity attr
                    # is the ext-attr tail's TERMINAL record, which
                    # extended_records excludes. Recover it so the usage
                    # classifier sees the real direction byte instead of an empty
                    # blob (which routes every param to a LocalTag).
                    if 0x01 not in exts_child:
                        _lc = getattr(r_child, "last_attribute_record", None)
                        if _lc is not None and getattr(_lc, "attribute_id", None) == 1:
                            exts_child[0x01] = bytes(_lc.value)
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
                        p = ParameterBuilder(self._cur, child_oid, _short_header=self._short_header, _owner_comment_id=aoi_comment_id, _member_desc=aoi_member_desc, _owner_def_cid=aoi_def_cid).build()
                        # Wire the value-emission maps so <DefaultData> can be
                        # built (mirrors how TagBuilder receives them). Failure
                        # to attach degrades to no-DefaultData, never crashes.
                        try:
                            p._data_types_map = self._data_types_map
                            p._taginfo_layout = self._taginfo_layout
                            p._short_header = self._short_header
                            p._raw_hex_data = _raw_hex_first(
                                self._short_header, self._acd_major)
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
                        lt = LocalTagBuilder(self._cur, child_oid, _short_header=self._short_header, _owner_comment_id=aoi_comment_id, _member_desc=aoi_member_desc, _owner_def_cid=aoi_def_cid).build()
                        try:
                            lt._data_types_map = self._data_types_map
                            lt._taginfo_layout = self._taginfo_layout
                            lt._short_header = self._short_header
                            lt._raw_hex_data = _raw_hex_first(
                                self._short_header, self._acd_major)
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
                if child_oid in dead:
                    continue
                try:
                    routines.append(RoutineBuilder(
                        self._cur, child_oid,
                        _short_header=self._short_header,
                        _short_routine_desc=self._short_routine_desc).build())
                except Exception:
                    pass

        # --- Description + RevisionNote + AdditionalHelpText ---
        aoi_description: Union[str, None] = None
        revision_note = ""
        additional_help = ""
        aoi_cp = ""
        if _r_aoi is not None:
            aoi_comment_parent = (_r_aoi.comment_id * 0x10000) + _r_aoi.cip_type
            try:
                # ACM/library <CustomProperties>: the AOI definition owns its block
                # keyed by its own comment parent (cip 0x338), owner_ref 0.
                aoi_cp = custom_properties_by_parent(
                    self._cur, aoi_comment_parent) or ""
            except Exception:
                aoi_cp = ""
            if self._short_header:
                # sub_record_length filter skips the cip-0x68 tag that may share
                # this comment_id (the AOI's own cip is 0x338).
                aoi_description = short_own_description(
                    self._cur, _r_aoi.comment_id, _r_aoi.cip_type)
            else:
                # The extended-help rows under the same key carry a nonzero
                # object_id (with a tag_reference such as UDI_EXT_HELP) and are
                # not emitted by OEM as a Description; own_description's
                # object_id == 1 filter excludes them.
                aoi_description = own_description(self._cur, aoi_comment_parent)
            try:
                # RevisionNote (UDI_HISTORY) keys on the bare comment_id in the
                # short-header family and on the long comment key otherwise
                # (same as UDI_EXT_HELP below).
                self._cur.execute(
                    "SELECT record_string FROM comments "
                    "WHERE parent IN (?, ?) AND tag_reference='__REVISION_NOTE__' "
                    "LIMIT 1",
                    (_r_aoi.comment_id, aoi_comment_parent),
                )
                rn_row = self._cur.fetchone()
                if rn_row:
                    revision_note = rn_row[0] or ""
            except Exception:
                pass
            try:
                # UDI_EXT_HELP rows key on the bare comment_id in the
                # short-header family and on the long comment key otherwise.
                self._cur.execute(
                    "SELECT record_string FROM comments "
                    "WHERE parent IN (?, ?) AND tag_reference='__EXT_HELP__' "
                    "LIMIT 1",
                    (_r_aoi.comment_id, aoi_comment_parent),
                )
                ah_row = self._cur.fetchone()
                if ah_row:
                    additional_help = ah_row[0] or ""
            except Exception:
                pass

        # @Class on a safety-controller project: Standard vs Safety per the AOI's
        # stored class enum, a u16 at ext-attr 0x01 offset 0x7C (0 = Standard,
        # 6 = Safety; verified string-exact on every classed AOI in both pools: 9
        # Safety at code 6, 206 Standard at code 0). Fail-closed: an absent/short
        # ext-attr or any unknown code keeps "Standard" (today's value). Omitted
        # entirely on a non-safety project (no SafetyController comp).
        aoi_class: Union[str, None] = None
        try:
            _rcc = self._cur.execute(
                "SELECT object_id FROM comps WHERE comp_name='RxControllerCollection' "
                "LIMIT 1").fetchone()
            if _rcc and self._cur.execute(
                    "SELECT 1 FROM comps WHERE parent_id=? AND comp_name="
                    "'SafetyController' LIMIT 1", (_rcc[0],)).fetchone():
                aoi_class = "Standard"
                if len(e01) > 0x7D and struct.unpack_from("<H", e01, 0x7C)[0] == 6:
                    aoi_class = "Safety"
        except Exception:
            aoi_class = None

        return AOI(
            name, name, aoi_class, revision,
            meta["revision_extension"],
            vendor,
            execute_prescan, "false", execute_enable_in_false,
            meta["created_date"], meta["created_by"],
            meta["edited_date"], meta["edited_by"],
            meta["software_revision"],
            parameters, local_tags, routines,
            aoi_description,
            revision_note,
            _additional_help_text=additional_help,
            _custom_properties=aoi_cp,
        )


# A source-protected AOI/ROUTINE is exported by Studio as an <EncodedData> blob
# (EncodedType "AddOnInstructionDefinition"/"Routine") rather than the plaintext
# element; in faithful mode our decoder must suppress the definition it recovers,
# or it over-emits (element_extra). The per-definition protection state lives in
# the definition's comps record (AOI: record_type 256 under
# RxUDIDefinitionCollection; routine: under RxRoutineCollection) in two layouts,
# and is decided STRUCTURALLY so the verdict is independent of where the comps
# record buffer is truncated (the size-eos un-truncation only appends bytes past
# the tail; every field read here sits early in the record).
#
#   * Encrypted-tail layout (V21 source-protected-at-rest): the ext-attr tail is
#     AES-encrypted and its plaintext count at body+78 is replaced by _SP_MARKER.
#     The 6 bytes at marker+14 flag a genuinely protected definition
#     (00 00 01 00 10 00) versus a plaintext-at-rest look-alike whose rungs Studio
#     re-decrypts and exports as plaintext (00 00 00 07 ..) -- the
#     the plaintext-at-rest look-alike projects, never suppressed.
#   * Plaintext key-bearing layout: a security-descriptor block inside ext-attr
#     0x1, at a fixed offset regardless of the attribute's order in the record.
#     Two forms share its key slot, and only one of them is key-bearing:
#       - padded key: the key is followed by zero padding out to the slot's
#         end, and the slot's leading 16 bytes are a protection-key hash -- a
#         real per-license hash when protected, the fixed no-protection
#         sentinel when source-protection is enabled-but-off, all-zero (or the
#         attribute is short, or absent on a definition layout without
#         source-protection support) otherwise.
#       - filled slot: the padding region is instead occupied by a
#         per-definition source key wrapped under the scheme's own config-5
#         material. The slot holds no plaintext key, so the "not zero and not
#         the sentinel" test is vacuously true for every such definition and
#         flags the whole file. source_key_unwraps() reads the real bit: a
#         definition is protected iff its wrapped key unwraps to a well-formed
#         plaintext (a public key we hold, plus a structural self-check). The
#         definitions Studio ships as plaintext share this form but carry no
#         valid wrapped key, so they fall through. keyhash_slot_readable()
#         remains the backstop for any other filled form (it keeps
#         encoded_data.security_descriptor() from reading a blob as a key).
#
# This is exact both ways over the paired corpus: on the filled-slot form the
# only misses are the PackMLv3 library seals, whose key is Rockwell library
# material we do not hold -- their wrapped key does not unwrap, so they read as
# plaintext (a documented floor, not a bug to chase). The short-key padded form
# ends before the pad; keyhash_slot_readable() returning True there is
# load-bearing -- a False would silently suppress that whole family of genuinely
# protected routines, most of them in version-skewed files the gauntlet scores 0
# on and cannot see.
#
# What IS cheaply re-measurable, and what a change here must not break: a record
# sweep (needs no reference) over both pools' definition records, checking the
# wrapped-key verdict against whether the reference ships each definition as
# <EncodedData>. Verify with the sweep, never with the gauntlet -- the decisive
# files are few and one is version-skewed.
_AOI_NO_PROTECTION_HASH = bytes.fromhex("4d53d3ff6f158fc1cbf49bcdc8d2f9a7")
_SP_MARKER_OFF = 78                                # SP-at-rest marker at body+78
_SP_PROTECTED_FLAG = bytes.fromhex("000001001000")  # marker+14..+20 -> protected
_AOI_KEYHASH_OFF = 272   # protection-key hash offset within ext-attr 0x1 (AOI)
_RT_KEYHASH_OFF = 202    # ... and for a routine definition record
_SP_ZERO_HASH = b"\x00" * 16


def _ext_attr01(rec: bytes):
    """Return ext-attr 0x1's value from a plaintext RxGeneric body (the comps
    ``record`` column), or None. Walks ``(u32 id, u32 len, bytes)`` records from
    body+82 (past the 14B prelude + 60B main_record + len/count words)."""
    pos, n = 82, len(rec)
    while pos + 8 <= n:
        attr_id = int.from_bytes(rec[pos:pos + 4], "little")
        ln = int.from_bytes(rec[pos + 4:pos + 8], "little")
        pos += 8
        if ln < 0 or pos + ln > n:
            break
        if attr_id == 1:
            return rec[pos:pos + ln]
        pos += ln
    return None


def _definition_is_source_protected(rec: bytes, keyhash_off: int) -> bool:
    """Structural source-protection test shared by AOI and routine definitions
    (see the layout note above). ``keyhash_off`` is the family's protection-key
    hash offset within ext-attr 0x1."""
    if rec[_SP_MARKER_OFF:_SP_MARKER_OFF + 4] == _SP_MARKER:
        return rec[_SP_MARKER_OFF + 14:_SP_MARKER_OFF + 20] == _SP_PROTECTED_FLAG
    a1 = _ext_attr01(rec)
    if a1 is None or len(a1) < keyhash_off + 16:
        return False
    if a1[keyhash_off:keyhash_off + 2] == _WRAPPED_KEY_VERSION:
        # Filled-slot (wrapped-key) form: protected iff the per-definition key
        # unwraps. Exact both ways -- unlike the zero-pad reject below, which
        # treats every filled slot as unprotected and so wrongly shows the few
        # protected ones as plaintext.
        return source_key_unwraps(a1, keyhash_off)
    if not keyhash_slot_readable(a1, keyhash_off):
        return False
    key_hash = a1[keyhash_off:keyhash_off + 16]
    return key_hash != _SP_ZERO_HASH and key_hash != _AOI_NO_PROTECTION_HASH


def _aoi_is_source_protected(rec: bytes) -> bool:
    return _definition_is_source_protected(rec, _AOI_KEYHASH_OFF)


def _routine_is_source_protected(rec: bytes) -> bool:
    return _definition_is_source_protected(rec, _RT_KEYHASH_OFF)


def _tagcoll_sig_attrs(cur, oid, short_header):
    """Rendered SafetySignature/SafetySignatureTimestamp attribute string for a
    <Tags> collection, or "" when unsigned. The collection's comps record
    embeds an (otype, cid, disc) triple at body+10/+12/+16 that keys the
    connection_signatures side table (which holds every GSS signature)."""
    try:
        # The triple sits at fixed body offsets, not in the attr table; the
        # size-eos comps.record IS the body (offset 0).
        cf = cur.execute("SELECT record FROM comps WHERE object_id=?", (oid,)).fetchone()
        if not cf or not cf[0]:
            return ""
        rb = bytes(cf[0])
        if len(rb) < 20:
            return ""
        sr = connection_signature_row(cur, rb, 0)
        if sr and sr[0]:
            a = f' SafetySignature="{sr[0]}"'
            if sr[1]:
                a += f' SafetySignatureTimestamp="{html.escape(sr[1], quote=True)}"'
            return a
    except Exception:
        pass
    return ""


def _utf16z(buf, start):
    """Decode a NUL-terminated UTF-16-LE string at buf[start:], scanning the
    terminator on a 2-byte boundary. Returns (string, index past terminator)."""
    i = start
    while i + 1 < len(buf) and not (buf[i] == 0 and buf[i + 1] == 0):
        i += 2
    return buf[start:i].decode("utf-16-le", "replace"), i + 2


def _safety_signature_attr_value(cur, rec):
    """The <SafetyInfo> @SafetySignature value ('HEXWORDS, date, time') or None.
    Short-header projects keep the single-word signature in a Nameless.Dat record
    marked 94 8f c2 c7 47 ad d9 f3 (the hash then a separate date + time string);
    long-header projects store a contiguous uppercase-hex run plus a length-prefixed
    (0x1b) timestamp inside the SafetyController record."""
    try:
        for (nr,) in cur.execute("SELECT record FROM nameless").fetchall():
            nr = bytes(nr)
            if len(nr) < 24 or nr[8:16] != bytes.fromhex("948fc2c747add9f3"):
                continue
            sighex = "%08X" % struct.unpack_from("<I", nr, 20)[0]
            date, nx = _utf16z(nr, 24)
            tm, _ = _utf16z(nr, nx)
            return f"{sighex}, {date}, {tm}"
    except Exception:
        pass
    mh = re.search(rb"[0-9A-F]{16,}", rec)
    mt = re.search(
        rb"\x1b\x00\x00\x00(\d\d/\d\d/\d{4}, \d\d:\d\d:\d\d\.\d{3} [AP]M)", rec)
    if mh and mt:
        h = mh.group().decode()
        if len(h) % 8 == 0 and set(h) != {"0"}:
            words = " - ".join(h[i:i + 8] for i in range(0, len(h), 8))
            return words + ", " + mt.group(1).decode()
    return None


def _safety_info_attr_string(cur, short_header):
    """Attribute string for the <SafetyInfo> open tag, recovered from the
    SafetyController comps record; '' when the project has no SafetyController (an
    unsigned / non-safety project, which keeps the empty <SafetyInfo/>). The
    SafetyController record is present in exactly the projects whose reference
    <SafetyInfo> carries attributes, so this is 0-false-positive."""
    row = cur.execute(
        "SELECT record FROM comps WHERE comp_name='SafetyController'").fetchone()
    if not row or not row[0]:
        return ""
    rec = bytes(row[0])
    attrs: Dict[str, str] = {}
    anch = rec.find(bytes.fromhex("34030000ffffffff00000000ffffffff"))
    if anch >= 0 and len(rec) > anch + 80:
        attrs["SafetyLocked"] = "true" if rec[anch + 78] == 1 else "false"
        attrs["ConfigureSafetyIOAlways"] = "true" if rec[anch + 80] == 1 else "false"
        attrs["SignatureRunModeProtect"] = "false"
    if not short_header:
        attrs["SafetyLevel"] = "SIL2/PLd"
    sig = _safety_signature_attr_value(cur, rec)
    if sig:
        attrs["SafetySignature"] = sig
    # Lock/Unlock passwords: 40-byte blocks following each 0x28 0x00 marker, in
    # record order (first = Lock, second = Unlock; a single block = Unlock only).
    # The encoding is keyed by the block's own leading format byte, NOT the count:
    # 0x01 is the binary-hash form Studio exports verbatim base64; any other lead
    # byte is the legacy 8-bit form Studio widens cp1252 -> UTF-16-LE before
    # base64. (The count-keyed rule this replaces coincided with the content rule
    # only on the legacy blocks and dropped every 0x01 block, since cp1252 raises
    # on the binary bytes.)
    blocks = []
    pos = 0
    while True:
        j = rec.find(b"\x28\x00", pos)
        if j < 0:
            break
        blk = rec[j + 2:j + 2 + 40]
        if len(blk) == 40:
            blocks.append(blk)
        pos = j + 2

    def _enc_block(blk):
        # Fail closed: a legacy block that is not decodable cp1252 -> None.
        if blk[0] == 0x01:
            return base64.b64encode(blk).decode().rstrip("=")
        try:
            return base64.b64encode(
                blk.decode("cp1252").encode("utf-16-le")).decode().rstrip("=")
        except Exception:
            return None
    if len(blocks) >= 2:
        lock = _enc_block(blocks[0])
        unlock = _enc_block(blocks[1])
        if lock:
            attrs["SafetyLockPassword"] = lock
        if unlock:
            attrs["SafetyUnlockPassword"] = unlock
    elif len(blocks) == 1:
        unlock = _enc_block(blocks[0])
        if unlock:
            attrs["SafetyUnlockPassword"] = unlock
    order = ("SafetySignature", "SafetyLocked", "SafetyLockPassword",
             "SafetyUnlockPassword", "SignatureRunModeProtect",
             "ConfigureSafetyIOAlways", "SafetyLevel")
    return "".join(f' {k}="{html.escape(attrs[k], quote=True)}"'
                   for k in order if k in attrs)


@dataclass
class ProgramBuilder(L5xElementBuilder):
    _data_types_map: Dict[str, "DataType"] = field(default_factory=dict)
    _redundancy_enabled: bool = field(default=False)
    _short_header: bool = field(default=False)
    _taginfo_layout: Dict[str, object] = field(default_factory=dict)
    _acd_major: int = field(default=0)
    # {owner_tag_object_id -> rendered <AlarmConditions>} for program-scope tags.
    _alarm_map: Dict[int, str] = field(default_factory=dict)
    # {routine_object_id -> own Description} for short-header files (collision-gated).
    _short_routine_desc: Dict[int, str] = field(default_factory=dict)
    # Faithful mode: omit source-protected routines (Studio exports them as
    # <EncodedData>) instead of recovering their plaintext. Default False = recover.
    _faithful: bool = field(default=False)

    def build(self) -> Program:
        self._cur.execute(
            "SELECT comp_name, object_id, parent_id, record FROM comps WHERE object_id="
            + str(self._object_id)
        )
        results = self._cur.fetchall()

        prog_record = bytes(results[0][3])
        name = results[0][0]

        # V10..V21 program bodies are source-protected/opaque -> decrypt the ext
        # tail so the routine references below still resolve.
        try:
            r = RxGeneric.from_bytes(prog_record)
            exts: Dict[int, bytes] = {e.attribute_id: bytes(e.value) for e in r.extended_records}
            _prog_comment_parent = (r.comment_id * 0x10000) + r.cip_type
        except Exception:
            r = None
            try:
                exts = CompsRecord.read_ext_attrs_from_record(prog_record)
            except Exception:
                exts = {}
            _prog_comment_parent = None
        _rxok = r is not None

        # routine object_id -> name for this program (children of its
        # RxRoutineCollection) -- the namespace MainRoutine/FaultRoutine reference.
        routs: Dict[int, str] = {}
        _rcoll = self._cur.execute(
            "SELECT object_id FROM comps WHERE parent_id=? AND "
            "comp_name='RxRoutineCollection' LIMIT 1", (self._object_id,)).fetchone()
        if _rcoll:
            for _rn, _ro in self._cur.execute(
                    "SELECT comp_name, object_id FROM comps WHERE parent_id=?",
                    (_rcoll[0],)).fetchall():
                routs[_ro] = _rn

        # --- MainRoutineName / FaultRoutineName ---
        # MainRoutine object_id is ext[0x12D] (long header / decrypted SP) or, when
        # absent, the u32 at record offset 0x1C6 (short header); resolve it within
        # THIS program's routines (a global comp lookup pulled in unrelated comps and
        # missed source-protected programs). A program with neither reference but
        # exactly one routine named "main" uses that. FaultRoutine is ext[0x066],
        # emitted only when it is a real (non-sentinel) routine of this program --
        # the prior global lookup matched a junk object_id 0xFFFFFFFF comp and
        # emitted a bogus FaultRoutineName.
        main_routine_name: Union[str, None] = None
        fault_routine_name: Union[str, None] = None
        if 0x12D in exts and len(exts[0x12D]) >= 4:
            _mo = struct.unpack_from("<I", exts[0x12D], 0)[0]
            if _mo in routs:
                main_routine_name = routs[_mo]
        if main_routine_name is None and _rxok and len(prog_record) >= 0x1CA:
            _mo = struct.unpack_from("<I", prog_record, 0x1C6)[0]
            if _mo in routs:
                main_routine_name = routs[_mo]
        if main_routine_name is None:
            _cand = [n for n in routs.values() if n.lower() == "main"]
            if len(_cand) == 1:
                main_routine_name = _cand[0]
        if 0x066 in exts and len(exts[0x066]) >= 4:
            _fo = struct.unpack_from("<I", exts[0x066], 0)[0]
            if _fo and _fo != 0xFFFFFFFF and _fo in routs:
                fault_routine_name = routs[_fo]

        # --- Disabled flag: the single byte at ext[0x01] offset 0x24 ---
        # 0xFF = disabled, 0x00 = enabled. Only this byte is the flag; the three
        # bytes above it are an unrelated field that the old u32 read mistook for a
        # set flag (false positives) on the long program layout.
        ext01 = exts.get(0x01, b"")
        disabled = "true" if (len(ext01) > 0x24 and ext01[0x24] != 0) else "false"
        if len(prog_record) < 2000:
            # Short program layout: the enable state is the record byte at
            # 0x10C (0xFF disabled / 0x00 enabled); ext[0x01] has no flag
            # there. Byte-validated pool-wide (42 disabled / 839 enabled).
            disabled = "true" if (len(prog_record) > 0x10C
                                  and prog_record[0x10C] != 0) else "false"

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

        dead = CompsRecord.dead_oids(self._cur, self._short_header)
        routines = []
        for child in routine_results:
            # A dead-relic (FDFD-only) routine is a deleted routine Studio never
            # exports; skip it (P6.9). This is the visible C3 win: one project's
            # spare programs carry such relics we currently over-emit.
            if child[1] in dead:
                continue
            # In faithful mode, a source-protected routine is exported by Studio as
            # <EncodedData>, not a plaintext <Routine>. Rebuild that blob when every
            # input resolves; otherwise emit nothing rather than fabricate one.
            # Recovery mode keeps the decoded plaintext routine.
            rec = bytes(child[3])
            protected = self._faithful and _routine_is_source_protected(rec)
            _rt = RoutineBuilder(
                self._cur, child[1], _short_header=self._short_header,
                _short_routine_desc=self._short_routine_desc).build()
            # A relic routine with no body decodes as Type="TypeLess" (routine
            # type index 0). OEM emits zero TypeLess routines pool-wide, so drop
            # them rather than fabricate a phantom <Routine>.
            if _rt.type in ("TypeLess", "Typeless"):
                continue
            if protected:
                a1 = _ext_attr01(rec)
                _rt._encoded = encoded_routine(
                    _rt, a1, _RT_KEYHASH_OFF,
                    source_protection_config(rec, a1, _RT_KEYHASH_OFF))
                if _rt._encoded is None:
                    continue
            routines.append(_rt)

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
            _prog_cid = (
                struct.unpack_from("<H", prog_record, 12)[0]
                if self._short_header and len(prog_record) >= 14 else 0
            )
            for result in self._cur.fetchall():
                if result[1] in dead:  # dead-relic (FDFD-only) tag -> skip (P6.9)
                    continue
                # Hidden/internal scratch tags (__SHADOW_/__DEFVAL_/__Map...) carry
                # the record_type 0x8 bit and a "__" name; Studio never exports them.
                # Both conditions guard the skip so a real tag is never dropped.
                if result[3] & 0x8 and (result[0] or "").startswith("__"):
                    continue
                _tb = TagBuilder(self._cur, result[1], _short_header=self._short_header,
                                 _acd_major=self._acd_major, _program_cid=_prog_cid,
                                 _taginfo_layout=self._taginfo_layout)
                tag = _tb.build()
                tag._data_types_map = self._data_types_map
                tag._taginfo_layout = self._taginfo_layout
                tag._alarm_xml = self._alarm_map.get(result[1], "")
                tags.append(tag)

        # SynchronizeRedundancyDataAfterExecution: present only for redundant controllers.
        # The binary does not expose a per-program flag for this attribute — it is implicit
        # for all programs in a redundant controller project.
        sync_redundancy = "true" if self._redundancy_enabled else None

        # UseAsFolder: the reference emits this attribute for every LONG-layout
        # program record and omits it for every short-layout one, regardless of
        # project version -- the record layout, not the save version, is the
        # deterministic signal. A folder program (no schedulable content of its
        # own) has record byte 0x119 == 0 AND u32 @0x60 == 0; both are nonzero
        # on every non-folder program. Validated 100% on ~1,600 long records
        # across both reference pools (157 folders, 0 confusions).
        use_as_folder: Union[str, None] = None
        if len(prog_record) >= 2000:
            use_as_folder = (
                "true" if (prog_record[0x119] == 0 and
                           struct.unpack_from("<I", prog_record, 0x60)[0] == 0)
                else "false")

        # --- Program own Description ---
        # Long header: object_id==1 own-description key. Short header (V10-V21):
        # the bare comment_id with sub_record_length == the owner cip. A program's
        # cip is 0x68 -- the SAME as ordinary tags -- so the cip filter alone
        # cannot tell a program-own row from a colliding tag row at a shared
        # comment_id; require EXACTLY ONE matching row (else a collision is
        # present and the description is dropped rather than fabricated).
        program_description: Union[str, None] = None
        if self._short_header:
            if len(prog_record) >= 14:
                _pcid = struct.unpack_from("<H", prog_record, 12)[0]
                _pcip = struct.unpack_from("<H", prog_record, 10)[0]
                program_description = short_own_description(
                    self._cur, _pcid, _pcip, require_unique=True)
        elif _prog_comment_parent is not None:
            program_description = own_description(self._cur, _prog_comment_parent)

        # Class: a safety controller marks each program Safety/Standard with a byte
        # at record offset 0x173 (short layout) / 0xE5 (long); standard controllers
        # omit @Class.
        prog_cls: Union[str, None] = None
        if self._cur.execute(
                "SELECT 1 FROM comps WHERE comp_name='SafetyController' "
                "AND record_type=256 LIMIT 1").fetchone():
            if len(prog_record) < 2000:
                prog_cls = ("Safety" if (len(prog_record) > 0x173
                            and prog_record[0x173] == 6) else "Standard")
            else:
                prog_cls = ("Safety" if (len(prog_record) > 0xE5
                            and prog_record[0xE5] == 6) else "Standard")

        # Safety signature: a signed safety program joins the side table by its
        # object type (record[0x0A]) and comment id (record[0x0C]).
        prog_sig = prog_sig_ts = None
        if len(prog_record) >= 16:
            _srow = safety_signature_row(self._cur, prog_record)
            if _srow:
                prog_sig, prog_sig_ts = _srow[0], _srow[1]

        # ACM/library <CustomProperties>: the program owns its block keyed by its
        # own comment parent (cip 0x68), owner_ref 0.
        prog_cp = ""
        if _prog_comment_parent is not None:
            try:
                prog_cp = custom_properties_by_parent(
                    self._cur, _prog_comment_parent) or ""
            except Exception:
                prog_cp = ""

        prog = Program(name, name, prog_cls, "false", main_routine_name,
                       fault_routine_name, disabled, sync_redundancy, use_as_folder,
                       tags, routines, safety_signature=prog_sig,
                       safety_signature_timestamp=prog_sig_ts,
                       _description=program_description,
                       _custom_properties=prog_cp)
        # The program-scoped <Tags> collection carries its own safety signature,
        # distinct from the program's. Render it on the <Tags> wrapper. Program has no
        # _section_attrs by default (the base to_xml reads it via getattr), so create it.
        if results:
            _ta = _tagcoll_sig_attrs(self._cur, results[0][1], self._short_header)
            if _ta:
                prog._section_attrs = {"tags": _ta}
        return prog


_TASK_TYPE_MAP = {1: "EVENT", 2: "PERIODIC", 4: "CONTINUOUS"}


def _read_task_config(e01: bytes):
    """Recover (type, rate, priority, watchdog, disable, inhibit) from a task's
    ext-attr 0x01 blob, or None if the blob is absent / an unrecognised layout.

    Type/Priority/Rate sit at fixed offsets from the START of the blob (a short
    layout at 0x28C, a long one at 0x109C); Watchdog/DisableUpdateOutputs/
    InhibitTask sit at fixed offsets from the END (a variable middle section moves
    them within the record, but the tail is constant: Watchdog u32 at len-0x64,
    the two flag bits at len-0x40 / len-0x3C). Rate/Watchdog are microseconds; a
    sub-millisecond value is rendered with three decimals to match the reference.
    The Type word must read as a valid enum or the layout is unrecognised -> None
    (caller falls back) so a wrong layout never emits garbage config.
    """
    L = len(e01)
    if L < 0x64:
        return None
    t_off, p_off, r_off = (0x28C, 0x28E, 0x202) if L < 2000 else (0x109C, 0x109E, 0x1012)
    if t_off + 2 > L:
        return None
    type_val = struct.unpack_from("<H", e01, t_off)[0]
    if type_val not in _TASK_TYPE_MAP:
        return None
    task_type = _TASK_TYPE_MAP[type_val]

    def _ms(us):
        return str(us // 1000) if us % 1000 == 0 else "%.3f" % (us / 1000.0)

    priority = str(struct.unpack_from("<H", e01, p_off)[0]) if p_off + 2 <= L else "10"
    rate = None
    if task_type != "CONTINUOUS" and r_off + 4 <= L:
        rate = _ms(struct.unpack_from("<I", e01, r_off)[0])
    # Watchdog is normally at the fixed tail offset len-0x64; a rare inline-payload
    # length variant shifts the tail so that lands on filler (an implausibly large
    # microsecond value) -- fall back to the fixed position relative to the type
    # word in that case.
    watchdog_us = struct.unpack_from("<I", e01, L - 0x64)[0]
    if watchdog_us > 600_000_000 and t_off + 0x18 <= L:
        watchdog_us = struct.unpack_from("<I", e01, t_off + 0x14)[0]
    return {
        "type": task_type,
        "rate": rate,
        "priority": priority,
        "watchdog": _ms(watchdog_us),
        "disable": "true" if (e01[L - 0x40] & 1) else "false",
        "inhibit": "true" if (e01[L - 0x3C] & 1) else "false",
    }


_EVENT_TRIGGER_MAP = {
    1: "Motion Group Execution",
    10: "Module Input Data State Change",
    15: "EVENT Instruction Only",
}


def _task_ref_list(record: bytes) -> Dict[int, bytes]:
    """Parse the task record's inline reference list at offset 0x4A: a u32 marker,
    a u32 entry count, then [u32 key][u32 length][length bytes] entries through the
    key==1 payload. Returns {key: value_bytes}. On a short-header / source-protected
    task the key==1 entry holds the same payload that ext-attr 0x01 carries on a
    normally-parsed task (it begins at record offset 0x8A, so the scheduled-program
    read is identical whether taken from here or the raw record)."""
    off = 0x4A
    if off + 8 > len(record):
        return {}
    count = struct.unpack_from("<I", record, off + 4)[0]
    off += 8
    refs: Dict[int, bytes] = {}
    for _ in range(count + 2):
        if off + 8 > len(record):
            break
        key = struct.unpack_from("<I", record, off)[0]
        length = struct.unpack_from("<I", record, off + 4)[0]
        refs[key] = record[off + 8:off + 8 + length]
        off += 8 + length
        if key == 1:
            break
    return refs


@dataclass
class TaskBuilder(L5xElementBuilder):
    _short_header: bool = False

    def _build_event_info(self, e01: bytes, record: bytes,
                          exts: Union[Dict[int, bytes], None] = None
                          ) -> Union[EventInfo, None]:
        """Build the <EventInfo> for an EVENT task.

        PRIMARY: the task's ext-attr 0x68 is the trigger-tag reference and its
        TARGET decides the trigger (validated 58/58 vs the reference across
        both pools, 0 confusions): 0xFFFFFFFF = "EVENT Instruction Only" (no
        tag); a MOTION_GROUP-datatype tag = "Motion Group Execution"; a module
        '&hex:slot:I' input element = "Module Input Data State Change"; an
        AXIS_*-datatype tag = an axis event, whose only pool-observed subtype
        is "Axis Registration 1" (the subtype field is not yet located -- a
        different axis subtype would need it). EnableTimeout is bit 0 at
        payload offset len-0x44 (0 mismatches pool-wide).

        FALLBACK (ext 0x68 absent -- older record layout): the enum at payload
        offset (type_off+2) + the MOTION_GROUP needle scan / ref-list module
        lookup, unchanged. Two pool tasks depend on this path.
        """
        L = len(e01)
        if L < 0x64:
            return None
        v68 = (exts or {}).get(0x68)
        if v68 is not None and len(v68) == 4:
            enable_timeout = "true" if (e01[L - 0x44] & 1) else "false"
            if v68 == b"\xff\xff\xff\xff":
                return EventInfo("EventInfo", "EVENT Instruction Only",
                                 None, enable_timeout)
            row = self._cur.execute(
                "SELECT comp_name, record FROM comps WHERE object_id=?",
                (int.from_bytes(v68, "little"),)).fetchone()
            if row and row[0]:
                nm = row[0]
                m = re.match(r"^&([0-9a-fA-F]+)(:.*:I)$", nm)
                if m:
                    mod = self._cur.execute(
                        "SELECT comp_name FROM comps WHERE object_id=?",
                        (int(m.group(1), 16),)).fetchone()
                    tag = (mod[0] + m.group(2)) if mod and mod[0] else nm
                    return EventInfo("EventInfo",
                                     "Module Input Data State Change",
                                     tag, enable_timeout)
                dt = None
                try:
                    tr = _parse_rec_tolerant(bytes(row[1]))
                    if tr and getattr(tr.main_record, "data_type", None):
                        dr = self._cur.execute(
                            "SELECT comp_name FROM comps WHERE object_id=?",
                            (tr.main_record.data_type,)).fetchone()
                        dt = dr[0] if dr else None
                except Exception:
                    dt = None
                if dt == "MOTION_GROUP":
                    return EventInfo("EventInfo", "Motion Group Execution",
                                     nm, enable_timeout)
                if dt and dt.startswith("AXIS_"):
                    return EventInfo("EventInfo", "Axis Registration 1",
                                     nm, enable_timeout)
            # A reference kind this decode does not model: omit rather than
            # emit a wrong trigger.
            return None
        t_off = 0x28C if L < 2000 else 0x109C
        if t_off + 4 > L or struct.unpack_from("<H", e01, t_off)[0] != 1:
            return None
        trig = struct.unpack_from("<H", e01, t_off + 2)[0]
        trigger = _EVENT_TRIGGER_MAP.get(trig)
        if trigger is None:
            return None
        enable_timeout = "true" if (e01[L - 0x44] & 1) else "false"
        event_tag: Union[str, None] = None
        if trig == 1:
            # Motion Group Execution: the motion-group tag (the record_type=256 comp
            # whose record references the MOTION_GROUP datatype comp).
            mg = self._cur.execute(
                "SELECT object_id FROM comps WHERE comp_name='MOTION_GROUP'").fetchone()
            if mg:
                needle = struct.pack("<I", mg[0])
                # Family-gate this by-VALUE scan: a dead-relic (FDFD-only) rt=256
                # row must not match the needle (its realigned body could gain a
                # spurious match post-flip). Long-header only; the general rule --
                # every comps.record VALUE scan is liveness-gated (P6.9).
                dead = CompsRecord.dead_oids(self._cur, self._short_header)
                for coid, cn, cr in self._cur.execute(
                        "SELECT object_id, comp_name, record FROM comps "
                        "WHERE record_type=256").fetchall():
                    if coid in dead:
                        continue
                    if cn and needle in bytes(cr):
                        event_tag = cn
                        break
        elif trig == 10:
            # Module Input Data State Change: the input tag, ref-list key 0x68 ->
            # object_id -> '&<modid>:<slot>:I' rewritten to '<Module>:<slot>:I'.
            v = _task_ref_list(record).get(0x68)
            if v and len(v) == 4:
                row = self._cur.execute(
                    "SELECT comp_name FROM comps WHERE object_id=?",
                    (int.from_bytes(v, "little"),)).fetchone()
                if row and row[0]:
                    m = re.match(r"^&([0-9a-fA-F]+)(:.*)$", row[0])
                    if m:
                        mod = self._cur.execute(
                            "SELECT comp_name FROM comps WHERE object_id=?",
                            (int(m.group(1), 16),)).fetchone()
                        event_tag = (mod[0] + m.group(2)) if mod and mod[0] else row[0]
                    else:
                        event_tag = row[0]
        return EventInfo("EventInfo", trigger, event_tag, enable_timeout)

    def build(self, comment_id_to_program: Dict[int, str]) -> Task:
        self._cur.execute(
            "SELECT comp_name, record FROM comps WHERE object_id=" + str(self._object_id)
        )
        row = self._cur.fetchone()
        name, record = row[0], bytes(row[1])

        # Task config comes from ext-attr 0x01 (a layout consistent across files);
        # fall back to the legacy single-file absolute record offsets, then to a
        # valid PERIODIC default for short/opaque (V10..V21) bodies.
        e01 = b""
        _task_exts: Dict[int, bytes] = {}
        try:
            _r = RxGeneric.from_bytes(record)
            _task_exts = {er.attribute_id: bytes(er.value)
                          for er in _r.extended_records}
        except Exception:
            try:
                _task_exts = CompsRecord.read_ext_attrs_from_record(record)
            except Exception:
                _task_exts = {}
        e01 = _task_exts.get(0x01, b"")
        if not e01:
            # Short-header / source-protected tasks carry the same payload inline as
            # the ref-list key==1 entry (RxGeneric drops ext 0x01 on them); use it so
            # config + EventInfo resolve identically to a normally-parsed task.
            e01 = _task_ref_list(record).get(0x01, b"")

        # Class: a safety controller marks each task Safety/Standard with a byte at
        # ext[0x01] offset len-0x38 (6 = Safety); standard controllers omit @Class.
        task_cls: Union[str, None] = None
        if self._cur.execute(
                "SELECT 1 FROM comps WHERE comp_name='SafetyController' "
                "AND record_type=256 LIMIT 1").fetchone():
            task_cls = ("Safety" if (len(e01) >= 0x38 and e01[len(e01) - 0x38] == 6)
                        else "Standard")

        # Safety signature: a signed safety task joins the side table by its object
        # type (record[0x0A]) and comment id (record[0x0C]).
        task_sig = task_sig_ts = None
        if len(record) >= 16:
            _srow = safety_signature_row(self._cur, record)
            if _srow:
                task_sig, task_sig_ts = _srow[0], _srow[1]

        cfg = _read_task_config(e01)
        if cfg is not None:
            task_type = cfg["type"]
            rate_str = cfg["rate"]
            priority_str = cfg["priority"]
            watchdog_str = cfg["watchdog"]
            disable_str = cfg["disable"]
            inhibit_str = cfg["inhibit"]
        elif len(record) >= 0x112F:
            rate_us = struct.unpack_from("<I", record, 0x106C)[0]
            type_val = struct.unpack_from("<H", record, 0x10F6)[0]
            priority = struct.unpack_from("<H", record, 0x10F8)[0]
            watchdog_us = struct.unpack_from("<I", record, 0x110A)[0]
            disable_update = record[0x112E]
            task_type = _TASK_TYPE_MAP.get(type_val, "PERIODIC")
            rate_str = str(rate_us // 1000) if task_type != "CONTINUOUS" else None
            priority_str = str(priority)
            watchdog_str = str(watchdog_us // 1000)
            disable_str = "true" if disable_update else "false"
            inhibit_str = "false"
        else:
            # Short/opaque (V10..V21) body: keep the valid PERIODIC default config
            # but still fall through so the scheduled-program list (which lives in
            # the raw record) is recovered.
            task_type = "PERIODIC"
            rate_str = "10"
            priority_str = "10"
            watchdog_str = "10"
            disable_str = "false"
            inhibit_str = "false"

        # Scheduled programs (ordered): a u16 count followed by that many u32
        # program comment_ids. When the task carries ext-attr 0x01 the list sits at
        # its offset 0x00 (count) / 0x02 (ids); otherwise it is in the raw record at
        # 0x8A / 0x8C. (The old fixed record[0x5A] read landed on the wrong field for
        # most layouts, dropping the schedule.)
        if e01:
            _buf, _oc, _oa = e01, 0x00, 0x02
        else:
            _buf, _oc, _oa = record, 0x8A, 0x8C
        scheduled_programs = []
        if _oc + 2 <= len(_buf):
            prog_count = struct.unpack_from("<H", _buf, _oc)[0]
            for i in range(prog_count):
                off = _oa + 4 * i
                if off + 4 > len(_buf):
                    break
                cid = struct.unpack_from("<I", _buf, off)[0]
                prog_name = (comment_id_to_program.get(cid)
                             or comment_id_to_program.get(cid & 0xFFFF))
                if prog_name:
                    scheduled_programs.append(ScheduledProgram(prog_name, prog_name))

        event_info = None
        if task_type == "EVENT":
            event_info = self._build_event_info(e01, record, _task_exts)

        # A task's own Description is stored under the same own-description key
        # scheme as tags/routines/programs (long: comment_id*0x10000 + cip_type,
        # object_id==1; short: bare comment_id filtered by owner cip). Verified
        # byte-exact vs OEM. Best-effort: any parse failure omits the Description.
        description: Union[str, None] = None
        try:
            _tr = RxGeneric.from_bytes(record)
            _tr.extended_records
            if self._short_header:
                description = short_own_description(
                    self._cur, _tr.comment_id, _tr.cip_type)
            else:
                description = own_description(
                    self._cur, (_tr.comment_id * 0x10000) + _tr.cip_type)
        except Exception:
            description = None

        return Task(
            name,
            name,
            task_cls,
            task_type,
            rate_str,
            priority_str,
            watchdog_str,
            disable_str,
            inhibit_str,
            event_info,
            scheduled_programs,
            safety_signature=task_sig,
            safety_signature_timestamp=task_sig_ts,
            _description=description,
        )


def _build_short_routine_descriptions(cur) -> Dict[int, str]:
    """Map routine object_id -> own Description for short-header (V10-V21) files.

    A short-header routine's own description lives in the comments table at
    parent == 0x6D0000 | (comment_id & 0xFFFF) -- the rung-comment record tag --
    keyed by the per-routine member_ref at record[16:20], with a zero
    rung_content (rung comments under the same parent carry the nonzero rung id).
    The (comment_id & 0xFFFF) parent collides across the routines of one program
    AND with UDI/AOI-internal routines (e.g. an AOI's "Logic") sharing the
    comment_id -- and member_ref alone cannot break the tie (it is a constant
    pool-wide). The owner's cip_type does: the description row stores it in the
    sub_record_length column (the same discriminator short_own_description
    uses), so the map is keyed on (parent, member_ref, cip_type) and the row
    lookup filters on it. Where two routines still map to the same key the
    description cannot be attributed to one of them, so BOTH are dropped (a
    fabricated description is worse than a missing one). Best-effort: any
    parse failure simply omits that routine.
    """
    cur.execute(
        "SELECT object_id, record FROM comps WHERE parent_id IN "
        "(SELECT object_id FROM comps WHERE comp_name='RxRoutineCollection')"
    )
    keyed: Dict[int, Tuple[int, int, int]] = {}
    counts: Dict[Tuple[int, int, int], int] = {}
    for oid, rec in cur.fetchall():
        rec = bytes(rec)
        if len(rec) < 20:
            continue
        try:
            _r = RxGeneric.from_bytes(rec)
            # The ext-attr tail parses lazily; materialise it so records with
            # unparseable tails stay excluded from the map (as before).
            _r.extended_records
            cid = _r.comment_id
            cip = _r.cip_type
        except Exception:
            continue
        parent = 0x6D0000 | (cid & 0xFFFF)
        mref = struct.unpack_from("<I", rec, 16)[0]
        keyed[oid] = (parent, mref, cip)
        counts[(parent, mref, cip)] = counts.get((parent, mref, cip), 0) + 1
    out: Dict[int, str] = {}
    for oid, (parent, mref, cip) in keyed.items():
        if counts[(parent, mref, cip)] != 1:
            continue
        cur.execute(
            "SELECT record_string FROM comments "
            "WHERE parent=? AND member_ref=? AND record_type=1 "
            "AND sub_record_length=? "
            "AND (rung_content IS NULL OR rung_content=0) "
            "AND record_string!='' LIMIT 1",
            (parent, mref, cip),
        )
        drow = cur.fetchone()
        if drow and drow[0]:
            out[oid] = drow[0]
    return out


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
    # Controller firmware revision from the project's QuickInfo DeviceIdentity (the
    # firmware the controller runs -- distinct from the Studio application SWVersion
    # used for SoftwareRevision). None -> fall back to the Local module's identity
    # record revision.
    _device_major: Union[int, None] = field(default=None)
    _device_minor: Union[int, None] = field(default=None)
    # Faithful mode: reproduce exactly what Studio exports. When True, a source-
    # protected AOI (whose source Studio withholds, emitting <EncodedData>) is
    # omitted rather than recovered as plaintext. Default False = recover as much as
    # possible (emit the decoded plaintext AOI definition).
    _faithful: bool = field(default=False)
    # The reference EXPORT language (a property of the export environment, like
    # ExportDate -- NOT stored in the ACD). Names the current/default project
    # language attributes on a multilingual project; see _project_language_attrs.
    _export_language: str = field(default="en-US")

    def _project_language_attrs(self):
        """(ControllerLanguage, CurrentProjectLanguage, DefaultProjectLanguage) for
        a genuinely multilingual project, else (None, None, None).

        ControllerLanguage is READ from the controller's ExtendedDevice record --
        a NUL-terminated locale string at a fixed offset, with a u16 length that is
        the string's length or (on the V20 short-header form) zero. The current and
        default project languages are the export language, an export-environment
        value the reference stamps like ExportDate (provably absent from the ACD).

        The attributes appear only on a multilingual project. Two families gate it:
        a long-header project carries language-keyed description rows in the
        comments table (a controller with a locale but no such rows -- source only
        ever authored in one language -- must NOT emit them); a short-header
        project is gated on the V20+ export epoch that introduced them. The short
        form additionally omits DefaultProjectLanguage. Fail-closed: any unresolved
        or malformed input yields all-None (the whole group is withheld).
        """
        try:
            row = self._cur.execute(
                "SELECT c.record FROM comps c JOIN comps p ON c.parent_id=p.object_id"
                " WHERE c.comp_name='ExtendedDevice'"
                " AND p.comp_name='RxControllerCollection' LIMIT 1").fetchone()
            if not row or not row[0]:
                return None, None, None
            rec = bytes(row[0])
            if len(rec) < 0x18B:
                return None, None, None
            ln = struct.unpack_from("<H", rec, 0x188)[0]
            loc = rec[0x18A:0x18A + 16].split(b"\x00")[0].decode("ascii")
            if not re.fullmatch(r"[a-z]{2,3}-[A-Z]{2}", loc) or ln not in (0, len(loc)):
                return None, None, None
            if self._short_header:
                if self._acd_major < 20:
                    return None, None, None
                return loc, self._export_language, None
            langs = {r[0] for r in self._cur.execute(
                "SELECT DISTINCT object_id FROM comments")} & _LANG_DESC_OIDS
            if not langs:
                return None, None, None
            return loc, self._export_language, self._export_language
        except Exception:
            return None, None, None

    def _pass_own_description(self, results, _comment_parent):
        # --- Controller own Description ---
        # Long header: own-description key parent = comment_id*0x10000 + cip_type,
        # member_ref 0, object_id == 1 (excludes scratch/operand rows). Recover the
        # comment_id from the plaintext main record for source-protected
        # controllers. Short header (V10-V21): the controller's own description is
        # keyed by the bare comment_id (member_ref 0, record_type 1/2) -- the same
        # scheme as short-header tags. Unlike datatypes/modules, a controller's
        # comment_id collides only with description-less records (its child
        # collections), so the lookup is unambiguous without a uniqueness gate
        # (verified pool-wide: 0 false positives across every short-header file).
        # Best-effort: any failure leaves no description.
        controller_description: Union[str, None] = None
        if self._short_header:
            _crec = bytes(results[0][4])
            if len(_crec) >= 14:
                _ccid = struct.unpack_from("<H", _crec, 12)[0]
                _ccip = struct.unpack_from("<H", _crec, 10)[0]
                controller_description = short_own_description(self._cur, _ccid, _ccip)
        else:
            _desc_parent = _comment_parent
            if _desc_parent is None:
                _pm = _rxgeneric_plaintext_main(bytes(results[0][4]))
                if _pm is not None:
                    _desc_parent = (_pm.comment_id * 0x10000) + _pm.cip_type
            if _desc_parent is not None:
                controller_description = own_description(self._cur, _desc_parent)
        return controller_description

    def _pass_ext_record_scalars(self, r, extended_records):
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
            # The CommPath is the record's FINAL attribute, which the counted
            # extended_records stop before; it parses as the trailing
            # last_attribute_record.
            _last = getattr(r, "last_attribute_record", None)
            if _last is not None and _last.attribute_id == 0x06A:
                _cp_val = getattr(_last, "value", None)
                if _cp_val:
                    _cp_str = bytes(_cp_val).decode("utf-16-le", errors="replace").rstrip("\x00")
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
        # and 0x00 for non-redundant controllers. Deliberately read from the
        # kaitai extended_records (the truncated record), not record_attrs.
        redundancy_enabled: bool = bool(ControllerProps.from_bytes(
            extended_records.get(0x001, b"")).redundancy_flag)
        return (sfc_execution_control, sfc_restart_position, sfc_last_scan, project_sn,
                project_creation_date, last_modified_date, _comm_path_prefix,
                major_fault_program, redundancy_enabled)

    def _pass_controller_props(self, results, sfc_execution_control, sfc_restart_position, sfc_last_scan):
        # Controller-properties attributes. These live in the controller record's
        # decrypted ext-attrs, which the kaitai extended_records cannot reach on
        # short-header (V10-V21) projects, so read them via read_value_attrs(full=True)
        # on the comps record body (the same dict the force gate uses).
        time_slice = None
        share_unused_time_slice = None
        compatibility_mode = None
        ethernet_ip_mode = None
        power_loss_program = None
        try:
            _ctlattrs = CompsRecord.record_attrs(
                self._cur, results[0][1], self._short_header)
        except Exception:
            _ctlattrs = {}
        # On a source-protected controller the ext-attr tail is encrypted, so the
        # kaitai extended_records are empty and the SFC fields above came back blank.
        # The decrypted attribute table still carries them -- recover from there.
        def _ct_utf16(key):
            raw = _ctlattrs.get(key)
            if not raw or len(raw) < 2:
                return ""
            return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
        if not sfc_execution_control:
            sfc_execution_control = _ct_utf16(0x6F)
        if not sfc_restart_position:
            sfc_restart_position = _ct_utf16(0x70)
        if not sfc_last_scan:
            sfc_last_scan = _ct_utf16(0x71)
        _ctlblob = _ctlattrs.get(0x1, b"")
        _props = ControllerProps.from_bytes(_ctlblob)
        # The continuous-task slice is carried by classic controllers, marked by
        # blob[16]==0x5a; 5x80 controllers (blob[16]==0) carry EtherNetIPMode
        # instead. share_flags present == the old len > 25 completeness gate.
        io_memory_pad_percentage = None
        data_table_pad_percentage = None
        if _props.share_flags is not None and _props.classic_marker == 0x5A:
            time_slice = str(_props.time_slice)
            share_unused_time_slice = str(_props.share_flags & 1)
            # RedundancyInfo pad percentages live just past the classic marker:
            # IOMemoryPadPercentage = u16 @ 16 (the 0x5A marker reads 90), and
            # DataTablePadPercentage = u16 @ 18 (a per-controller value, 50 or 0).
            io_memory_pad_percentage = str(_props.io_memory_pad)
            data_table_pad_percentage = str(_props.data_table_pad)
        # CompatibilityMode "V20.01" marks the pre-V21 classic save format, whose
        # controller-properties blob is exactly 62 bytes.
        if _props.size == 62:
            compatibility_mode = "V20.01"
        # EtherNetIPMode: ext-attr 0x7c is a u16 dual-port mode index on 5x80
        # controllers (1 -> Dual-IP, 2 -> Linear/DLR).
        _eth = _ctlattrs.get(0x7C)
        if _eth is not None and len(_eth) >= 2:
            ethernet_ip_mode = {1: "A1/A2: Dual-IP", 2: "A1/A2: Linear/DLR"}.get(
                struct.unpack_from("<H", _eth, 0)[0])
        # PowerLossProgram: ext-attr 0x67 holds the program object id (same scheme as
        # MajorFaultProgram at 0x68); 0 / 0xffffffff means none.
        _plp = _ctlattrs.get(0x67)
        if _plp is not None and len(_plp) >= 4:
            _plp_oid = struct.unpack_from("<I", _plp, 0)[0]
            if _plp_oid not in (0, 0xFFFFFFFF):
                self._cur.execute(
                    "SELECT comp_name FROM comps WHERE object_id=?", (_plp_oid,))
                _plp_row = self._cur.fetchone()
                if _plp_row:
                    power_loss_program = _plp_row[0]
        return (time_slice, share_unused_time_slice, compatibility_mode, ethernet_ip_mode,
                power_loss_program, io_memory_pad_percentage, data_table_pad_percentage,
                sfc_execution_control, sfc_restart_position, sfc_last_scan, _ctlattrs,
                _ctlblob)

    def _pass_time_sync_cst(self):
        # TimeSynchronize PTPEnable / Priority1 / Priority2 from the controller's
        # TimeSynchronize config record (RxControllerCollection child): PTPEnable is
        # bit 0 of its ext-attr 0x1, Priority1/Priority2 are the bytes at offset
        # 272/273. Validated against the reference (115/115 records: PTPEnable 0
        # mismatch, priorities byte-exact). Defaults stay true/128/128 when absent.
        ts_ptp_enable, ts_priority1, ts_priority2 = "true", "128", "128"
        cst_master_id = "0"

        def _rcc_attr(child):
            _rcc = self._cur.execute(
                "SELECT object_id FROM comps WHERE parent_id=? AND "
                "comp_name='RxControllerCollection'", (self._object_id,)).fetchone()
            if not _rcc:
                return b""
            _r = self._cur.execute(
                "SELECT object_id FROM comps WHERE parent_id=? AND comp_name=?",
                (_rcc[0], child)).fetchone()
            if not _r:
                return b""
            return CompsRecord.record_attrs(
                self._cur, _r[0], self._short_header).get(0x1, b"")
        try:
            _tb = _rcc_attr("TimeSynchronize")
            if len(_tb) > 273:
                ts_ptp_enable = "true" if (_tb[0] & 1) else "false"
                ts_priority1 = str(_tb[272])
                ts_priority2 = str(_tb[273])
            # CST MasterID = u16 @ offset 14 of the CST record's 0x1 attribute.
            _cb = _rcc_attr("CST")
            if len(_cb) >= 16:
                cst_master_id = str(struct.unpack_from("<H", _cb, 14)[0])
        except Exception:
            pass
        return ts_ptp_enable, ts_priority1, ts_priority2, cst_master_id

    def _pass_data_types(self):
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
        # Dead-relic (FDFD-only) datatype children -- e.g. the
        # ZZZ_TEMPORARY_IMPORT_DATATYPE_NAME import leftovers -- are deleted
        # types Studio never exports; skip them below (P6.9).
        dead = CompsRecord.dead_oids(self._cur, self._short_header)

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
                "SELECT object_id, comp_name FROM comps WHERE parent_id="
                + str(_aoi_coll_row[0])
                + " AND record_type=256"
            )
            aoi_names = {nm for oid, nm in self._cur.fetchall() if oid not in dead}

        data_types: List[DataType] = []
        # all_data_types_map includes ProductDefined types (excluded from L5X output but
        # needed for generating Decorated XML for tags that reference those types).
        all_data_types_map: Dict[str, DataType] = {}
        for result in results:
            _data_type_object_id = result[1]
            if _data_type_object_id in dead:
                continue
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
        return data_types, data_types_map

    def _pass_controller_tags(self, data_types_map):
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
        _ctrl_tags_sig = _tagcoll_sig_attrs(
            self._cur, _tag_collection_object_id, self._short_header)
        self._cur.execute(
            "SELECT comp_name, object_id, parent_id, record_type FROM comps WHERE parent_id="
            + str(_tag_collection_object_id)
        )
        results = self._cur.fetchall()
        # Consumed controller tags: their connection details live in the producer
        # modules' RxMapConnectionCollection, keyed by the consumed tag's object_id
        # (built once for the whole controller). A tag found here is emitted as
        # TagType="Consumed" with a <ConsumeInfo> child and no Constant attribute.
        consume_map = _build_consume_map(self._cur, self._short_header)
        # Produced controller tags: their connection/mapping config lives in the
        # producer modules' RxMapConnectionCollection (FULL form) or in the tag's
        # own record (PLC-mapped form), keyed by the produced tag's object_id. A
        # tag found here is emitted as TagType="Produced" with a <ProduceInfo>
        # child; unlike Consumed it keeps its Constant attribute (OEM emits it).
        produce_map = _build_produce_map(self._cur, self._short_header)
        tags: List[Tag] = []
        # Module <Communications> tag content, captured from the controller config
        # (:C), input (:I) and output (:O) tags as they are built (their rendered
        # <Data> blocks ARE the module's ConfigTag/InputTag/OutputTag content,
        # validated byte-identical to the reference). Keyed by the &hex object-id
        # reference parsed from the tag's stored name so the owning module can look it
        # up; see ModuleBuilder for the key shape and per-IO-type value.
        io_data_map: Dict[tuple, dict] = {}
        # Which (owner oid, slot) carry an :I / :O module tag, independent of whether
        # that tag has a design-value image. A rack input card's :I tag has none, so
        # the value-keyed capture below would miss it; this presence flag lets a
        # rack module decide its InAliasTag / OutAliasTag without a value image.
        self._cur.execute(
            "SELECT comp_name FROM comps WHERE comp_name LIKE '&%:I' "
            "OR comp_name LIKE '&%:O'"
        )
        for (_cn,) in self._cur.fetchall():
            _pm = re.match(r"^&([0-9a-fA-F]+)(?::(\d+))?:([IO])$", _cn)
            if _pm:
                _k = (int(_pm.group(1), 16),
                      int(_pm.group(2)) if _pm.group(2) is not None else None)
                io_data_map.setdefault(_k, {})["has_" + _pm.group(3)] = True
        # Force-image holders: RxDataCollection children carry an I/O tag's installed
        # force image as a length-prefixed blob at record offset 410 (u32 length at
        # 406), keyed by object id. A forced I/O tag points at its holder via the
        # 4-byte ext-attr 0x6b on the tag's backing. Built once and looked up below.
        force_pool: Dict[int, bytes] = {}
        try:
            self._cur.execute(
                "SELECT c.object_id, c.record FROM comps c JOIN comps p "
                "ON c.parent_id = p.object_id WHERE p.comp_name = 'RxDataCollection'"
            )
            for _foid, _frec in self._cur.fetchall():
                _frec = bytes(_frec)
                if len(_frec) >= 410:
                    _flen = struct.unpack_from("<I", _frec, 406)[0]
                    if 0 < _flen <= len(_frec) - 410:
                        force_pool[_foid] = _frec[410:410 + _flen]
        except Exception:
            force_pool = {}
        # Installed I/O forces are exported only by legacy-save-format controllers:
        # the controller-properties ext-attr 0x1 is 62 (V10-V20) or 70 (V24) bytes,
        # whereas newer Studio appends a trailing block (len 71+) and never exports
        # installed forces. This file-level flag gates the source-protected force
        # recovery below. It is required because a relocated-value holder on an
        # UNFORCED tag is byte-identical in structure to a real force holder; without
        # the gate, a non-force project whose I/O values happen to be relocated would
        # over-emit one <ForceData> per such tag. (The plaintext short-read path above
        # self-gates via force_pool and so needs no flag.)
        _forces_installed = False
        try:
            _ca = CompsRecord.record_attrs(
                self._cur, self._object_id, self._short_header)
            _forces_installed = len(_ca.get(0x1, b"")) in (62, 70)
        except Exception:
            _forces_installed = False
        # Per-tag <AlarmConditions> blocks (V33+), keyed by owning tag object id.
        try:
            alarm_map = _build_alarm_conditions(self._cur, self._short_header)
        except Exception:
            alarm_map = {}
        # Short-header (V10-V21) routine own descriptions, resolved file-wide with
        # a cross-routine collision gate (see _build_short_routine_descriptions).
        # Long-header routines resolve their description inline in RoutineBuilder.
        try:
            short_routine_desc = (
                _build_short_routine_descriptions(self._cur)
                if self._short_header else {}
            )
        except Exception:
            short_routine_desc = {}
        dead = CompsRecord.dead_oids(self._cur, self._short_header)
        for result in results:
            _tag_object_id = result[1]
            if _tag_object_id in dead:  # dead-relic (FDFD-only) tag -> skip (P6.9)
                continue
            _tb = TagBuilder(self._cur, _tag_object_id, _short_header=self._short_header,
                             _acd_major=self._acd_major,
                             _taginfo_layout=self._taginfo_layout)
            tag = _tb.build()
            tag._alarm_xml = alarm_map.get(_tag_object_id, "")
            tag._data_types_map = data_types_map
            tag._taginfo_layout = self._taginfo_layout
            ci = consume_map.get(_tag_object_id)
            if ci is not None:
                tag.tag_type = "Consumed"
                tag.constant = None
                tag._consume_info = ci
            pi = produce_map.get(_tag_object_id)
            if pi is not None:
                tag.tag_type = "Produced"
                tag._produce_info = pi
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
                # Installed forces apply to EVERY tag type (I/O, Produced, Consumed,
                # Base, status :S), so read the force pointer for every kept tag with a
                # value image. A forced tag's backing points at its force-image holder
                # via the 4-byte ext-attr 0x6b, present only when forces are installed.
                # A genuine force image is exactly 3x the tag's data image
                # (mask/value/state) -- that invariant gates out the other small blobs
                # 0x6b resolves to on the occasional unforced tag. Set before to_xml so
                # the rendered <Data> (and the captured InputTag/OutputTag below) carry
                # the <ForceData>.
                if tag._value_bytes:
                    self._cur.execute(
                        "SELECT record FROM comps WHERE object_id=?",
                        (_tag_object_id,),
                    )
                    _fr = self._cur.fetchone()
                    if _fr:
                        _frb = bytes(_fr[0])
                        try:
                            # The short read exposes 0x6b only when forces are
                            # actually installed; the full decryption also surfaces the
                            # idle force allocation every tag carries, which would
                            # over-emit on unforced tags, so deliberately do NOT use it.
                            _fv = CompsRecord.read_value_attrs(
                                _frb, self._short_header,
                                body_mode=True).get(0x6B)
                        except Exception:
                            _fv = None
                        if _fv and len(_fv) == 4:
                            _fimg = force_pool.get(struct.unpack("<I", _fv)[0])
                            if _fimg and len(_fimg) == 3 * len(tag._value_bytes):
                                tag._force_data = _tag_value.render_hex(_fimg)
                        elif _fv is None and _forces_installed:
                            # Source-protected backing: the short read cannot reach the
                            # force pointer (0x6b sits past the encrypted 0x66), and the
                            # design value is relocated (ext-0x66 is a 4-byte self-id
                            # sentinel, not the real image), so force_pool's 3x-value
                            # guard cannot apply. Recover from the FULL decrypt instead:
                            # 0x6b -> a holder whose 0x1 declares [data_size][3] and
                            # whose 0x66 is exactly 3x data_size (the mask/value/state
                            # image). The holder is self-describing, so the size guard
                            # comes from the holder itself, not the (sentinel) value.
                            # Gated by _forces_installed so an unforced relocated holder
                            # -- structurally identical -- never over-emits.
                            try:
                                _fp = CompsRecord.read_value_attrs(
                                    _frb, self._short_header, full=True,
                                    body_mode=True).get(0x6B)
                            except Exception:
                                _fp = None
                            if _fp and len(_fp) == 4:
                                self._cur.execute(
                                    "SELECT record FROM comps WHERE object_id=?",
                                    (struct.unpack("<I", _fp)[0],),
                                )
                                _hr = self._cur.fetchone()
                                if _hr:
                                    try:
                                        _ha = CompsRecord.read_value_attrs(
                                            bytes(_hr[0]), self._short_header,
                                            full=True, body_mode=True)
                                    except Exception:
                                        _ha = {}
                                    _h1 = _ha.get(0x1, b"")
                                    _h66 = _ha.get(0x66)
                                    if _h66 is not None and len(_h1) >= 8:
                                        _dsz = struct.unpack_from("<I", _h1, 0)[0]
                                        _mult = struct.unpack_from("<I", _h1, 4)[0]
                                        if _mult == 3 and _dsz > 0 and \
                                                len(_h66) == 3 * _dsz:
                                            tag._force_data = \
                                                _tag_value.render_hex(_h66)
                # Capture this module's <Communications> tag content from its config
                # (:C), input (:I) and output (:O) controller tags. The stored name is
                # &<hex>:<slot>:X (slotted card) or &<hex>:X (Ethernet device); the hex
                # is the comps object_id the owning module resolves against. The tag's
                # rendered inner IS a connection's ConfigTag/OutputTag/InputTag content:
                # an OutputTag keeps the inner verbatim; an InputTag (and the status :S
                # tag) keeps it minus the raw value block and any <AlarmConditions>.
                if tag._io and tag._value_bytes:
                    # Suffix may be a plain C/I/O/S, a safety input :SI / config :SC,
                    # safety output :SO, or an IO-Link numbered I1/O1/I2/O2 (a module
                    # owns one input family but may own a :SO alongside a standard :O).
                    # The safety OUTPUT :SO is kept verbatim like a standard output:
                    # every OEM safety OutputTag in the pool carries the same Decorated
                    # <Data> structure the backing tag renders (validated 139/139).
                    cm = re.match(
                        r"^&([0-9a-fA-F]+)(?::(\d+))?:(SI|SC|SO|I1|I2|O1|O2|[CIOS])$",
                        result[0])
                    if cm:
                        ref_oid = int(cm.group(1), 16)
                        ref_slot = int(cm.group(2)) if cm.group(2) is not None else None
                        io_type = cm.group(3)
                        rendered = tag.to_xml()
                        gt = rendered.find(">")
                        inner = rendered[gt + 1:]
                        if inner.endswith("</Tag>"):
                            inner = inner[:-len("</Tag>")]
                        slot_entry = io_data_map.setdefault((ref_oid, ref_slot), {})
                        if io_type in ("C", "SC") and inner and len(tag._value_bytes) >= 4:
                            # ConfigSize = first u32 of the config image minus 4.
                            size = int.from_bytes(tag._value_bytes[0:4], "little") - 4
                            slot_entry["C"] = (inner, size)
                        elif io_type in ("O", "O1", "O2", "SO") and inner:
                            # Output tags (standard and safety) keep the inner verbatim.
                            slot_entry[io_type] = inner
                        elif inner:  # I*/S* input/status tags: strip the raw value block
                            si = _strip_input_tag_inner(inner)
                            # An OEM safety InputTag carries no <Description> (a safety
                            # I/O tag's description is not rendered inside the connection
                            # tag -- verified: every safety connection InputTag in the
                            # reference is description-less); a standard input tag keeps
                            # its Description. The safety backing tag may use a plain :I
                            # suffix, so key off the tag's Safety class, not the suffix.
                            if getattr(tag, "_class_attr", None) == "Safety":
                                si = _DESC_BLOCK_RE.sub("", si)
                            slot_entry[io_type] = si
                # A rack per-point ALIAS tag (<Chassis>:<slot>:I|O) has no value
                # image, but its Description and operand-comment blocks are
                # duplicated by OEM inside the point card's <RackConnection>
                # In/OutAliasTag. Capture the rendered inner (which now carries
                # the Description too) under the same (chassis oid, slot) key the
                # point module resolves its entry by.
                _has_desc = any(t for _r, t in tag._comments)
                if (tag._io and tag.alias_for and not tag._value_bytes
                        and (_has_desc or tag._operand_comments or tag._eng_units
                             or tag._maxes or tag._mins)):
                    am = re.match(r"^&([0-9a-fA-F]+):(\d+):([IO])$", result[0])
                    if am:
                        rendered = tag.to_xml()
                        gt = rendered.find(">")
                        inner = rendered[gt + 1:]
                        if inner.endswith("</Tag>"):
                            inner = inner[:-len("</Tag>")]
                        if inner:
                            io_data_map.setdefault(
                                (int(am.group(1), 16), int(am.group(2))), {}
                            )["alias_inner_" + am.group(3)] = inner
        return tags, io_data_map, alarm_map, short_routine_desc, _ctrl_tags_sig

    def _pass_programs(self, data_types_map, redundancy_enabled, alarm_map, short_routine_desc):
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
                ProgramBuilder(self._cur, _program_object_id, data_types_map, redundancy_enabled, _short_header=self._short_header, _taginfo_layout=self._taginfo_layout, _acd_major=self._acd_major, _alarm_map=alarm_map, _short_routine_desc=short_routine_desc, _faithful=self._faithful).build()
            )

        # <ChildPrograms> name index: a child program's record head u32
        # (record[0:4]) is the object id of its PARENT program's nested
        # RxProgramCollection (top-level programs carry the controller-level
        # collection oid there). Purely additive: a head that resolves to
        # neither collection attaches nothing (today's output).
        try:
            _prog_oids = [r[1] for r in results]
            _nested_owner: Dict[int, int] = {}   # nested collection oid -> program oid
            for _poid in _prog_oids:
                _nrow = self._cur.execute(
                    "SELECT object_id FROM comps WHERE parent_id=? "
                    "AND comp_name='RxProgramCollection'", (_poid,)).fetchone()
                if _nrow:
                    _nested_owner[_nrow[0]] = _poid
            _by_oid = dict(zip(_prog_oids, programs))
            _pending: Dict[int, list] = {}   # parent oid -> [(order key, name)]
            for _poid, _prog in zip(_prog_oids, programs):
                _rrow = self._cur.execute(
                    "SELECT record FROM comps WHERE object_id=?",
                    (_poid,)).fetchone()
                if not _rrow or _rrow[0] is None or len(bytes(_rrow[0])) < 8:
                    continue
                _rec = bytes(_rrow[0])
                _head = struct.unpack_from("<I", _rec, 0)[0]
                _owner_oid = _nested_owner.get(_head)
                if _owner_oid is None or _owner_oid not in _by_oid:
                    continue
                # Sibling order key: the u16 at record offset 6 ascends in the
                # reference's ChildPrograms order (validated on every affected
                # file of both pools).
                _pending.setdefault(_owner_oid, []).append(
                    (struct.unpack_from("<H", _rec, 6)[0], _prog.name))
            for _owner_oid, _kids in _pending.items():
                _by_oid[_owner_oid].child_programs = [
                    ChildProgram(_n, _n) for _, _n in sorted(_kids)]
        except Exception:
            pass

        # Build comment_id → program name map for task scheduled-program resolution.
        # comment_id is a u16 at BLOB offset 0x0C in each program's RxGeneric record.
        self._cur.execute(
            "SELECT comp_name, record FROM comps WHERE parent_id=" + str(_program_collection_object_id)
        )
        comment_id_to_program: Dict[int, str] = {
            struct.unpack_from("<H", rec, 0x0C)[0]: pname
            for pname, rec in self._cur.fetchall()
        }
        return programs, comment_id_to_program

    def _pass_tasks(self, comment_id_to_program):
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
            dead = CompsRecord.dead_oids(self._cur, self._short_header)
            for task_result in self._cur.fetchall():
                if task_result[1] in dead:  # dead-relic task -> skip (P6.9)
                    continue
                tasks.append(TaskBuilder(
                    self._cur, task_result[1],
                    _short_header=self._short_header).build(comment_id_to_program))
        return tasks

    def _pass_aois(self, data_types_map, short_routine_desc):
        # Get the AOI Collection and get the AOIs
        self._cur.execute(
            "SELECT comp_name, object_id, parent_id, record_type FROM comps WHERE parent_id="
            + str(self._object_id)
            + " AND comp_name='RxUDIDefinitionCollection'"
        )
        results = self._cur.fetchall()
        if len(results) > 1:
            raise Exception("Contains more than one AOI collection")
        if not results:
            # A project with no Add-On Instructions has no
            # RxUDIDefinitionCollection comp -- there are simply no AOIs to
            # emit. Mirror the empty-guard the task-collection pass uses above.
            return []
        _aoi_collection_object_id = results[0][1]
        self._cur.execute(
            "SELECT comp_name, object_id, parent_id, record_type, record FROM comps WHERE parent_id="
            + str(_aoi_collection_object_id)
            + " AND record_type=256"
        )
        results = self._cur.fetchall()
        dead = CompsRecord.dead_oids(self._cur, self._short_header)
        aois: List[AOI] = []
        for result in results:
            # A dead-relic (FDFD-only) AOI definition is a deleted AOI Studio never
            # exports; skip it (P6.9). This is the top-level AOI-definition enum
            # (distinct from AoiBuilder's internal tag/routine child enums).
            if result[1] in dead:
                continue
            # In faithful mode, a source-protected AOI is exported by Studio as an
            # <EncodedData> blob, not a plaintext <AddOnInstructionDefinition>; skip
            # it (the keyed ciphertext OEM emits is unrecoverable -> under-emit rather
            # than fabricate). In the default recovery mode we keep the decoded
            # plaintext definition (more useful for recovering the protected source).
            if self._faithful and _aoi_is_source_protected(bytes(result[4])):
                continue
            _aoi_object_id = result[1]
            aois.append(AoiBuilder(
                self._cur, _aoi_object_id,
                _data_types_map=data_types_map,
                _short_header=self._short_header,
                _taginfo_layout=self._taginfo_layout,
                _short_routine_desc=short_routine_desc,
                _acd_major=self._acd_major,
            ).build())
        return aois

    def _pass_modules(self, io_data_map):
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
            # Drop dead-relic (FDFD-only) device children BEFORE either pass. These
            # are deleted-module ghosts Studio never exports (e.g. one project's
            # six ghost fan modules, whose live 193-ECM-ETR twins we already
            # emit in full).
            # Filtering the source list keeps a ghost from BOTH emitting a spurious
            # <Module> AND writing modid_to_name/modid_to_oid unconditionally below
            # (a realigned ghost body could otherwise clobber a live module's modid
            # mapping -> ParentModule / :C ConfigTag cascade). Long-header only;
            # its own gauntlet (P6.9 C4). Hard prerequisite of the FDFD flip (C5).
            _dead = CompsRecord.dead_oids(self._cur, self._short_header)
            mod_rows = [r for r in self._cur.fetchall() if r[1] not in _dead]

            # First pass: build modid→name map so child modules can resolve their
            # parent name. Identity resolution runs the shared recovery chain
            # (_module_identity_e1: truncated-record parse -> 44 02 00 00 marker
            # alias -> the comps.record body); the map-write policy differs per
            # source, so dispatch on it.
            modid_to_name: Dict[int, str] = {}
            # modid→object_id map for ConfigTag keying. On short-header (V10..V20)
            # projects it applies the 44 02 00 00 marker fallback so it is complete.
            modid_to_oid: Dict[int, int] = {}
            for db_name, mod_oid, mod_rec in mod_rows:
                display_name = "?" if (db_name.startswith("$") and db_name.endswith("$")) else db_name
                e1, _cid, _src = _module_identity_e1(
                    self._cur, mod_oid, bytes(mod_rec) if mod_rec else b"",
                    self._short_header)
                _mid = ModuleIdentity.from_bytes(e1).modid
                if _mid is None:
                    continue
                if _src == "record":
                    # e1[0x2C] is the modid that backplane children reference
                    # (their e1[0x16]). It reads 0 for an Ethernet-family rack
                    # adapter (1734-AENT and the like) whose own identity sits
                    # behind the EtherNet/IP attrs; the real modid for those is
                    # the record-header comment_id (RxGeneric.comment_id), which
                    # equals e1[0x2C] wherever the latter is nonzero. Prefer
                    # e1[0x2C]; fall back to comment_id only when it is 0, so
                    # existing keys are byte-identical and the adapter's cards
                    # (which today wrongly resolve ParentModule to "Local" and
                    # miss their :C ConfigTag) resolve to it.
                    modid = _mid or _cid
                    if modid:
                        modid_to_name[modid] = display_name
                        modid_to_oid[modid] = mod_oid
                elif _src == "marker":
                    modid_to_oid[_mid] = mod_oid
                    # Map modid->name too (previously only the oid was
                    # mapped here): a child module behind this marker
                    # references its parent by this modid, so without the
                    # name entry it fell back to ParentModule="Local". Key
                    # it the way children reference it (e1[0x2C], or the
                    # record comment_id when that is 0) and never overwrite
                    # a name a normally-parsed record already provided.
                    _mk_modid = _mid or _cid
                    if _mk_modid and _mk_modid not in modid_to_name:
                        modid_to_name[_mk_modid] = display_name
                else:
                    # Module whose truncated record omits the 0x001 identity
                    # (or does not parse at all): the modid was recovered from
                    # the comps.record body so the adapter is mapped and its child
                    # cards resolve their :C ConfigTag (e.g. a POINT I/O adapter / Local,
                    # whose own modid is the comment_id). Collision-safe:
                    # never overwrite a modid already mapped from a
                    # normally-parsed record.
                    _modid = _mid or _cid
                    if _modid and _modid not in modid_to_oid:
                        modid_to_name[_modid] = display_name
                        modid_to_oid[_modid] = mod_oid

            # Supplement modid_to_oid with the owners of slotted :C config tags. A
            # &<ownerOid>:<slot>:C config tag is owned by the parent module that holds
            # that slot's card; map the owner's OWN modid -> its object_id so a child
            # card resolves its real parent through the PRIMARY (parent_modid, slot)
            # path. The device-collection pass above misses chassis/bridge parents
            # that are not entered under a recognised modid (a remote DeviceNet/EN
            # chassis, or the local controller whose implicit modid 1 no record
            # carries), which is why those cards previously fell through to the
            # "Local"-named fallback and grabbed a same-slot :C from the wrong module.
            # Collision-safe: never overwrite a modid already mapped above.
            _c_owners = {oid for (oid, _s) in io_data_map
                         if io_data_map.get((oid, _s), {}).get("C") is not None}
            for _owner in _c_owners:
                # Same shared recovery chain: a remote DeviceNet/EN chassis whose
                # truncated caller copy omits the identity surfaces its modid
                # only in the comps.record body; short-header owners carry it
                # inline behind the 44 02 00 00 marker.
                _orow = self._cur.execute(
                    "SELECT record FROM comps WHERE object_id=?", (_owner,)).fetchone()
                _oe1, _ocid, _osrc = _module_identity_e1(
                    self._cur, _owner,
                    bytes(_orow[0]) if _orow and _orow[0] is not None else b"",
                    self._short_header)
                _omid = ModuleIdentity.from_bytes(_oe1).modid
                _omodid = (_omid or _ocid) if _omid is not None else None
                if _omodid and _omodid not in modid_to_oid:
                    modid_to_oid[_omodid] = _owner

            # Second pass: build Module objects. The connection decode map (RPI/
            # Unicast/EventID per connection record), the ConfigData/ConfigScript
            # holder indexes and the ordered RxDataCollection child index are
            # built once and shared.
            conn_decode = _build_connection_map(self._cur, self._short_header)
            cfg_mr28, cfg_cid, cfg_pool = _build_config_holders(
                self._cur, self._short_header)
            rxdata_by_cid = _build_rxdata_holders(self._cur, self._short_header)
            modules = []
            for _, mod_oid, _ in mod_rows:
                modules.append(
                    ModuleBuilder(self._cur, mod_oid, modid_to_name,
                                  _rxdata_by_cid=rxdata_by_cid,
                                  _conn_decode=conn_decode,
                                  _io_map=io_data_map,
                                  _modid_to_oid=modid_to_oid,
                                  _cfg_by_mr28=cfg_mr28,
                                  _cfg_by_cid=cfg_cid,
                                  _cfg_pool=cfg_pool,
                                  _short_header=self._short_header).build()
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
        # Stash the modid->name map for the post-build axis pass (CIP-drive
        # MotionModule resolution reads it).
        self._modid_to_name = modid_to_name
        return modules

    def _pass_processor_identity(self, modules, _comm_path_prefix, _ctlattrs):
        # ProcessorType is the CatalogNumber of the root controller module (the one
        # whose parent resolves to itself). (MajorFault is no longer root-only, so
        # the root is identified by parent_module==name instead.)
        processor_type = next(
            (m.catalog_number for m in modules if m.parent_module == m.name and m.catalog_number),
            None,
        )

        # MajorRev/MinorRev are the controller firmware revision. The project's
        # QuickInfo DeviceIdentity carries it directly; prefer that. Fall back to the
        # Local (backplane controller) module's identity record (ext[0x01] bytes
        # [0x08]/[0x09]) when DeviceIdentity is unavailable.
        local_module = next(
            (m for m in modules if m.name == "Local"),
            next((m for m in modules if m.parent_module == m.name), None),
        )
        if self._device_major is not None and self._device_minor is not None:
            major_rev = str(self._device_major)
            minor_rev = str(self._device_minor)
        elif local_module is not None:
            major_rev = str(local_module.major)
            minor_rev = str(local_module.minor)
        else:
            major_rev = "0"
            minor_rev = "0"

        # CommPath: the complete path string is stored in ext-attr 0x06A and already
        # includes the trailing backplane slot / address segment. Read the
        # untruncated value from the decrypted attribute table and use it verbatim --
        # the kaitai / last-attribute reads above drop its final character (then the
        # slot was appended back, which only matched when the dropped character
        # happened to equal the slot). Fall back to the old prefix+slot form when the
        # full attribute is unavailable.
        comm_path: Union[str, None] = None
        if _comm_path_prefix is not None:
            _ctrl_slot = next(
                (m._slot for m in modules if m._is_root), None
            )
            if _ctrl_slot is not None:
                # Same presence as before (a stored prefix + a root slot); only the
                # value source changes to the untruncated 0x06A attribute.
                _cp_full = _ctlattrs.get(0x06A)
                comm_path = (
                    _cp_full.decode("utf-16-le", errors="replace").rstrip("\x00")
                    if _cp_full else _comm_path_prefix + str(_ctrl_slot)
                )
        return processor_type, major_rev, minor_rev, comm_path

    def _pass_project_settings(self, processor_type, _ctlattrs, _ctlblob,
                               major_rev="0"):
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
        # Controller FIRMWARE MajorRev (== OEM <Controller MajorRev>), not the
        # ACD container save version (self._acd_major): PassThrough/DownloadDocs
        # appear from v24, but DownloadProjectCustomProperties/ReportMinorOverflow
        # only from v28 (verified 58/58 absent <=24, 58/58 present >=28), so
        # gating those on _v24_plus over-emits on the 4 v24 files.
        _fw = int(major_rev) if str(major_rev).isdigit() else 0
        _v24_plus = is_5x80 or self._acd_major >= 24
        _v28_plus = is_5x80 or _fw >= 28
        pass_through = "EnabledWithAppend" if _v24_plus else None
        download_docs = "true" if _v24_plus else None
        download_custom = "true" if _v28_plus else None
        report_minor_overflow = "false" if _v28_plus else None
        # AutoDiags/WebServer hinge on the 5x80 generation, which we read from
        # the catalog number. When the root catalog can't be resolved
        # (processor_type is None) we can't tell the generation, so fall back to
        # the save version: these features never appear below v32, so a modern
        # save with an unknown catalog is treated as 5x80 rather than dropping a
        # value the reference keeps.
        # AutoDiags first appears at firmware v33 (absent <=32, present-mixed
        # >=33 vs OEM), so add a firmware floor: 3 v30 5x80 files over-emit it
        # without it.
        _modern_unknown_cpu = processor_type is None and self._acd_major >= 32
        _autodiags_gen = (is_5x80 or _modern_unknown_cpu) and _fw >= 33
        # AutoDiagsEnabled is a real per-controller flag: bit 0 of the final byte
        # (offset 135) of the 5x80 controller-properties blob. Validated 16 true /
        # 10 false vs OEM, 0 mismatch. WebServerEnabled lives in the controller's
        # embedded Ethernet config: decrypted ext-attr 0x81, byte 0 (1=true/0=false).
        # Emit only on a controller that actually carries the embedded-ethernet attrs
        # (0x81 or 0x7e); a 5x80 without them (e.g. 5069-L310ERM) omits the attribute
        # like OEM. Validated 0 over-emit / 0 value-mismatch pool-wide.
        if _autodiags_gen:
            auto_diags = "true" if (len(_ctlblob) > 135 and (_ctlblob[135] & 1)) else "false"
        else:
            auto_diags = None
        if (is_5x80 or _modern_unknown_cpu) and (0x81 in _ctlattrs or 0x7e in _ctlattrs):
            web_server = "true" if (_ctlattrs.get(0x81) and _ctlattrs[0x81][0] == 1) else "false"
        else:
            web_server = None
        return (pass_through, download_docs, download_custom, report_minor_overflow,
                auto_diags, web_server, _v24_plus)

    def _pass_aoi_signature(self):
        # <AddOnInstructionDefinitions> safety signature: a safety-signed project
        # carries Generated-Safety-Signature timestamp comments (tag_reference
        # "Timestamp\x11GSS"). When present, the reference stamps the AOI collection
        # element with an all-zero signature and the (modal) GSS timestamp.
        aoi_sig = aoi_sig_ts = None
        try:
            _gss = [g[0] for g in self._cur.execute(
                "SELECT record_string FROM comments WHERE tag_reference=?",
                ("Timestamp\x11GSS",)).fetchall() if g[0]]
            if _gss:
                aoi_sig = " - ".join(["00000000"] * 8)
                aoi_sig_ts = max(sorted(set(_gss)), key=_gss.count)
        except Exception:
            aoi_sig = aoi_sig_ts = None
        return aoi_sig, aoi_sig_ts

    def _pass_message_alarm_data(self, tags, programs, modules):
        # --- MESSAGE tag <Data Format="Message"> blocks (post-process) ---
        # Resolved here, not in TagBuilder, because the CIP ConnectionPath
        # resolves against the module topology, which is only complete once every
        # module is built. Best-effort: any tag (controller- or program-scope)
        # that does not decode with full confidence keeps its prior no-<Data>.
        try:
            _msg_nr, _msg_rc = _msg_build_module_routes(modules)
            _msg_oid2name = {o: n for o, n in self._cur.execute(
                "SELECT object_id, comp_name FROM comps")}
            _msg_tags = list(tags)
            for _prog in programs:
                _msg_tags.extend(_prog.tags)
            for _mt in _msg_tags:
                if (_mt.data_type or "").upper() == "MESSAGE" and _mt.tag_type != "Alias":
                    _mt._message_data_xml = _render_message_data(
                        self._cur, self._short_header, _mt._data_table_instance,
                        _msg_oid2name, _msg_nr, _msg_rc)
        except Exception:
            pass

        # ALARM_DIGITAL tags carry a dedicated <Data Format="Alarm"> block decoded
        # from their data-table backing. Short-header (V20/21) form only; the V31+
        # variant (extra Shelve attrs/bools) is not emitted here.
        if self._short_header:
            try:
                _al_tags = list(tags)
                for _prog in programs:
                    _al_tags.extend(_prog.tags)
                for _at in _al_tags:
                    if (_at.data_type or "").upper() == "ALARM_DIGITAL" and _at.tag_type != "Alias":
                        _at._alarm_data_xml = _render_alarm_digital_data(
                            self._cur, self._short_header, _at._data_table_instance)
            except Exception:
                pass

        # Axis tags carry a <Data Format="Axis"> block whose value image is
        # attr 0x01 of the cip-0x6a backing (not 0x66); MotionGroup resolves
        # against every MOTION_GROUP tag, so this runs post-build. AXIS_VIRTUAL
        # renders at every fitting blob length; AXIS_CIP_DRIVE/AXIS_SERVO_DRIVE
        # render through the length-keyed schema in axis_cip.py (fail-closed:
        # unrecognised lengths/profiles keep element_missing rather than go
        # net-worse).
        try:
            _ax_tags = list(tags)
            for _prog in programs:
                _ax_tags.extend(_prog.tags)
            # {MOTION_GROUP backing comment_id -> group tag name}
            _grp_by_cid: Dict[int, str] = {}
            for _gt in _ax_tags:
                if (_gt.data_type or "").upper() != "MOTION_GROUP":
                    continue
                _gr = self._cur.execute(
                    "SELECT record FROM comps WHERE object_id=?",
                    (_gt._data_table_instance,)).fetchone()
                if _gr and _gr[0] is not None and len(bytes(_gr[0])) >= 14:
                    _cid = struct.unpack_from("<H", bytes(_gr[0]), 12)[0]
                    _grp_by_cid[_cid] = _gt.name
            _modid_name = getattr(self, "_modid_to_name", {}) or {}
            for _at in _ax_tags:
                _adt = (_at.data_type or "").upper()
                if (_adt not in ("AXIS_VIRTUAL", "AXIS_CIP_DRIVE",
                                 "AXIS_SERVO_DRIVE", "MOTION_GROUP")
                        or _at.tag_type == "Alias"):
                    continue
                _br = self._cur.execute(
                    "SELECT record FROM comps WHERE object_id=?",
                    (_at._data_table_instance,)).fetchone()
                if not _br or _br[0] is None:
                    continue
                _blob = CompsRecord.read_value_attrs(
                    bytes(_br[0]), self._short_header, full=True,
                    body_mode=True).get(0x01)
                if not _blob or len(_blob) < 14:
                    continue
                if _adt == "MOTION_GROUP":
                    _at._axis_data_xml = _render_motion_group(_blob)
                    continue
                _gcid = struct.unpack_from("<H", _blob, 8)[0]
                _gname = _grp_by_cid.get(_gcid)
                if _adt == "AXIS_VIRTUAL":
                    if _gname is None:
                        continue
                    _at._axis_data_xml = _render_axis_virtual(_blob, _gname)
                else:
                    # _gname may be None for a group-less drive axis: the
                    # renderer emits MotionGroup only when the blob's group
                    # reference is set, and fails closed when the name is
                    # needed but unresolved.
                    _at._axis_data_xml = _render_axis_cip_drive(
                        _blob, _gname, _modid_name, _adt)
        except Exception:
            pass

    def _pass_motion_sync(self, tags, programs, modules):
        # CIP Motion: a 2094-family integrated-motion drive (ProductType 37) exports
        # its MotionSync connection with RPI 0 when the drive is UNSCHEDULED -- when
        # it owns no axis, OR its axis is not assigned to a motion group. A scheduled
        # drive keeps the connection blob's RPI (the group's coarse update period).
        # Two record fields decide it, both on the AXIS_CIP_DRIVE tag's data-table
        # record: the drive modid (u32 at full-payload offset 250 = body 102 on the
        # long header) links the axis to its module, and the axis' group assignment
        # (u16 at offset 8 of the record's ext-attr 0x1 value image) names its motion
        # group -- 0, or a cid no MOTION_GROUP tag carries, means unassigned. Only act
        # when EVERY axis' modid resolves to a known module (that confirms the layout
        # for this project); an unreadable group image counts the axis as scheduled,
        # so a drive that really is grouped is never wrongly zeroed. Long-header only.
        try:
            if not self._short_header:
                _axis_tags = [t for t in tags if (t.data_type or "") == "AXIS_CIP_DRIVE"]
                _grp_tags = [t for t in tags
                             if (t.data_type or "").upper() == "MOTION_GROUP"]
                for _prog in programs:
                    _axis_tags += [t for t in _prog.tags
                                   if (t.data_type or "") == "AXIS_CIP_DRIVE"]
                    _grp_tags += [t for t in _prog.tags
                                  if (t.data_type or "").upper() == "MOTION_GROUP"]
                _grp_cids = set()
                for _gt in _grp_tags:
                    _gr = self._cur.execute(
                        "SELECT record FROM comps WHERE object_id=?",
                        (_gt._data_table_instance,)).fetchone()
                    if _gr and _gr[0] is not None and len(bytes(_gr[0])) >= 14:
                        _grp_cids.add(struct.unpack_from("<H", bytes(_gr[0]), 12)[0])
                _known = {m._modid for m in modules if m._modid}
                _scheduled = set()
                _complete = bool(_axis_tags)
                for _at in _axis_tags:
                    _arow = self._cur.execute(
                        "SELECT record FROM comps WHERE object_id=?",
                        (_at._data_table_instance,)).fetchone()
                    _buf = bytes(_arow[0]) if _arow and _arow[0] else b""
                    _cand = (struct.unpack_from("<I", _buf, 102)[0]
                             if len(_buf) >= 106 else None)
                    if _cand not in _known:
                        _complete = False
                        continue
                    _vb = CompsRecord.read_value_attrs(
                        _buf, self._short_header, full=True,
                        body_mode=True).get(0x01)
                    # Fail toward scheduled (keep the blob RPI) on an unreadable
                    # image -- never emit a wrong 0.
                    if (_vb is None or len(_vb) < 10
                            or struct.unpack_from("<H", _vb, 8)[0] in _grp_cids):
                        _scheduled.add(_cand)
                if _complete:
                    for _m in modules:
                        if _m._product_type == 37 and _m._modid and _m._modid not in _scheduled:
                            for _c in _m._connections:
                                if _c.get("type") == "MotionSync":
                                    _c["rpi"] = "0"
        except Exception:
            pass

    def _pass_trends(self):
        # <Trends>: the RSTrendX trend objects hanging off the controller's
        # RxTrendCollection (see acd.l5x.trends). sw_major is the DERIVED
        # SoftwareRevision major from project_flags -- the same value the export
        # header carries -- and keys the <Template> newline band and the v19 pen
        # attribute order. It is underivable as 0, which no witnessed band covers,
        # so the renderer then withholds every trend and the section degrades to
        # the '<Trends/>' emitted before this pass existed.
        try:
            _pf = self._cur.execute(
                "SELECT sw_major FROM project_flags").fetchone()
            _sw_major = (_pf[0] if _pf else 0) or 0
        except Exception:
            _sw_major = 0
        return build_trends(self._cur, self._object_id, self._short_header,
                            _sw_major)

    def _pass_safety_info(self):
        # Controller-level <SafetyInfo> signature children (safety-signed projects
        # only). The named_safety_signatures table is keyed by (otype, embedded name);
        # it is empty on unsigned projects, so the lookups return None and nothing is
        # emitted (0 false-positive). RootSignature and ControllerAttributesSignature
        # share otype 820 and are split by the name ("OverallSignature" vs none).
        def _named_sig(_ot, _nm):
            try:
                _r = self._cur.execute(
                    "SELECT signature, timestamp FROM named_safety_signatures "
                    "WHERE otype=? AND name=?", (_ot, _nm)).fetchone()
                if _r and _r[0]:
                    return (_r[0], _r[1])
            except Exception:
                pass
            return None
        root_sig = _named_sig(820, "OverallSignature")
        ctrl_attr_sig = _named_sig(820, "")
        tag_map_sig = _named_sig(112, "TagMap")
        app_rollup_sig = _named_sig(142, "")
        safety_info_attrs = _safety_info_attr_string(self._cur, self._short_header)
        alarm_definitions = _alarm_definitions_xml(self._cur, self._short_header)
        safety_tag_map = self._safety_tag_map_text()
        return (root_sig, ctrl_attr_sig, tag_map_sig, app_rollup_sig, safety_info_attrs,
                alarm_definitions, safety_tag_map)

    def _safety_tag_map_text(self):
        # <SafetyTagMap> body: the SafetyTask owns ONE nameless kind-0x899
        # record holding an ordered u32 list of kind-0x89b pair records; each
        # pair's two '@%08x@' UTF-16 strings are the standard/safety tag object
        # ids. Fail-closed: anything unresolvable (or 2+ structurally valid
        # lists) withholds the element (today's output). Validated byte-exact,
        # including pair order, on every emitting file of both pools.
        try:
            _hexstr = re.compile(rb"\x40\x00((?:[0-9a-f]\x00){8})\x40\x00")
            _oid2name = {o: n for o, n in self._cur.execute(
                "SELECT object_id, comp_name FROM comps")}
            _nameless = {o: (p, bytes(r)) for o, p, r in self._cur.execute(
                "SELECT object_id, parent_id, record FROM nameless")
                if r is not None}
            _valid = []
            for _noid, (_pid, _b) in _nameless.items():
                if len(_b) < 20 or struct.unpack_from("<I", _b, 16)[0] != 0x899:
                    continue
                _off = 20
                if len(_b) >= _off + 4 and _b[_off:_off + 4] == b"\xff\xff\xff\xff":
                    _off += 4
                if len(_b) < _off + 2:
                    continue
                _count = struct.unpack_from("<H", _b, _off)[0]
                _off += 2
                if _count == 0 or len(_b) < _off + 4 * _count:
                    continue
                _pairs = []
                for _i in range(_count):
                    _poid = struct.unpack_from("<I", _b, _off + 4 * _i)[0]
                    _ent = _nameless.get(_poid)
                    if _ent is None:
                        break
                    _pb = _ent[1]
                    if len(_pb) < 20 or struct.unpack_from("<I", _pb, 16)[0] != 0x89b:
                        break
                    _hx = _hexstr.findall(_pb)
                    if len(_hx) != 2:
                        break
                    _names = [_oid2name.get(int(_h.decode("utf-16-le"), 16))
                              for _h in _hx]
                    if None in _names:
                        break
                    _pairs.append("%s=%s" % (_names[0], _names[1]))
                else:
                    _valid.append(_pairs)
            if len(_valid) != 1:
                return None
            return " " + ", ".join(_valid[0])
        except Exception:
            return None

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

        controller_description = self._pass_own_description(results, _comment_parent)
        # ACM/library <CustomProperties>: the controller root owns its block keyed
        # by its own comment parent (cip 0x8E), owner_ref 0.
        controller_cp = ""
        if _comment_parent is not None:
            try:
                controller_cp = custom_properties_by_parent(
                    self._cur, _comment_parent) or ""
            except Exception:
                controller_cp = ""
        # @DataExchangeId for the controller root (comments-table object_id 45).
        controller_dxid = None
        if _comment_parent is not None:
            try:
                controller_dxid = own_data_exchange_id(self._cur, _comment_parent)
            except Exception:
                controller_dxid = None
        (sfc_execution_control, sfc_restart_position, sfc_last_scan, project_sn,
         project_creation_date, last_modified_date, _comm_path_prefix, major_fault_program,
         redundancy_enabled) = self._pass_ext_record_scalars(r, extended_records)
        (time_slice, share_unused_time_slice, compatibility_mode, ethernet_ip_mode,
         power_loss_program, io_memory_pad_percentage, data_table_pad_percentage,
         sfc_execution_control, sfc_restart_position, sfc_last_scan, _ctlattrs, _ctlblob) = \
            self._pass_controller_props(results, sfc_execution_control, sfc_restart_position, sfc_last_scan)

        self._object_id = results[0][1]
        controller_name = results[0][0]

        ts_ptp_enable, ts_priority1, ts_priority2, cst_master_id = self._pass_time_sync_cst()
        data_types, data_types_map = self._pass_data_types()
        tags, io_data_map, alarm_map, short_routine_desc, _ctrl_tags_sig = \
            self._pass_controller_tags(data_types_map)
        programs, comment_id_to_program = \
            self._pass_programs(data_types_map, redundancy_enabled, alarm_map, short_routine_desc)
        tasks = self._pass_tasks(comment_id_to_program)
        aois = self._pass_aois(data_types_map, short_routine_desc)
        modules = self._pass_modules(io_data_map)
        processor_type, major_rev, minor_rev, comm_path = \
            self._pass_processor_identity(modules, _comm_path_prefix, _ctlattrs)
        comm_ports_xml = build_comm_ports(
            self._cur, self._object_id, self._short_header)
        internet_protocol_xml = build_internet_protocol(
            self._cur, self._object_id, self._short_header, major_rev)
        ethernet_ports_xml = build_ethernet_ports(
            self._cur, self._object_id, self._short_header, major_rev)
        ethernet_network_xml = build_ethernet_network(
            self._cur, self._object_id, self._short_header)
        (pass_through, download_docs, download_custom, report_minor_overflow, auto_diags,
         web_server, _v24_plus) = self._pass_project_settings(
            processor_type, _ctlattrs, _ctlblob, major_rev)
        aoi_sig, aoi_sig_ts = self._pass_aoi_signature()
        self._pass_message_alarm_data(tags, programs, modules)
        self._pass_motion_sync(tags, programs, modules)
        (root_sig, ctrl_attr_sig, tag_map_sig, app_rollup_sig, safety_info_attrs,
         alarm_definitions, safety_tag_map) = self._pass_safety_info()
        trends_xml = self._pass_trends()
        (controller_language, current_project_language,
         default_project_language) = self._project_language_attrs()

        controller = Controller(
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
            controller_language=controller_language,
            current_project_language=current_project_language,
            default_project_language=default_project_language,
            # <DataLogs> ships with the DataLog feature in v24; gate it on the
            # same v24+/5x80 signal as the project-download settings above.
            _emit_data_logs=_v24_plus,
            _description=controller_description,
            _custom_properties=controller_cp,
            _data_exchange_id=controller_dxid,
            _aoi_safety_signature=aoi_sig,
            _aoi_safety_signature_timestamp=aoi_sig_ts,
            time_slice=time_slice,
            share_unused_time_slice=share_unused_time_slice,
            compatibility_mode=compatibility_mode,
            ethernet_ip_mode=ethernet_ip_mode,
            power_loss_program=power_loss_program,
            _io_memory_pad_percentage=io_memory_pad_percentage,
            _data_table_pad_percentage=data_table_pad_percentage,
            _comm_ports_xml=comm_ports_xml,
            _internet_protocol_xml=internet_protocol_xml,
            _ethernet_ports_xml=ethernet_ports_xml,
            _ethernet_network_xml=ethernet_network_xml,
            _ts_ptp_enable=ts_ptp_enable,
            _ts_priority1=ts_priority1,
            _ts_priority2=ts_priority2,
            _cst_master_id=cst_master_id,
            _root_signature=root_sig,
            _ctrl_attr_signature=ctrl_attr_sig,
            _tag_map_signature=tag_map_sig,
            _app_rollup_signature=app_rollup_sig,
            _safety_info_attrs=safety_info_attrs,
            _alarm_definitions=alarm_definitions,
            _safety_tag_map=safety_tag_map,
            _trends_xml=trends_xml,
        )
        # Controller-scoped <Tags> safety signature (separate from the AOI-section one).
        if _ctrl_tags_sig:
            controller._section_attrs["tags"] = _ctrl_tags_sig
        # <Modules> safety signature (otype 105, empty name): present only on the
        # 14 OEM-signed projects, byte-exact there; both signature and timestamp
        # are required so an incomplete row never renders a bare attribute.
        try:
            _mod_sig = self._cur.execute(
                "SELECT signature, timestamp FROM named_safety_signatures "
                "WHERE otype=105 AND name=''").fetchone()
        except Exception:
            _mod_sig = None
        if _mod_sig and _mod_sig[0] and _mod_sig[1]:
            controller._section_attrs["modules"] = (
                f' SafetySignature="{_mod_sig[0]}"'
                f' SafetySignatureTimestamp="'
                f'{html.escape(_mod_sig[1], quote=True)}"')
        return controller


@dataclass
class ProjectBuilder:
    quick_info_filename: PathLike
    # Controller decoded from Comps.Dat, used to source the project name and
    # revision when QuickInfo.XML is absent (pre-V10 ACDs never carry it).
    fallback_controller: "Union[Controller, None]" = None

    def build(self) -> RSLogix5000Content:
        # QuickInfo.XML supplies the top-level project name / schema / software
        # revision. Pre-V10 ACDs predate this stream; degrade to the controller
        # record (which is decoded from Comps.Dat regardless), mirroring the
        # os.path.exists guard the controller() property already applies.
        element = None
        if os.path.exists(self.quick_info_filename):
            element = ET.parse(self.quick_info_filename)

        target_name = None
        schema_revision = "1.0"
        software_revision = None
        if element is not None:
            rslogix_content_element = element.find(".")
            if rslogix_content_element is not None:
                target_name = rslogix_content_element.attrib.get("Name")

            schema_version_element = element.find("SchemaVersion")
            if schema_version_element is not None:
                schema_version_major = schema_version_element.attrib["Major"]
                schema_version_minor = schema_version_element.attrib["Minor"]
                schema_revision = f"{schema_version_major}.{schema_version_minor}"

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
            if software_revision is None:
                # SWVersion missing or in an unexpected format — fall back to the
                # DeviceIdentity firmware version.
                device_identity = element.find("DeviceIdentity")
                if device_identity is not None:
                    software_revision = (
                        f"{device_identity.attrib['MajorRevision']}"
                        f".{device_identity.attrib['MinorRevision']}"
                    )

        # QuickInfo absent (or incomplete): source name/revision from the
        # controller record so the project still carries a correct TargetName.
        if target_name is None and self.fallback_controller is not None:
            target_name = self.fallback_controller.name
        if software_revision is None and self.fallback_controller is not None:
            software_revision = (
                f"{self.fallback_controller.major_rev}"
                f".{self.fallback_controller.minor_rev}"
            )
        if software_revision is None:
            software_revision = "33.01"

        target_type = "Controller"
        # Full controller-project exports (TargetType="Controller") always carry the
        # surrounding context; the reference emits "true" on every such export.
        contains_context = "true"
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
            current_language=getattr(
                self.fallback_controller, "current_project_language", None),
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
