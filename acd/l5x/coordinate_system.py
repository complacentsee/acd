"""Render the ``<Data Format="CoordinateSystem">`` block for COORDINATE_SYSTEM tags.

A COORDINATE_SYSTEM tag's configuration image is attr 0x01 of its data-table
backing comp (``_data_table_instance``) -- the SAME cip-0x6a body-mode value
image the motion axis/group renderer reads (see ``acd.l5x.axis_cip``), and a
member of the same length-keyed struct family. Three blob lengths appear across
the pools (353, 361, 522); each is a firmware generation with its own tail
layout and its own emitted attribute set (older = fewer attributes). Every
supported length + offset was reverse-engineered from the pool differentials and
validated byte-exact against the OEM export on every in-pool COORDINATE_SYSTEM
tag before being added here.

The struct is a flat little-endian image:
  * a shared HEADER (offsets 0..179 identical across every length) carrying the
    MotionGroupInstance cid (u32@0 -> the MOTION_GROUP tag whose backing record
    holds that value at u16@12, exactly like the axis MotionGroup reference),
    the SystemType enum, Dimension, the per-axis cid array (u16@14 stride 4 ->
    the AXIS tag whose backing holds that value at u16@12), CoordinationMode,
    the CoordinationUnits ASCII string, the Conversion ratio arrays and the
    kinematics velocity/tolerance REALs;
  * a per-length TAIL carrying JointRatio, the kinematics offset REALs and the
    Dynamics/Master/SwingArm fields -- offsets differ per length (newer firmware
    inserts padding), so each length owns an explicit ordered emit schema.

Fail-closed: any unrecognised length, unknown enum code, unresolved
MotionGroup/Axis cid, or inconsistent count gate returns None, so the tag keeps
its prior no-<Data> output (element_missing) rather than emit a wrong,
net-worse block.
"""
import html
import struct
from typing import Dict, Optional

from acd.l5x import tag_value as _tag_value

# SystemType enum (u32). Only the codes proven byte-exact in-pool are mapped;
# any other code fails the render closed.
_SYSTEM_TYPE = {1: "Cartesian", 4: "Articulated Independent", 8: "Delta"}
_COORD_MODE = {0: "Primary", 1: "Ancillary"}
_AUTO_TAG_UPDATE = {0: "Disabled", 1: "Enabled"}
_MAX_DIM = 3


def _u8(b, o):
    return b[o]


def _u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def _real(b, o):
    return _tag_value._fmt_real_decorated(struct.unpack_from("<f", b, o)[0])


# Ordered emit schema per blob length. Each entry is (attr_name, kind, *args).
# Kinds:
#   grp                      MotionGroupInstance: u32@0 -> group cid map
#   sys                      SystemType enum:     u32@4
#   dim                      Dimension:           u32@8 (already validated)
#   axes                     Axes:                u16@(14+4i) -> axis cid map
#   u32/o                    unsigned int -> str at offset o
#   cmode                    CoordinationMode:    u8@(52+i)
#   ascii                    CoordinationUnits:   len u16@60, str@62
#   atu                      CoordinateSystemAutoTagUpdate: u8@162
#   real/o                   REAL at offset o
#   farr/o                   dim REALs at o, stride 4
#   u32arr/o                 dim u32 ints at o, stride 4
#   const/v                  literal string v
#   joint_num/o              JointRatioNumerator (dim REALs @o) -- only if TD>0
#   joint_den/o              JointRatioDenominator (dim u32 @o) -- only if TD>0
_COMMON_HEAD = [
    ("MotionGroupInstance", "grp"),
    ("SystemType", "sys"),
    ("Dimension", "dim"),
    ("Axes", "axes"),
    ("MaximumPendingMoves", "u32", 26),
    ("CoordinationMode", "cmode"),
    ("CoordinationUnits", "ascii"),
    ("ConversionRatioNumerator", "farr", 96),
    ("ConversionRatioDenominator", "u32arr", 130),
    ("CoordinateSystemAutoTagUpdate", "atu"),
    ("MaximumSpeed", "real", 163),
    ("MaximumAcceleration", "real", 167),
    ("MaximumDeceleration", "real", 171),
    ("ActualPositionTolerance", "real", 175),
    ("CommandPositionTolerance", "real", 179),
    ("TransformDimension", "u32", 257),
]


def _kinematics(ko):
    """The 11-REAL kinematics block (LinkLength/ZeroAngle/BaseOffset/EndEffector),
    contiguous from offset ``ko`` (stride 4)."""
    names = ["LinkLength1", "LinkLength2",
             "ZeroAngleOffset1", "ZeroAngleOffset2", "ZeroAngleOffset3",
             "BaseOffset1", "BaseOffset2", "BaseOffset3",
             "EndEffectorOffset1", "EndEffectorOffset2", "EndEffectorOffset3"]
    return [(n, "real", ko + 4 * i) for i, n in enumerate(names)]


# 353: oldest generation. JointRatioDenominator @281, kinematics @297, ends at
# MaximumDecelerationJerk (no Master*/CoordinateDefinition/SwingArm).
_SCHEMA_353 = (
    _COMMON_HEAD
    + [("JointRatioNumerator", "joint_num", 263),
       ("JointRatioDenominator", "joint_den", 281)]
    + _kinematics(297)
    + [("DynamicsConfigurationBits", "u32", 341),
       ("MaximumAccelerationJerk", "real", 345),
       ("MaximumDecelerationJerk", "real", 349)]
)

# 361: adds MasterInputConfigurationBits/MasterPositionFilterBandwidth.
_SCHEMA_361 = (
    _COMMON_HEAD
    + [("JointRatioNumerator", "joint_num", 263),
       ("JointRatioDenominator", "joint_den", 281)]
    + _kinematics(297)
    + [("DynamicsConfigurationBits", "u32", 341),
       ("MaximumAccelerationJerk", "real", 345),
       ("MaximumDecelerationJerk", "real", 349),
       ("MasterInputConfigurationBits", "u32", 353),
       ("MasterPositionFilterBandwidth", "real", 357)]
)

# 522: newest generation. Adds CoordinateDefinition (after SystemType) and the
# full SwingArm/orientation extension. JointRatioDenominator @297, kinematics
# @329, Dynamics/Master block @373. The reference fields CoordinateDefinition
# and SwingArmCouplingDirection are "<none>" (unset) on every in-pool instance.
_SCHEMA_522 = (
    _COMMON_HEAD[:2]
    + [("CoordinateDefinition", "const", "<none>")]
    + _COMMON_HEAD[2:]
    + [("JointRatioNumerator", "joint_num", 263),
       ("JointRatioDenominator", "joint_den", 297)]
    + _kinematics(329)
    + [("DynamicsConfigurationBits", "u32", 373),
       ("MaximumAccelerationJerk", "real", 377),
       ("MaximumDecelerationJerk", "real", 381),
       ("MasterInputConfigurationBits", "u32", 385),
       ("MasterPositionFilterBandwidth", "real", 389),
       ("LinkLength3", "real", 393),
       ("BallScrewLead", "real", 397),
       ("ZeroAngleOffset4", "real", 401),
       ("ZeroAngleOffset5", "real", 405),
       ("ZeroAngleOffset6", "real", 409),
       ("MaximumOrientationSpeed", "real", 413),
       ("MaximumOrientationAcceleration", "real", 417),
       ("MaximumOrientationDeceleration", "real", 421),
       ("SwingArmA3", "real", 425),
       ("SwingArmD3", "real", 429),
       ("SwingArmA4", "real", 433),
       ("SwingArmD4", "real", 437),
       ("SwingArmD5", "real", 441),
       ("SwingArmCouplingRatioNumerator", "u16", 517),
       ("SwingArmCouplingRatioDenominator", "u16", 519),
       ("SwingArmCouplingDirection", "const", "<none>")]
)

_SCHEMAS = {353: _SCHEMA_353, 361: _SCHEMA_361, 522: _SCHEMA_522}

# Length-keyed offsets of the two u16 array COUNT gates (Conversion numerator /
# denominator) and the axis count -- all must equal Dimension for the image to
# be the shape this schema decodes; otherwise fail closed.
_AXIS_COUNT_OFF = 12
_CONV_NUM_COUNT_OFF = 94
_CONV_DEN_COUNT_OFF = 128
# JointRatio numerator/denominator count offsets, per length.
_JOINT_COUNT = {353: (261, 279), 361: (261, 279), 522: (261, 295)}


def render_coordinate_system(blob, group_by_cid: Dict[int, str],
                             axis_by_cid: Dict[int, Optional[str]]) -> Optional[str]:
    """Full ``<Data Format="CoordinateSystem">`` block for a COORDINATE_SYSTEM
    tag, or None.

    ``group_by_cid`` maps a MOTION_GROUP backing's u16@12 -> group tag name.
    ``axis_by_cid`` maps an AXIS backing's u16@12 -> axis tag name, with the
    value None for any cid that is ambiguous (claimed by more than one axis).
    None is returned on any unrecognised/unreconstructable condition so the
    caller keeps the tag's prior no-<Data> output (0-worse).
    """
    try:
        b = bytes(blob)
        schema = _SCHEMAS.get(len(b))
        if schema is None:
            return None
        dim = _u32(b, 8)
        if dim < 1 or dim > _MAX_DIM:
            return None
        # Shape gates: every count field the schema relies on must equal Dimension.
        if _u16(b, _AXIS_COUNT_OFF) != dim:
            return None
        if _u16(b, _CONV_NUM_COUNT_OFF) != dim or _u16(b, _CONV_DEN_COUNT_OFF) != dim:
            return None
        td = _u32(b, 257)
        jnum_off, jden_off = _JOINT_COUNT[len(b)]
        if td > 0 and (_u16(b, jnum_off) != dim or _u16(b, jden_off) != dim):
            return None

        attrs = []
        for entry in schema:
            name, kind = entry[0], entry[1]
            if name in ("JointRatioNumerator", "JointRatioDenominator") and td <= 0:
                # These attributes are absent when there is no transform.
                continue
            val = _decode(b, kind, entry, dim, group_by_cid, axis_by_cid)
            if val is None:
                return None
            attrs.append('%s="%s"' % (name, html.escape(val, quote=True)))
        return ('<Data Format="CoordinateSystem">\n<CoordinateSystemParameters '
                + " ".join(attrs) + "/>\n</Data>")
    except Exception:
        return None


def _decode(b, kind, entry, dim, group_by_cid, axis_by_cid) -> Optional[str]:
    if kind == "grp":
        return group_by_cid.get(_u32(b, 0))
    if kind == "sys":
        return _SYSTEM_TYPE.get(_u32(b, 4))
    if kind == "dim":
        return str(dim)
    if kind == "axes":
        names = []
        for i in range(dim):
            cid = _u16(b, 14 + 4 * i)
            nm = axis_by_cid.get(cid)
            if nm is None:
                return None
            names.append(nm)
        return " ".join(names)
    if kind == "cmode":
        modes = []
        for i in range(dim):
            m = _COORD_MODE.get(_u8(b, 52 + i))
            if m is None:
                return None
            modes.append(m)
        return " ".join(modes)
    if kind == "ascii":
        ln = _u16(b, 60)
        if ln > 64 or 62 + ln > len(b):
            return None
        return b[62:62 + ln].decode("latin1")
    if kind == "atu":
        return _AUTO_TAG_UPDATE.get(_u8(b, 162))
    if kind == "u32":
        return str(_u32(b, entry[2]))
    if kind == "u16":
        return str(_u16(b, entry[2]))
    if kind == "real":
        return _real(b, entry[2])
    if kind in ("farr", "joint_num"):
        return " ".join(_real(b, entry[2] + 4 * i) for i in range(dim))
    if kind in ("u32arr", "joint_den"):
        return " ".join(str(_u32(b, entry[2] + 4 * i)) for i in range(dim))
    if kind == "const":
        return entry[2]
    return None
