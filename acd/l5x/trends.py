# The controller's <Trends> section: RSTrendX trend objects, their <Template>
# blob, their own <Description> and their <Pens>/<Pen> children.
#
# Every value is READ from the trend's own comps record through the existing
# CompsRecord.record_attrs ext-attr table (which slices both header families and
# transparently decrypts the source-protected variant, so an SP trend needs no
# special-casing here) and formatted by the converter's existing emitters
# (tag_value._format_int_radix / _fmt_real_decorated, base._xml_sane). Nothing is
# keyed by catalog, plant or file name.
#
# FAIL-CLOSED, ALL-OR-NOTHING PER TREND: if any attribute, pen, the template or
# the <Template> newline band cannot be reconstructed from the record, the WHOLE
# <Trend> is withheld -- today's output is a missing element, so a withhold is
# never worse than the status quo, while a partially-guessed <Trend> would be. If
# no trend renders, the section degrades to the bare <Trends/> emitted before this
# module existed.
#
# ---------------------------------------------------------------------------
# RECORD FAMILY
#
# A trend is an ordinary comps component hanging off the collection record named
# 'RxTrendCollection', itself a direct child of the controller record. Selection
# is by PARENTAGE ONLY:
#   * record_type is NOT a discriminator -- trends occur as BOTH 0 and 256, mixed
#     inside a single collection, so filtering on 256 silently drops trends (15 of
#     the reference's 137, and every trend in two projects);
#   * a name lookup must never be used either -- trend names collide with
#     components of other collections (e.g. RxMapDeviceCollection).
# Deleted relics are dropped through the established CompsRecord.dead_oids
# liveness gate, so a trend the reference never exports is never emitted.
#
# The measured ext-attr inventory (137/137 reference trends):
#   0x01        record marker            0x64  OLE template == <Template> blob[:-4]
#   0x67        pen count (u32)          0x68  SamplePeriod, MICROSECONDS (u64)
#   0x6e..0xb4  pen trios, stride 10     0xbe  capture/trigger config blob
# 0xbe (190) sits on the same stride-10 lattice as the pen trios but is the
# capture blob, NOT a 9th pen: the lattice must stop at 180 or every trend is
# off-by-one on its pen count.
#
# ---------------------------------------------------------------------------
# THE 0xbe BLOB IS THREE STRUCTS
#
#   8808 = 4118 (start trigger) + 4118 (stop trigger) + 572 (capture)
#          |__ base 0 __|__ base 4118 __|__ base 8236 __|
# Every field of the start struct re-appears at exactly +4118 in the stop struct
# and drives the matching Stop* attribute, and the capture struct begins exactly
# where the second trigger struct ends.
#
# Each trigger struct is
#   +0 TriggerType, +4 ConditionCount, then conditions at +8, stride 0x55a,
# and each condition is
#   +0 TargetType, +4 Operation, +8 TargetValue, +0xc ValueType (u16),
#   +0xb0 Tag (UTF-16), +0x352 TargetTag (UTF-16), +0x552 LogicalOp.
# This inner layout is NOT fitted to the reference -- it is read out of the
# vendor's own RxTrendGroup routines (the blob IS their sTriggerInfo struct,
# memcpy'd into attr 0xbe at its natural size of 0x2268). That matters because
# the reference holds exactly ONE distinct trigger configuration, so several
# rival offset assignments score 2/2 against it: notably +4 reads 1 and would
# "confirm" TargetValue1="1", but +4 is the CONDITION COUNT and reads 1 only
# because this witness has one condition. Field identity here comes from the
# code that writes each field, not from the values it happens to hold.

import html
import struct
from sqlite3 import Cursor
from typing import Dict, List, Optional, Tuple

from acd.l5x.base import (
    _AT_TOKEN_RE,
    _xml_sane,
    own_description,
    resolve_at_tokens,
    short_own_description,
)
from acd.l5x.tag_value import _fmt_real_decorated, _format_int_radix
from acd.record.comps import CompsRecord

#: The collection record every trend hangs off (a direct controller child).
TREND_COLLECTION = "RxTrendCollection"

#: cip_type of a trend component, read from its record prelude (@+10). Uniform
#: across the reference (137/137, both header families); a record that does not
#: carry it is a shape we have not decoded -> withhold.
TREND_CIP_TYPE = 0xB2

#: --- ext-attr ids ---------------------------------------------------------
ATTR_TEMPLATE = 0x64
ATTR_PEN_COUNT = 0x67
ATTR_SAMPLE_PERIOD = 0x68
ATTR_CAPTURE = 0xBE

#: --- <Template> -----------------------------------------------------------
#: Decimal bytes per line in the reference's <Template> rendering.
TEMPLATE_BYTES_PER_LINE = 40

#: Modulus used by RxTrendGroup::CalculateCRC (largest prime below 2**15).
TRENDX_MODULUS = 32749  # 0x7FED

#: FLAG -- THE <Template> NEWLINE BAND.
#: The reference contains two renderings of the <Template> line break and the
#: difference survives XML normalisation (an extra blank line is a text
#: mismatch): raw '\r\n ' -> '\n ' (121/142 templates) vs raw '\r\r\n ' ->
#: '\n\n ' (21/142). Every reference file is CRLF throughout, so '\r\r\n' is the
#: classic artifact of an exporter that already held a '\r\n' in the string when
#: the file went through a text-mode '\n'->'\r\n' translation: it is a quirk of
#: the EXPORTING Studio build, and since the template is binary in the ACD (attr
#: 0x64) no newline of any kind is stored there and it cannot be read out of the
#: record. It partitions the reference perfectly by the DERIVED SoftwareRevision
#: major, and keying a rendering convention on that revision has in-repo
#: precedent (tag_value._wrap_l5k picks its indent by 'SoftwareRevision >= 32').
#: The band is INTERPOLATED from the majors that actually occur, so an
#: unwitnessed major (29, 32-34) is NOT guessed: it withholds the trend. That
#: costs 0 today -- every major present in the reference is witnessed.
_NL_REPEAT_BY_SW_MAJOR = {
    19: 1, 20: 1, 24: 1, 28: 1,
    30: 2, 31: 2,
    35: 1, 36: 1, 37: 1,
}

#: --- 0xbe geometry --------------------------------------------------------
CAPTURE_BLOB_LEN = 8808
TRIGGER_STRIDE = 4118
TRIGGER_BASE_START = 0
TRIGGER_BASE_STOP = TRIGGER_BASE_START + TRIGGER_STRIDE   # 4118
CAPTURE_BASE = TRIGGER_BASE_STOP + TRIGGER_STRIDE         # 8236

#: relative to a trigger base
OFF_TRIGGER_TYPE = 0
OFF_CONDITION_COUNT = 4
OFF_CONDITION_0 = 8

#: A trigger's conditions are a dense array at trigger_base + 8, stride 0x55a.
CONDITION_STRIDE = 0x55A  # 1370

#: relative to a condition base
OFF_COND_TARGET_TYPE = 0
OFF_COND_OPERATION = 4
OFF_COND_TARGET_VALUE = 8
OFF_COND_VALUE_TYPE = 0x0C  # u16
OFF_COND_TAG = 0xB0
#: The tag slot is a fixed 674-byte (337 UTF-16 unit) buffer: cond+0xb0..+0x351,
#: where the TargetTag buffer begins.
COND_TAG_LEN = 0x352 - 0xB0

#: absolute, inside the capture struct (expressed off CAPTURE_BASE so the
#: three-struct factoring above stays the single source of these offsets)
OFF_PRE_SAMPLE_TYPE = CAPTURE_BASE + 0      # 8236
OFF_PRE_SAMPLES = CAPTURE_BASE + 4          # 8240
OFF_POST_SAMPLE_TYPE = CAPTURE_BASE + 8     # 8244
OFF_POST_SAMPLES = CAPTURE_BASE + 12        # 8248
OFF_CAPTURE_UNIT = CAPTURE_BASE + 16        # 8252
OFF_CAPTURE_SIZE = CAPTURE_BASE + 20        # 8256
OFF_NUMBER_OF_CAPTURES = CAPTURE_BASE + 36  # 8272

#: Vocabularies DERIVED from the reference; an unseen code fails closed.
TRIGGER_TYPE_NONE = 3
TRIGGER_TYPE_EVENT = 2
TRIGGER_TYPE_VOCAB = {TRIGGER_TYPE_EVENT: "Event Trigger",
                      TRIGGER_TYPE_NONE: "No Trigger"}

#: Pre/PostSampleType. The companion count is a sample count under "Samples" and
#: MILLISECONDS under "Time Period" -- either way the reference renders the
#: stored u32 verbatim, so the unit never reaches the renderer.
SAMPLE_TYPE_VOCAB = {1: "Samples", 2: "Time Period"}

#: TriggerTargetType is a 0/1 selector: 1 = the target is a literal value, 0 =
#: the target is a TAG (held at cond+0x352). Only 1 has a KNOWN L5X spelling --
#: the string for 0 is absent from both the vendor binary and the reference, so
#: 0 is deliberately NOT in this table and fails closed rather than guess
#: "Target Tag". The cond+0x352 TargetTag slot is unreachable for the same
#: reason and is therefore not decoded at all.
TARGET_TYPE_VOCAB = {1: "Target Value"}

#: TriggerTargetValue's storage discriminator (u16 at cond+0xc).
VALUE_TYPE_INT = 1
VALUE_TYPE_FLOAT = 2

#: TriggerOperation is emitted as a RAW INTEGER -- there is no value->string
#: table anywhere and the reference literally renders Operation1="0". The vendor
#: validator rejects <0 and >14, so a code outside that range means the field has
#: been mis-read -> fail closed. (The validator additionally rejects 9..14 for
#: float operands; that is an operand-typing rule, not a decode rule, so it is
#: not enforced here.)
TRIGGER_OPERATION_MAX = 14

CAPTURE_UNIT_SAMPLES = 1
CAPTURE_UNIT_TIME = 2
CAPTURE_UNIT_TIME_AS_SAMPLES = 0xFFFFFFFF

#: SamplePeriod: microseconds -> milliseconds.
SAMPLE_PERIOD_DIVISOR = 1000

#: CONST-RENDER -- SETTLED. TrendxVersion is "5.2" on all 142 reference trends,
#: across 9 SoftwareRevisions and both pools, and it is not in the 0xbe blob, not
#: a string in the OLE template, and not tracked by the template's Contents
#: header. That alone could not settle it: with ZERO variance across the
#: reference, any constant field would "derive" it and no candidate could ever be
#: falsified. The vendor binary settles it. L"5.2" is a literal assigned to the
#: RxTrendGroup member at +0x598 in its CONSTRUCTOR; the getter that feeds the
#: export returns that member; the setter that would overwrite it has zero
#: callers anywhere in the library; and the measured attr inventory of the trend
#: record (137/137) carries no version attribute at all -- so there is nothing
#: for it to be derived FROM. It is genuinely a build constant of the trend
#: component, const-rendered like elements.py's `schema_revision = "1.0"`.
#: SCOPE: it is a constant of the EXPORTING Studio build, not of the record, so a
#: future Studio major could carry a different literal. Our reference is 100%
#: "5.2" across V7-V37.
TRENDX_VERSION = "5.2"

#: --- pens ------------------------------------------------------------------
#: Pen-trio bases. 190 (0xbe) is the capture blob, NOT a pen.
PEN_BASES = tuple(range(110, 190, 10))

#: Fixed-head field offsets inside the pen props blob (base+2).
OFF_SENTINEL, OFF_COLOR, OFF_WIDTH, OFF_VISIBLE = 0, 4, 8, 12
OFF_MIN, OFF_MAX, OFF_STYLE, OFF_TYPE, OFF_MARKER = 16, 20, 24, 28, 32
OFF_STRINGS = 36

#: The u32 at +0 on every reference pen. A different value means a layout we do
#: not understand -> withhold rather than mis-read every field behind it.
PROPS_SENTINEL = 0xFFFFFFFF

VISIBLE_VOCAB = {0: "false", 1: "true"}
TYPE_VOCAB = {0: "Analog", 1: "Digital"}
#: Reference-degenerate: only 0 is witnessed for Style/Marker, so the offset
#: assignment could not be confirmed from a corpus in which both fields are
#: always 0. The vendor binary CONFIRMS both: the pen blob is a verbatim memcpy
#: of RxCChartPen+0x0c, and its one-instruction getters put Style at member
#: +0x24 (= blob +24) and Marker at member +0x2c (= blob +32) -- exactly where
#: this module reads them. The soft spot is closed for the OFFSETS. The
#: VOCABULARIES stay reference-only and fail-closed: the binary bounds Style to
#: 0..4 and Marker to 0..83 but never maps a code to an L5X spelling, so a
#: non-zero pen still withholds rather than guess.
STYLE_VOCAB = {0: "0"}
MARKER_VOCAB = {0: "0"}

#: Reference-canonical <Pen> attribute order (536/556 reference pens; EngUnits,
#: when present, always trails Max).
PEN_ATTR_ORDER = ("Name", "Color", "Visible", "Style", "Type", "Width",
                  "Marker", "Min", "Max", "EngUnits")

#: The older exporter's Style/Type/Width permutation, witnessed only at
#: SoftwareRevision 19 (2/544 in-scope pens, in a single project). XML attribute
#: order is semantically void, but reproducing the reference's raw bytes is free
#: here, so it is keyed on the same derived SoftwareRevision the newline band
#: uses.
PEN_ATTR_ORDER_V19 = ("Name", "Color", "Visible", "Width", "Type", "Style",
                      "Marker", "Min", "Max", "EngUnits")


class _Withhold(Exception):
    """A trend that cannot be reconstructed exactly -> omit the whole element."""


def _trendx_tail(buf: bytes) -> int:
    """RxTrendGroup::CalculateCRC(buf, len(buf)) -> the template's u32 tail.

    `buf` is the template blob minus its trailing 4 bytes (the OLE2 document
    followed by the u32 flag). Despite the vendor's name this is not a CRC: it is
    position-dependent through a `* i` term and reduces modulo a prime, which is
    why it is neither GF(2)- nor Z-linear. Reimplemented from the routine in the
    v21 services library; verified against every reference template plus a
    controlled-delta set (107/107 on the FULL 32-bit tail, not just its low u16).

    The trailing 4 bytes are ONE little-endian u32, not a u16 checksum plus a u16
    version: byte 2 is always 3 because the OLE part is a multiple of 512 and the
    flag's high byte is 0, and byte 3 is always 0 because the final write lands in
    byte 2. So no "version" constant is emitted -- it falls out of the checksum.
    """
    acc = 0
    for i, b in enumerate(buf):
        # al = ((p[i] + 1) * i) & 0xFF  -- the vendor's `inc al` wraps and only
        # AL is consumed, so signedness cannot affect the result.
        al = ((b + 1) * i) & 0xFF
        if i == 0:
            acc = (acc & 0xFFFF00FF) | (al << 8)      # byte1, no reduce
        elif i & 1:
            acc = (acc & 0xFF00FFFF) | (al << 16)     # byte2, no reduce
        else:
            acc = (acc & 0x00FFFFFF) | (al << 24)     # byte3, then reduce
            acc %= TRENDX_MODULUS
    return acc


class _TrendRecord(object):
    """One live trend comps component."""

    __slots__ = ("name", "oid", "attrs", "raw", "seq")

    def __init__(self, name: str, oid: int, attrs: Dict[int, bytes],
                 raw: bytes, seq: int = 0):
        self.name = name
        self.oid = oid
        self.attrs = attrs
        self.raw = raw
        self.seq = seq


def _parse_trends(cur: Cursor, controller_oid: int,
                  short_header: bool) -> List[_TrendRecord]:
    """Every live trend in the project, in the reference's export order.

    Reuses CompsRecord.record_attrs, so the source-protected trend decrypts
    through the converter's existing key set with no special-casing.

    ORDER: the reference sorts trends by name, case-insensitively, by
    UPPERCASING -- not by lowercasing and not by raw code point. The three keys
    differ only where a name contains '_' (0x5F, which falls between 'Z' and
    'a'), and the reference decides that case against both alternatives:
    'AlphaZeta_Fault' precedes 'Alpha_Tracking' and 'Betaline_Fault'
    precedes 'Beta_Verification', i.e. '_' sorts AFTER every letter, which only
    an uppercased comparison produces. Measured over both pools: upper 39/39
    files, lower/casefold 38/39, raw code point 35/39. seq_number is the
    per-collection export ordinal and is 0 on every reference trend, so it never
    discriminates today; it leads the key because it is the record's own ordering
    field, leaving the uppercased name as the effective sort. An exact
    case-insensitive name collision is unwitnessed; Python's stable sort then
    keeps the records in record order.
    """
    dead = CompsRecord.dead_oids(cur, short_header)
    colls = [r[0] for r in cur.execute(
        "SELECT object_id FROM comps WHERE parent_id=? AND comp_name=?",
        (controller_oid, TREND_COLLECTION))]
    out: List[_TrendRecord] = []
    for coll in colls:
        if coll in dead:
            continue
        rows = cur.execute(
            "SELECT object_id, comp_name, seq_number, record FROM comps "
            "WHERE parent_id=?", (coll,)).fetchall()
        for oid, name, seq, rec in rows:
            if oid in dead:
                continue
            out.append(_TrendRecord(
                name=name, oid=oid,
                attrs=CompsRecord.record_attrs(cur, oid, short_header),
                raw=(bytes(rec) if rec is not None else b""),
                seq=(seq or 0)))
    out.sort(key=lambda t: (t.seq, t.name.upper()))
    return out


def _u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


# ------------------------------------------------------------- <Template> --

def _nl_repeat_for_revision(sw_major: int) -> int:
    """Newline repeat count for the exporting Studio major revision.

    Raises _Withhold for a major the reference never witnessed -- see the
    _NL_REPEAT_BY_SW_MAJOR flag: this is a renderer quirk that cannot be read out
    of the record, so an unwitnessed major is withheld rather than coin-flipped.
    """
    try:
        nl = _NL_REPEAT_BY_SW_MAJOR.get(int(sw_major))
    except (TypeError, ValueError):
        nl = None
    if nl is None:
        raise _Withhold(
            "SoftwareRevision major %r is not witnessed; the <Template> newline "
            "rendering of that Studio build is unknown" % (sw_major,))
    return nl


def _render_template_text(blob: bytes, nl_repeat: int) -> str:
    """The exact text node of <Template> for a complete template blob.

    Grammar, extracted from every inter-token separator of all 142 reference
    templates: space-separated decimal bytes, 40 per line, '\\n'*nl_repeat + ' '
    at each line break (that leading space is CONTENT, inside the text node, not
    indentation), and a trailing '\\n'*nl_repeat iff the length is a multiple of
    40. The trailing newline is invisible to the comparator's outer strip(), but
    it is reproduced anyway so the raw bytes match the reference.
    """
    per = TEMPLATE_BYTES_PER_LINE
    nl = "\n" * nl_repeat
    chunks = [blob[i:i + per] for i in range(0, len(blob), per)]
    s = (nl + " ").join(" ".join(str(b) for b in c) for c in chunks)
    if len(blob) % per == 0:
        s += nl
    return s


def _render_template(trend: _TrendRecord, sw_major: int) -> str:
    """The <Template> element, tail appended and checksummed."""
    body = trend.attrs.get(ATTR_TEMPLATE)
    if not body:
        raise _Withhold("attr 0x64 (template) missing")
    body = bytes(body)
    blob = body + struct.pack("<I", _trendx_tail(body))
    return "<Template>%s</Template>" % _render_template_text(
        blob, _nl_repeat_for_revision(sw_major))


# ------------------------------------------------------------ attributes ---

def _sample_period_ms(attrs: Dict[int, bytes]) -> int:
    """SamplePeriod in ms: the LOW u32 of attr 0x68, microseconds, TRUNCATED.

    The 32-bit read and the truncation are each witnessed by exactly one trend
    (0x68 = 00 a0 b8 30 02 00 00 00: as u64 /1000 = 9407340 and rounding gives
    817406, but the reference says 817405 == low u32 // 1000 floored). Every
    other trend has a zero high u32 and an exact multiple of 1000, so `u64 //
    1000` scores 136/137 and would have looked correct on a smaller sample.
    """
    v = attrs.get(ATTR_SAMPLE_PERIOD)
    if v is None or len(v) < 4:
        raise _Withhold("attr 0x68 missing or short")
    return _u32(bytes(v), 0) // SAMPLE_PERIOD_DIVISOR


def _capture_size(blob: bytes, sp: int) -> Tuple[str, Optional[int]]:
    """(CaptureSizeType, CaptureSize or None).

    unit @8252 alone is NOT a discriminator -- unit==1 covers both "Samples" and
    "No Limit"; the size @8256 completes it, so "No Limit" is READ (size==0), not
    assumed. unit==0xffffffff stores a TIME in ms that the reference renders as a
    sample count (size // SamplePeriod).
    """
    unit = _u32(blob, OFF_CAPTURE_UNIT)
    raw = _u32(blob, OFF_CAPTURE_SIZE)
    if unit == CAPTURE_UNIT_SAMPLES:
        if raw == 0:
            return "No Limit", None
        return "Samples", raw
    if unit == CAPTURE_UNIT_TIME:
        if raw == 0:
            raise _Withhold("unit=Time with size 0 is unwitnessed")
        return "Time Period", raw
    if unit == CAPTURE_UNIT_TIME_AS_SAMPLES:
        if raw == 0:
            raise _Withhold("unit=TimeAsSamples with size 0 is unwitnessed")
        if sp <= 0:
            raise _Withhold("SamplePeriod 0 cannot convert ms->samples")
        if raw % sp:
            # Every witness divides exactly, so floor-vs-round is unwitnessed for
            # THIS conversion and is not extrapolated from _sample_period_ms.
            raise _Withhold("ms->samples division is inexact (%d %% %d)" % (raw, sp))
        return "Samples", raw // sp
    raise _Withhold("unseen capture-size unit %#x" % unit)


def _trigger_type(blob: bytes, base: int) -> Tuple[int, str]:
    """(code, TriggerType string) for the trigger struct at `base`."""
    code = _u32(blob, base + OFF_TRIGGER_TYPE)
    try:
        return code, TRIGGER_TYPE_VOCAB[code]
    except KeyError:
        raise _Withhold("unseen trigger-type code %r at +%d" % (code, base))


def _trigger_tag(cur: Cursor, blob: bytes, cond: int) -> str:
    """The resolved source-tag name of one trigger condition.

    The tag is NOT stored as a name: the exporter replaces names with object
    UIDs on the way out (its own '@<hex>@<member path>' encoding), so the stored
    '@6b2bd9d8@.2' has to be resolved through comps to render 'SomeTag.2'.
    Emitting the stored string raw would emit garbage. Resolution reuses the
    converter's existing @hex@ token resolver.
    """
    raw = blob[cond + OFF_COND_TAG:cond + OFF_COND_TAG + COND_TAG_LEN]
    try:
        stored = _utf16z(raw)
    except (UnicodeDecodeError, ValueError):
        raise _Withhold("trigger tag slot is not UTF-16LE")
    if not stored:
        raise _Withhold("event-trigger condition has an empty tag")
    if not _AT_TOKEN_RE.search(stored):
        # The on-disk form is UID-encoded; a bare name here is a shape neither
        # the vendor's writer nor the reference witnesses, so it is not passed
        # through on the assumption that it is already a name.
        raise _Withhold("trigger tag %r carries no @hex@ token" % stored)
    name = resolve_at_tokens(cur, stored)
    if not name:
        raise _Withhold("trigger tag %r does not resolve" % stored)
    return name


def _target_value(blob: bytes, cond: int) -> str:
    """TriggerTargetValue, formatted per the condition's ValueType.

    ValueType decides how the dword at cond+8 is ENCODED, so it cannot be
    ignored: the reference's integer 1 reinterpreted as f32 would render
    1.4e-45. Only the integer path is witnessed (ValueType=1 on both event
    trends); the float path reads the dword as the f32 the vendor's own
    string<->value converter stores there and hands it to the converter's
    existing REAL formatter -- the same one this module already uses for a
    <Pen>'s Min/Max.
    """
    vtype = struct.unpack_from("<H", blob, cond + OFF_COND_VALUE_TYPE)[0]
    if vtype == VALUE_TYPE_INT:
        return str(_u32(blob, cond + OFF_COND_TARGET_VALUE))
    if vtype == VALUE_TYPE_FLOAT:
        return _fmt_real_decorated(
            struct.unpack_from("<f", blob, cond + OFF_COND_TARGET_VALUE)[0])
    raise _Withhold("unseen trigger ValueType %r" % vtype)


def _trigger_conditions(cur: Cursor, blob: bytes, base: int,
                        prefix: str) -> List[Tuple[str, str]]:
    """The <i>-suffixed condition attributes of one EVENT trigger.

    ConditionCount MUST be 1. The struct holds room for more and the vendor
    supports a second condition, but a second condition exists precisely when
    condition 0's LogicalOp (cond+0x552) is non-zero -- and that logical
    operator has to appear in the L5X too, under an attribute name and
    vocabulary that are in neither the vendor binary nor the reference (which
    contains no *Tag2/*Operation2/LogicalOp attribute at all). Rendering a
    2-condition trigger would therefore silently DROP the operator that joins
    them, which is exactly the partial emission this module refuses. So 2 fails
    closed as loudly as 3 does, and costs nothing today.
    """
    count = _u32(blob, base + OFF_CONDITION_COUNT)
    if count != 1:
        raise _Withhold(
            "trigger declares %d conditions; only the single-condition L5X "
            "shape is known (the LogicalOp attribute is undecoded)" % count)
    out: List[Tuple[str, str]] = []
    for i in range(count):
        cond = base + OFF_CONDITION_0 + i * CONDITION_STRIDE
        n = str(i + 1)
        op = _u32(blob, cond + OFF_COND_OPERATION)
        if op > TRIGGER_OPERATION_MAX:
            raise _Withhold("trigger operation %d is out of the vendor's "
                            "0..%d range" % (op, TRIGGER_OPERATION_MAX))
        ttype = _u32(blob, cond + OFF_COND_TARGET_TYPE)
        if ttype not in TARGET_TYPE_VOCAB:
            raise _Withhold(
                "TriggerTargetType=%r has no known L5X spelling" % ttype)
        out.append((prefix + "TriggerTag" + n, _trigger_tag(cur, blob, cond)))
        out.append((prefix + "TriggerOperation" + n, str(op)))
        out.append((prefix + "TriggerTargetType" + n, TARGET_TYPE_VOCAB[ttype]))
        out.append((prefix + "TriggerTargetValue" + n, _target_value(blob, cond)))
    return out


def _sample_attrs(blob: bytes, type_off: int, count_off: int,
                  type_attr: str, count_attr: str) -> List[Tuple[str, str]]:
    """The Pre*/Post* sample-window attributes of one EVENT trigger.

    The vendor binds the Pre window to the START trigger and the Post window to
    the STOP trigger, and the reference agrees: the sample window appears on
    exactly the 2 event trends and on none of the 140 'No Trigger' ones.
    """
    return [
        (type_attr, _vocab(SAMPLE_TYPE_VOCAB, _u32(blob, type_off), type_attr)),
        (count_attr, str(_u32(blob, count_off))),
    ]


def _trend_attrs(cur: Cursor, trend: _TrendRecord) -> List[Tuple[str, str]]:
    """The <Trend> attributes in reference order.

    Order (read off the raw reference text, not an attrib dict):
        Name, SamplePeriod, NumberOfCaptures, CaptureSizeType, [CaptureSize,]
        StartTriggerType, [StartTriggerTag1, StartTriggerOperation1,
                           StartTriggerTargetType1, StartTriggerTargetValue1,
                           PreSampleType, PreSamples,]
        StopTriggerType,  [StopTriggerTag1, ... PostSampleType, PostSamples,]
        TrendxVersion
    Each bracketed event block is emitted iff ITS OWN trigger is an Event
    Trigger -- the two triggers are independent structs and the vendor binds the
    Pre window to the start trigger and the Post window to the stop trigger. All
    137 in-scope trends are symmetric (both No Trigger, or both Event Trigger),
    so a one-sided event trend renders by this per-trigger rule rather than by a
    witnessed example; it costs 0 today.
    """
    blob = trend.attrs.get(ATTR_CAPTURE)
    if blob is None:
        raise _Withhold("attr 0xbe missing")
    blob = bytes(blob)
    if len(blob) != CAPTURE_BLOB_LEN:
        raise _Withhold("attr 0xbe is %d bytes, expected %d"
                        % (len(blob), CAPTURE_BLOB_LEN))

    sp = _sample_period_ms(trend.attrs)
    start_code, start = _trigger_type(blob, TRIGGER_BASE_START)
    stop_code, stop = _trigger_type(blob, TRIGGER_BASE_STOP)
    cst, csize = _capture_size(blob, sp)

    out = [
        ("Name", trend.name),
        ("SamplePeriod", str(sp)),
        ("NumberOfCaptures", str(_u32(blob, OFF_NUMBER_OF_CAPTURES))),
        ("CaptureSizeType", cst),
    ]
    if csize is not None:
        out.append(("CaptureSize", str(csize)))

    out.append(("StartTriggerType", start))
    if start_code == TRIGGER_TYPE_EVENT:
        out += _trigger_conditions(cur, blob, TRIGGER_BASE_START, "Start")
        out += _sample_attrs(blob, OFF_PRE_SAMPLE_TYPE, OFF_PRE_SAMPLES,
                             "PreSampleType", "PreSamples")

    out.append(("StopTriggerType", stop))
    if stop_code == TRIGGER_TYPE_EVENT:
        out += _trigger_conditions(cur, blob, TRIGGER_BASE_STOP, "Stop")
        out += _sample_attrs(blob, OFF_POST_SAMPLE_TYPE, OFF_POST_SAMPLES,
                             "PostSampleType", "PostSamples")

    out.append(("TrendxVersion", TRENDX_VERSION))
    return out


# ----------------------------------------------------------- description ---

def _trend_description(cur: Cursor, trend: _TrendRecord,
                       short_header: bool) -> Optional[str]:
    """The trend's own <Description> text, or None when it has none.

    Keyed exactly like every other component's own description, off the trend
    record's RxGeneric prelude (comps.record IS the body, so the prelude sits at
    offset 0): cip_type @+10, comment_id @+12, then the established join --
    parent == comment_id*0x10000 + cip_type on the long header, the bare
    comment_id filtered by cip_type on the short header.
    """
    rec = trend.raw
    if len(rec) < 14:
        raise _Withhold("record too short to hold the RxGeneric prelude")
    cip = struct.unpack_from("<H", rec, 10)[0]
    cid = struct.unpack_from("<H", rec, 12)[0]
    if cip != TREND_CIP_TYPE:
        raise _Withhold("trend record cip_type is %#x, expected %#x"
                        % (cip, TREND_CIP_TYPE))
    if short_header:
        desc = short_own_description(cur, cid, cip)
    else:
        desc = own_description(cur, (cid * 0x10000) + cip)
    # own_description's '' is the foreign-only-description sentinel, meaning the
    # reference emits a literal empty <Description/>. No reference trend hits it,
    # so the shape of an empty trend description is unwitnessed -> fail closed
    # rather than invent one. Costs 0 today.
    if desc == "":
        raise _Withhold("empty-description sentinel is unwitnessed on a trend")
    return desc


# ------------------------------------------------------------------ pens ---

def _utf16z(buf: bytes) -> str:
    """Decode a UTF-16LE buffer up to its first NUL terminator."""
    return bytes(buf).decode("utf-16-le", errors="strict").split("\x00", 1)[0]


def _utf16_tail(buf: bytes, off: int) -> Tuple[str, str]:
    """The consecutive NUL-terminated UTF-16LE strings starting at `off`.

    Returns (caption, engunits); a run that ends early yields "" for the rest,
    which is exactly how a 40-byte blob (two bare NULs) reads.
    """
    out: List[str] = []
    i = off
    while i + 1 < len(buf):
        j = i
        while j + 1 < len(buf) and buf[j:j + 2] != b"\x00\x00":
            j += 2
        out.append(bytes(buf[i:j]).decode("utf-16-le", errors="strict"))
        i = j + 2
    while len(out) < 2:
        out.append("")
    return out[0], out[1]


def _vocab(table: Dict[int, str], value: int, what: str) -> str:
    """table[value], or fail closed on a code the reference never witnessed."""
    try:
        return table[value]
    except KeyError:
        raise _Withhold("%s=%r is not witnessed in the reference" % (what, value))


def _parse_pen(trio: Tuple[Optional[bytes], Optional[bytes], Optional[bytes]]
               ) -> Dict[str, Optional[str]]:
    """Decode one pen trio into the exact reference attribute strings + caption.

    Two layouts exist:
        gen1: base+0 = 20-byte tag handle,  base+1 = UTF-16 pen name
        gen2: base+0 = UTF-16 pen name,     base+1 = UTF-16 '@<hex>@<suffix>' ref
    The pen NAME is stored VERBATIM as UTF-16 in one of the two slots for every
    reference pen -- it is never a token needing resolution. In gen2 the @hex@ ref
    sits in the OTHER slot and the plain name is right there in base+0; that
    base+1 ref is the authoritative tag pointer while base+0 is the exporter's
    cached display form, and the reference demonstrably emits the CACHED form, so
    resolving the token instead would produce a different, unvalidated string.

    The DISCRIMINATOR is read from the record, never from a length: gen2 iff
    base+1 matches the converter's existing @hex@ token grammar at position 0.
    The tempting `len(base+0) == 20 -> gen1` test is a TRAP -- a gen2 pen whose
    name is 9 characters is also exactly 20 bytes (9*2 + NUL*2), so the layouts
    genuinely collide on length. A Logix tag name can never begin with '@', so the
    token test cannot misfire on a gen1 name.

    The props blob (base+2) is a fixed head plus a self-describing string tail,
    which is why it is variable length: 40 bytes is simply "both strings empty".
    Width@8 / Visible@12 are NOT swapped between generations even though a naive
    per-generation probe says so -- gen1's pens are all Width==1/Visible==true, so
    both offsets "explain" both fields there; gen2 breaks the tie and that single
    assignment then validates every pen of BOTH generations.
    """
    a0, a1, a2 = trio
    if a0 is None or a1 is None or a2 is None:
        raise _Withhold("incomplete pen trio")
    a0, a1, a2 = bytes(a0), bytes(a1), bytes(a2)
    if len(a2) < OFF_STRINGS:
        raise _Withhold("pen props blob is %d bytes, need >= %d"
                        % (len(a2), OFF_STRINGS))

    try:
        ref = _utf16z(a1)
    except (UnicodeDecodeError, ValueError):
        ref = None
    if ref is not None and _AT_TOKEN_RE.match(ref):
        name_buf = a0
    elif len(a0) == 20:
        name_buf = a1
    else:
        raise _Withhold(
            "base+1 is not an @hex@ ref and base+0 is %d bytes (not a 20-byte "
            "handle)" % len(a0))
    try:
        name = _utf16z(name_buf)
    except (UnicodeDecodeError, ValueError):
        raise _Withhold("pen name slot is not UTF-16LE")
    if not name:
        raise _Withhold("empty pen name")

    if struct.unpack_from("<I", a2, OFF_SENTINEL)[0] != PROPS_SENTINEL:
        raise _Withhold("pen props sentinel is not %#010x" % PROPS_SENTINEL)

    try:
        caption, engunits = _utf16_tail(a2, OFF_STRINGS)
    except (UnicodeDecodeError, ValueError):
        raise _Withhold("pen props string tail is not UTF-16LE")

    return {
        "Name": name,
        "Color": _format_int_radix(
            "DINT", struct.unpack_from("<I", a2, OFF_COLOR)[0], 4, "Hex"),
        "Visible": _vocab(VISIBLE_VOCAB,
                          struct.unpack_from("<I", a2, OFF_VISIBLE)[0], "Visible"),
        "Style": _vocab(STYLE_VOCAB,
                        struct.unpack_from("<I", a2, OFF_STYLE)[0], "Style"),
        "Type": _vocab(TYPE_VOCAB,
                       struct.unpack_from("<I", a2, OFF_TYPE)[0], "Type"),
        "Width": str(struct.unpack_from("<I", a2, OFF_WIDTH)[0]),
        "Marker": _vocab(MARKER_VOCAB,
                         struct.unpack_from("<I", a2, OFF_MARKER)[0], "Marker"),
        "Min": _fmt_real_decorated(struct.unpack_from("<f", a2, OFF_MIN)[0]),
        "Max": _fmt_real_decorated(struct.unpack_from("<f", a2, OFF_MAX)[0]),
        "EngUnits": engunits or None,
        "caption": caption,
    }


def _render_pen(pen: Dict[str, Optional[str]],
                attr_order: Tuple[str, ...]) -> str:
    """The <Pen> element for a _parse_pen() result.

    A non-empty caption renders a <Description> child -- including the very common
    single-SPACE caption, which the reference emits as a real Description block.
    That block normalises to "" in the comparator but is still a missing ELEMENT
    if dropped, so it is emitted whenever the caption is non-empty.
    """
    attrs = "".join(
        ' %s="%s"' % (k, html.escape(_xml_sane(pen[k]), quote=True))
        for k in attr_order if pen.get(k) is not None)
    if not pen["caption"]:
        return "<Pen%s/>" % attrs
    return ("<Pen%s>\n<Description>\n<![CDATA[%s]]>\n</Description>\n</Pen>"
            % (attrs, _xml_sane(pen["caption"])))


def _render_pens(trend: _TrendRecord, attr_order: Tuple[str, ...]) -> str:
    """The <Pens> block, or "" when the trend has no pens.

    Three reference trends legitimately have zero pens and the reference then
    omits <Pens> ENTIRELY -- there is no empty <Pens/> anywhere in it (142 <Trend>
    vs 139 <Pens>) -- so "" means "emit nothing".
    """
    trios = [tuple(trend.attrs.get(base + k) for k in (0, 1, 2))
             for base in PEN_BASES if base in trend.attrs]
    # Cross-check the lattice against the record's own count (137/137 agree). A
    # lattice we have mis-walked must never render a silently short <Pens> block.
    raw = trend.attrs.get(ATTR_PEN_COUNT)
    if raw is None or len(bytes(raw)) < 4:
        raise _Withhold("attr 0x67 (pen count) missing or short")
    declared = struct.unpack_from("<I", bytes(raw), 0)[0]
    if declared != len(trios):
        raise _Withhold("record declares %d pens but the lattice holds %d"
                        % (declared, len(trios)))
    if not trios:
        return ""
    return "<Pens>\n%s\n</Pens>" % "\n".join(
        _render_pen(_parse_pen(t), attr_order) for t in trios)


# ----------------------------------------------------------------- build ---

def _trend_body(cur: Cursor, trend: _TrendRecord, short_header: bool,
                sw_major: int) -> str:
    """One complete <Trend> element, or raise _Withhold to omit it.

    Child order, read off the raw reference text: Description (when present),
    Template, Pens (when the trend has pens).
    """
    attrs = _trend_attrs(cur, trend)
    description = _trend_description(cur, trend, short_header)
    template = _render_template(trend, sw_major)
    pens = _render_pens(
        trend, PEN_ATTR_ORDER_V19 if int(sw_major or 0) == 19 else PEN_ATTR_ORDER)

    attr_text = "".join(
        ' %s="%s"' % (k, html.escape(_xml_sane(v), quote=True)) for k, v in attrs)
    desc_xml = (
        "<Description>\n<![CDATA[%s]]>\n</Description>\n" % _xml_sane(description)
        if description else "")
    return "<Trend%s>\n%s%s%s\n</Trend>" % (
        attr_text, desc_xml, template, ("\n" + pens) if pens else "")


def build_trends(cur: Cursor, controller_oid: int, short_header: bool,
                 sw_major: int) -> str:
    """The controller's <Trends> section.

    Returns the rendered <Trends>...</Trends>, or the bare '<Trends/>' when the
    project has no trends or none of them can be reconstructed exactly. Each
    trend is independently all-or-nothing: one withheld trend never suppresses
    the others, and a withheld trend leaves the pre-existing missing-element
    residual rather than a fabricated one.
    """
    try:
        trends = _parse_trends(cur, controller_oid, short_header)
    except Exception:
        return "<Trends/>"
    rendered: List[str] = []
    for trend in trends:
        try:
            rendered.append(_trend_body(cur, trend, short_header, sw_major))
        except (_Withhold, struct.error, ValueError, UnicodeDecodeError):
            continue
    if not rendered:
        return "<Trends/>"
    return "<Trends>\n%s\n</Trends>" % "\n".join(rendered)
