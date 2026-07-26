"""Consumed/produced/module connection decoding for the L5X exporter.

Builders that decode the cip-0x69 connection records of a controller into the
per-tag / per-module maps the exporter renders: consumed tags
(``_build_consume_map``), produced tags (``_build_produce_map``), module I/O
connections (``_build_connection_map``) and the config-holder records backing
ConfigData/ConfigScript (``_build_config_holders`` / ``_config_holder_image``).
All offsets are into the raw comps record; see the per-constant comments.
"""
import math
import re
import struct
from typing import Dict

from acd.record.blobs import ConnectionParams
from acd.record.comps import CompsRecord


def _consume_conn_tuple(rec: bytes):
    """Locate a consumed/produced connection's parameter tuple in a cip-0x69 record.

    The tuple is (u32 typeid in 0x300..0x330)(u16 fmt)(u32 rpi_microseconds), where
    the RPI is a positive whole multiple of 500 us. Absolute offsets shift with the
    ACD/record version, so the tuple is located by scan rather than a fixed offset.
    Returns (offset_of_typeid, fmt, rpi_us) or None. fmt == 9 marks a CONSUMED
    connection (10 = produced; other values are motion/diagnostic connections).
    """
    for off in range(0x4E, len(rec) - 10):
        t2 = struct.unpack_from("<I", rec, off)[0]
        if not (0x300 <= t2 <= 0x330):
            continue
        fmt = struct.unpack_from("<H", rec, off + 4)[0]
        rpi = struct.unpack_from("<I", rec, off + 6)[0]
        if 0 < rpi <= 10_000_000 and rpi % 500 == 0:
            return off, fmt, rpi
    return None


_CONSUME_CONN_FMT = 9           # connection-format word marking a consumed tag
_CONSUME_CONN_FMT_SAFETY = 30   # safety (peer-GuardLogix) consumed tag


def _build_consume_map(cur, short_header: bool) -> Dict[int, dict]:
    """Map a consumed controller tag's object_id -> its <ConsumeInfo> attributes.

    A consumed tag's connection details are NOT in the tag's own record; they live
    in a cip-0x69 "connection" record under the producer module's
    RxMapConnectionCollection. For each such record with a CONSUMED parameter tuple
    (fmt == 9, see _consume_conn_tuple) we recover:
      Producer       = the connection collection's parent module friendly name
      RPI            = rpi_microseconds // 1000  (the L5X RPI is in ms)
      RemoteTag      = u16-length-prefixed ASCII at tuple_offset + 38
      Unicast        = 'true' iff the transport enum (u32 at the producer object
                       reference found from offset 0x100) == 2, else 'false'
      RemoteInstance = '0' (constant across the reference corpus)
    The consumed tag's own object_id is the u32 in the trailing 0x0190 TLV
    (b"\\x90\\x01\\x00\\x00\\x04\\x00\\x00\\x00"); 0xFFFFFFFF means it is not stored
    and the connection is skipped. A second pass (see below) recovers connections
    the plaintext scan cannot read -- a source-protected/encrypted record, or one
    that omits the body tag-oid TLV -- from the record's extended attributes.
    Returns {} on any failure.
    """
    out: Dict[int, dict] = {}
    o2name: Dict[int, str] = {}
    o2parent: Dict[int, int] = {}
    coll_oids: set = set()
    dead = CompsRecord.dead_oids(cur, short_header)
    try:
        cur.execute("SELECT object_id, parent_id, comp_name, record FROM comps")
        rows = cur.fetchall()
        o2name = {r[0]: r[2] for r in rows}
        o2parent = {r[0]: r[1] for r in rows}
        coll_oids = {r[0] for r in rows if r[2] == "RxMapConnectionCollection"}
        for oid, pid, nm, rec in rows:
            # Skip dead-relic (FDFD-only) rows: the cip==rec[10] gate below is a
            # fixed offset, so a realigned relic could pass it post-flip and
            # OVERWRITE a live tag's ConsumeInfo (last-write-wins). Long-header
            # only; zero-delta today (relics fail the pre-flip rec[10] gate).
            if oid in dead:
                continue
            if pid not in coll_oids or not rec:
                continue
            rec = bytes(rec)
            if len(rec) < 12 or rec[10] != 0x69:
                continue
            ft = _consume_conn_tuple(rec)
            if ft is None:
                continue
            t2pos, fmt, rpi_us = ft
            if fmt not in (_CONSUME_CONN_FMT, _CONSUME_CONN_FMT_SAFETY):
                continue
            m = rec.rfind(b"\x90\x01\x00\x00\x04\x00\x00\x00")
            if m < 0 or m + 12 > len(rec):
                continue
            tag_oid = struct.unpack_from("<I", rec, m + 8)[0]
            if tag_oid in (0, 0xFFFFFFFF):
                continue
            rp = t2pos + 38
            remote_tag = None
            if rp + 2 <= len(rec):
                ln = struct.unpack_from("<H", rec, rp)[0]
                if 1 <= ln <= 60 and rp + 2 + ln <= len(rec):
                    try:
                        remote_tag = rec[rp + 2:rp + 2 + ln].decode("ascii")
                    except Exception:
                        remote_tag = None
            if not remote_tag:
                continue
            unicast = "false"
            obj2 = rec[0x16:0x1A]
            up = rec.find(obj2, 0x100)
            if up >= 0 and up + 0x17 <= len(rec):
                if struct.unpack_from("<I", rec, up + 0x13)[0] == 2:
                    unicast = "true"
            safety_extra = None
            if fmt == _CONSUME_CONN_FMT_SAFETY:
                # Safety consumed connection: the timing extras live in the
                # parameter blob at the same offsets the module safety
                # connections read (ConnectionParams fields, validated there
                # pool-wide). ReactionTimeLimit is the CIP data-age limit
                # RPI*(TimeoutMultiplier + NetworkDelayMultiplier/100), snapped
                # up to the 0.128 ms safety time base -- the same expression as
                # the module input-connection formula it generalises
                # (TM=2/NDM=200 -> 4*RPI). Fail-closed: an unreadable blob
                # skips the connection so the tag stays Base (as today).
                try:
                    ea = CompsRecord.read_value_attrs(rec, short_header,
                                                      full=True, body_mode=True)
                    cp = ConnectionParams.from_bytes(
                        ea.get(_PRODUCE_EXT_PARAMS, b""))
                except Exception:
                    cp = None
                if (cp is None or not cp.timeout_multiplier
                        or not cp.network_delay_multiplier
                        or cp.max_observed_delay_raw is None):
                    continue
                rtl = math.ceil((cp.timeout_multiplier
                                 + cp.network_delay_multiplier / 100.0)
                                * (rpi_us / 1000.0) / 0.128) * 0.128
                safety_extra = {
                    "TimeoutMultiplier": str(cp.timeout_multiplier),
                    "NetworkDelayMultiplier": str(cp.network_delay_multiplier),
                    "ReactionTimeLimit": _conn_num(rtl),
                    "MaxObservedNetworkDelay": _conn_num(
                        cp.max_observed_delay_raw * 0.128),
                }
                unicast = "true" if cp.transport == 2 else "false"
            out[tag_oid] = {
                "Producer": o2name.get(o2parent.get(pid)) or "",
                "RemoteTag": remote_tag,
                "RemoteInstance": "0",
                "RPI": str(rpi_us // 1000),
                "Unicast": unicast,
            }
            if safety_extra:
                out[tag_oid].update(safety_extra)
    except Exception:
        return out
    # Fallback: recover consumed connections the plaintext body scan could not
    # read -- a source-protected (encrypted) connection record, or one that omits
    # the body tag-oid TLV. Reading the connection's extended attributes
    # transparently decrypts a protected ext-attr tail; a consumed controller-tag
    # connection carries 0x190 (= the tag's object_id) but not 0x191, and its
    # parameter blob (ext-attr 0x01) leads with the consumed format word. The
    # blob's internal offsets differ from the body-record offsets the primary
    # scan walks. Producer is the connection collection's parent module name,
    # which stays plaintext even on a protected record.
    try:
        cur.execute(
            "SELECT object_id, parent_id, record FROM comps"
        )
        for oid, pid, rec in cur.fetchall():
            if oid in dead:
                continue
            if pid not in coll_oids or not rec:
                continue
            rec = bytes(rec)
            if len(rec) < 12 or rec[10] != 0x69:
                continue
            ea = CompsRecord.read_value_attrs(rec, short_header, full=True,
                                              body_mode=True)
            a190 = ea.get(_PRODUCE_EXT_CONSUMED)
            if not a190 or len(a190) < 4 or _PRODUCE_EXT_PRODUCED in ea:
                continue
            tag_oid = struct.unpack_from("<I", a190, 0)[0]
            if tag_oid in out or tag_oid in (0, 0xFFFFFFFF):
                continue
            blob = ea.get(_PRODUCE_EXT_PARAMS)
            if not blob:
                continue
            cp = ConnectionParams.from_bytes(blob)
            # Admit the legacy short consumed blob: Producer/RemoteTag/RPI recover
            # from the head, and the u8@323 transport byte is simply absent -- an
            # absent transport means multicast, so Unicast renders "false" below.
            # Still reject the unknown 343..785 layout, which lacks the trailing
            # transport byte only because it is a different, untrusted structure.
            if cp.fmt != _CONSUME_CONN_FMT:
                continue
            if cp.transport is None and len(blob) > _PRODUCE_SHORT_BLOB_MAX:
                continue
            if (cp.remote_len is None or not (1 <= cp.remote_len <= 60)
                    or cp.remote_tag_bytes is None):
                continue
            try:
                remote_tag = cp.remote_tag_bytes.decode("ascii")
            except Exception:
                continue
            out[tag_oid] = {
                "Producer": o2name.get(o2parent.get(pid)) or "",
                "RemoteTag": remote_tag,
                "RemoteInstance": "0",
                "RPI": str(cp.rpi_us // 1000),
                "Unicast": "true" if cp.transport == 2 else "false",
            }
    except Exception:
        return out
    return out


# --- Produced controller tags ------------------------------------------------
# A produced tag advertises a tag for other controllers to consume. Its config
# takes one of two forms, both decoded by _build_produce_map:
#  * FULL (networked produce): the parameters live in a cip-0x69 connection
#    record under a RxMapConnectionCollection that carries extended attribute
#    0x191 (= the produced tag's object_id) and NOT 0x190; the parameter blob is
#    ext-attr 0x01, whose leading connection-format word is 10 (9 marks a
#    consumed connection, and other values mark the module I/O class-1
#    connections that share the same 0x190/0x191/0x192 attributes). ProduceCount,
#    the two boolean flags and the RPI triple sit at fixed offsets in the blob.
#  * PLC (PLC/SLC-mapped produce): the tag's OWN record carries a single ext-attr
#    0x67 (the u32 PLCMappingFile) and there is no connection record.
_PRODUCE_CONN_FMT = 10          # connection-format word marking a produced tag
_PRODUCE_CONN_FMT_SAFETY = 31   # safety (peer-GuardLogix) produced tag
_PRODUCE_EXT_PRODUCED = 0x191   # produced-tag object_id (on the connection record)
_PRODUCE_EXT_CONSUMED = 0x190   # present on consumed / module I/O connections
_PRODUCE_EXT_PARAMS = 0x01      # connection parameter blob
_PRODUCE_EXT_PLCMAP = 0x67      # PLCMappingFile (u32) on the tag's own record
# Legacy (V1x) produced-tag blobs pack their fields into a short blob (<= this)
# with the RPI triple right after the flags, instead of the V24+ long blob's
# 774/778/782 triple; any length beyond this and below the long form is an
# unrecognised layout the decoder refuses (fail-closed).
_PRODUCE_SHORT_BLOB_MAX = 342


def _produce_rpi_ms(us: int) -> str:
    """Render a connection RPI (microseconds) as its L5X millisecond string.

    Whole milliseconds print with no fraction (2000 -> "2"); a sub-millisecond
    remainder prints three decimals to match Logix (200 -> "0.200",
    536870900 -> "536870.900").
    """
    if us % 1000 == 0:
        return str(us // 1000)
    return f"{us // 1000}.{us % 1000:03d}"


def _build_produce_map(cur, short_header: bool) -> Dict[int, dict]:
    """Map a produced controller tag's object_id -> its <ProduceInfo> attributes.

    Both produce forms are keyed here by the produced tag's own object_id. FULL
    connections are found by walking cip-0x69 records under a
    RxMapConnectionCollection and selecting those whose ext attrs carry 0x191 but
    not 0x190 and whose parameter blob (ext-attr 0x01) leads with format word 10;
    ProduceCount, the flags and the RPI triple are read from fixed blob offsets.
    PLC-mapped produces are found by reading ext-attr 0x67 from the tag's own
    record (a cheap byte pre-filter avoids walking every tag's attributes).
    Returns {} on any failure. read_value_attrs transparently decrypts a
    source-protected ext-attr tail, so an encrypted produce connection decodes
    from the same attributes.
    """
    out: Dict[int, dict] = {}
    dead = CompsRecord.dead_oids(cur, short_header)
    try:
        cur.execute(
            "SELECT object_id, parent_id, comp_name, record FROM comps"
        )
        rows = cur.fetchall()
        coll_oids = {r[0] for r in rows if r[2] == "RxMapConnectionCollection"}
        plc_sig = struct.pack("<I", _PRODUCE_EXT_PLCMAP)
        for oid, pid, nm, rec in rows:
            # Skip dead-relic (FDFD-only) rows: cip==rec[10] and the 0x6B PLC
            # branch's fixed-offset gate could admit a realigned relic post-flip
            # and overwrite a live tag's ProduceInfo. Long-header only; zero-delta
            # today (relics fail the pre-flip rec[10] gate).
            if oid in dead:
                continue
            if not rec:
                continue
            rec = bytes(rec)
            if len(rec) < 12:
                continue
            cip = rec[10]
            if cip == 0x69 and pid in coll_oids:
                ea = CompsRecord.read_value_attrs(rec, short_header, full=True,
                                                  body_mode=True)
                a191 = ea.get(_PRODUCE_EXT_PRODUCED)
                if not a191 or len(a191) < 4 or _PRODUCE_EXT_CONSUMED in ea:
                    continue
                blob = ea.get(_PRODUCE_EXT_PARAMS)
                if not blob:
                    continue
                cp = ConnectionParams.from_bytes(blob)
                if cp.fmt_dword not in (_PRODUCE_CONN_FMT,
                                        _PRODUCE_CONN_FMT_SAFETY):
                    continue
                tag_oid = struct.unpack_from("<I", a191, 0)[0]
                if tag_oid in (0, 0xFFFFFFFF):
                    continue
                # Two blob layouts carry the produced-tag fields. The LONG (V24+)
                # blob keeps the RPI triple at 774/778/782 (cp.min/max/default_rpi_us,
                # None below 786). The legacy SHORT blob packs the same head fields
                # (ProduceCount u16@321, SendEventTrigger u32@308) but reads the
                # UnicastPermitted flag as u8@324 -- a u32 there would swallow the
                # min-RPI bytes -- and the RPI triple immediately after, at
                # 326/330/334; fields past the blob's end are the format defaults
                # Studio materialises on import. An in-between length is an
                # unrecognised layout -> skip (fail-closed).
                L = len(blob)
                rpi3 = None
                if cp.default_rpi_us is not None:
                    pc, se, up = (cp.produce_count, cp.send_event_trigger,
                                  cp.unicast_permitted)
                    if cp.fmt_dword == _PRODUCE_CONN_FMT:
                        # A safety produced tag (fmt 31) omits the triple (matches OEM).
                        rpi3 = (cp.min_rpi_us, cp.max_rpi_us, cp.default_rpi_us)
                elif L <= _PRODUCE_SHORT_BLOB_MAX and cp.fmt_dword == _PRODUCE_CONN_FMT:
                    pc = struct.unpack_from("<H", blob, 321)[0] if L >= 323 else 1
                    se = struct.unpack_from("<I", blob, 308)[0] if L >= 312 else 0
                    up = blob[324] if L >= 325 else 0
                    rpi3 = (
                        struct.unpack_from("<I", blob, 326)[0] if L >= 330 else 200,
                        struct.unpack_from("<I", blob, 330)[0] if L >= 334 else 536870900,
                        struct.unpack_from("<I", blob, 334)[0] if L >= 338 else 0,
                    )
                else:
                    continue
                out[tag_oid] = {
                    "ProduceCount": str(pc),
                    "ProgrammaticallySendEventTrigger": "true" if se else "false",
                    "UnicastPermitted": "true" if up else "false",
                }
                if rpi3 is not None:
                    out[tag_oid].update({
                        "MinimumRPI": _produce_rpi_ms(rpi3[0]),
                        "MaximumRPI": _produce_rpi_ms(rpi3[1]),
                        "DefaultRPI": _produce_rpi_ms(rpi3[2]),
                    })
            elif cip == 0x6B and plc_sig in rec:
                if oid in out:
                    continue
                ea = CompsRecord.read_value_attrs(rec, short_header, full=True,
                                                  body_mode=True)
                plc = ea.get(_PRODUCE_EXT_PLCMAP)
                if not plc or len(plc) < 4:
                    continue
                out[oid] = {"PLCMappingFile": str(struct.unpack_from("<I", plc, 0)[0])}
    except Exception:
        return out
    return out


# --- Module I/O connections --------------------------------------------------
# A module's I/O connections live in cip-0x69 records under the module's
# RxMapConnectionCollection (the same record family as the produced/consumed tag
# connections, distinguished by the parameter blob's leading format word). The
# format word identifies the connection's L5X Type; the rest of the blob carries
# the requested-packet interval, the unicast/multicast transport, and the event
# trigger id at fixed, version-stable offsets.
_CONN_TYPE_BY_FMT = {
    5: "Input", 6: "Output", 7: "DiagnosticInput",
    23: "MotionSync", 24: "MotionAsync", 25: "MotionEvent",
    28: "SafetyInput", 29: "SafetyOutput",
    48: "StandardDataDriven", 49: "SafetyInputDataDriven",
    50: "SafetyOutputDataDriven",
}
# The blob's fixed byte offsets (version-stable across the V10..V36 reference
# corpus) are documented on acd.record.blobs.ConnectionParams, which decodes
# them; the maps below give the decoded values their L5X meaning. The modern
# (data-driven / safety) attribute set was validated byte-exact pool-wide
# against the OEM <Connection>.
_CONN_DATADRIVEN_FMTS = frozenset({48, 49, 50})
_CONN_SAFETY_FMTS = frozenset({28, 29, 50, 49})
_CONN_PRIORITY_MAP = {1: "High", 2: "Scheduled"}
_CONN_ICT_MAP = {2: "Unicast", 1: "Multicast"}
_CONN_IPT_MAP = {0: "Cyclic", 2: "Application"}
_CONN_SAFETY_ASM_INSTANCES = frozenset({0x66, 0x0360})
# A data-driven connection's backing I/O tag comp is named
# '&<modhex>[:<slot>]:<suffix>'; the trailing token IS the rendered
# Input/OutputTagSuffix (reached via ext-attr 0x190/0x191, the direction's
# backing-tag object_id).
_CONN_BACKING_TAG_RE = re.compile(r"^&[0-9a-fA-F]+(?::\d+)?:([A-Za-z0-9]+)$")


def _conn_num(x: float) -> str:
    """Render a connection timing value: whole numbers bare, else 3 decimals."""
    return str(int(round(x))) if abs(x - round(x)) < 1e-9 else "%.3f" % x


def _conn_path_from_blob(cp: ConnectionParams):
    """The verbatim CIP ConnectionPath EPATH ('20 04 24 ..') or None.

    Rendered as space-separated lowercase hex, and only when the declared
    word-count's full path is contained in the blob (a truncated path yields
    None, matching the old bounds check).
    """
    if not cp.cpath_words or cp.cpath_raw is None:
        return None
    if len(cp.cpath_raw) != cp.cpath_words * 2:
        return None
    return " ".join("%02x" % x for x in cp.cpath_raw)


def _conn_first_instance(cp: ConnectionParams):
    """First Assembly logical-segment instance of the embedded EPATH, or None.

    Unlike _conn_path_from_blob this reads the clamped path prefix, so a
    truncated path can still yield its leading Assembly segment.
    """
    p = cp.cpath_raw if cp.cpath_raw is not None else b""
    if len(p) < 4 or p[0] != 0x20 or p[1] != 0x04:
        return None
    if p[2] == 0x24:
        return p[3]
    if p[2] == 0x25 and len(p) >= 6:
        return struct.unpack_from("<H", p, 4)[0]
    return None


def _conn_backing_suffix(cur, ea: dict, attr_id: int):
    """The direction's TagSuffix from its backing-tag comp name, or None.

    The connection record's ext-attr 0x190 (input) / 0x191 (output) holds the
    backing I/O tag's object_id; that comp's name ends in the suffix Studio
    renders ('SI'/'SO' on safety assemblies, 'I1'/'O1' on numbered slots...).
    Reading it beats inferring from the EPATH assembly instance, which cannot
    separate e.g. a dual-personality safety adapter's connections.
    """
    v = ea.get(attr_id)
    if not v or len(v) < 4:
        return None
    row = cur.execute("SELECT comp_name FROM comps WHERE object_id=?",
                      (struct.unpack_from("<I", v, 0)[0],)).fetchone()
    m = _CONN_BACKING_TAG_RE.match(row[0]) if row and row[0] else None
    return m.group(1) if m else None


def _conn_modern_attrs(cp: ConnectionParams, fmt: int,
                       in_sfx=None, out_sfx=None) -> dict:
    """Recover the data-driven / safety <Connection> attributes from the blob."""
    out: dict = {}
    if fmt in _CONN_DATADRIVEN_FMTS:
        if cp.priority is not None:
            out["Priority"] = _CONN_PRIORITY_MAP.get(cp.priority)
        if cp.input_connection_type is not None:
            out["InputConnectionType"] = _CONN_ICT_MAP.get(
                cp.input_connection_type)
        if cp.input_production_trigger is not None:
            out["InputProductionTrigger"] = _CONN_IPT_MAP.get(
                cp.input_production_trigger)
        path_hex = _conn_path_from_blob(cp)
        if path_hex is not None:
            out["ConnectionPath"] = path_hex
        inst = _conn_first_instance(cp)
        # A suffix names that direction's I/O tag, so it is emitted only when
        # the connection actually carries that direction (size > 0). A plain
        # StandardDataDriven (fmt 48) input-only module has out_size 0 and the
        # reference omits OutputTagSuffix there; gating each side on its size
        # matches the reference (no suffix ever appears without its tag). The
        # backing-tag name (in_sfx/out_sfx) is authoritative; the
        # first-EPATH-instance heuristic covers records without the attr.
        in_size = cp.input_size if cp.input_size is not None else 0
        out_size = cp.output_size if cp.output_size is not None else 0
        if fmt in (48, 49) and in_size:   # has an input side
            if in_sfx is None and inst is not None:
                in_sfx = ("I1" if inst == 1
                          else "SI" if inst in _CONN_SAFETY_ASM_INSTANCES
                          else "I")
            if in_sfx is not None:
                out["InputTagSuffix"] = in_sfx
        if fmt in (48, 50) and out_size:  # has an output side
            if out_sfx is None and inst is not None:
                out_sfx = ("O1" if inst == 1
                           else "SO" if inst in _CONN_SAFETY_ASM_INSTANCES
                           else "O")
            if out_sfx is not None:
                out["OutputTagSuffix"] = out_sfx
    if fmt in _CONN_SAFETY_FMTS:
        if cp.timeout_multiplier is not None:
            out["TimeoutMultiplier"] = str(cp.timeout_multiplier)
        if cp.network_delay_multiplier is not None:
            out["NetworkDelayMultiplier"] = str(cp.network_delay_multiplier)
        if cp.max_observed_delay_raw is not None:
            out["MaxObservedNetworkDelay"] = _conn_num(
                cp.max_observed_delay_raw * 0.128)
        if cp.reaction_time_units is not None:
            # ReactionTimeLimit is the stored CIP-safety limit in 0.128us units
            # (u16 @312); the output direction reports it net of the RPI. Read it
            # rather than reconstruct it from the RPI (the prior 4*/3* estimate
            # was only ever an approximation).
            base = cp.reaction_time_units * 0.128
            if fmt in (28, 49):  # input
                out["ReactionTimeLimit"] = _conn_num(base)
            else:                # output (29, 50)
                out["ReactionTimeLimit"] = _conn_num(base - cp.rpi_us / 1000.0)
    return {k: v for k, v in out.items() if v is not None}
# Data-driven connection formats always carry the connection size; the plain
# Output format carries size AND connection points, but only for generic/drive
# modules (see ModuleBuilder).
_CONN_FMT_OUTPUT = 6
# Modules whose I/O assembly is user-configured rather than fixed by a catalog
# Module Definition state their connection points and sizes explicitly. These are
# the drive families (CIP ProductType below) and the generic profiles (ProductType
# 0 with the Rockwell vendor id); a catalog I/O card omits them because its
# Module Definition already fixes the assembly. See ModuleBuilder.
_CONN_DIRECT_PRODUCT_TYPES = {123, 127, 142, 143, 150, 151}
_CONN_GENERIC_VENDOR = 1
# Serial-ASCII carrier modules (1734-232ASC / 1734-485ASC) as
# (vendor, product_type, product_code): the reference emits their connection's
# CIP In/OutputCxnPoint + In/OutputSize, but the connection record is
# byte-identical to non-carrier product-type-115 modules that omit them, so the
# emit gate is keyed on module identity (same pattern as
# _CONN_DIRECT_PRODUCT_TYPES). The values themselves are read from the record.
_CONN_SERIAL_ASCII_KEYS = frozenset({(1, 115, 110), (1, 115, 133)})
# The rack-optimized CommMethod (0x40000000): such a module bundles its I/O into
# the rack adapter's connection and emits a single <RackConnection> instead of a
# discrete <Connection>.
_RACK_COMM_METHOD = "1073741824"

# A connection <InputTag> reuses its backing controller tag's rendered inner, but
# with the raw value block (Format="L5K" or a format-less raw-hex <Data>) and any
# <AlarmConditions> removed -- the reference keeps only Description / Comments /
# EngineeringUnits / Maxes / Mins / ForceData / <Data Format="Decorated"> there.
# An <OutputTag> keeps the backing inner verbatim. (Validated byte- and order-
# identical pool-wide.)
_RAW_DATA_BLOCK_RE = re.compile(
    r'<Data\b(?![^>]*Format="(?:Decorated|String)")[^>]*>.*?</Data>', re.S)
_ALARM_BLOCK_RE = re.compile(r'<AlarmConditions\b.*?</AlarmConditions>', re.S)
_DESC_BLOCK_RE = re.compile(r'<Description\b.*?</Description>\s*', re.S)


_FORCE_BLOCK_RE = re.compile(r"<ForceData\b.*?</ForceData>", re.S)


def _strip_input_tag_inner(inner: str, strip_force: bool = False) -> str:
    """Transform a backing tag's rendered inner into an <InputTag>'s inner.

    ``strip_force``: the L5K-era reference renders a connection InputTag
    WITHOUT the <ForceData> block (the block stays on the controller-scope
    tag's own <Data>); the raw-hex era keeps it.
    """
    inner = _ALARM_BLOCK_RE.sub("", inner)
    inner = _RAW_DATA_BLOCK_RE.sub("", inner)
    if strip_force:
        inner = _FORCE_BLOCK_RE.sub("", inner)
    return inner


def _build_connection_map(cur, short_header: bool) -> Dict[int, dict]:
    """Map a module connection record's object_id -> decoded connection values.

    Decodes, for every cip-0x69 record under a RxMapConnectionCollection whose
    parameter blob (ext-attr 0x01) leads with a recognised module connection
    format word: the format word, Type, RPI, transport (Unicast), EventID, and the
    raw InputSize/OutputSize/InputCxnPoint/OutputCxnPoint. ModuleBuilder looks the
    values up by the connection record's object_id and decides which of the
    size/connection-point attributes to emit. Records that are not module
    connections (e.g. produced/consumed tag connections, or other format words)
    are simply absent from the map and keep the caller's defaults. Returns {} on
    any failure.
    """
    out: Dict[int, dict] = {}
    dead = CompsRecord.dead_oids(cur, short_header)
    try:
        cur.execute(
            "SELECT c.object_id, c.record "
            "FROM comps c JOIN comps p ON c.parent_id = p.object_id "
            "WHERE p.comp_name = 'RxMapConnectionCollection'"
        )
        for oid, rec in cur.fetchall():
            # Defensive family gate (long-header): its consumer binds by exact
            # tree-oid so a relic entry is never read, but gating keeps every
            # RxMapConnectionCollection scan uniformly liveness-filtered (P6.9).
            if oid in dead:
                continue
            if not rec:
                continue
            rec = bytes(rec)
            if len(rec) < 12 or rec[10] != 0x69:
                continue
            ea = CompsRecord.read_value_attrs(rec, short_header, full=True,
                                              body_mode=True)
            blob = ea.get(_PRODUCE_EXT_PARAMS)
            if not blob:
                continue
            cp = ConnectionParams.from_bytes(blob)
            # transport (u8 @323) present is the old len > 323 completeness gate.
            if cp.transport is None:
                continue
            fmt = cp.fmt
            if fmt not in _CONN_TYPE_BY_FMT:
                continue
            entry = {
                "fmt": fmt,
                "Type": _CONN_TYPE_BY_FMT[fmt],
                "RPI": str(cp.rpi_us),
                # Unicast PRESENCE is a per-module property not encoded here:
                # safety connections always carry it, plain Input/Output carry it
                # only when point-to-point (transport==2); every other connection
                # type omits it. The value, when present, is transport==2.
                "_unicast_present": (
                    fmt in (28, 29)
                    or (fmt in (5, 6) and cp.transport == 2)
                ),
                "Unicast": "true" if cp.transport == 2 else "false",
                "EventID": str(cp.event_id),
                "InputCxnPoint": cp.input_cxn_point,
                "InputSize": cp.input_size,
                "OutputCxnPoint": cp.output_cxn_point,
                "OutputSize": cp.output_size,
            }
            _in_sfx = _out_sfx = None
            if fmt in _CONN_DATADRIVEN_FMTS:
                _in_sfx = _conn_backing_suffix(cur, ea, _PRODUCE_EXT_CONSUMED)
                _out_sfx = _conn_backing_suffix(cur, ea, _PRODUCE_EXT_PRODUCED)
            entry.update(_conn_modern_attrs(cp, fmt, _in_sfx, _out_sfx))
            # Safety connections carry a per-connection SafetySignature: the GSS
            # record keyed (otype 105, cid=u32@rec[12], disc=u32@rec[16]).
            if fmt in (28, 29, 49, 50) and len(rec) >= 20:
                try:
                    srow = cur.execute(
                        "SELECT signature, timestamp FROM connection_signatures "
                        "WHERE otype=105 AND cid=? AND disc=?",
                        (struct.unpack_from("<I", rec, 12)[0],
                         struct.unpack_from("<I", rec, 16)[0])).fetchone()
                except Exception:
                    srow = None
                if srow and srow[0]:
                    entry["SafetySignature"] = srow[0]
                    if srow[1]:
                        entry["SafetySignatureTimestamp"] = srow[1]
                # The module's combined signature (rendered on the <Connections>
                # container) is the same GSS family at disc 0 for this cid.
                try:
                    crow = cur.execute(
                        "SELECT signature, timestamp FROM connection_signatures "
                        "WHERE otype=105 AND cid=? AND disc=0",
                        (struct.unpack_from("<I", rec, 12)[0],)).fetchone()
                except Exception:
                    crow = None
                if crow and crow[0]:
                    entry["_connections_signature"] = crow[0]
                    entry["_connections_signature_ts"] = crow[1]
            out[oid] = entry
    except Exception:
        return out
    return out


# Module config images that have no controller :C tag are emitted as <ConfigData>
# (raw image, no Decorated tree) and an optional <ConfigScript>. The image lives in
# a hash-named child of RxDataCollection; the module points at it by object id.
_CONFIG_IMG_MAX = 65536          # sanity bound on a derived ConfigSize/Size
_CONFIG_MARK = b"\x44\x02\x00\x00"
# PowerFlex 753-NET-E drive: its config image is a parameter-download script the
# reference renders only as <ConfigScript>, never <ConfigData>.
_CONFIGSCRIPT_ONLY_PT = 123
_CONFIG_IMG_VALUE = 0x66          # ext-attr holding the config/script image
# Module ext-attr 0x12c is a coarse DEVICE-PROFILE code. Communications adapters
# (product_type 12) split on it: the profiles at or above this value are the ones
# observed to carry a raw config image the reference renders as <ConfigData>, the
# ones below it are not (they include the DeviceNet scanners whose 0x13e image the
# reference leaves unrendered). A THRESHOLD FITTED TO OBSERVATION -- 8 distinct
# codes seen, no documentation behind it -- so it is used only to widen a route
# that is otherwise blanket-closed, never to suppress one that already works.
_MOD_PROFILE_HAS_CONFIG = 10


def _build_config_holders(cur, short_header: bool = False):
    """Index RxDataCollection holder records for ConfigData/ConfigScript lookup.

    Returns (by_mr28, by_cid, pool_oids):
      * by_mr28 {u32 -> object_id}: the holder's main_record@0x28 (record[54:58]),
        unique only -- used by the long-header ConfigData link (module e1[0x20:0x24]).
      * by_cid  {u16 -> object_id}: the holder's comment_id (record[12:14]), unique
        only -- used by the ConfigScript link (module e1[556:558]).
      * pool_oids: the set of holder object_ids (used by the short-header ConfigData
        trailer pointer).
    Only unique keys are kept so an ambiguous (byte-identical-sibling) link is simply
    skipped rather than mislinked. Returns empty maps on any failure.

    Dead-relic (FDFD-only) holders are excluded (long-header only): their bodies
    contribute no live link today, and skipping them keeps the unique-only cid/mr28
    sets flip-invariant (a realigned dead body would otherwise shift the key it
    contributes, changing which live keys survive the unique-only filter -- P6.9).
    """
    by_mr28: Dict[int, object] = {}
    by_cid: Dict[int, object] = {}
    pool_oids = set()
    seen28: Dict[int, int] = {}
    seencid: Dict[int, int] = {}
    dead = CompsRecord.dead_oids(cur, short_header)
    try:
        cur.execute(
            "SELECT c.object_id, c.record FROM comps c JOIN comps p "
            "ON c.parent_id = p.object_id WHERE p.comp_name = 'RxDataCollection'"
        )
        for oid, rec in cur.fetchall():
            if oid in dead:
                continue
            rec = bytes(rec)
            pool_oids.add(oid)
            if len(rec) >= 58:
                mr28 = struct.unpack_from("<I", rec, 54)[0]
                seen28[mr28] = seen28.get(mr28, 0) + 1
                by_mr28[mr28] = oid
            if len(rec) >= 14:
                # The cid slot (record[12:14]) is only meaningful on a
                # controller-scope (cip 0x6A) holder; other classes store
                # unrelated data there, and counting them in the uniqueness
                # census turned genuinely-unique cids ambiguous -- dropping
                # the module -> ConfigScript link exactly on modules whose
                # (shared) config image has many holders.
                if struct.unpack_from("<H", rec, 10)[0] == 0x006A:
                    cid = struct.unpack_from("<H", rec, 12)[0]
                    seencid[cid] = seencid.get(cid, 0) + 1
                    by_cid[cid] = oid
        by_mr28 = {k: v for k, v in by_mr28.items() if seen28[k] == 1}
        by_cid = {k: v for k, v in by_cid.items() if seencid[k] == 1}
    except Exception:
        return {}, {}, set()
    return by_mr28, by_cid, pool_oids


def _config_holder_image(cur, oid, short_header):
    """Return the raw config image bytes stored in holder record ``oid``, or None.

    The image is the ext-attribute 0x66 value of the holder's record body,
    falling back to the length-prefixed blob at record offset 410
    (record[406:410] = byte length). Reads full=False (not record_attrs)
    deliberately.

    A dead-relic (FDFD-only) holder is never a live module's config source, so
    its image is not read: this is the single gate that also covers the module
    0x13e DIRECT-pointer path (module_builder.py), which resolves a holder oid
    without consulting the family-gated _build_config_holders index. Long-header
    only (see CompsRecord.dead_oids); zero-delta today (no live module resolves a
    dead holder) and flip-safe (the realigned dead body is never decoded).
    """
    if oid in CompsRecord.dead_oids(cur, short_header):
        return None
    try:
        cur.execute("SELECT record FROM comps WHERE object_id=?", (oid,))
        row = cur.fetchone()
        if row:
            rec = bytes(row[0])
            try:
                attrs = CompsRecord.read_value_attrs(rec, short_header,
                                                     body_mode=True)
                img = attrs.get(_CONFIG_IMG_VALUE)
                if img and len(img) >= 4:
                    return bytes(img)
            except Exception:
                pass
            if len(rec) >= 414:
                length = struct.unpack_from("<I", rec, 406)[0]
                if 4 <= length <= len(rec) - 410:
                    return rec[410:410 + length]
    except Exception:
        return None
    return None
