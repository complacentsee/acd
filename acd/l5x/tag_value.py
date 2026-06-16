"""Step 6c — render a tag's design value (ext attr 0x66 image) to L5X <Data>.

The raw value bytes come from acd.record.comps.read_tag_value (ext attr 0x66 of
the cip-0x6a backing). This module turns those bytes + the tag's DataType /
dimensions into the two OEM <Data> blocks Logix emits for a Base, non-IO tag:

  * <Data Format="L5K">  — a CDATA L5K literal (scalar value, or a bracketed
                           comma list for arrays/structs).
  * <Data Format="Decorated"> — the structured element with real Value=... attrs.

Everything is best-effort: any structural surprise raises and the caller falls
back to today's zero-placeholder behaviour, so the long (V24+) path can never
regress below current output.
"""
from __future__ import annotations

import struct
from typing import Dict, List, Optional, Tuple, Union

# Atomic primitive byte widths and struct-unpack formats.
_ATOMIC: Dict[str, Tuple[int, str]] = {
    "BOOL": (1, "<b"),
    "SINT": (1, "<b"),
    "USINT": (1, "<B"),
    "INT": (2, "<h"),
    "UINT": (2, "<H"),
    "DINT": (4, "<i"),
    "UDINT": (4, "<I"),
    "LINT": (8, "<q"),
    "ULINT": (8, "<Q"),
    "REAL": (4, "<f"),
    "LREAL": (8, "<d"),
}

# Logix radix string per atomic type (BOOL has none in scalar DataValue? — OEM
# emits Radix="Decimal" for BOOL scalars, so we keep Decimal here).
_RADIX: Dict[str, str] = {
    "BOOL": "Decimal", "SINT": "Decimal", "USINT": "Decimal",
    "INT": "Decimal", "UINT": "Decimal", "DINT": "Decimal", "UDINT": "Decimal",
    "LINT": "Decimal", "ULINT": "Decimal",
    "REAL": "Float", "LREAL": "Float",
}

# Built-in struct member layouts: ordered (name, type). Image words are int32 for
# the L5K bracket form (status/control word + DINTs); BOOL flags are NOT in the
# L5K list (OEM's TIMER L5K is [status, PRE, ACC] = 3 int32 of the 12-byte image).
_BUILTIN_STRUCT: Dict[str, List[Tuple[str, str]]] = {
    "TIMER": [("PRE", "DINT"), ("ACC", "DINT"),
              ("EN", "BOOL"), ("TT", "BOOL"), ("DN", "BOOL")],
    "COUNTER": [("PRE", "DINT"), ("ACC", "DINT"),
                ("CU", "BOOL"), ("CD", "BOOL"), ("DN", "BOOL"),
                ("OV", "BOOL"), ("UN", "BOOL")],
    "CONTROL": [("LEN", "DINT"), ("POS", "DINT"),
                ("EN", "BOOL"), ("EU", "BOOL"), ("DN", "BOOL"), ("EM", "BOOL"),
                ("ER", "BOOL"), ("UL", "BOOL"), ("IN", "BOOL"), ("FD", "BOOL")],
}


def _fmt_real(v: float) -> str:
    """Format a REAL/LREAL like Logix: 8-significand scientific, 3-digit exp.

    Non-finite values use the Logix L5K sentinels: NaN -> 1.#QNAN000e+000,
    +Inf -> 1.#INF0000e+000, -Inf -> -1.#INF0000e+000 (these crash a plain
    %e format, so they are handled explicitly).
    """
    if v != v:                      # NaN
        return "1.#QNAN000e+000"
    if v == float("inf"):
        return "1.#INF0000e+000"
    if v == float("-inf"):
        return "-1.#INF0000e+000"
    s = f"{v:.8e}"               # e.g. '5.00000000e+01'
    mant, _, exp = s.partition("e")
    sign = exp[0]
    digits = exp[1:].lstrip("0") or "0"
    return f"{mant}e{sign}{int(digits):03d}"


def _atomic_text(dt: str, b: bytes) -> str:
    """Decode one atomic value from its bytes to its L5K/Value text."""
    width, fmt = _ATOMIC[dt]
    val = struct.unpack(fmt, b[:width])[0]
    if dt in ("REAL", "LREAL"):
        return _fmt_real(val)
    if dt == "BOOL":
        return "1" if val else "0"
    return str(val)


def _atomic_text_decorated(dt: str, b: bytes) -> str:
    """Decode one atomic value to its Decorated <DataValue>/<Element> Value text.

    Identical to ``_atomic_text`` except REAL/LREAL use the shortest-round-trip
    decimal form Logix writes in the Decorated block (e.g. 28795.67, 0.0,
    1.#QNAN) rather than the 8-digit scientific form used only in the L5K CDATA
    block.  Integer/BOOL forms are unchanged.
    """
    width, fmt = _ATOMIC[dt]
    val = struct.unpack(fmt, b[:width])[0]
    if dt == "LREAL":
        return _fmt_lreal_decorated(val)
    if dt == "REAL":
        return _fmt_real_decorated(val)
    if dt == "BOOL":
        return "1" if val else "0"
    return str(val)


def _fmt_real_decorated(v: float) -> str:
    """Format a REAL value the way Logix writes it in a Decorated Value attribute.

    Unlike the L5K CDATA form (8-digit scientific), Decorated REALs use the
    shortest decimal that round-trips through IEEE-754 single precision, with a
    trailing '.0' for integral values (e.g. 380.0, 0.1, 34.805748). Very large /
    small magnitudes fall back to 3-digit-exponent scientific. The two single
    +/-FLT_MAX sentinels (common PID limit defaults) are matched to OEM exactly.
    """
    import math
    f = struct.unpack("<f", struct.pack("<f", v))[0]
    if f != f:                      # NaN -> Logix Decorated form
        return "1.#QNAN"
    if f == float("inf"):
        return "1.#INF"
    if f == float("-inf"):
        return "-1.#INF"
    if f == 0.0:
        return "0.0"
    if f == struct.unpack("<f", struct.pack("<f", 3.40282347e38))[0]:
        return "3.40282347e+038"
    if f == struct.unpack("<f", struct.pack("<f", -3.40282347e38))[0]:
        return "-3.40282347e+038"
    best = None
    for p in range(1, 10):
        s = "%.*g" % (p, f)
        try:
            rt = struct.unpack("<f", struct.pack("<f", float(s)))[0]
        except OverflowError:
            continue
        if rt == f:
            best = s
            break
    if best is None:
        best = "%.9g" % f
    if "e" in best or "E" in best:
        a = abs(f)
        exp = math.floor(math.log10(a))
        if -4 <= exp < 16:
            sig = len(best.split("e")[0].replace("-", "").replace(".", ""))
            decimals = max(0, sig - 1 - exp)
            best = "%.*f" % (decimals, f)
    if "." not in best and "e" not in best and "E" not in best:
        best += ".0"
    if "e" in best:
        m, _, e = best.partition("e")
        sign = e[0]
        ev = int(e[1:])
        best = "%se%s%03d" % (m, sign, ev)
    return best


def _fmt_lreal_decorated(v: float) -> str:
    """Decorated form of an LREAL (double): shortest round-trip through IEEE-754
    double precision.  Mirrors ``_fmt_real_decorated`` but does NOT re-quantize
    to single precision (which would corrupt high-precision doubles)."""
    import math
    f = v
    if f != f:
        return "1.#QNAN"
    if f == float("inf"):
        return "1.#INF"
    if f == float("-inf"):
        return "-1.#INF"
    if f == 0.0:
        return "0.0"
    best = None
    for p in range(1, 18):
        s = "%.*g" % (p, f)
        if float(s) == f:
            best = s
            break
    if best is None:
        best = "%.17g" % f
    if "e" in best or "E" in best:
        a = abs(f)
        exp = math.floor(math.log10(a))
        if -4 <= exp < 16:
            sig = len(best.split("e")[0].replace("-", "").replace(".", ""))
            decimals = max(0, sig - 1 - exp)
            best = "%.*f" % (decimals, f)
    if "." not in best and "e" not in best and "E" not in best:
        best += ".0"
    if "e" in best:
        m, _, e = best.partition("e")
        sign = e[0]
        ev = int(e[1:])
        best = "%se%s%03d" % (m, sign, ev)
    return best


def _atomic_value_decorated(dt: str, image: bytes, offset: int) -> Optional[str]:
    """Decode one atomic value at `offset` for a Decorated Value attribute."""
    width, fmt = _ATOMIC[dt]
    if offset + width > len(image):
        return None
    val = struct.unpack_from(fmt, image, offset)[0]
    if dt in ("REAL", "LREAL"):
        return _fmt_real_decorated(val)
    if dt == "BOOL":
        return "1" if val else "0"
    return str(val)


def _dims_total(dimensions: Optional[str]) -> Tuple[int, List[int]]:
    if not dimensions:
        return 0, []
    parts = [int(d) for d in dimensions.split(",") if d.strip().lstrip("-").isdigit()]
    total = 1
    for d in parts:
        total *= d
    return (total if parts else 0), parts


def render_hex(image: bytes) -> str:
    """Uppercase hex of the raw value image, OEM-wrapped at 16 bytes/line.

    Logix writes the raw <Data> block as space-separated hex bytes, 16 per line,
    with a trailing space before each newline (e.g. "01 00 ... 42 \\n00 A0 ...").
    """
    lines = []
    for i in range(0, len(image), 16):
        chunk = image[i:i + 16]
        lines.append(" ".join("%02X" % b for b in chunk))
    return " \n".join(lines)


# Built-in struct status/control-word BOOL flag bit positions (within word 0).
_BUILTIN_FLAG_BITS: Dict[str, Dict[str, int]] = {
    "TIMER": {"EN": 31, "TT": 30, "DN": 29},
    "COUNTER": {"CU": 31, "CD": 30, "DN": 29, "OV": 28, "UN": 27},
    "CONTROL": {"EN": 31, "EU": 30, "DN": 29, "EM": 28, "ER": 27,
                "UL": 26, "IN": 25, "FD": 24},
}


# --------------------------------------------------------------------------- #
# L5K rendering                                                                #
# --------------------------------------------------------------------------- #
def render_l5k(dt_base: str, dimensions: Optional[str], image: bytes,
               data_types_map: Dict) -> Optional[str]:
    """Return the CDATA payload for <Data Format="L5K">, or None if unsupported.

    Scalar atomic  -> "50"
    Atomic array   -> "[0,0,0,0]"
    Struct / array of struct / UDT -> "[w0,w1,...]" where wN are the raw image
    reinterpreted as int32 words (matches OEM, e.g. TIMER -> [status,PRE,ACC]).
    """
    total, _ = _dims_total(dimensions)

    if dt_base in _ATOMIC:
        width, _ = _ATOMIC[dt_base]
        if total == 0:
            if len(image) < width:
                return None
            return _atomic_text(dt_base, image[:width])
        # atomic array: comma list of element values
        vals = []
        for i in range(total):
            off = i * width
            if off + width > len(image):
                return None
            vals.append(_atomic_text(dt_base, image[off:off + width]))
        return "[" + ",".join(vals) + "]"

    # Struct (built-in or UDT), or array of struct: OEM emits the raw image as a
    # bracketed list of int32 words.
    if len(image) % 4 != 0 or not image:
        return None
    words = struct.unpack("<%di" % (len(image) // 4), image)
    return "[" + ",".join(str(w) for w in words) + "]"


def render_l5k_layout(dt_base: str, dimensions: Optional[str], image: bytes,
                      layout_map: Dict, data_types_map: Dict) -> Optional[str]:
    """Layout-driven <Data Format="L5K"> rendering for module / struct types.

    The flat int32-word form in ``render_l5k`` is wrong for module config/input
    types whose members have mixed widths (an INT[18] config array packs two
    16-bit words into each int32, etc.).  OEM instead emits the L5K bracket tree
    that mirrors the datatype's MEMBER tree using the TagInfo byte-offset layout:

        struct           -> ``[m0, m1, ...]``  (members in declared order)
        atomic scalar    -> signed decimal of the member's image bytes
        atomic array     -> ``[v0, v1, ...]``  (nested bracket, one per element)
        nested struct    -> ``[...]``          (recursively)

    Values are always plain (signed) decimals here, regardless of the member's
    display radix (the radix only affects the Decorated block).  Returns the
    CDATA payload, or None on any failure / unsupported shape so the caller
    keeps today's behaviour (no regression).
    """
    if not layout_map:
        return None
    total, dim_parts = _dims_total(dimensions)

    if dt_base in _ATOMIC:
        # Atomic scalar/array: the flat form is already correct & byte-faithful.
        return render_l5k(dt_base, dimensions, image, data_types_map)

    if dt_base.upper() not in layout_map:
        return None

    if total == 0:
        return _l5k_struct(dt_base, image, layout_map, data_types_map, 0)

    stride = _struct_stride(dt_base, layout_map, data_types_map)
    if stride is None:
        return None
    elems = []
    for i in range(total):
        sub = image[i * stride:(i + 1) * stride]
        frag = _l5k_struct(dt_base, sub, layout_map, data_types_map, 1)
        if frag is None:
            return None
        elems.append(frag)
    return "[" + ",".join(elems) + "]"


def _l5k_atomic(mdt: str, image: bytes, offset: int) -> Optional[str]:
    """Signed decimal of one atomic member at ``offset`` for the L5K bracket form."""
    if mdt not in _ATOMIC:
        return None
    width, fmt = _ATOMIC[mdt]
    if offset + width > len(image):
        return None
    val = struct.unpack_from(fmt, image, offset)[0]
    if mdt in ("REAL", "LREAL"):
        return _fmt_real(val)
    return str(val)


def _l5k_struct(dt_name: str, image: bytes, layout_map: Dict,
                data_types_map: Dict, depth: int) -> Optional[str]:
    """Render one struct as the L5K bracket tree ``[m0,m1,...]``."""
    if depth > 24:
        return None
    layout = _resolve_layout(dt_name, layout_map, data_types_map)
    if layout is None:
        return None
    # The L5K bracket form serialises the physical STORAGE image: one entry per
    # distinct storage location.  Unlike the Decorated block it DOES include
    # HIDDEN members (e.g. AB:1734_4SLOT:O:0's SlotStatusBits DINTs, or the
    # connection-header CfgSize/CfgIDNum/Reserved words that Logix hides from the
    # Decorated view but still serialises).  BUT a BOOL member that is merely a
    # BIT-ALIAS of a wider integer member at the same byte (e.g. Pt0FaultMode
    # overlaying the FaultMode SINT) is NOT a separate storage location and must
    # be skipped -- only the containing integer member is emitted.  Build the set
    # of byte offsets owned by non-BOOL atomic / struct members, then drop any
    # BOOL/BIT scalar member whose byte falls inside one of those.
    covered = set()
    for (name, mdt, off, bit, hidden, dims, def_radix) in layout:
        if mdt in ("BOOL", "BIT") and not dims:
            continue
        if mdt in _ATOMIC:
            w = _ATOMIC[mdt][0]
        else:
            w = _struct_stride(mdt, layout_map, data_types_map) or 1
        n = 1
        if dims:
            for d in dims:
                n *= d
        for b in range(off, off + w * n):
            covered.add(b)
    parts: List[str] = []
    for (name, mdt, off, bit, hidden, dims, def_radix) in layout:
        if mdt in ("BOOL", "BIT") and not dims and off in covered:
            # bit-alias of a wider integer member -> not a distinct storage slot
            continue
        frag = _l5k_member(mdt, off, bit, dims, image, layout_map,
                           data_types_map, depth)
        if frag is None:
            return None
        parts.append(frag)
    return "[" + ",".join(parts) + "]"


def _l5k_member(mdt: str, off: int, bit, dims, image: bytes, layout_map: Dict,
                data_types_map: Dict, depth: int) -> Optional[str]:
    """Render one member's L5K fragment (scalar text, or nested bracket)."""
    if dims:
        total = 1
        for d in dims:
            total *= d
        if mdt in _ATOMIC:
            width, _ = _ATOMIC[mdt]
            if mdt in ("BOOL", "BIT"):
                # packed BOOL array -> one int per element (0/1) from the bits
                vals = []
                for i in range(total):
                    byte = off + (i // 8)
                    if byte >= len(image):
                        return None
                    vals.append(str((image[byte] >> (i % 8)) & 1))
                return "[" + ",".join(vals) + "]"
            vals = []
            for i in range(total):
                vt = _l5k_atomic(mdt, image, off + i * width)
                if vt is None:
                    return None
                vals.append(vt)
            return "[" + ",".join(vals) + "]"
        # array of nested struct
        stride = _struct_stride(mdt, layout_map, data_types_map)
        if stride is None:
            return None
        elems = []
        for i in range(total):
            sub = image[off + i * stride: off + (i + 1) * stride]
            frag = _l5k_struct(mdt, sub, layout_map, data_types_map, depth + 1)
            if frag is None:
                return None
            elems.append(frag)
        return "[" + ",".join(elems) + "]"

    if mdt in ("BOOL", "BIT"):
        b = bit if bit is not None else 0
        byte = off + (b // 8)
        if byte >= len(image):
            return None
        return str((image[byte] >> (b % 8)) & 1)

    if mdt in _ATOMIC:
        return _l5k_atomic(mdt, image, off)

    # nested struct member
    stride = _struct_stride(mdt, layout_map, data_types_map)
    if stride is None:
        return None
    return _l5k_struct(mdt, image[off: off + stride], layout_map,
                       data_types_map, depth + 1)


# --------------------------------------------------------------------------- #
# Decorated rendering                                                          #
# --------------------------------------------------------------------------- #
def _struct_member_layout(dt_name: str, data_types_map: Dict
                          ) -> Optional[List[Tuple[str, str, int, Optional[int]]]]:
    """Return [(member_name, member_dt, dimension, bit_or_None), ...] for a struct.

    bit is set for BOOL members packed into a backing byte (built-in flag bits);
    for those we cannot recover the source byte offset cheaply, so we emit them
    from the trailing flag word of the image when available, else 0.
    """
    builtin = _BUILTIN_STRUCT.get(dt_name)
    if builtin is not None:
        # built-in: PRE/ACC are the first int32 words; BOOL flags packed in the
        # status word (word 0). We don't decode individual flag bits (OEM rarely
        # has them nonzero); they default 0.
        return [(n, t, 0, None) for n, t in builtin]
    dt = data_types_map.get(dt_name)
    if dt is None:
        return None
    out = []
    for m in dt.members:
        if getattr(m, "hidden", False):
            continue
        out.append((m.name, m.data_type.upper(), m.dimension,
                    getattr(m, "bit_number", None)))
    return out


def _decorated_scalar(dt_base: str, value_text: str) -> str:
    radix = _RADIX.get(dt_base, "Decimal")
    if dt_base == "BOOL":
        return f'<DataValue DataType="BOOL" Radix="Decimal" Value="{value_text}"/>'
    return f'<DataValue DataType="{dt_base}" Radix="{radix}" Value="{value_text}"/>'


def _decorated_struct(dt_name: str, image: bytes, data_types_map: Dict) -> Optional[str]:
    """Render <Structure DataType=..>..</Structure> from a struct image.

    For built-in TIMER/COUNTER/CONTROL the layout is well-known (2 leading DINTs
    + BOOL flags). For UDTs we slice each member from its declared offset image
    sequentially; if member offsets are unavailable we bail (None -> caller keeps
    the zero Decorated fallback).
    """
    layout = _struct_member_layout(dt_name, data_types_map)
    if layout is None:
        return None
    parts: List[str] = []
    builtin = _BUILTIN_STRUCT.get(dt_name)
    if builtin is not None:
        # Image is [status/control word][PRE/LEN][ACC/POS] as three int32 words.
        # The status/control word is word 0 (it carries the BOOL flag bits and is
        # NOT a visible PRE/ACC member); PRE/LEN = word 1, ACC/POS = word 2.
        if len(image) < 12:
            return None
        status = struct.unpack_from("<I", image, 0)[0]
        pre = struct.unpack_from("<i", image, 4)[0]
        acc = struct.unpack_from("<i", image, 8)[0]
        word_vals = {"PRE": pre, "ACC": acc, "LEN": pre, "POS": acc}
        flag_bits = _BUILTIN_FLAG_BITS.get(dt_name, {})
        for name, mdt in builtin:
            if mdt == "BOOL":
                bit = flag_bits.get(name)
                v = 1 if (bit is not None and (status >> bit) & 1) else 0
                parts.append(f'<DataValueMember Name="{name}" DataType="BOOL" Value="{v}"/>')
            else:
                parts.append(
                    f'<DataValueMember Name="{name}" DataType="{mdt}" '
                    f'Radix="Decimal" Value="{word_vals.get(name, 0)}"/>'
                )
        return f'<Structure DataType="{dt_name}">{"".join(parts)}</Structure>'
    return None  # UDT decorated value slicing is deferred (zero fallback kept)


def render_decorated(dt_base: str, dimensions: Optional[str], image: bytes,
                     data_types_map: Dict) -> Optional[str]:
    """Return the inner XML for <Data Format="Decorated">, or None if unsupported."""
    total, dim_parts = _dims_total(dimensions)

    if dt_base in _ATOMIC:
        width, _ = _ATOMIC[dt_base]
        if total == 0:
            if len(image) < width:
                return None
            return _decorated_scalar(dt_base, _atomic_text_decorated(dt_base, image[:width]))
        # atomic array
        radix = _RADIX.get(dt_base, "Decimal")
        elems = []
        for i in range(total):
            off = i * width
            if off + width > len(image):
                return None
            elems.append(
                f'<Element Index="[{i}]" Value="{_atomic_text_decorated(dt_base, image[off:off+width])}"/>'
            )
        dim_str = ",".join(str(d) for d in dim_parts)
        return (f'<Array DataType="{dt_base}" Dimensions="{dim_str}" Radix="{radix}">'
                f'{"".join(elems)}</Array>')

    # Scalar struct (built-in only for now)
    if total == 0:
        return _decorated_struct(dt_base, image, data_types_map)
    return None


# --------------------------------------------------------------------------- #
# Step 6d — TagInfo.XML-layout-driven Decorated rendering                      #
# --------------------------------------------------------------------------- #
# This path uses the per-datatype member byte-offset / bit map extracted from
# the project's TagInfo.XML (passed in as `layout_map`) so that EVERY visible
# member — including nested UDTs, BOOL bits packed into a backing word, and
# member arrays — is sliced from the raw value image at its real offset, rather
# than the sequential/zero approximation of `_decorated_struct`. Everything is
# best-effort; the caller wraps the entry point in try/except and falls back to
# the existing zero generator, so the V24+ path can never regress.
#
# layout_map: {DATATYPE_UPPER: [LayoutMember, ...]} where LayoutMember is a tuple
#   (name, member_dt_str, byte_offset, bit_or_None, hidden_bool, dims_list_or_None)
# byte_offset is the member's offset within its parent struct image; bit is the
# bit index (0..) within that offset for BOOL/BIT members; dims is a list of
# array sizes (e.g. [4]) or None for scalars.

# Radix string per atomic type for the value formatter, when the member def did
# not supply one (BOOL/BIT carry no Radix attribute and are not in this map).
_DEFAULT_RADIX: Dict[str, str] = dict(_RADIX)


def _format_int_radix(dt: str, val: int, width: int, radix: Optional[str]) -> str:
    """Format an integer value honoring its Logix Radix string."""
    if radix == "Binary":
        bits = width * 8
        u = val & ((1 << bits) - 1)
        s = format(u, "0%db" % bits)
        grouped = "_".join(s[i:i + 4] for i in range(0, len(s), 4))
        return "2#" + grouped
    if radix == "Hex":
        nyb = width * 2
        u = val & ((1 << (width * 8)) - 1)
        s = format(u, "0%dx" % nyb)
        grouped = "_".join(s[i:i + 4] for i in range(0, len(s), 4))
        return "16#" + grouped
    if radix == "Octal":
        u = val & ((1 << (width * 8)) - 1)
        return "8#" + format(u, "o")
    # Decimal / ASCII / anything else -> signed decimal
    return str(val)


def _member_value_text(dt: str, image: bytes, offset: int, radix: Optional[str]
                       ) -> Optional[str]:
    """Decode one atomic member's value text from the image at `offset`."""
    width, fmt = _ATOMIC[dt]
    if offset + width > len(image):
        return None
    val = struct.unpack_from(fmt, image, offset)[0]
    if dt == "LREAL":
        return _fmt_lreal_decorated(val)
    if dt == "REAL":
        return _fmt_real_decorated(val)
    return _format_int_radix(dt, val, width, radix)


def _radix_for(member_dt: str, def_radix: Optional[str]) -> Optional[str]:
    """Pick the Radix attribute for a DataValue(Member) of a given atomic type.

    Prefer the radix declared on the DataType member definition (e.g. Binary,
    Hex). Fall back to the conventional default (Float for REAL, Decimal for
    ints). BOOL/BIT carry no Radix.
    """
    if member_dt in ("BOOL", "BIT"):
        return None
    if def_radix and def_radix not in ("NullType",):
        return def_radix
    return _DEFAULT_RADIX.get(member_dt, "Decimal")


def _resolve_layout(dt_name: str, layout_map: Dict, data_types_map: Dict):
    """Return the ordered member layout for a struct datatype, or None.

    Each entry: (name, member_dt_upper, byte_offset, bit_or_None, hidden_bool,
    dims_list_or_None, def_radix_or_None). def_radix comes from data_types_map
    when available (TagInfo.XML carries no Radix attribute).
    """
    members = layout_map.get(dt_name.upper())
    if not members:
        return None
    # radix lookup from the parsed DataType definition (by member name).
    dt_def = data_types_map.get(dt_name.upper())
    radix_by_name = {}
    if dt_def is not None:
        for m in getattr(dt_def, "members", []):
            radix_by_name[m.name] = getattr(m, "radix", None)
    out = []
    for (name, mdt, off, bit, hidden, dims) in members:
        out.append((name, mdt.upper(), off, bit, hidden, dims,
                    radix_by_name.get(name)))
    return out


def _is_string_layout(layout) -> bool:
    """True if a struct layout is the Logix STRING shape: LEN (int) + DATA SINT[].

    Logix renders STRING (and STRING-family) values as a single CDATA DATA
    member rather than an array of SINT bytes, so these need special handling.
    """
    if not layout:
        return False
    vis = [m for m in layout if not m[4]]      # m[4] = hidden
    names = {m[0].upper() for m in vis}
    if names != {"LEN", "DATA"}:
        return False
    data = next((m for m in vis if m[0].upper() == "DATA"), None)
    if data is None:
        return False
    # DATA must be a SINT array.
    return data[1] == "SINT" and bool(data[5])


def _render_string_inner(layout, image: bytes) -> Optional[str]:
    """Render the inner members of a STRING-shaped struct (LEN + CDATA DATA)."""
    parts: List[str] = []
    for (name, mdt, off, bit, hidden, dims, def_radix) in layout:
        if hidden:
            continue
        if name.upper() == "LEN":
            if off + 4 > len(image):
                return None
            length = struct.unpack_from("<i", image, off)[0]
            parts.append(
                f'<DataValueMember Name="{name}" DataType="DINT" '
                f'Radix="Decimal" Value="{length}"/>'
            )
        elif name.upper() == "DATA":
            total = 1
            for d in (dims or []):
                total *= d
            raw = image[off:off + total]
            length = 0
            # Use LEN if present/valid; else stop at first NUL.
            length = next((struct.unpack_from("<i", image, m[2])[0]
                           for m in layout if m[0].upper() == "LEN"
                           and m[2] + 4 <= len(image)), 0)
            if length <= 0 or length > len(raw):
                length = len(raw.split(b"\x00", 1)[0])
            text = _ascii_string_cdata(raw[:length])
            parts.append(
                f'<DataValueMember Name="{name}" DataType="STRING" '
                f'Radix="ASCII">\n<![CDATA[{text}]]>\n</DataValueMember>'
            )
        else:
            return None
    return "".join(parts)


def _ascii_string_cdata(b: bytes) -> str:
    """Encode raw SINT-array bytes as a Logix STRING CDATA literal.

    Printable ASCII passes through; the few Logix escape sequences ($ control
    chars) are emitted as $-codes the way Studio writes them.
    """
    out = []
    for ch in b:
        if ch == 0x24:           # '$'
            out.append("$$")
        elif ch == 0x27:         # "'"
            out.append("$'")
        elif ch == 0x09:
            out.append("$t")
        elif ch == 0x0A:
            out.append("$l")
        elif ch == 0x0D:
            out.append("$r")
        elif 0x20 <= ch < 0x7F:
            out.append(chr(ch))
        else:
            out.append("$%02X" % ch)
    return "".join(out)


def _decorated_struct_layout(dt_name: str, image: bytes, layout_map: Dict,
                             data_types_map: Dict, depth: int = 0
                             ) -> Optional[str]:
    """Render <Structure DataType=..>..</Structure> using the TagInfo layout."""
    if depth > 24:
        return None
    layout = _resolve_layout(dt_name, layout_map, data_types_map)
    if layout is None:
        return None
    if _is_string_layout(layout):
        inner = _render_string_inner(layout, image)
        if inner is None:
            return None
        return f'<Structure DataType="{dt_name}">{inner}</Structure>'
    parts: List[str] = []
    for (name, mdt, off, bit, hidden, dims, def_radix) in layout:
        if hidden:
            continue
        frag = _decorated_member(name, mdt, off, bit, dims, def_radix,
                                 image, layout_map, data_types_map, depth)
        if frag is None:
            return None
        parts.append(frag)
    return f'<Structure DataType="{dt_name}">{"".join(parts)}</Structure>'


def _decorated_member(name: str, mdt: str, off: int, bit, dims,
                      def_radix: Optional[str], image: bytes, layout_map: Dict,
                      data_types_map: Dict, depth: int) -> Optional[str]:
    """Render one DataValueMember / ArrayMember / StructureMember."""
    # ---- array member ----------------------------------------------------- #
    if dims:
        total = 1
        for d in dims:
            total *= d
        dim_str = ",".join(str(d) for d in dims)
        if mdt in _ATOMIC:
            width, _ = _ATOMIC[mdt]
            # BOOL/BIT scalar members carry no Radix, but a BOOL *array* member
            # is emitted with Radix="Decimal" by Logix.
            radix = "Decimal" if mdt in ("BOOL", "BIT") else _radix_for(mdt, def_radix)
            elems = []
            for i in range(total):
                eoff = off + i * width
                if mdt in ("BOOL", "BIT"):
                    # packed BOOL array: 1 bit per element from the base offset
                    byte = off + (i // 8)
                    if byte >= len(image):
                        return None
                    v = (image[byte] >> (i % 8)) & 1
                    elems.append(f'<Element Index="[{i}]" Value="{v}"/>')
                    continue
                vt = _member_value_text(mdt, image, eoff, radix)
                if vt is None:
                    return None
                elems.append(f'<Element Index="[{i}]" Value="{vt}"/>')
            ra = f' Radix="{radix}"' if radix else ""
            return (f'<ArrayMember Name="{name}" DataType="{mdt}" '
                    f'Dimensions="{dim_str}"{ra}>{"".join(elems)}</ArrayMember>')
        # array of struct/UDT
        sub_layout = _resolve_layout(mdt, layout_map, data_types_map)
        if sub_layout is None:
            return None
        # element size = struct size from layout map (max offset+width). We need a
        # per-element stride; derive from the datatype Size if present, else span.
        stride = _struct_stride(mdt, layout_map, data_types_map)
        if stride is None:
            return None
        elems = []
        for i in range(total):
            sub = image[off + i * stride: off + (i + 1) * stride]
            inner = _decorated_struct_inner(mdt, sub, layout_map, data_types_map,
                                            depth + 1)
            if inner is None:
                return None
            # OEM wraps each array-of-struct element's members in <Structure>.
            elems.append(
                f'<Element Index="[{i}]"><Structure DataType="{mdt}">'
                f'{inner}</Structure></Element>'
            )
        return (f'<ArrayMember Name="{name}" DataType="{mdt}" '
                f'Dimensions="{dim_str}">{"".join(elems)}</ArrayMember>')

    # ---- BOOL / BIT scalar member ---------------------------------------- #
    if mdt in ("BOOL", "BIT"):
        b = bit if bit is not None else 0
        byte = off + (b // 8)
        if byte >= len(image):
            return None
        v = (image[byte] >> (b % 8)) & 1
        return f'<DataValueMember Name="{name}" DataType="BOOL" Value="{v}"/>'

    # ---- atomic scalar member -------------------------------------------- #
    if mdt in _ATOMIC:
        radix = _radix_for(mdt, def_radix)
        vt = _member_value_text(mdt, image, off, radix)
        if vt is None:
            return None
        ra = f' Radix="{radix}"' if radix else ""
        return f'<DataValueMember Name="{name}" DataType="{mdt}"{ra} Value="{vt}"/>'

    # ---- nested struct/UDT member ---------------------------------------- #
    stride = _struct_stride(mdt, layout_map, data_types_map)
    if stride is None:
        return None
    sub = image[off: off + stride]
    inner = _decorated_struct_inner(mdt, sub, layout_map, data_types_map, depth + 1)
    if inner is None:
        return None
    return f'<StructureMember Name="{name}" DataType="{mdt}">{inner}</StructureMember>'


def _decorated_struct_inner(dt_name: str, image: bytes, layout_map: Dict,
                            data_types_map: Dict, depth: int) -> Optional[str]:
    """Render the INNER member list of a struct (no <Structure> wrapper)."""
    if depth > 24:
        return None
    layout = _resolve_layout(dt_name, layout_map, data_types_map)
    if layout is None:
        return None
    if _is_string_layout(layout):
        return _render_string_inner(layout, image)
    parts: List[str] = []
    for (name, mdt, off, bit, hidden, dims, def_radix) in layout:
        if hidden:
            continue
        frag = _decorated_member(name, mdt, off, bit, dims, def_radix,
                                 image, layout_map, data_types_map, depth)
        if frag is None:
            return None
        parts.append(frag)
    return "".join(parts)


def _struct_stride(dt_name: str, layout_map: Dict, data_types_map: Dict
                   ) -> Optional[int]:
    """Per-element byte stride of a struct datatype.

    Uses the TagInfo Size if cached on the layout map (key "@size@<NAME>"); else
    falls back to max(member_offset + member_width) over the layout.
    """
    sz = layout_map.get("@size@" + dt_name.upper())
    if isinstance(sz, int) and sz > 0:
        return sz
    layout = _resolve_layout(dt_name, layout_map, data_types_map)
    if layout is None:
        return None
    span = 0
    for (_n, mdt, off, _bit, _hidden, dims, _r) in layout:
        if mdt in _ATOMIC:
            w = _ATOMIC[mdt][0]
        else:
            w = _struct_stride(mdt, layout_map, data_types_map)
            if w is None:
                return None
        n = 1
        if dims:
            for d in dims:
                n *= d
        end = off + w * n
        if end > span:
            span = end
    # round up to 4-byte alignment (Logix struct padding)
    if span % 4:
        span += 4 - (span % 4)
    return span or None


def render_decorated_layout(dt_base: str, dimensions: Optional[str], image: bytes,
                            layout_map: Dict, data_types_map: Dict) -> Optional[str]:
    """Layout-driven Decorated rendering (Step 6d). Returns inner XML or None.

    Falls back (returns None) for anything it cannot decode so the caller keeps
    today's behaviour. Handles: atomic scalar/array (delegated), and struct /
    array-of-struct using the TagInfo byte-offset map for full member fidelity.
    """
    if not layout_map:
        return None
    total, dim_parts = _dims_total(dimensions)

    # Atomic scalar/array: the existing path is already correct & byte-faithful.
    if dt_base in _ATOMIC:
        return render_decorated(dt_base, dimensions, image, data_types_map)

    # Struct datatype must be present in the layout map.
    if dt_base.upper() not in layout_map:
        return None

    if total == 0:
        return _decorated_struct_layout(dt_base, image, layout_map, data_types_map)

    # Array of struct.
    stride = _struct_stride(dt_base, layout_map, data_types_map)
    if stride is None:
        return None
    dim_str = ",".join(str(d) for d in dim_parts)
    elems = []
    for i in range(total):
        sub = image[i * stride:(i + 1) * stride]
        inner = _decorated_struct_inner(dt_base, sub, layout_map, data_types_map, 1)
        if inner is None:
            return None
        # OEM wraps each array-of-struct element's members in <Structure>.
        elems.append(
            f'<Element Index="[{i}]"><Structure DataType="{dt_base}">'
            f'{inner}</Structure></Element>'
        )
    return (f'<Array DataType="{dt_base}" Dimensions="{dim_str}">'
            f'{"".join(elems)}</Array>')
