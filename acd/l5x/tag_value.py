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
    """Format a REAL/LREAL like Logix: 8-significand scientific, 3-digit exp."""
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
            return _decorated_scalar(dt_base, _atomic_text(dt_base, image[:width]))
        # atomic array
        radix = _RADIX.get(dt_base, "Decimal")
        elems = []
        for i in range(total):
            off = i * width
            if off + width > len(image):
                return None
            elems.append(
                f'<Element Index="[{i}]" Value="{_atomic_text(dt_base, image[off:off+width])}"/>'
            )
        dim_str = ",".join(str(d) for d in dim_parts)
        return (f'<Array DataType="{dt_base}" Dimensions="{dim_str}" Radix="{radix}">'
                f'{"".join(elems)}</Array>')

    # Scalar struct (built-in only for now)
    if total == 0:
        return _decorated_struct(dt_base, image, data_types_map)
    return None
