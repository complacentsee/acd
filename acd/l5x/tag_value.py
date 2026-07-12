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
from decimal import Decimal, localcontext, ROUND_HALF_UP
from typing import Dict, List, Optional, Tuple

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


# L5K CDATA non-finite sentinels (Logix-specific strings, not %e output).
_L5K_QNAN = "1.#QNAN000e+000"
_L5K_PINF = "1.#INF0000e+000"
_L5K_NINF = "-1.#INF0000e+000"


def _round_sig_haway(v: float, p: int) -> Tuple[str, int, bool]:
    """Round |v| to ``p`` significant figures, ROUND-HALF-AWAY-FROM-ZERO.

    Returns ``(digits, exp10, neg)``: a p-char digit string, the base-10 exponent
    of the leading digit, and the sign flag (negative-zero aware). Pure-python and
    byte-identical to a Windows-CRT ``sprintf("%.*e", p-1, (double)v)`` across the
    whole OEM float corpus. ``Decimal(v)`` is the exact value of the IEEE float, so
    the rounding sees the float's true decimal expansion.
    """
    neg = (v < 0.0) or (v == 0.0 and bool(struct.pack("<d", v)[7] & 0x80))
    d = Decimal(abs(v))
    if d == 0:
        return "0" * p, 0, neg
    e = d.adjusted()                                   # exp of the leading digit
    m = d.scaleb(-e)                                   # mantissa in [1, 10)
    q = m.quantize(Decimal(1).scaleb(-(p - 1)), rounding=ROUND_HALF_UP)
    if q >= 10:                                        # 9.99.. rounded up to 10.0
        q = (q / 10).quantize(Decimal(1).scaleb(-(p - 1)), rounding=ROUND_HALF_UP)
        e += 1
    return f"{q:.{p - 1}f}".replace(".", ""), e, neg


def _emit9(digits: str, exp: int, neg: bool) -> str:
    """Render a digit string + base-10 exponent as ``D.DDDDDDDDe(+/-)EEE``."""
    d9 = (digits + "0" * 9)[:9]
    sign = "-" if neg else ""
    es = "+" if exp >= 0 else "-"
    return f"{sign}{d9[0]}.{d9[1:]}e{es}{abs(exp):03d}"


# Smallest positive *normal* float32 (2**-126); below this a value is subnormal.
_F32_SMALLEST_NORMAL = Decimal(2) ** (-126)


def _fmt_real(v: float) -> str:
    """Format a REAL (IEEE-754 single) the way Logix writes it in an L5K CDATA.

    The form is 9-significant-figure scientific (1 leading + 8 fractional digits),
    rounding HALF-AWAY-FROM-ZERO, with a 3-digit explicit-sign exponent. On top of
    that base, Studio's float32 digit-generation collapses the trailing (9th) digit
    to zero for "near-clean" magnitudes: when a value sits within ~half a float32
    ULP at or above a shorter decimal, that decimal's noisy tail is dropped. This
    reproduces the OEM converter byte-for-byte over the full pool corpus (every
    distinct REAL literal and every weighted occurrence). NaN/+-Inf use the Logix
    sentinels, which are NOT %e output.
    """
    if v != v:
        return _L5K_QNAN
    if v == float("inf"):
        return _L5K_PINF
    if v == float("-inf"):
        return _L5K_NINF
    # Quantize to single precision so the exact-decimal rounding always sees the
    # true float32 value (callers already feed an <f-unpacked value; be defensive).
    f = struct.unpack("<f", struct.pack("<f", v))[0]
    if f != f:
        return _L5K_QNAN
    if f == float("inf"):
        return _L5K_PINF
    if f == float("-inf"):
        return _L5K_NINF
    with localcontext() as ctx:
        ctx.prec = 80                                  # ample; default 28 also works
        if f == 0.0:
            return _emit9("0" * 9, 0, bool(struct.pack("<d", f)[7] & 0x80))

        def _cand(p: int):
            dig, exp, neg = _round_sig_haway(f, p)
            d9 = (dig + "0" * 9)[:9]
            mag = Decimal(d9[0] + "." + d9[1:]).scaleb(exp)
            val = float((-1 if neg else 1) * mag)
            try:
                rt = (struct.unpack("<f", struct.pack("<f", val))[0] == f)
            except OverflowError:
                rt = False
            return dig, exp, neg, mag, rt

        av = Decimal(abs(f))
        dig9, exp9, neg9 = _round_sig_haway(f, 9)      # default: full 9-sig form
        dig8, exp8, neg8, mag8, rt8 = _cand(8)         # 8-sig (9th position is 0)

        # PRIMARY collapse: the 8-sig form ends in 0, round-trips, and was reached
        # by rounding DOWN (does not overshoot v) -> the 9th digit is pure noise.
        if dig8[-1] == "0" and rt8 and mag8 <= av:
            return _emit9(dig8, exp8, neg8)

        # ULTRA-CLEAN collapse: the 1-sig form round-trips and sits at-or-below v
        # by less than ~half a float32 ULP (8th-digit noise <= 2) -> emit it clean.
        if av >= _F32_SMALLEST_NORMAL:
            dig1, exp1, neg1, mag1, rt1 = _cand(1)
            if rt1 and mag1 <= av and int(dig8[-1]) <= 2:
                return _emit9(dig1, exp1, neg1)

        return _emit9(dig9, exp9, neg9)


def _fmt_lreal(v: float) -> str:
    """Format an LREAL (IEEE-754 double) for an L5K CDATA.

    Same 9-significant-figure, half-away, 3-digit-exponent scientific shape as
    :func:`_fmt_real`, applied to the raw double WITHOUT the float32 re-quant/
    collapse (that is a single-precision dtoa artifact and ``pack('<f', ...)``
    would overflow for large doubles). The pool contains no LREAL L5K literals, so
    this is the by-analogy shared base rule; sentinels and signed zero are identical.
    """
    if v != v:
        return _L5K_QNAN
    if v == float("inf"):
        return _L5K_PINF
    if v == float("-inf"):
        return _L5K_NINF
    with localcontext() as ctx:
        ctx.prec = 80
        if v == 0.0:
            return _emit9("0" * 9, 0, bool(struct.pack("<d", v)[7] & 0x80))
        dig9, exp9, neg9 = _round_sig_haway(v, 9)
        return _emit9(dig9, exp9, neg9)


def _atomic_text(dt: str, b: bytes) -> str:
    """Decode one atomic value from its bytes to its L5K/Value text."""
    width, fmt = _ATOMIC[dt]
    val = struct.unpack(fmt, b[:width])[0]
    if dt == "LREAL":
        return _fmt_lreal(val)
    if dt == "REAL":
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


def _shortest_sig(f: float) -> int:
    """Number of significant digits in the SHORTEST decimal that round-trips ``f``.

    Logix's Decorated formatter picks fixed vs scientific notation (and how many
    fractional digits to show in fixed form) from this shortest-round-trip digit
    count ``p`` (1..9 for float32). Reproduces a C ``%g`` precision-selection.
    """
    for p in range(1, 10):
        s = "%.*g" % (p, f)
        try:
            if struct.unpack("<f", struct.pack("<f", float(s)))[0] == f:
                return p
        except OverflowError:
            continue
    return 9


def _decorated_fixed(f: float, p: int, exp: int, neg: bool) -> str:
    """Render ``f`` in Decorated FIXED-point form (trailing-zero-trimmed, ``.0``).

    The integer part always shows ALL its digits (the exact float32 integer, so
    large integral values like 138100384.0 keep every digit); the fraction shows
    ``p - 1 - exp`` digits rounded HALF-AWAY-FROM-ZERO via ``_round_sig_haway``.
    When there is no fractional part the value is the exact rounded integer + ``.0``.
    """
    frac_digits = p - 1 - exp
    sign = "-" if neg else ""
    if frac_digits <= 0:
        # Integral to this precision: emit the exact (half-away rounded) integer.
        iv = Decimal(abs(f)).quantize(Decimal(1), rounding=ROUND_HALF_UP)
        return f"{sign}{iv}.0"
    dig, e2, _ = _round_sig_haway(f, p)                 # p-digit, half-away
    if e2 >= 0:
        intlen = e2 + 1
        if intlen >= len(dig):
            ipart = dig + "0" * (intlen - len(dig))
            fpart = ""
        else:
            ipart = dig[:intlen]
            fpart = dig[intlen:]
    else:
        ipart = "0"
        fpart = "0" * (-e2 - 1) + dig
    fpart = fpart.rstrip("0")
    return f"{sign}{ipart}.{fpart}" if fpart else f"{sign}{ipart}.0"


def _fmt_real_decorated(v: float) -> str:
    """Format a REAL value the way Logix writes it in a Decorated Value attribute.

    The Decorated REAL form uses C ``%g``-style GENERAL notation but with the
    SAME digit/rounding machinery as the L5K CDATA form (:func:`_fmt_real`:
    round HALF-AWAY, float32 precision). The mantissa digits are the shortest
    round-trip decimal (``p`` significant figures); the choice of notation is:

      * SCIENTIFIC when the leading-digit exponent ``exp >= 9`` (large) OR the
        fixed form would need ``>= 10`` digits after the decimal point
        (``p - 1 - exp >= 10``, very small). Scientific reuses the 9-significant
        -figure form: ``D.DDDDDDDDe(+/-)EEE`` (8 fractional digits, 3-digit exp).
      * FIXED otherwise: shortest round-trip rendered fixed-point, trailing
        zeros trimmed, integral values shown in full with a trailing ``.0``.

    Validated byte-exact (8123/8123 distinct, all weighted occurrences) against
    the full OEM Decorated REAL corpus. NaN/+-Inf use the Logix Decorated
    sentinels (NOT the longer L5K CDATA sentinel strings).
    """
    import math
    f = struct.unpack("<f", struct.pack("<f", v))[0]
    if f != f:                      # NaN -> Logix Decorated form
        return "1.#QNAN"
    if f == float("inf"):
        return "1.$"
    if f == float("-inf"):
        return "-1.$"
    with localcontext() as ctx:
        ctx.prec = 80
        if f == 0.0:
            neg0 = bool(struct.pack("<d", f)[7] & 0x80)
            return "-0.0" if neg0 else "0.0"
        a = abs(f)
        exp = math.floor(math.log10(a))
        # log10 can land just on the wrong side of a power of ten for values that
        # are exactly (or float-near) 10**k; pin exp to the decimal truth.
        if Decimal(a) >= Decimal(10) ** (exp + 1):
            exp += 1
        elif Decimal(a) < Decimal(10) ** exp:
            exp -= 1
        p = _shortest_sig(f)
        sci = (exp >= 9) or (p - 1 - exp >= 10)
        if sci:
            return _fmt_real(f)                         # 9-sig scientific (L5K form)
        return _decorated_fixed(f, p, exp, f < 0.0)


def _fmt_lreal_decorated(v: float) -> str:
    """Decorated form of an LREAL (double).

    By analogy with :func:`_fmt_real_decorated` but operating on the raw double:
    the shortest round-trip decimal selects fixed vs scientific via the same
    ``exp >= 9`` / ``>= 10`` fractional-digit GENERAL-notation bands, with
    HALF-AWAY rounding. The OEM pool contains no LREAL Decorated literals, so
    this is the shared-rule extrapolation (single-precision re-quant is NOT
    applied, which would corrupt high-precision doubles); the scientific branch
    uses the double 9-sig form via :func:`_fmt_lreal`-style rounding.
    """
    import math
    f = v
    if f != f:
        return "1.#QNAN"
    if f == float("inf"):
        return "1.$"
    if f == float("-inf"):
        return "-1.$"
    with localcontext() as ctx:
        ctx.prec = 80
        if f == 0.0:
            neg0 = bool(struct.pack("<d", f)[7] & 0x80)
            return "-0.0" if neg0 else "0.0"
        a = abs(f)
        exp = math.floor(math.log10(a))
        if Decimal(a) >= Decimal(10) ** (exp + 1):
            exp += 1
        elif Decimal(a) < Decimal(10) ** exp:
            exp -= 1
        # shortest round-trip sig digits for a double (1..17)
        p = 17
        for cand_p in range(1, 18):
            if float("%.*g" % (cand_p, f)) == f:
                p = cand_p
                break
        sci = (exp >= 9) or (p - 1 - exp >= 10)
        if sci:
            return _fmt_lreal(f)
        frac_digits = p - 1 - exp
        sign = "-" if f < 0.0 else ""
        if frac_digits <= 0:
            iv = Decimal(abs(f)).quantize(Decimal(1), rounding=ROUND_HALF_UP)
            return f"{sign}{iv}.0"
        dig, e2, _ = _round_sig_haway(f, p)
        if e2 >= 0:
            intlen = e2 + 1
            if intlen >= len(dig):
                ipart = dig + "0" * (intlen - len(dig))
                fpart = ""
            else:
                ipart = dig[:intlen]
                fpart = dig[intlen:]
        else:
            ipart = "0"
            fpart = "0" * (-e2 - 1) + dig
        fpart = fpart.rstrip("0")
        return f"{sign}{ipart}.{fpart}" if fpart else f"{sign}{ipart}.0"


def _dims_total(dimensions: Optional[str]) -> Tuple[int, List[int]]:
    if not dimensions:
        return 0, []
    # The Dimensions string may be space-separated (tag attribute form) or
    # comma-separated (AOI param/local form); accept either.
    parts = [int(d) for d in dimensions.replace(",", " ").split()
             if d.lstrip("-").isdigit()]
    total = 1
    for d in parts:
        total *= d
    return (total if parts else 0), parts


def _index_str(i: int, dims: List[int]) -> str:
    """Render a flat element ordinal `i` as an L5X Decorated <Element> Index.

    Logix lays multi-dimensional arrays out row-major over the Dimensions string
    exactly as written (left-to-right), with the LAST dimension varying fastest:
    dims [26,11,11] -> [0,0,0],[0,0,1],...,[0,0,10],[0,1,0],...  A 1-D array
    keeps the simple "[i]" form. Verified against OEM V17/V34 multi-dim arrays.
    """
    if len(dims) <= 1:
        return f"[{i}]"
    coords = []
    rem = i
    for j in range(len(dims)):
        stride = 1
        for d in dims[j + 1:]:
            stride *= d
        coords.append((rem // stride) % dims[j] if stride else 0)
    return "[" + ",".join(str(c) for c in coords) + "]"


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


def _wrap_l5k(flat: str, depth: int, budget: int = 81) -> str:
    """Re-wrap a flat one-line L5K bracket list exactly as Logix Designer does.

    The writer wraps a long ``Format="L5K"`` bracket list by inserting
    ``"\\n" + "\\t"*depth`` before a ``,`` or ``]`` once the VALUE-character column
    reaches ``budget`` (81). Only value characters count toward the column —
    ``[``, ``]`` and ``,`` contribute 0, and a nested ``[...]`` sub-list is never
    broken (it accumulates into the surrounding column). ``depth`` is the writer's
    per-format-version indent (2 tabs for SoftwareRevision >= 32, else 5).

    Reproduces the reference wrap byte-exact (4216/4216 corpus blocks). Scalars
    and any non-bracket body pass through unchanged.
    """
    if not flat or flat[0] != "[":
        return flat
    out: List[str] = []
    col = 0
    in_str = False
    for ch in flat:
        if in_str:
            out.append(ch)
            col += 1
            if ch == "'":
                in_str = False
            continue
        if ch == "'":
            in_str = True
            out.append(ch)
            col += 1
            continue
        if ch == "," or ch == "]":
            if col >= budget:
                out.append("\n")
                out.append("\t" * depth)
                col = 0
            out.append(ch)             # separators/closers cost 0 columns
            continue
        if ch == "[":
            out.append(ch)             # openers cost 0 and never trigger a wrap
            continue
        out.append(ch)                 # value chars count 1 column each
        col += 1
    return "".join(out)


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
        # BOOL/BIT array: bit-packed (one bit per element, so a 256-element array
        # occupies 32 bytes), NOT one byte each. Element i = bit (i & 7) of byte
        # i>>3; OEM writes each as the binary literal 2#0 / 2#1.
        if dt_base in ("BOOL", "BIT"):
            vals = []
            for i in range(total):
                v = _unpack_bit(image, 0, i)
                if v is None:
                    return None
                vals.append("2#%d" % v)
            return "[" + ",".join(vals) + "]"
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
        return _emit_l5k(_walk_struct(dt_base, image, layout_map,
                                      data_types_map, 0))

    stride = _struct_stride(dt_base, layout_map, data_types_map)
    if stride is None:
        return None
    elems = []
    for i in range(total):
        sub = image[i * stride:(i + 1) * stride]
        frag = _emit_l5k(_walk_struct(dt_base, sub, layout_map,
                                      data_types_map, 1))
        if frag is None:
            return None
        elems.append(frag)
    return "[" + ",".join(elems) + "]"


def _l5k_value(mdt: str, val) -> str:
    """L5K text of one decoded atomic value (signed decimal; L5K floats)."""
    if mdt == "LREAL":
        return _fmt_lreal(val)
    if mdt == "REAL":
        return _fmt_real(val)
    return str(val)


def _l5k_string(layout, image: bytes) -> Optional[str]:
    """Render a STRING-shaped struct in the L5K bracket form ``[LEN,'TEXT...']``.

    Logix serialises a STRING (LEN int + DATA SINT[]) in the L5K CDATA as a
    two-entry bracket: the LEN integer, then a single-quoted L5K string literal
    covering the FULL DATA[] capacity (the active LEN characters followed by
    ``$00`` NUL padding to the declared array dimension), with ``$``-escapes for
    control / non-printable bytes.  Mirrors the Decorated string path but in the
    bracket/quoted form.
    """
    len_off = None
    data_off = None
    data_cap = 0
    for (name, mdt, off, bit, hidden, dims, def_radix) in layout:
        up = name.upper()
        if up == "LEN":
            len_off = off
        elif up == "DATA":
            data_off = off
            data_cap = 1
            for d in (dims or []):
                data_cap *= d
    if len_off is None or data_off is None or data_cap <= 0:
        return None
    if len_off + 4 > len(image) or data_off + data_cap > len(image):
        return None
    length = struct.unpack_from("<i", image, len_off)[0]
    raw = image[data_off:data_off + data_cap]
    text = _ascii_string_cdata(raw)
    return "[%d,'%s']" % (length, text)


# --------------------------------------------------------------------------- #
# Unified layout traversal (P4) — ONE walker over the TagInfo layout decodes
# every member into a small value tree; the L5K and Decorated emitters
# (_emit_l5k below, _emit_decorated_inner further down) consume it. The two
# serialisations deliberately differ in POLICY, applied at emit time from the
# per-member flags:
#   hidden     L5K serialises the physical STORAGE image (hidden members
#              included, e.g. AB:1734_4SLOT:O:0's SlotStatusBits DINTs or the
#              connection-header CfgSize/CfgIDNum/Reserved words); Decorated
#              serialises the VIEW (hidden skipped).
#   bit_alias  a scalar BOOL whose base byte falls inside a wider member
#              (e.g. Pt0FaultMode overlaying the FaultMode SINT) is NOT a
#              distinct storage slot: L5K skips it, Decorated shows it.
# Decode failures become ("err",) nodes evaluated per-emitter, so a failing
# member only fails the serialisation(s) that actually include it.
#
# Nodes:
#   ("err",)                                undecodable (bounds/layout/depth)
#   ("atomic", mdt, val, width, def_radix)  decoded atomic scalar
#   ("bool", v, explicit_bit)               scalar BOOL; explicit_bit = a bit
#                                           index was declared (packed BOOL)
#   ("aarr", mdt, dims, vals, def_radix)    atomic array (BOOL: 0/1 ints)
#   ("sarr", mdt, dims, walk_elem, total,   struct array; elements walked
#           layout_ok)                      LAZILY via walk_elem(i) so a
#                                           skipping/bailing consumer never
#                                           pays for the subtree; layout_ok =
#                                           element member list resolves
#                                           (Decorated requires it, L5K
#                                           renders from stride alone)
#   ("struct", dt_name, members)            members = [(name, mdt, hidden,
#                                           bit_alias, node), ...]
#   ("string", dt_name, layout, image)      STRING-shaped struct; the two
#                                           leaf formatters (_l5k_string /
#                                           _render_string_inner) keep their
#                                           distinct capacity/tolerance rules
#   ("literal", inner_xml)                  pre-rendered Decorated inner XML
#                                           (the zero-value STRING default
#                                           from elements' zero generator,
#                                           which Logix writes with no CDATA
#                                           block); Decorated-only
# --------------------------------------------------------------------------- #


def _unpack_bit(image: bytes, off: int, i: int) -> Optional[int]:
    """Element/bit ``i`` of the packed BOOL run based at byte ``off``: bit
    (i & 7) of byte off + (i >> 3), LSB-first. None when out of the image."""
    byte = off + (i >> 3)
    if byte < 0 or byte >= len(image):
        return None
    return (image[byte] >> (i & 7)) & 1


def _walk_struct(dt_name: str, image: bytes, layout_map: Dict,
                 data_types_map: Dict, depth: int):
    """Decode one struct image into a value-tree node.

    Contract: never raises on any layout_map/image input — every
    undecodable member (out-of-bounds or negative offset, unresolvable or
    cyclic type, depth cap) becomes an ("err",) node for the emitters to
    judge. The walker decodes policy-skipped members too (hidden /
    bit-alias); their flags are applied at emit time.
    """
    if depth > 24:
        return ("err",)
    layout = _resolve_layout(dt_name, layout_map, data_types_map)
    if layout is None:
        return ("err",)
    if _is_string_layout(layout):
        return ("string", dt_name, layout, image)
    # Byte offsets owned by non-BOOL atomic / struct members: a scalar BOOL
    # whose base byte falls inside one is a bit-alias of that member.
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
    members = []
    for (name, mdt, off, bit, hidden, dims, def_radix) in layout:
        bit_alias = mdt in ("BOOL", "BIT") and not dims and off in covered
        node = _walk_member(mdt, off, bit, dims, def_radix, image,
                            layout_map, data_types_map, depth)
        members.append((name, mdt, hidden, bit_alias, node))
    return ("struct", dt_name, members)


def _walk_member(mdt: str, off: int, bit, dims, def_radix, image: bytes,
                 layout_map: Dict, data_types_map: Dict, depth: int):
    """Decode one member (scalar, array, or nested struct) into a node."""
    if dims:
        total = 1
        for d in dims:
            total *= d
        if mdt in _ATOMIC:
            width, fmt = _ATOMIC[mdt]
            vals = []
            if mdt in ("BOOL", "BIT"):
                # packed BOOL array: 1 bit per element from the base offset
                for i in range(total):
                    v = _unpack_bit(image, off, i)
                    if v is None:
                        return ("err",)
                    vals.append(v)
            else:
                for i in range(total):
                    eoff = off + i * width
                    if eoff < 0 or eoff + width > len(image):
                        return ("err",)
                    vals.append(struct.unpack_from(fmt, image, eoff)[0])
            return ("aarr", mdt, dims, vals, def_radix)
        # array of nested struct. Elements are walked LAZILY via walk_elem(i)
        # so a consumer that skips this member (Decorated on hidden) or bails
        # at its first failing element (both, like the old walkers) never
        # pays for the remaining subtree -- this also keeps depth-capped
        # self-referential layouts from exploding exponentially. layout_ok
        # records whether the element type's member list resolves; the
        # Decorated emitter refuses the member without it (the old
        # pre-check), L5K renders from the stride alone.
        stride = _struct_stride(mdt, layout_map, data_types_map)
        if stride is None:
            return ("err",)
        layout_ok = _resolve_layout(mdt, layout_map, data_types_map) is not None

        def walk_elem(i, _mdt=mdt, _off=off, _stride=stride, _depth=depth):
            return _walk_struct(
                _mdt, image[_off + i * _stride: _off + (i + 1) * _stride],
                layout_map, data_types_map, _depth + 1)

        return ("sarr", mdt, dims, walk_elem, total, layout_ok)

    if mdt in ("BOOL", "BIT"):
        v = _unpack_bit(image, off, bit if bit is not None else 0)
        if v is None:
            return ("err",)
        return ("bool", v, bit is not None)

    if mdt in _ATOMIC:
        width, fmt = _ATOMIC[mdt]
        if off < 0 or off + width > len(image):
            return ("err",)
        return ("atomic", mdt, struct.unpack_from(fmt, image, off)[0],
                width, def_radix)

    # nested struct member
    stride = _struct_stride(mdt, layout_map, data_types_map)
    if stride is None:
        return ("err",)
    return _walk_struct(mdt, image[off: off + stride], layout_map,
                        data_types_map, depth + 1)


def _emit_l5k(node) -> Optional[str]:
    """Serialise a value-tree node in the L5K bracket form ``[m0,m1,...]``.

    Storage policy: hidden members included, bit-alias scalar BOOLs skipped
    (only their containing integer member is emitted). Values are plain signed
    decimals regardless of display radix.
    """
    kind = node[0]
    if kind == "err":
        return None
    if kind == "string":
        return _l5k_string(node[2], node[3])
    if kind == "struct":
        parts: List[str] = []
        for (_name, _mdt, _hidden, bit_alias, sub) in node[2]:
            if bit_alias:
                # bit-alias of a wider integer member -> not a storage slot
                continue
            frag = _emit_l5k(sub)
            if frag is None:
                return None
            parts.append(frag)
        return "[" + ",".join(parts) + "]"
    if kind == "atomic":
        return _l5k_value(node[1], node[2])
    if kind == "bool":
        return str(node[1])
    if kind == "aarr":
        _kind, mdt, _dims, vals, _radix = node
        return "[" + ",".join(_l5k_value(mdt, v) for v in vals) + "]"
    if kind == "sarr":
        _kind, _mdt, _dims, walk_elem, total, _layout_ok = node
        parts = []
        for i in range(total):
            frag = _emit_l5k(walk_elem(i))
            if frag is None:
                return None
            parts.append(frag)
        return "[" + ",".join(parts) + "]"
    return None


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


def _decorated_scalar(dt_base: str, value_text: str,
                      radix: Optional[str] = None) -> str:
    eff = radix if (radix and radix not in ("NullType", "General")) \
        else _RADIX.get(dt_base, "Decimal")
    return f'<DataValue DataType="{dt_base}" Radix="{eff}" Value="{value_text}"/>'


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
                     data_types_map: Dict, radix: Optional[str] = None
                     ) -> Optional[str]:
    """Return the inner XML for <Data Format="Decorated">, or None if unsupported.

    ``radix`` is the tag's declared Radix (best-effort; default None keeps today's
    per-type default). Integer atomics honour it (Binary/Hex/Octal/ASCII) via
    _format_int_radix; REAL/LREAL stay on the float formatter; BOOL stays Decimal.
    When radix is absent/Decimal the output is byte-identical to the prior code.
    """
    total, dim_parts = _dims_total(dimensions)

    if dt_base in _ATOMIC:
        width, fmt = _ATOMIC[dt_base]
        eff = radix if (radix and radix not in ("NullType", "General")) \
            else _RADIX.get(dt_base, "Decimal")

        def _val(off: int) -> str:
            if dt_base in ("REAL", "LREAL"):
                return _atomic_text_decorated(dt_base, image[off:off + width])
            v = struct.unpack_from(fmt, image, off)[0]
            if dt_base in ("BOOL", "BIT"):
                return "1" if v else "0"
            return _format_int_radix(dt_base, v, width, eff)

        if total == 0:
            if len(image) < width:
                return None
            return _decorated_scalar(dt_base, _val(0), eff)
        # BOOL/BIT array: bit-packed (one bit per element), NOT one byte each, so
        # a 32-element array occupies 4 bytes. Element i = bit (i & 7) of byte i>>3,
        # LSB-first; Radix is always Decimal.
        if dt_base in ("BOOL", "BIT"):
            need = (total + 7) // 8
            if len(image) < need:
                return None
            belems = [
                f'<Element Index="{_index_str(i, dim_parts)}" '
                f'Value="{_unpack_bit(image, 0, i)}"/>'
                for i in range(total)
            ]
            dim_str = ",".join(str(d) for d in dim_parts)
            return (f'<Array DataType="{dt_base}" Dimensions="{dim_str}" '
                    f'Radix="Decimal">{"".join(belems)}</Array>')
        # atomic array
        elems = []
        for i in range(total):
            off = i * width
            if off + width > len(image):
                return None
            elems.append(
                f'<Element Index="{_index_str(i, dim_parts)}" Value="{_val(off)}"/>'
            )
        dim_str = ",".join(str(d) for d in dim_parts)
        return (f'<Array DataType="{dt_base}" Dimensions="{dim_str}" Radix="{eff}">'
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


def _sint_char_escape(ch: int) -> str:
    """L5K single-byte char escape for one SINT ASCII array/scalar element.

    Mirrors :func:`_ascii_string_cdata` but for a single byte: printable ASCII
    passes through, the named control mnemonics use ``$t/$l/$p/$r`` and ``$$``/
    ``$'``, everything else is ``$XX`` (uppercase hex).
    """
    if ch == 0x24:           # '$'
        return "$$"
    if ch == 0x27:           # "'"
        return "$'"
    if ch == 0x09:
        return "$t"
    if ch == 0x0A:
        return "$l"
    if ch == 0x0C:
        return "$p"
    if ch == 0x0D:
        return "$r"
    if 0x20 <= ch < 0x7F:
        return chr(ch)
    return "$%02X" % ch


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
    if radix == "ASCII":
        # One char literal per element: OEM writes Value="&apos;$00&apos;".
        return "&apos;" + _sint_char_escape(val & 0xFF) + "&apos;"
    # Decimal / anything else -> signed decimal
    return str(val)


def _decorated_value(mdt: str, val, width: int, radix: Optional[str]) -> str:
    """Decorated text of one decoded atomic value (radix-aware)."""
    if mdt == "LREAL":
        return _fmt_lreal_decorated(val)
    if mdt == "REAL":
        return _fmt_real_decorated(val)
    return _format_int_radix(mdt, val, width, radix)


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

    Each entry: (name, member_dt, byte_offset, bit_or_None, hidden_bool,
    dims_list_or_None, def_radix_or_None). def_radix comes from data_types_map
    when available (TagInfo.XML carries no Radix attribute).

    ``member_dt`` keeps the datatype's DECLARED case (e.g. ``UDT_MixedCase``)
    because it is written verbatim into the rendered ``DataType`` attribute, and
    Logix preserves project case there. Every consumer that uses it as a lookup
    KEY or atomic-classification test upper-cases at the boundary (layout_map /
    data_types_map / @size@ keys all key on the upper form; the _ATOMIC/BOOL
    membership tests are satisfied because atomic type names are canonically
    all-caps), so resolution is unchanged — only the emitted string keeps case.
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
        out.append((name, mdt, off, bit, hidden, dims,
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


def _render_string_inner(layout, image: bytes, dt_name: str = "STRING"
                         ) -> Optional[str]:
    """Render the inner members of a STRING-shaped struct (LEN + CDATA DATA).

    ``dt_name`` is the enclosing STRING datatype's declared name; the DATA member
    carries it verbatim as its DataType (OEM writes the actual string type, e.g.
    ``String50`` / ``PF525FaultDesc`` / ``STRING28``, not a hardcoded ``STRING``).
    """
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
            # The Decorated DATA member shows the LOGICAL string -- exactly the
            # first LEN characters. A valid LEN of 0 is an EMPTY string even when
            # the SINT buffer still holds stale bytes past LEN (which OEM does not
            # surface); only fall back to a first-NUL scan when the LEN member is
            # absent or its value is out of range (corrupt). Reading LEN==0 as
            # "invalid -> NUL-scan" was the bug: it leaked cleared strings' stale
            # buffer content.
            _len_off = next((m[2] for m in layout if m[0].upper() == "LEN"
                             and m[2] + 4 <= len(image)), None)
            if _len_off is not None:
                length = struct.unpack_from("<i", image, _len_off)[0]
                if length < 0 or length > len(raw):
                    length = len(raw.split(b"\x00", 1)[0])
            else:
                length = len(raw.split(b"\x00", 1)[0])
            text = _ascii_string_cdata(raw[:length])
            # OEM wraps non-empty STRING DATA member content in single quotes
            # (the L5K string-literal form, embedded quotes already $-escaped);
            # an empty string (LEN 0) is emitted as empty CDATA, no quotes.
            cdata = f"'{text}'" if text else ""
            parts.append(
                f'<DataValueMember Name="{name}" DataType="{dt_name}" '
                f'Radix="ASCII">\n<![CDATA[{cdata}]]>\n</DataValueMember>'
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
        elif ch == 0x0C:
            out.append("$p")
        elif ch == 0x0D:
            out.append("$r")
        elif 0x20 <= ch < 0x7F:
            out.append(chr(ch))
        else:
            out.append("$%02X" % ch)
    return "".join(out)


def _emit_decorated_inner(node) -> Optional[str]:
    """Serialise a struct/string node's INNER members (no <Structure> wrap).

    View policy: hidden members skipped, bit-alias scalar BOOLs shown.
    """
    kind = node[0]
    if kind == "literal":
        return node[1]
    if kind == "string":
        return _render_string_inner(node[2], node[3], node[1])
    if kind != "struct":
        return None
    parts: List[str] = []
    for (name, mdt, hidden, _bit_alias, sub) in node[2]:
        if hidden:
            continue
        frag = _emit_decorated_member(name, mdt, sub)
        if frag is None:
            return None
        parts.append(frag)
    return "".join(parts)


def _emit_decorated_member(name: str, mdt: str, node) -> Optional[str]:
    """Serialise one member: DataValueMember/ArrayMember/StructureMember."""
    kind = node[0]
    if kind == "err":
        return None

    # ---- BOOL / BIT scalar member ---------------------------------------- #
    if kind == "bool":
        # A standalone (byte-aligned) BOOL member carries Radix="Decimal"; a BOOL
        # packed into a backing byte (an explicit bit index) carries no Radix.
        ra = "" if node[2] else ' Radix="Decimal"'
        return (f'<DataValueMember Name="{name}" DataType="BOOL"{ra} '
                f'Value="{node[1]}"/>')

    # ---- atomic scalar member -------------------------------------------- #
    if kind == "atomic":
        _kind, _mdt, val, width, def_radix = node
        radix = _radix_for(mdt, def_radix)
        vt = _decorated_value(mdt, val, width, radix)
        ra = f' Radix="{radix}"' if radix else ""
        return f'<DataValueMember Name="{name}" DataType="{mdt}"{ra} Value="{vt}"/>'

    # ---- atomic array member ---------------------------------------------- #
    if kind == "aarr":
        _kind, _mdt, dims, vals, def_radix = node
        dim_str = ",".join(str(d) for d in dims)
        # BOOL/BIT scalar members carry no Radix, but a BOOL *array* member
        # is emitted with Radix="Decimal" by Logix.
        if mdt in ("BOOL", "BIT"):
            radix = "Decimal"
            elems = [f'<Element Index="{_index_str(i, dims)}" Value="{v}"/>'
                     for i, v in enumerate(vals)]
        else:
            radix = _radix_for(mdt, def_radix)
            width = _ATOMIC[mdt][0]
            elems = [
                f'<Element Index="{_index_str(i, dims)}" '
                f'Value="{_decorated_value(mdt, v, width, radix)}"/>'
                for i, v in enumerate(vals)
            ]
        ra = f' Radix="{radix}"' if radix else ""
        return (f'<ArrayMember Name="{name}" DataType="{mdt}" '
                f'Dimensions="{dim_str}"{ra}>{"".join(elems)}</ArrayMember>')

    # ---- struct array member ---------------------------------------------- #
    if kind == "sarr":
        _kind, _mdt, dims, walk_elem, total, layout_ok = node
        if not layout_ok:
            return None
        dim_str = ",".join(str(d) for d in dims)
        elems = []
        for i in range(total):
            inner = _emit_decorated_inner(walk_elem(i))
            if inner is None:
                return None
            # OEM wraps each array-of-struct element's members in <Structure>.
            elems.append(
                f'<Element Index="{_index_str(i, dims)}"><Structure DataType="{mdt}">'
                f'{inner}</Structure></Element>'
            )
        return (f'<ArrayMember Name="{name}" DataType="{mdt}" '
                f'Dimensions="{dim_str}">{"".join(elems)}</ArrayMember>')

    # ---- nested struct/UDT (or STRING-shaped) member ----------------------- #
    inner = _emit_decorated_inner(node)
    if inner is None:
        return None
    return f'<StructureMember Name="{name}" DataType="{mdt}">{inner}</StructureMember>'


def _struct_stride(dt_name: str, layout_map: Dict, data_types_map: Dict,
                   _seen: frozenset = frozenset()) -> Optional[int]:
    """Per-element byte stride of a struct datatype.

    Uses the TagInfo Size if cached on the layout map (key "@size@<NAME>"); else
    falls back to max(member_offset + member_width) over the layout. ``_seen``
    guards the recursion against a (malformed) cyclic member graph: a type
    whose stride is already being computed resolves to None instead of
    recursing forever.
    """
    sz = layout_map.get("@size@" + dt_name.upper())
    if isinstance(sz, int) and sz > 0:
        return sz
    if dt_name.upper() in _seen:
        return None
    layout = _resolve_layout(dt_name, layout_map, data_types_map)
    if layout is None:
        return None
    span = 0
    for (_n, mdt, off, _bit, _hidden, dims, _r) in layout:
        if mdt in _ATOMIC:
            w = _ATOMIC[mdt][0]
        else:
            w = _struct_stride(mdt, layout_map, data_types_map,
                               _seen | {dt_name.upper()})
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
                            layout_map: Dict, data_types_map: Dict,
                            radix: Optional[str] = None) -> Optional[str]:
    """Layout-driven Decorated rendering (Step 6d). Returns inner XML or None.

    Falls back (returns None) for anything it cannot decode so the caller keeps
    today's behaviour. Handles: atomic scalar/array (delegated), and struct /
    array-of-struct using the TagInfo byte-offset map for full member fidelity.
    ``radix`` is the tag's declared Radix, threaded to the atomic delegation so a
    top-level Binary/Hex/ASCII array honours it (struct members carry their own).
    """
    if not layout_map:
        return None
    total, dim_parts = _dims_total(dimensions)

    # Atomic scalar/array: the existing path is already correct & byte-faithful.
    if dt_base in _ATOMIC:
        return render_decorated(dt_base, dimensions, image, data_types_map,
                                radix=radix)

    # Struct datatype must be present in the layout map.
    if dt_base.upper() not in layout_map:
        return None

    if total == 0:
        inner = _emit_decorated_inner(
            _walk_struct(dt_base, image, layout_map, data_types_map, 0))
        if inner is None:
            return None
        return f'<Structure DataType="{dt_base}">{inner}</Structure>'

    # Array of struct.
    stride = _struct_stride(dt_base, layout_map, data_types_map)
    if stride is None:
        return None
    dim_str = ",".join(str(d) for d in dim_parts)
    elems = []
    for i in range(total):
        sub = image[i * stride:(i + 1) * stride]
        inner = _emit_decorated_inner(
            _walk_struct(dt_base, sub, layout_map, data_types_map, 1))
        if inner is None:
            return None
        # OEM wraps each array-of-struct element's members in <Structure>.
        elems.append(
            f'<Element Index="{_index_str(i, dim_parts)}"><Structure DataType="{dt_base}">'
            f'{inner}</Structure></Element>'
        )
    return (f'<Array DataType="{dt_base}" Dimensions="{dim_str}">'
            f'{"".join(elems)}</Array>')
