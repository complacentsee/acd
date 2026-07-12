"""Alias (AliasFor) resolution for the L5X exporter's TagBuilder.

``TagAliasResolver`` is the mixin carrying TagBuilder's alias-detection and
alias-target decoding methods: the short-header ``@hex@`` blob, the V24+
long-header module-I/O and internal-tag forms (layout-driven member walk),
and the source-protected fallback. Split out of elements.py; the decode
logic is unchanged.

Host-class contract: the mixin reads ``self._cur`` / ``self._object_id`` /
``self._short_header`` / ``self._taginfo_layout`` and calls
``self._parse_rec_tolerant``.
"""
import re
import struct
from typing import Dict, Union

from acd.generated.comps.rx_generic import RxGeneric
from acd.record.comps import CompsRecord, _SP_MARKER


# Bit-width of a base symbol's element type, used to decode an internal alias's
# bit-offset (u32 @ record 0x26) into an array index + member bit. Structured
# legacy types (TIMER/COUNTER/CONTROL = 3 DINTs) are 96 bits; only base element
# types whose width is known appear here. A base whose element type is absent
# (e.g. a module connection image) is left undecoded (no AliasFor emitted).
_ALIAS_ELEM_BITS: Dict[str, int] = {
    "BOOL": 1, "BIT": 1, "SINT": 8, "USINT": 8, "BYTE": 8,
    "INT": 16, "UINT": 16, "WORD": 16,
    "DINT": 32, "UDINT": 32, "DWORD": 32, "REAL": 32,
    "LINT": 64, "ULINT": 64, "LWORD": 64, "LREAL": 64,
    "TIMER": 96, "COUNTER": 96, "CONTROL": 96,
}


class TagAliasResolver:

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
            # A genuine Base tag's data_table_instance points at its own
            # ``$<hex>$`` RxData value backing (the same discriminator
            # _long_header_alias_like uses); such a tag is NOT an alias even
            # when a stale ``@hex@`` blob survives in its record. Reject only
            # on a positive ``$`` match so a parse failure keeps the blob path.
            try:
                r = self._parse_rec_tolerant(raw_rec)
                dti = r.main_record.data_table_instance if r is not None else None
                if dti:
                    drow = self._cur.execute(
                        "SELECT comp_name FROM comps WHERE object_id=" + str(dti)
                    ).fetchone()
                    if drow and drow[0] and drow[0].startswith("$"):
                        return None
            except Exception:
                pass
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

    def _alias_elem_width(self, dtname: "Union[str, None]") -> "Union[int, None]":
        """Bit width of an alias base/member element type, or None if unknown.

        Atomic/legacy-struct types come from the static table; a user/module
        datatype's width is its TagInfo @size@ (bytes) * 8.
        """
        if dtname is None:
            return None
        u = dtname.upper()
        if u in _ALIAS_ELEM_BITS:
            return _ALIAS_ELEM_BITS[u]
        sz = self._taginfo_layout.get("@size@" + u)
        return sz * 8 if sz else None

    def _alias_walk_members(self, dtname: str, target_bit: int,
                            alias_is_bool: bool, prefix: str = "",
                            alias_dt: "Union[str, None]" = None
                            ) -> "Union[str, None]":
        """Return the member-path string locating target_bit inside dtname, or
        None. Walks the TagInfo member layout: a BOOL alias first matches an
        explicit named bit-member at the exact bit (so AxisStatus.1 wins over a
        wider word at the same offset), then the containing member (array element,
        atomic word + .bit for a BOOL, whole member for an element-aligned
        non-BOOL, or recursion into a nested struct). A BOOL alias onto a
        BOOL-element array element is the whole element [idx] (1-bit element ->
        no .bit). alias_dt is the alias tag's own datatype: when it equals a
        member's datatype at that member's start, the walk stops at the whole
        member (so e.g. a TIMER-typed alias resolves to the .PRE/.ACC member
        rather than a raw bit)."""
        mem = self._taginfo_layout.get((dtname or "").upper())
        if mem is None:
            return None
        adu = (alias_dt or "").upper()
        if alias_is_bool:
            for (mname, mdt, off, bit, hidden, dims) in mem:
                if dims:
                    continue
                if (bit is not None and (off * 8 + bit) == target_bit
                        and mdt.upper() in ("BOOL", "BIT")):
                    return prefix + mname
        for (mname, mdt, off, bit, hidden, dims) in mem:
            mbits = self._alias_elem_width(mdt)
            base_bit = off * 8 + (bit or 0)
            if dims:
                if mbits is None:
                    continue
                total = mbits * (dims[0] if dims else 1)
                if base_bit <= target_bit < base_bit + total:
                    rel = target_bit - base_bit
                    idx = rel // mbits
                    inner = rel % mbits
                    seg = "%s%s[%d]" % (prefix, mname, idx)
                    # BOOL-element array: alias onto element idx is the whole
                    # element [idx] (1-bit element -> no .bit suffix).
                    if mdt.upper() in ("BOOL", "BIT"):
                        return seg
                    if (alias_is_bool and inner != 0) or (
                            mdt.upper() in _ALIAS_ELEM_BITS
                            and _ALIAS_ELEM_BITS.get(mdt.upper(), 0) > 1
                            and alias_is_bool):
                        return seg + ".%d" % inner
                    if not alias_is_bool and inner == 0:
                        return seg
                    if mdt.upper() not in _ALIAS_ELEM_BITS:
                        # whole-member stop: alias dt == member dt at element start
                        if inner == 0 and adu and adu == mdt.upper():
                            return seg
                        sub = self._alias_walk_members(mdt, inner, alias_is_bool,
                                                       "", alias_dt)
                        if sub is not None:
                            return seg + "." + sub
                    if alias_is_bool:
                        return seg + ".%d" % inner
                    return None
            else:
                if mbits is None:
                    continue
                if bit is not None:
                    if base_bit == target_bit and alias_is_bool:
                        return prefix + mname
                    continue
                if base_bit <= target_bit < base_bit + mbits:
                    if mdt.upper() in _ALIAS_ELEM_BITS:
                        inner = target_bit - base_bit
                        if alias_is_bool:
                            return (prefix + mname) if inner == 0 and mbits == 1 \
                                else (prefix + mname + ".%d" % inner)
                        if inner == 0:
                            return prefix + mname
                        return None
                    # non-atomic struct member: whole-member stop if alias dt matches
                    inner = target_bit - base_bit
                    if inner == 0 and adu and adu == mdt.upper():
                        return prefix + mname
                    sub = self._alias_walk_members(mdt, inner, alias_is_bool,
                                                   "", alias_dt)
                    if sub is not None:
                        return prefix + mname + "." + sub
                    return None
        return None

    def _layout_alias_for(self, raw_rec: bytes) -> "Union[str, None]":
        """Layout-driven @AliasFor for a long-header alias tag, byte-exact.

        Generalises the module-I/O and internal resolvers below: the bit offset
        at raw_rec[0x26] is mapped to a member PATH inside the base symbol by
        walking the base datatype's TagInfo member layout. Covers module-I/O
        channel members (Local:2:I.Ch0Data), internal UDT members
        (SomeUDT.Faults.Transducer), array-of-struct elements, nested structs /
        bit members, and whole-element aliases. Fail-closed: returns None on any
        parse failure, a source-protected/undecodable base, or a walk that does
        not land on a real member, so the caller keeps the tag Base rather than
        emit a wrong (schema-invalid) Alias.
        """
        try:
            r = self._parse_rec_tolerant(raw_rec)
            if r is None or r.cip_type not in (0x6B, 0x68):
                return None
            dti = r.main_record.data_table_instance
            if not dti or len(raw_rec) < 0x2A:
                return None
            row = self._cur.execute(
                "SELECT comp_name, record FROM comps WHERE object_id=" + str(dti)
            ).fetchone()
            if not row or not row[0]:
                return None
            base = row[0]
            if base.startswith("$"):
                return None
            bitoff = struct.unpack_from("<I", raw_rec, 0x26)[0]
            alias_dt = None
            if r.main_record.data_type:
                ar = self._cur.execute(
                    "SELECT comp_name FROM comps WHERE object_id="
                    + str(r.main_record.data_type)
                ).fetchone()
                alias_dt = ar[0] if ar else None
            alias_is_bool = (alias_dt or "").upper() in ("BOOL", "BIT")
            # Base datatype + array-ness, tolerant of source-protected base records
            # (the plaintext RxGeneric parser throws on an encrypted tail).
            base_dt = None
            base_is_array = False
            if row[1] is not None:
                try:
                    br = self._parse_rec_tolerant(bytes(row[1]))
                except Exception:
                    br = None
                if br is not None and getattr(br, "main_record", None) is not None:
                    if getattr(br.main_record, "data_type", None):
                        bdr = self._cur.execute(
                            "SELECT comp_name FROM comps WHERE object_id="
                            + str(br.main_record.data_type)
                        ).fetchone()
                        base_dt = bdr[0] if bdr else None
                    base_is_array = bool(getattr(br.main_record, "dimension_1", 0))
            if base_dt is None:
                return None
            bdu = base_dt.upper()
            # A base datatype WITH a TagInfo member layout (TIMER/COUNTER/CONTROL and
            # module-image AB:* types) resolves through the member walker to the OEM
            # named member; the flat numeric-bit fallback below is only for atomic
            # bases that have no layout.
            has_layout = self._taginfo_layout.get(bdu) is not None

            if base.startswith("&"):
                m = re.match(r"^&([0-9a-fA-F]+)(:.*)$", base)
                if not m:
                    return None
                mr = self._cur.execute(
                    "SELECT comp_name FROM comps WHERE object_id="
                    + str(int(m.group(1), 16))
                ).fetchone()
                if not mr or not mr[0]:
                    return None
                full = mr[0] + m.group(2)
                if bdu in _ALIAS_ELEM_BITS and not has_layout:
                    ms = re.match(r"^(.+):(\d+):([IO])$", full)
                    if not ms:
                        return None
                    slot = int(ms.group(2))
                    width = _ALIAS_ELEM_BITS[bdu]
                    bit = bitoff - (64 + slot * 8)
                    if not (0 <= bit < width):
                        return None
                    if (not alias_is_bool and (alias_dt or "").upper() == bdu
                            and bit == 0):
                        return full
                    if not alias_is_bool:
                        return None
                    return "%s.%d" % (full, bit)
                if bitoff == 0 and (alias_dt or "").upper() == bdu:
                    return full
                path = self._alias_walk_members(base_dt, bitoff, alias_is_bool,
                                                "", alias_dt)
                return (full + "." + path) if path else None

            # internal tag base (not a module &hex: element)
            if alias_dt and alias_dt == base_dt and bitoff == 0 and not base_is_array:
                return base
            if bdu in _ALIAS_ELEM_BITS and not has_layout:
                w = _ALIAS_ELEM_BITS[bdu]
                idx = bitoff // w
                bit = bitoff % w
                if alias_is_bool:
                    if base_is_array:
                        # BOOL-element array: whole element [idx], no .bit.
                        if w == 1:
                            return "%s[%d]" % (base, idx)
                        return "%s[%d].%d" % (base, idx, bit)
                    # Scalar 1-bit BOOL base: the alias is the whole base (a nonzero
                    # bitoff here is an alias-to-alias artifact, not a real bit index).
                    if w == 1:
                        return base
                    return ("%s.%d" % (base, bit)) if idx == 0 \
                        else ("%s[%d].%d" % (base, idx, bit))
                if base_is_array:
                    return "%s[%d]" % (base, idx)
                return base if idx == 0 else "%s[%d]" % (base, idx)
            if base_is_array:
                stride = self._taginfo_layout.get("@size@" + bdu)
                if not stride:
                    return None
                sbits = stride * 8
                idx = bitoff // sbits
                inner = bitoff % sbits
                seg = "%s[%d]" % (base, idx)
                if inner == 0 and (alias_dt or "").upper() == bdu:
                    return seg
                sub = self._alias_walk_members(base_dt, inner, alias_is_bool,
                                               "", alias_dt)
                return (seg + "." + sub) if sub else None
            path = self._alias_walk_members(base_dt, bitoff, alias_is_bool,
                                            "", alias_dt)
            return (base + "." + path) if path else None
        except Exception:
            return None

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
            bdname = None
            try:
                br = RxGeneric.from_bytes(bytes(row[1]))
                # The ext-attr tail parses lazily; materialise it so an
                # unparseable base record still bails out (as before).
                br.extended_records
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

            bit_off = struct.unpack_from("<I", raw_rec, 0x26)[0]

            # Whole-tag alias: the alias mirrors the entire base scalar tag -- its
            # datatype equals the base's and it points at the base's start -- so the
            # target is the bare base symbol with no subscript or member (e.g. a
            # motion axis/group alias onto another axis/group). This holds for any
            # base type, so resolve it before the atomic-only element-width path.
            if (alias_dt_name and bdname and alias_dt_name == bdname
                    and bit_off == 0 and not base_is_array):
                return base

            if base_elem_bits is None:
                return None

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

    def _resolve_comp_oid(self, oid: int, depth: int = 0) -> Union[str, None]:
        """Resolve a comps object id to its export name, following the
        ``&<parentHex><suffix>`` module-reference convention recursively."""
        if depth > 6:
            return None
        row = self._cur.execute(
            "SELECT comp_name FROM comps WHERE object_id=?", (oid,)).fetchone()
        if not row or row[0] is None:
            return None
        nm = row[0]
        m = re.match(r"^&([0-9a-fA-F]+)(.*)$", nm)
        if m:
            parent = self._resolve_comp_oid(int(m.group(1), 16), depth + 1)
            return (parent + m.group(2)) if parent is not None else None
        return nm

    def _sp_alias_for(self) -> Union[str, None]:
        """Recover an alias target from a source-protected tag record.

        A protected tag's live alias data sits in the AES-encrypted main record, so
        the offset-based resolvers above cannot read it (the tag falls to Base). The
        decrypted attribute table still carries ext-attr 0x65: a UTF-16 template of
        the form ``@<hex>@.@<hex>@<member>`` where each ``@<hex>@`` token is the
        object id of a comps component. Substitute each token with the component's
        resolved comp_name to rebuild the AliasFor string.

        Gated on the record actually being source-protected: a NON-protected record
        can also carry a 0x65 template, but a stale one that disagrees with the live
        (offset-decoded) target, so it must not be trusted there.
        """
        # Reads the raw comps record body: the SP-marker gate below needs the
        # body bytes, not just the attr dict.
        row = self._cur.execute(
            "SELECT record FROM comps WHERE object_id=?",
            (self._object_id,)).fetchone()
        if not row or not row[0]:
            return None
        rec = bytes(row[0])
        if rec.find(_SP_MARKER, 74) < 0:
            return None
        attrs = CompsRecord.read_value_attrs(rec, self._short_header, full=True,
                                             body_mode=True)
        raw = attrs.get(0x65)
        if not raw or len(raw) < 4:
            return None
        s = raw.decode("utf-16-le", errors="replace").split("\x00")[0]
        at_re = re.compile(r"@([0-9a-fA-F]+)@")
        if not at_re.search(s):
            return None
        out = at_re.sub(
            lambda m: (self._resolve_comp_oid(int(m.group(1), 16)) or m.group(0)), s)
        # Only accept a fully-resolved template (every token resolved).
        return out if "@" not in out else None
