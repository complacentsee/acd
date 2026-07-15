"""DataType domain: the <DataTypes> section of the exported L5X.

``DataTypeBuilder`` renders one datatype comps record — child Member records
on modern projects, or the V10..V21 short-header inline member layout carried
in the record's own 0x6E+ extended attributes — into the L5X <DataType>
element; ``MemberBuilder`` renders a single member row.
"""
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Union

from acd.generated.comps.member_descriptor import MemberDescriptor
from acd.generated.comps.rx_generic import RxGeneric
from acd.l5x.base import (
    L5xElement,
    L5xElementBuilder,
    _parse_rec_tolerant,
    _rxgeneric_plaintext_main,
    _xml_sane,
    external_access_enum,
    lang_description,
    own_description,
    project_lang_oid,
    radix_enum,
    render_custom_properties,
    short_own_description,
)
from acd.record.comps import CompsRecord


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
        if self._description is None:
            return base
        # A "" description is the foreign-only sentinel: the member has a
        # description in some non-export language, which the reference exports as
        # a literal empty <Description/> (minidom self-closes it).
        desc_xml = (f'<Description>\n<![CDATA[{_xml_sane(self._description)}]]>\n'
                    f'</Description>' if self._description
                    else '<Description></Description>')
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
    # Verbatim <CustomProperties> provider block (library raC_*/STR* UDTs only),
    # recovered from Comments.Dat; None for ordinary datatypes. Rendered as the
    # first child (before Description/Members), matching the reference order.
    _custom_properties: Union[str, None] = field(default=None)

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
        # CustomProperties is the first child (before Description), then Description.
        # A "" description is the foreign-only sentinel -> literal <Description/>.
        prefix = self._custom_properties or ""
        if self._description is not None:
            prefix += (f'<Description>\n<![CDATA[{_xml_sane(self._description)}]]>\n'
                       f'</Description>' if self._description
                       else '<Description></Description>')
        if not prefix:
            return base
        idx = base.index(">")
        return base[:idx + 1] + prefix + base[idx + 1:]


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
    # Export-schema major (see ExportL5x.project_flags.sw_major), passed down by
    # DataTypeBuilder. Below major 18 the reference emits no @ExternalAccess on
    # Members (rule A); 0 == underivable -> today's emission.
    _sw_major: int = field(default=0)

    def build(self) -> Member:
        if self._short_name is not None:
            return self._build_short()

        self._cur.execute(
            "SELECT comp_name, object_id, parent_id, record FROM comps WHERE object_id="
            + str(self._object_id)
        )
        results = self._cur.fetchall()

        name = results[0][0]
        # A source-protected member record's own ext-attr tail is encrypted, but
        # every field this builder needs comes from ``self.record`` (the member
        # descriptor blob, passed in already-decrypted by the datatype builder),
        # and the member-description key resolves from the plaintext main_record.
        # Fall back to a plain member only when even the main_record is unreadable.
        r = _parse_rec_tolerant(results[0][3])
        if r is None:
            return Member(name, name, "", 0, "Decimal", False, None, None, "Read/Write")

        extended_records: Dict[int, List[int]] = {}
        for extended_record in getattr(r, "extended_records", []):
            extended_records[extended_record.attribute_id] = extended_record.value

        md = MemberDescriptor.from_bytes(self.record)
        # A descriptor too short to hold the 0x74 word could never complete the
        # old fixed-offset reads either; raising preserves the caller's
        # skip-the-member behaviour (struct.error used to do the same).
        if md.legacy_access_word is None:
            raise ValueError("member descriptor truncated")
        dimension = md.dimension
        # A bogus dimension (e.g. 0x20000) appears in the 0x5C slot for some
        # non-array scalar members of predefined types; clamp implausible values
        # to 0 so we don't emit a garbage Dimension attribute. (BIT members
        # override dimension to 0 below regardless.)
        if dimension > 0x10000:
            dimension = 0
        radix = radix_enum(md.radix)
        data_type_id = md.data_type_id
        hidden = bool(md.hidden)
        # ExternalAccess is the single byte at 0xA0 of the member-descriptor
        # ext-record (0=Read/Write, 2=Read Only, 3=None), NOT the u32 at 0x74
        # (which is uniformly 1 and is not ExternalAccess). Fall back to the old
        # 0x74 enum path only when the record is too short to hold 0xA0.
        if md.external_access_byte is not None:
            external_access = external_access_enum(md.external_access_byte)
        else:
            external_access = external_access_enum(md.legacy_access_word)
        # Rule A: the reference omits @ExternalAccess on Members below schema
        # major 18 (0/10302 v17 Members carry it, corpus-wide).
        if 1 <= self._sw_major < 18:
            external_access = None

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
            target_key = md.target_key
            val_68 = md.host_ordinal
            # A BOOL member is a BIT overlay unless it is a real standalone BOOL
            # (0x6c == FFFFFFFF and 0x68 == 0x800).
            is_plain_bool = (target_key == 0xFFFFFFFF and val_68 == 0x800)
            if not is_plain_bool:
                # offset 0x5C holds a bit-offset into the host register, not an
                # array size — force dimension to 0 so _member_decorated_xml
                # treats this as a scalar rather than emitting many <Element>s.
                data_type = "BIT"
                dimension = 0
                bit_number = md.bit_number
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
                        target = self._offset60_to_name.get(md.offset)
                    else:
                        target = self._fallback_target

        # --- Description ---
        # The member's description is identified in the comments table by a
        # member_ref value extracted from bytes [14:18] of the comps record.
        # This value is non-zero for sub-elements (members) and zero for the
        # owning object's own description. Source-protected members work the same
        # way: comment_id/cip_type come from the plaintext main record and the
        # comment text is decrypted in the comments table, so the same key
        # resolves (the member_ref is unique per member, so a member with no
        # description simply finds no row -- no over-emission).
        description: Union[str, None] = None
        raw_comps = bytes(results[0][3])
        if len(raw_comps) >= 18:
            member_ref = struct.unpack_from("<I", raw_comps, 14)[0]
            if member_ref:
                _parent = (r.comment_id * 0x10000) + r.cip_type
                _lang_oid = project_lang_oid(self._cur)
                if _lang_oid:
                    # Language-enabled: pick the export-language row, else the
                    # legacy row, else the empty sentinel for a foreign-only
                    # member description (the unfiltered LIMIT 1 would otherwise
                    # emit a wrong-language row where the reference emits an empty
                    # <Description/>).
                    description = lang_description(
                        self._cur, _parent, member_ref, _lang_oid)
                else:
                    self._cur.execute(
                        "SELECT record_string FROM comments "
                        "WHERE parent=? AND member_ref=? LIMIT 1",
                        (_parent, member_ref),
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
            md = MemberDescriptor.from_bytes(self.record)
            # Same completeness gate as the long path: a descriptor ending
            # before the 0x74 word degrades (the old unpacks raised here too).
            if md.legacy_access_word is None:
                raise ValueError("member descriptor truncated")
            dimension = md.dimension
            radix = radix_enum(md.radix)
            data_type_id = md.data_type_id
            hidden = bool(md.hidden)
            # ExternalAccess = byte at 0xA0 (0=Read/Write, 2=Read Only, 3=None),
            # not the u32 at 0x74. Fall back to 0x74 only for short records.
            if md.external_access_byte is not None:
                external_access = external_access_enum(md.external_access_byte)
            else:
                external_access = external_access_enum(md.legacy_access_word)
            # Rule A: the reference omits @ExternalAccess on Members below schema
            # major 18 (0/10302 v17 Members carry it, corpus-wide).
            if 1 <= self._sw_major < 18:
                external_access = None

            self._cur.execute(
                "SELECT comp_name FROM comps WHERE object_id=" + str(data_type_id)
            )
            dt_row = self._cur.fetchone()
            data_type = dt_row[0] if dt_row else ""

            target: Union[str, None] = None
            bit_number: Union[int, None] = None
            if data_type == "BOOL":
                # V10..V21 BIT rule (validated 5735/5735 on a V10 project): a BOOL
                # member is a BIT alias UNLESS 0x68 == 0x800 (a real standalone
                # BOOL). The bit index is 0x64; the backing field is the
                # non-BIT member whose byte range covers 0x6c (or 0x60 when
                # 0x6c == 0xFFFFFFFF) -> resolved via the byte-range
                # offset60_to_name map (target+bit 2832/2832 correct).
                val_68 = md.host_ordinal
                if val_68 != 0x800:
                    data_type = "BIT"
                    dimension = 0
                    bit_number = md.bit_number
                    target_key = md.target_key
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
                        target = self._offset60_to_name.get(md.offset)
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


# Byte size of each atomic backing type, used when walking a predefined type's
# member descriptors to compute offsets.
_BACKING_SIZE = {"SINT": 1, "USINT": 1, "BYTE": 1, "BOOL": 1,
                 "INT": 2, "UINT": 2, "WORD": 2,
                 "DINT": 4, "UDINT": 4, "DWORD": 4,
                 "LINT": 8, "ULINT": 8, "LWORD": 8}


@dataclass
class DataTypeBuilder(L5xElementBuilder):
    # V10..V21 short-header datatypes carry their members inline (extended
    # records 0x6E+) instead of as child Comps records, and the OEM L5X emits
    # the full lean set (User + ProductDefined + IO). Set True by the
    # short-header ControllerBuilder path; defaults False -> identical V24+
    # behaviour.
    _short_header: bool = field(default=False)

    def build(self) -> DataType:
        # Export-schema major, passed to each MemberBuilder for the rule-A
        # @ExternalAccess suppression (see ExportL5x.project_flags.sw_major).
        try:
            self._cur.execute("SELECT sw_major FROM project_flags")
            _row = self._cur.fetchone()
            _sw_major = (_row[0] if _row else 0) or 0
        except Exception:
            _sw_major = 0

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
        except Exception:
            # Source-protected datatype: the ext-attr tail (member descriptors at
            # 0x6E.., the member_count at 0x64, class flags at 0x67/0x69/0x6C) is
            # AES-encrypted, so the kaitai parser throws. Recover the WHOLE attr
            # table by decrypting the untruncated payload, and take comment_id /
            # cip_type from the plaintext main_record, so members (and their radix /
            # data type / dimensions) are still built. Returns the no-members stub
            # only when the record is too short or no key validates.
            r = _rxgeneric_plaintext_main(results[0][3])
            if r is not None:
                extended_records = CompsRecord.record_attrs(
                    self._cur, self._object_id, self._short_header
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
            # must take precedence (verified 142/142 vs OEM on a V10 project). The long
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

            # Real datatype members are record_type 256. A re-saved long-header
            # project can inject phantom record_type 512 records (stray rung-logic
            # operand fragments) into a member-collection; left in, they shift the
            # member<->descriptor (BitNumber/DataType/Radix) alignment by one. Filter
            # them out -- short-header collections carry no such records.
            self._cur.execute(
                "SELECT comp_name, object_id, parent_id, seq_number, record FROM comps "
                f"WHERE parent_id={member_collection_id} AND record_type=256 "
                "ORDER BY seq_number"
            )
            children_results = self._cur.fetchall()

            # Build offset60→name map so BIT members can resolve their Target name.
            # Each member's extended record stores the byte offset of that member's data
            # within the UDT at [0x60]; BIT members reference their backing field's
            # offset via [0x6c].  Non-BIT members have [0x6c]=0xFFFFFFFF and 0x68=0x800.
            # Only include non-BIT members (0x68==0x800) so that BIT members sharing the
            # same 0x60 value as their backing field do not overwrite the backing entry.
            offset60_to_name: Dict[int, str] = {}
            for idx2, child2 in enumerate(children_results):
                key2 = 0x6E + idx2
                if key2 not in extended_records:
                    break
                md2 = MemberDescriptor.from_bytes(bytes(extended_records[key2]))
                # target_key present (descriptor reaches 0x70) is the same
                # completeness gate the old len(rec2) >= 0x70 check applied.
                if md2.target_key is not None:
                    if md2.target_key == 0xFFFFFFFF and md2.host_ordinal == 0x800:
                        val_60 = md2.offset
                        offset60_to_name[val_60] = child2[0]
                        # A BIT member's 0x6c is a BYTE offset that can land in
                        # the high byte of a multi-byte backing word (e.g. an INT
                        # at 0x0e covering bytes 0x0e..0x0f). Map every byte the
                        # backing field covers to its name so Pattern-1 lookups by
                        # the exact byte resolve. setdefault keeps the first (the
                        # word's own 0x60) authoritative for collisions.
                        self._cur.execute(
                            "SELECT comp_name FROM comps WHERE object_id="
                            + str(md2.data_type_id)
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
                # Update last_hidden_backing when we see a hidden member
                # (hidden is None when the descriptor ends before 0x74).
                if MemberDescriptor.from_bytes(bytes(extended_records[key])).hidden:
                    last_hidden_backing = child[0]
                try:
                    children.append(
                        MemberBuilder(
                            self._cur, child[1], bytes(extended_records[key]),
                            offset60_to_name,
                            last_hidden_backing,
                            _owner_cls=class_type,
                            _members_by_index=members_by_index,
                            _sw_major=_sw_major,
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
                # byte 0; the grammar clamps the field to its 0..0x53 span (the
                # radix u32 begins at 0x54) and _decode_utf16z stops at the
                # first NUL, so shorter names are unaffected.
                _nm = MemberDescriptor.from_bytes(blob).name_raw
                mname = _decode_utf16z(_nm) if _nm is not None else ""
                short_recs.append((mname, blob))

            # The counted extended_records stop before the record's FINAL
            # attribute; the last member is carried in the trailing
            # last_attribute_record (absent on the plaintext-main SP view).
            # Recover it so datatypes don't lose their last member.
            if len(short_recs) < member_count:
                _last = getattr(r, "last_attribute_record", None)
                tail_blob = getattr(_last, "value", None) if _last is not None else None
                if tail_blob:
                    tail_blob = bytes(tail_blob)
                    # Same name-field boundary as the inline path (0x54).
                    tail_name = _decode_utf16z(tail_blob[0:0x54])
                    if tail_name:
                        short_recs.append((tail_name, tail_blob))

            # offset60 -> backing-field name map (non-BIT members only), so BIT
            # members can resolve their Target, mirroring the long path. A BIT
            # member's 0x6c is the BYTE offset of the bit it occupies; for a
            # multi-byte backing field (INT/DINT) that byte offset can land
            # past the backing field's own 0x60 (e.g. the high byte of an INT),
            # so we map EVERY byte the backing field covers to its name (sizes
            # below). _build_short still tries the exact 0x60 first.
            offset60_to_name = {}
            for mname, blob in short_recs:
                md_b = MemberDescriptor.from_bytes(blob)
                # Same completeness gate as the old len(blob) < 0x78 skip.
                if md_b.legacy_access_word is None:
                    continue
                self._cur.execute(
                    "SELECT comp_name FROM comps WHERE object_id="
                    + str(md_b.data_type_id)
                )
                _row = self._cur.fetchone()
                base = _row[0] if _row else ""
                # A BIT alias (BOOL with 0x68 != 0x800) is NOT a backing field;
                # every other member (atomic scalar, or a real BOOL with
                # 0x68==0x800) backs the bits that overlay its byte range.
                if base == "BOOL" and md_b.host_ordinal != 0x800:
                    continue
                val_60 = md_b.offset
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
                if MemberDescriptor.from_bytes(blob).hidden:
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
                            _sw_major=_sw_major,
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
        if self._short_header:
            # sub_record_length == this datatype's cip_type (a datatype is 0x6c;
            # the colliding tag is 0x68) selects the right row unambiguously --
            # no uniqueness gate needed.
            description = short_own_description(self._cur, r.comment_id, r.cip_type)
        else:
            description = own_description(self._cur, (r.comment_id * 0x10000) + r.cip_type)

        # A DataType (raC_*/STR* library UDT or an ACM-managed type) carries a
        # verbatim <CustomProperties> provider block captured into the
        # custom_properties table, keyed by this datatype's own comment parent
        # (comment_id<<16 | cip_type) with owner_ref 0.
        custom_props = None
        try:
            if getattr(r, "cip_type", None) is not None:
                cp_rows = self._cur.execute(
                    "SELECT provider_id, ext, blob FROM custom_properties "
                    "WHERE parent=? AND owner_ref=0 AND rung_content=0",
                    ((r.comment_id * 0x10000) + r.cip_type,)).fetchall()
                custom_props = render_custom_properties(cp_rows)
        except Exception:
            custom_props = None

        dt = DataType(name, name, string_family, class_type, children, description,
                      _custom_properties=custom_props)
        dt._emit_predefined = self._short_header
        return dt
