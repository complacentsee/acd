"""Base primitives shared by every L5X element/builder module.

``L5xElement`` is the generic to_xml() dataclass all exported elements extend;
``L5xElementBuilder`` carries the (cursor, object_id) pair every builder needs.
``_xml_sane`` strips the C0 control characters XML 1.0 forbids.
"""
import html
import locale as _locale
import re
import struct
from dataclasses import dataclass
from sqlite3 import Cursor
from typing import List, Union


def _desc_oid_for_langid(langid: int) -> int:
    """Comments.Dat description object_id for a Windows LANGID: the packed
    ((sublang<<8 | primarylang) << 8) | kind, kind 0x01 = Description."""
    return ((((langid >> 10) << 8) | (langid & 0x3FF)) << 8) | 1


# Every valid Windows-locale description object_id, derived from the stdlib
# locale table (no hardcoded numeric list). Used to recognise a "foreign-only"
# description (a row that exists in some language but not the export language),
# which the reference exports as a literal empty <Description/>.
_LANG_DESC_OIDS = frozenset(
    _desc_oid_for_langid(_lid) for _lid in _locale.windows_locale)
_LANG_BY_LOCALE = {v.replace("_", "-"): k for k, v in _locale.windows_locale.items()}


def language_desc_oid(export_language: str) -> int:
    """Description object_id for an export language name ("en-US"), or 0 if the
    name is unknown. en-US -> 0x10901, de-DE -> 0x10701."""
    langid = _LANG_BY_LOCALE.get(export_language)
    return _desc_oid_for_langid(langid) if langid is not None else 0

from acd.generated.comps.rx_generic import RxGeneric
from acd.record.comps import CompsRecord


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
    "child_programs": "ChildPrograms",
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
                        # OEM omits an empty <ScheduledPrograms> entirely (the
                        # Task self-closes); every other empty list section (e.g.
                        # <Tags/>) IS emitted, so scope the suppression to
                        # scheduled_programs only.
                        if attribute == "scheduled_programs" and not new_child_list:
                            continue
                        # A list section is normally a bare wrapper, but some
                        # carry their own attributes (e.g. the safety signature on
                        # AddOnInstructionDefinitions); _section_attrs maps the field
                        # name to a pre-rendered attribute string.
                        _sa = getattr(self, "_section_attrs", {}).get(attribute, "")
                        child_list.append(
                            f'<{section_name}{_sa}>{"".join(new_child_list)}</{section_name}>'
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


def safety_signature_row(cur: Cursor, rec: bytes):
    """The (signature, timestamp) row of a component's 2-key GSS join, or None.

    A signed safety component joins the safety_signatures side table by its
    object type (u16 @ record 0x0A) and comment id (u32 @ 0x0C). Returns the
    raw row; callers keep their own truthiness gates.
    """
    return cur.execute(
        "SELECT signature, timestamp FROM safety_signatures "
        "WHERE otype=? AND cid=?",
        (struct.unpack_from("<H", rec, 0x0A)[0],
         struct.unpack_from("<I", rec, 0x0C)[0])).fetchone()


def connection_signature_row(cur: Cursor, rec: bytes, body_offset: int):
    """The (signature, timestamp) row of a record's 3-key GSS join, or None.

    Names collide across the 2-key safety_signatures table, so per-object
    signatures join the 3-key connection_signatures side table (which holds
    every GSS signature) by the (otype u16 @ body+10, cid u32 @ body+12,
    disc u32 @ body+16) triple embedded in the decrypted comps.record body.
    Returns the raw row; callers keep their own truthiness gates.
    """
    return cur.execute(
        "SELECT signature, timestamp FROM connection_signatures "
        "WHERE otype=? AND cid=? AND disc=?",
        (struct.unpack_from("<H", rec, body_offset + 10)[0],
         struct.unpack_from("<I", rec, body_offset + 12)[0],
         struct.unpack_from("<I", rec, body_offset + 16)[0])).fetchone()


def project_lang_oid(cur: Cursor) -> int:
    """The export-language description object_id for a language-enabled project,
    else 0 (a legacy, single-language project). See ExportL5x.project_lang."""
    try:
        row = cur.execute("SELECT lang_oid FROM project_lang").fetchone()
        return (row[0] if row else 0) or 0
    except Exception:
        return 0


def lang_description(cur: Cursor, parent: int, member_ref: int, lang_oid: int,
                     exclude_revnote: bool = False) -> Union[str, None]:
    """Language-aware description for a (parent, member_ref) key in a
    language-enabled project. Returns, in priority order:
      - the export-language row's text;
      - the legacy object_id==1 row's text;
      - '' (the empty sentinel) when a row exists whose object_id is a VALID
        Windows-locale description id (a foreign-only description -> the
        reference emits a literal empty <Description/>);
      - None (no Description element).
    The valid-language gate (never a bare object_id&255==1) keeps stray
    operand/scratch rows whose token ids merely end in 0x01 from triggering the
    empty sentinel."""
    where = ("FROM comments WHERE parent=? AND member_ref=? AND rung_content=0"
             + (" AND tag_reference!='__REVISION_NOTE__'"
                if exclude_revnote else ""))
    key = (parent, member_ref)
    row = cur.execute(
        "SELECT record_string " + where + " AND object_id=? LIMIT 1",
        key + (lang_oid,)).fetchone()
    if row and row[0]:
        return row[0]
    row = cur.execute(
        "SELECT record_string " + where + " AND object_id=1 LIMIT 1",
        key).fetchone()
    if row and row[0]:
        return row[0]
    for (oid,) in cur.execute("SELECT object_id " + where, key).fetchall():
        if oid in _LANG_DESC_OIDS:
            return ""
    return None


def own_description(cur: Cursor, comment_parent: int) -> Union[str, None]:
    """A component's own Description (long-header form), or None.

    The own-description row lives at parent == comment_id*0x10000 + cip_type
    with member_ref 0 and carries object_id == 1; rows sharing the key with a
    nonzero object_id are scratch/extended-help values whose record_string
    would leak in as a fabricated Description, so they are excluded. An AOI's
    UDI_HISTORY row (RevisionNote) shares the whole key with object_id 1 too;
    it is stored under the __REVISION_NOTE__ tag_reference sentinel and is
    fetched separately, so it must not shadow the real description row here.

    In a language-enabled project (project_lang set) the own-description row is
    keyed by the export language's object_id, not 1, so route through the
    language-aware picker (which also emits the empty <Description/> sentinel for
    a foreign-only description).
    """
    lang_oid = project_lang_oid(cur)
    if lang_oid:
        return lang_description(cur, comment_parent, 0, lang_oid,
                                exclude_revnote=True)
    cur.execute(
        "SELECT record_string FROM comments "
        "WHERE parent=? AND member_ref=0 AND object_id=1 "
        "AND tag_reference!='__REVISION_NOTE__' LIMIT 1",
        (comment_parent,),
    )
    row = cur.fetchone()
    return row[0] if row and row[0] else None


_CP_EXT_RE = re.compile(r"^(.*?)(\d+)$")


def _cp_ext_sortkey(ext: str):
    """Natural sort key for a <Provider> Ext string: split a trailing run of
    digits so 'Origin_0' < 'Origin_1' and pure-numeric '0' < '1' both order
    numerically (Comments.Dat storage order is not reliable). Degenerates to
    the plain numeric order for pure-digit Ext values."""
    s = str(ext)
    m = _CP_EXT_RE.match(s)
    if m:
        return (m.group(1), int(m.group(2)))
    return (s, -1)


def render_custom_properties(rows) -> Union[str, None]:
    """Render an ACM/library <CustomProperties> block from custom_properties
    rows [(provider_id, ext, blob), ...]. Providers are ordered by the natural
    Ext key; each blob is emitted VERBATIM (already the exact inner XML, never
    re-escaped or CDATA-wrapped). None when there are no rows.

    Exact-duplicate rows are dropped: Comments.Dat stores some provider records
    twice, so a raw join can return each provider two or more times; the export
    carries exactly one per (provider_id, ext, blob)."""
    if not rows:
        return None
    _seen = set()
    _uniq = []
    for _t in rows:
        _k = (_t[0], _t[1], _t[2])
        if _k in _seen:
            continue
        _seen.add(_k)
        _uniq.append(_t)
    ordered = sorted(_uniq, key=lambda t: _cp_ext_sortkey(t[1]))
    inner = "\n".join(
        f'<Provider ID="{pid}" Ext="{ext}">\n{blob}\n</Provider>'
        for pid, ext, blob in ordered)
    return f'<CustomProperties>\n{inner}\n</CustomProperties>'


def custom_properties_by_parent(cur: Cursor, parent: int) -> Union[str, None]:
    """Scope-level <CustomProperties> (owner_ref == 0) for an owner keyed by its
    own comment parent (comment_id<<16 | cip_type): controller-scope Tag,
    Program, Controller root, DataType, AOI definition. None when absent."""
    rows = cur.execute(
        "SELECT provider_id, ext, blob FROM custom_properties "
        "WHERE parent=? AND owner_ref=0 AND rung_content=0", (parent,)).fetchall()
    return render_custom_properties(rows)


def custom_properties_by_scope_owner(cur: Cursor, parent: int,
                                     owner_ref: int) -> Union[str, None]:
    """Member-level <CustomProperties> (a program-scope Tag or a Routine's own
    block) keyed by BOTH the containing program's scope parent
    (program_comment_id<<16 | 0x68) and the owning comp's own key
    (record[14:18]). owner_ref alone is only a program-scoped ordinal and is not
    globally unique -- a bare-owner match cross-attributes another program's
    block -- so the scope parent is required. Rung-level rows (rung_content != 0)
    are excluded. None when owner_ref is 0 or absent."""
    if not owner_ref:
        return None
    rows = cur.execute(
        "SELECT provider_id, ext, blob FROM custom_properties "
        "WHERE parent=? AND owner_ref=? AND rung_content=0",
        (parent, owner_ref)).fetchall()
    return render_custom_properties(rows)


# A DataExchangeId is stored as a plain ASCII GUID string in Comments.Dat under
# the comment kind 0x2D (object_id 45 in the comments table); the record_string
# is already the exact "{...}" brace/upper/dash form the reference emits.
def own_data_exchange_id(cur: Cursor, parent: int) -> Union[str, None]:
    """The @DataExchangeId GUID for a scope-level owner (controller-scope Tag,
    Module, Controller root) keyed by its own comment parent
    (comment_id<<16 | cip_type), owner_ref 0. None when absent."""
    row = cur.execute(
        "SELECT record_string FROM comments "
        "WHERE parent=? AND member_ref=0 AND object_id=45 "
        "AND record_string GLOB '{*-*-*-*-*}' LIMIT 1", (parent,)).fetchone()
    return row[0] if row and row[0] else None


def scope_owner_data_exchange_id(cur: Cursor, parent: int,
                                 owner_ref: int) -> Union[str, None]:
    """The @DataExchangeId GUID for a program-scope Tag, keyed by the program's
    scope parent (program_comment_id<<16 | 0x68) and the tag's own key
    (record[14:18]). None when owner_ref is 0 or absent."""
    if not owner_ref:
        return None
    row = cur.execute(
        "SELECT record_string FROM comments "
        "WHERE parent=? AND owner_ref=? AND object_id=45 "
        "AND record_string GLOB '{*-*-*-*-*}' LIMIT 1",
        (parent, owner_ref)).fetchone()
    return row[0] if row and row[0] else None


_AT_TOKEN_RE = re.compile(r"@([0-9a-fA-F]+)@")


def resolve_at_tokens(cur: Cursor, s: str) -> Union[str, None]:
    """Resolve every ``@<hex>@`` comps-object token in `s`, or None.

    Each ``@<hex>@`` is a comps object_id whose comp_name replaces the token in
    place; a comp_name that is itself of the form ``&<parentHex><suffix>`` is a
    further reference and is followed recursively (the module-reference
    convention). Text outside the tokens passes through verbatim, so a stored
    ``@6b2bd9d8@.2`` renders as ``SomeTag.2``.

    FAIL-CLOSED: returns None unless EVERY token resolves -- a half-resolved
    string still carries an '@' and would name the wrong object.
    """
    def _resolve(oid: int, depth: int = 0) -> "Union[str, None]":
        if depth > 6:
            return None
        row = cur.execute(
            "SELECT comp_name FROM comps WHERE object_id=?",
            (oid,)).fetchone()
        if not row or row[0] is None:
            return None
        m = re.match(r"^&([0-9a-fA-F]+)(.*)$", row[0])
        if m:
            p = _resolve(int(m.group(1), 16), depth + 1)
            return (p + m.group(2)) if p is not None else None
        return row[0]

    out = _AT_TOKEN_RE.sub(
        lambda m: (_resolve(int(m.group(1), 16)) or m.group(0)), s)
    return out if "@" not in out else None


def resolve_aoi_alias_target(cur: Cursor, raw_rec: bytes,
                             short_header: bool) -> Union[str, None]:
    """The AliasFor target of an AOI alias parameter, or None.

    The target is stored in ext-attr 0x65 as a UTF-16LE ``@<hex>@.@<hex>@``
    template where each ``@<hex>@`` is a comps object_id (following the
    ``&<parentHex><suffix>`` module-reference convention recursively). This is
    the same encoding _sp_alias_for decodes for source-protected tag aliases,
    but the AOI-parameter records are NOT source-protected, so read 0x65
    directly (no SP-marker gate) via the full body-mode attr walk (the terminal
    0x65 record is past what RxGeneric.extended_records exposes). Fail-closed:
    returns None unless every token resolves.
    """
    try:
        attrs = CompsRecord.read_value_attrs(raw_rec, short_header, full=True,
                                             body_mode=True)
        raw = attrs.get(0x65)
        if not raw or len(raw) < 4:
            return None
        s = raw.decode("utf-16-le", errors="replace").split("\x00")[0]
        if not _AT_TOKEN_RE.search(s):
            return None
        return resolve_at_tokens(cur, s)
    except Exception:
        return None


_HEX_MEMBER_TOKEN_RE = re.compile(r"\.!([0-9A-Fa-f]{8})")


def resolve_hex_operand(cur: Cursor, operand: str) -> Union[str, None]:
    """Resolve every ``.!<8hex>`` member token in a comment operand, or None.

    A ``.!XXXXXXXX`` token is a (collection_id << 16) | member_id key into the
    member_resolve side table (built from live RxTypeMemberCollection records);
    the OEM renders the member's comp_name uppercased as an ordinary ``.NAME``
    segment, with array/bit suffixes passing through verbatim. Multi-level
    operands carry one token per nesting level. FAIL-CLOSED: if ANY token is
    missing from the table (unknown or non-unique key) the whole operand is
    unresolvable and the caller keeps it suppressed -- a partially fabricated
    operand mis-attributes the comment, which is worse than omitting it.
    """
    def _sub(m: "re.Match") -> str:
        row = cur.execute(
            "SELECT name FROM member_resolve WHERE k=?",
            (int(m.group(1), 16),)).fetchone()
        if not row or not row[0]:
            raise LookupError(m.group(0))
        return "." + row[0].upper()
    try:
        out = _HEX_MEMBER_TOKEN_RE.sub(_sub, operand)
    except LookupError:
        return None
    except Exception:
        return None
    # A leftover '!' means a malformed token the regex did not cover; never
    # emit it.
    return out if "!" not in out else None


def short_own_description(cur: Cursor, comment_id: int, cip_type: int,
                          require_unique: bool = False) -> Union[str, None]:
    """A component's own Description (short-header V10-V21 form), or None.

    Keyed by the bare comment_id (member_ref 0, record_type 1/2). The bare key
    collides with cip-0x68 tags sharing the comment_id, but the own-description
    record stores its OWNER's cip_type in the sub_record_length column, so
    filtering on it selects the right row. ``require_unique`` demands exactly
    one matching row instead of first-match (program descriptions, whose
    collisions the cip filter alone cannot break).
    """
    sql = (
        "SELECT record_string FROM comments "
        "WHERE parent=? AND member_ref=0 AND record_type IN (1,2) "
        "AND sub_record_length=? AND record_string!=''"
    )
    if require_unique:
        cur.execute(sql, (comment_id, cip_type))
        rows = cur.fetchall()
        return rows[0][0] if len(rows) == 1 and rows[0][0] else None
    cur.execute(sql + " LIMIT 1", (comment_id, cip_type))
    row = cur.fetchone()
    return row[0] if row and row[0] else None


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


def _parse_rec_tolerant(raw_rec: bytes):
    """Parse a comps record, tolerating a source-protected (encrypted) tail.

    Returns the kaitai RxGeneric when it parses, else a plaintext-main view
    (cip_type/comment_id/main_record from fixed offsets), else None. Used by the
    alias detectors so source-protected aliases are still recognised (the
    kaitai parser throws on their encrypted ext-attr tail).
    """
    try:
        r = RxGeneric.from_bytes(raw_rec)
        # The ext-attr tail parses lazily; materialise it here so an
        # encrypted tail still yields the plaintext-main view instead.
        r.extended_records
        return r
    except Exception:
        return _rxgeneric_plaintext_main(raw_rec)


def _parse_rec_and_exts(raw_rec: bytes):
    """(record view, ext-attr dict, source_protected) for a comps record.

    Kaitai path: (RxGeneric, {attr_id: bytes}, False). A source-protected
    record's encrypted ext-attr tail defeats the kaitai parser; then the tail
    is decrypted to recover the attrs and the main_record is read at fixed
    plaintext offsets: (plaintext view or None, decrypted attrs, True).
    """
    try:
        r = RxGeneric.from_bytes(raw_rec)
        exts = {er.attribute_id: bytes(er.value) for er in r.extended_records}
        # extended_records stops before the ext-attr TAIL's terminal record,
        # which the kaitai parser keeps in last_attribute_record. In the compact
        # AOI-tag format (record_type 260/1284) the 0x01 identity attr IS that
        # terminal record, so it is absent from exts and the AOI usage classifier
        # sees an empty blob (every SCP param then misroutes to <LocalTag>).
        # Recover it when 0x01 is otherwise missing; the normal path (0x01 in the
        # regular records) is untouched.
        if 0x01 not in exts:
            _last = getattr(r, "last_attribute_record", None)
            if _last is not None and getattr(_last, "attribute_id", None) == 1:
                exts[0x01] = bytes(_last.value)
        return r, exts, False
    except Exception:
        return _rxgeneric_plaintext_main(raw_rec), CompsRecord.read_ext_attrs_from_record(raw_rec), True
