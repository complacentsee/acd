"""Base primitives shared by every L5X element/builder module.

``L5xElement`` is the generic to_xml() dataclass all exported elements extend;
``L5xElementBuilder`` carries the (cursor, object_id) pair every builder needs.
``_xml_sane`` strips the C0 control characters XML 1.0 forbids.
"""
import html
import re
from dataclasses import dataclass
from sqlite3 import Cursor
from typing import List, Union


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


def own_description(cur: Cursor, comment_parent: int) -> Union[str, None]:
    """A component's own Description (long-header form), or None.

    The own-description row lives at parent == comment_id*0x10000 + cip_type
    with member_ref 0 and carries object_id == 1; rows sharing the key with a
    nonzero object_id are scratch/extended-help values whose record_string
    would leak in as a fabricated Description, so they are excluded.
    """
    cur.execute(
        "SELECT record_string FROM comments "
        "WHERE parent=? AND member_ref=0 AND object_id=1 LIMIT 1",
        (comment_parent,),
    )
    row = cur.fetchone()
    return row[0] if row and row[0] else None


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
