"""Unit tests for the parameter/member Min/Max limit recovery
(``acd.l5x.base.load_member_limits``).

An AOI parameter's or UDT member's engineering @Min/@Max limit is not stored on
the definition (an AOI's rides inside its source-protected blob; a UDT member's
is absent from the member record). It is stored, in plaintext, on every instance
of the type -- as operand comments (kind 0x02 = Min, 0x03 = Max) under the
instance tag's comment scope. ``load_member_limits`` propagates those back to the
definition, keyed by ``(DataType, member)``.

These fixtures pin the association (comment scope -> owning tag's DataType via the
tag_datatype table) and every fail-closed branch: both bounds required, agreement
across instances required, latest revision wins, nested operands and ambiguous
scopes dropped.
"""

import sqlite3
import struct

from acd.l5x.base import load_member_limits


def _rec(comment_id, cip=0x6B):
    """A minimal comps record carrying cip_type @ +10 and comment_id @ +12."""
    b = bytearray(14)
    struct.pack_into("<H", b, 10, cip)
    struct.pack_into("<H", b, 12, comment_id)
    return bytes(b)


def _db():
    con = sqlite3.connect(":memory:")
    cur = con.cursor()
    cur.execute("CREATE TABLE comments(parent int, tag_reference text, "
                "record_string text, member_ref int, revision int)")
    cur.execute("CREATE TABLE comps(comp_name text, record blob)")
    cur.execute("CREATE TABLE tag_datatype(tagname text, datatype text)")
    return con, cur


def _scope(comment_id, cip=0x6B):
    return (comment_id << 16) | cip


def _instance(cur, tagname, datatype, comment_id, limits, cip=0x6B, rev=0):
    """Add one instance tag with a set of (operand, kind, value) operand limits."""
    cur.execute("INSERT INTO comps VALUES (?,?)", (tagname, _rec(comment_id, cip)))
    cur.execute("INSERT INTO tag_datatype VALUES (?,?)", (tagname, datatype))
    for operand, kind, value in limits:
        cur.execute("INSERT INTO comments VALUES (?,?,?,?,?)",
                    (_scope(comment_id, cip), operand, value, kind, rev))


def test_both_bounds_present_emits_pair():
    con, cur = _db()
    _instance(cur, "Inst1", "MyAOI", 100,
              [(".Port", 2, "0"), (".Port", 3, "7")])
    assert load_member_limits(cur) == {("MYAOI", "PORT"): ("0", "7")}


def test_only_one_bound_is_withheld():
    con, cur = _db()
    _instance(cur, "Inst1", "MyAOI", 100, [(".Port", 2, "0")])  # Min but no Max
    assert load_member_limits(cur) == {}


def test_conflicting_instances_withheld():
    con, cur = _db()
    _instance(cur, "Inst1", "MyAOI", 100,
              [(".Port", 2, "0"), (".Port", 3, "7")])
    _instance(cur, "Inst2", "MyAOI", 101,
              [(".Port", 2, "0"), (".Port", 3, "15")])  # Max disagrees
    assert load_member_limits(cur) == {}


def test_agreeing_instances_emit_once():
    con, cur = _db()
    _instance(cur, "Inst1", "MyAOI", 100,
              [(".Port", 2, "0"), (".Port", 3, "7")])
    _instance(cur, "Inst2", "MyAOI", 101,
              [(".Port", 2, "0"), (".Port", 3, "7")])
    assert load_member_limits(cur) == {("MYAOI", "PORT"): ("0", "7")}


def test_latest_revision_wins_within_a_scope():
    con, cur = _db()
    # Same scope + operand, two revisions of the Max; the newest (rev 2) wins.
    cur.execute("INSERT INTO comps VALUES (?,?)", ("Inst1", _rec(100)))
    cur.execute("INSERT INTO tag_datatype VALUES (?,?)", ("Inst1", "MyAOI"))
    for kind, value, rev in [(2, "0", 1), (3, "5", 1), (3, "7", 2)]:
        cur.execute("INSERT INTO comments VALUES (?,?,?,?,?)",
                    (_scope(100), ".Port", value, kind, rev))
    assert load_member_limits(cur) == {("MYAOI", "PORT"): ("0", "7")}


def test_nested_operand_skipped():
    con, cur = _db()
    _instance(cur, "Inst1", "MyAOI", 100,
              [(".Sub.Port", 2, "0"), (".Sub.Port", 3, "7")])
    assert load_member_limits(cur) == {}


def test_ambiguous_scope_dropped():
    con, cur = _db()
    # Two tags of different DataTypes collide on one comment scope -> ambiguous.
    cur.execute("INSERT INTO comps VALUES (?,?)", ("InstA", _rec(100)))
    cur.execute("INSERT INTO comps VALUES (?,?)", ("InstB", _rec(100)))
    cur.execute("INSERT INTO tag_datatype VALUES (?,?)", ("InstA", "TypeA"))
    cur.execute("INSERT INTO tag_datatype VALUES (?,?)", ("InstB", "TypeB"))
    for kind, value in [(2, "0"), (3, "7")]:
        cur.execute("INSERT INTO comments VALUES (?,?,?,?,?)",
                    (_scope(100), ".Port", value, kind, 0))
    assert load_member_limits(cur) == {}


def test_no_limit_rows_returns_empty():
    con, cur = _db()
    cur.execute("INSERT INTO comps VALUES (?,?)", ("Inst1", _rec(100)))
    cur.execute("INSERT INTO tag_datatype VALUES (?,?)", ("Inst1", "MyAOI"))
    cur.execute("INSERT INTO comments VALUES (?,?,?,?,?)",
                (_scope(100), ".Port", "hello", 1, 0))  # a description, not a limit
    assert load_member_limits(cur) == {}
