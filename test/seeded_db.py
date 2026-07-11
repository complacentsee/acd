"""Seeded in-memory staging DB for decoder unit tests.

``seeded_cursor`` builds the same staging schema ``ExportL5x`` creates (the
DDL below mirrors acd/l5x/export_l5x.py) and inserts the rows a test needs,
so record-level decoders (MESSAGE configs, alarms, connections, identity
recovery) can be driven end-to-end without an ACD pool. All tables exist --
empty unless seeded -- because the decoders probe several of them and expect
"no rows", not "no such table".

Record-payload builders for the comps/comps_full byte formats live with the
tests that use them (see test_module_identity_chain / test_message_config).
"""

import sqlite3

_SCHEMA = (
    "CREATE TABLE comps(object_id int, parent_id int, comp_name text,"
    " seq_number int, record_type int, record BLOB NOT NULL)",
    "CREATE TABLE comps_full(object_id int PRIMARY KEY, record BLOB NOT NULL)",
    "CREATE TABLE comps_family(object_id INTEGER PRIMARY KEY,"
    " winner_family INTEGER, fafa_seen INTEGER)",
    "CREATE TABLE comments(seq_number int, sub_record_length int, object_id int,"
    " record_string text, record_type int, parent int, tag_reference text,"
    " rung_content int, member_ref int)",
    "CREATE TABLE rungs(object_id int, rung text, seq_number int)",
    "CREATE TABLE nameless(object_id int, parent_id int, record BLOB NOT NULL)",
    "CREATE TABLE project_flags(opc_ua int, is_safety int)",
    "CREATE TABLE safety_signatures(otype int, cid int, signature text,"
    " timestamp text)",
    "CREATE TABLE connection_signatures(otype int, cid int, disc int,"
    " signature text, timestamp text)",
    "CREATE TABLE named_safety_signatures(otype int, name text, signature text,"
    " timestamp text)",
    "CREATE TABLE custom_properties(cid int, ext text, provider_id text,"
    " blob text)",
    "CREATE TABLE alarm_messages(joinkey int, mtype text, text text)",
)


def seeded_cursor(comps=(), comps_full=(), comments=(), alarm_messages=(),
                  comps_family=()):
    """A cursor over a fresh in-memory staging DB with the given rows.

    ``comps`` rows are (object_id, parent_id, comp_name, seq_number,
    record_type, record); ``comps_full`` rows are (object_id, record);
    ``comments`` rows are full 9-tuples in schema order; ``alarm_messages``
    rows are (joinkey, mtype, text); ``comps_family`` rows are
    (object_id, winner_family, fafa_seen).
    """
    cur = sqlite3.connect(":memory:").cursor()
    for ddl in _SCHEMA:
        cur.execute(ddl)
    cur.executemany("INSERT INTO comps VALUES (?,?,?,?,?,?)", list(comps))
    cur.executemany("INSERT INTO comps_full VALUES (?,?)", list(comps_full))
    cur.executemany("INSERT INTO comps_family VALUES (?,?,?)",
                    list(comps_family))
    cur.executemany("INSERT INTO comments VALUES (?,?,?,?,?,?,?,?,?)",
                    list(comments))
    cur.executemany("INSERT INTO alarm_messages VALUES (?,?,?)",
                    list(alarm_messages))
    return cur
