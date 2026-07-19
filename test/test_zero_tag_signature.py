"""Unit test for the all-zero (unsigned) safety <Tags> signature emission.

A safety collection with no real signature but an all-zero-hash GSS record
still emits SafetySignature="00000000 - ..." + its stored timestamp; a
collection with neither emits nothing.
"""

import sqlite3
import struct

from acd.l5x.elements import _tagcoll_sig_attrs


def _coll_record(otype, cid, disc):
    b = bytearray(20)
    struct.pack_into("<H", b, 10, otype)
    struct.pack_into("<I", b, 12, cid)
    struct.pack_into("<I", b, 16, disc)
    return bytes(b)


def _cur(zero_rows):
    db = sqlite3.connect(":memory:")
    c = db.cursor()
    c.execute("CREATE TABLE comps(object_id int, record BLOB)")
    c.execute("CREATE TABLE connection_signatures(otype int, cid int, "
              "disc int, signature text, timestamp text)")
    c.execute("CREATE TABLE zero_tag_signatures(otype int, cid int, "
              "disc int, timestamp text)")
    c.execute("INSERT INTO comps VALUES (7, ?)",
              (_coll_record(104, 7067526, 0),))
    for row in zero_rows:
        c.execute("INSERT INTO zero_tag_signatures VALUES (?,?,?,?)", row)
    return c


def test_all_zero_signature_emitted_with_timestamp():
    cur = _cur([(104, 7067526, 0, "09/04/2025, 07:42:43.047 AM")])
    a = _tagcoll_sig_attrs(cur, 7, False)
    assert 'SafetySignature="' + " - ".join(["00000000"] * 8) + '"' in a
    assert 'SafetySignatureTimestamp="09/04/2025, 07:42:43.047 AM"' in a


def test_no_signature_when_no_zero_record():
    cur = _cur([])          # neither a real nor a zero record for this triple
    assert _tagcoll_sig_attrs(cur, 7, False) == ""
