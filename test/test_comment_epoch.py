"""Unit tests for the file-global comment save-epoch derivation.

Studio re-stamps every LIVE operand-comment row with the project's current edit
revision on save; rows left below the file maximum belong to deleted comments and
are exported as EMPTY <Comment>. _file_comment_epoch reads that file-global
maximum so a tag whose comments were ALL deleted (its per-tag maximum equals its
own stale revision) is still recognised as stale.
"""
import sqlite3

from acd.l5x import elements as E


def _comments_cur(rows):
    """A cursor over a comments table (revision-bearing) seeded with `rows`.

    Each row is (tag_reference, record_string, revision).
    """
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE comments(tag_reference text, record_string text, "
        "revision int)")
    conn.executemany("INSERT INTO comments VALUES (?,?,?)", rows)
    return conn.cursor()


def test_epoch_is_max_live_revision():
    cur = _comments_cur([
        (".14", "Limit Positiv", 263),      # stale (deleted)
        (".15", "Limit Negativ", 263),      # stale (deleted)
        (".DATA", "live text", 265),        # current epoch
        (".OTHER", "another", 265),
    ])
    assert E._file_comment_epoch(cur) == 265


def test_epoch_excludes_noise_rows():
    cur = _comments_cur([
        ("", "own description", 999),               # empty tag_reference
        ("__REVISION_NOTE__", "aoi metadata", 998),  # AOI UDI metadata
        (".x", "", 997),                             # empty record_string
        (".14", "Limit Positiv", 263),               # the only real live row
    ])
    assert E._file_comment_epoch(cur) == 263


def test_epoch_zero_when_no_stamped_rows():
    # A short-header / unepoch'd project stages revision 0 everywhere -> epoch 0,
    # making the blanking rule a no-op there.
    cur = _comments_cur([(".14", "text", 0), (".15", "text", 0)])
    assert E._file_comment_epoch(cur) == 0


def test_epoch_memo_is_per_cursor():
    cur1 = _comments_cur([(".a", "t", 100)])
    assert E._file_comment_epoch(cur1) == 100
    # A different cursor (a different export) recomputes rather than returning the
    # first cursor's cached value.
    cur2 = _comments_cur([(".a", "t", 200)])
    assert E._file_comment_epoch(cur2) == 200
