"""Unit tests for sfc_order -- the replayed Logix-v20 SFC element sort.

For a routine with fewer than 33 language elements the exporter's introsort
reduces to a stable insertion sort, so same-Y branches keep their self-hash
enumeration order; that makes the tie order deterministically checkable here
without an ACD.  Larger routines exercise the quicksort partition and are
covered by the corpus gauntlet.
"""
from acd.l5x.sfc_order import Elem, order_branches


def _b(hash_last, y):
    return Elem(1017, bytes([0, 0, 0, hash_last]), 0, y, "", ("B", hash_last, y))


def test_distinct_y_orders_ascending():
    elems = [_b(3, 200), _b(1, 50), _b(2, 120)]
    got = [r[2] for r in order_branches(elems)]
    assert got == [50, 120, 200]


def test_same_y_small_routine_keeps_hash_order():
    # two bars share Y; a handful of other elements keep the set < 33 so the
    # sort is a stable insertion sort -> tie broken by ascending self-hash
    elems = [
        Elem(1003, b"\x00\x00\x00\x09", 10, 20, "StepB", "s"),
        Elem(1006, b"\x00\x00\x00\x08", 10, 40, "TranA", "t"),
        _b(5, 300),          # higher hash, same Y
        _b(4, 300),          # lower hash, same Y
    ]
    got = [r[1] for r in order_branches(elems)]
    assert got == [4, 5]     # ascending self-hash within the Y tie


def test_returns_all_branches_and_is_deterministic():
    elems = [_b(7, 100), _b(3, 100), _b(5, 100), _b(1, 200)]
    a = order_branches(list(elems))
    b = order_branches(list(elems))
    assert a == b
    assert len(a) == 4


def test_non_branch_elements_are_excluded():
    elems = [
        Elem(1003, b"\x00\x00\x00\x01", 0, 0, "S", "s"),
        Elem(1006, b"\x00\x00\x00\x02", 0, 0, "T", "t"),
        Elem(1021, b"\x00\x00\x00\x03", 0, 0, "P", "p"),
        _b(4, 10),
    ]
    got = order_branches(elems)
    assert [r[0] for r in got] == ["B"]
