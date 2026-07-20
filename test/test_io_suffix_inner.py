"""Unit tests for per-suffix I/O tag inner selection.

A module owning several I/O families (e.g. a FANUC robot adapter with both a
standard :I1 and a safety :SI backing tag) must render each connection's
InputTag/OutputTag from that connection's own decoded suffix, not a single merged
inner. Single-family modules and unmapped suffixes fall back to the merged inner.
"""
from acd.l5x.module_builder import _inner_for_suffix

_MAP = {"I1": "<i1>", "SI": "<si>", "O1": "<o1>", "SO": "<so>"}


def test_picks_the_connection_own_suffix():
    # The standard slot resolves :I1, the safety slot resolves :SI -- distinct
    # inners on the same multi-family module.
    assert _inner_for_suffix(_MAP, "I1", "<merged>") == "<i1>"
    assert _inner_for_suffix(_MAP, "SI", "<merged>") == "<si>"
    assert _inner_for_suffix(_MAP, "O1", "<merged>") == "<o1>"
    assert _inner_for_suffix(_MAP, "SO", "<merged>") == "<so>"


def test_fails_open_to_merged_inner():
    # No map (single-family module): always the merged default.
    assert _inner_for_suffix(None, "I1", "<merged>") == "<merged>"
    assert _inner_for_suffix({}, "I1", "<merged>") == "<merged>"
    # Suffix absent on the connection (legacy connection): merged default.
    assert _inner_for_suffix(_MAP, None, "<merged>") == "<merged>"
    assert _inner_for_suffix(_MAP, "", "<merged>") == "<merged>"
    # Suffix decoded but not in the map (e.g. suffix 'I' where the module only
    # owns :I1): fail open rather than emit nothing (protects 0-worse).
    assert _inner_for_suffix(_MAP, "I", "<merged>") == "<merged>"


def test_mapped_none_falls_back():
    # A suffix present but mapping to None keeps the merged inner.
    assert _inner_for_suffix({"I1": None}, "I1", "<merged>") == "<merged>"
