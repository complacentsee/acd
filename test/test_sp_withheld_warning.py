"""Faithful-mode 'knowingly incomplete' diagnostics for withheld source-protected
<EncodedData> components (chiefly EncryptionConfig 9 / Studio V31+)."""
from acd.l5x.elements import (
    reset_sp_withheld,
    sp_withheld_report,
    note_sp_withheld,
    _SP_MARKER,
    _SP_PROTECTED_FLAG,
)
from acd.api import _warn_sp_incomplete


def _record(flag: bytes) -> bytes:
    # marker at body+78; the 6 bytes at marker+14..+20 select the scheme.
    rec = bytearray(120)
    rec[78:82] = _SP_MARKER
    rec[78 + 14:78 + 20] = flag
    return bytes(rec)


def test_note_sp_withheld_labels_and_report():
    reset_sp_withheld()
    assert sp_withheld_report() == {}
    note_sp_withheld(_record(_SP_PROTECTED_FLAG), "routine")   # config-9
    note_sp_withheld(_record(_SP_PROTECTED_FLAG), "aoi")       # config-9
    note_sp_withheld(_record(b"\x00" * 6), "routine")          # some other scheme
    rep = sp_withheld_report()
    assert rep[("routine", "config9")] == 1
    assert rep[("aoi", "config9")] == 1
    assert rep[("routine", "other")] == 1
    reset_sp_withheld()
    assert sp_withheld_report() == {}


def test_warn_sp_incomplete_emits_only_on_nonempty():
    from loguru import logger
    msgs = []
    sink_id = logger.add(lambda m: msgs.append(str(m)), level="WARNING")
    try:
        _warn_sp_incomplete("proj.ACD", {})
        assert msgs == []  # nothing withheld -> silent (output is complete)
        _warn_sp_incomplete(
            "proj.ACD", {("routine", "config9"): 3, ("aoi", "config9"): 2})
        assert len(msgs) == 1
        m = msgs[0]
        assert "KNOWINGLY INCOMPLETE" in m
        assert "EncryptionConfig 9" in m
        assert "5 source-protected" in m           # total withheld
        assert "3 routine(s), 2 AOI(s)" in m
    finally:
        logger.remove(sink_id)
