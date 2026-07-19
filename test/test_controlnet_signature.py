"""Unit tests for the ControlNet keeper-signature gating + rendering.

(The keeper-image value read is validated end-to-end against the reference by
the gauntlet; here we pin the config_ref gate and the two-u16-half rendering.)
"""

import sqlite3

from acd.l5x.module_builder import _controlnet_keeper, Module


def _empty_cur():
    db = sqlite3.connect(":memory:")
    c = db.cursor()
    c.execute("CREATE TABLE comps(object_id int, parent_id int, "
              "comp_name text, record BLOB)")
    return c


def test_keeper_zero_without_config_ref():
    assert _controlnet_keeper(_empty_cur(), 0, False) == 0
    assert _controlnet_keeper(_empty_cur(), None, False) == 0


def test_keeper_zero_when_no_matching_record():
    assert _controlnet_keeper(_empty_cur(), 0x1234, False) == 0


def test_signature_renders_as_two_u16_halves():
    m = Module("m", "m", "C", 1, 1, 1, 1, 1, "Local", 1, "false", "false",
               _controlnet_signature=0x1ce69686)
    assert 'ControlNetSignature="16#1ce6_9686"' in m.to_xml()


def test_zero_signature_still_emitted():
    m = Module("m", "m", "C", 1, 1, 1, 1, 1, "Local", 1, "false", "false",
               _controlnet_signature=0)
    assert 'ControlNetSignature="16#0000_0000"' in m.to_xml()


def test_signature_omitted_when_none():
    m = Module("m", "m", "C", 1, 1, 1, 1, 1, "Local", 1, "false", "false")
    assert "ControlNetSignature" not in m.to_xml()
