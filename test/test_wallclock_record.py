"""Unit tests for the WallClockTime TimeZone/LocalTimeAdjustment decode.

The values ride the controller's WallClockTime config record (an
RxControllerCollection child): TimeZone = u16@8, LocalTimeAdjustment = u16@18
of ext-attr 0x1. An LTA outside {0,1} marks an unknown layout and keeps the
0/0 defaults (fail-closed: never fabricate a timezone).
"""

import struct

from acd.l5x.elements import ControllerBuilder

try:
    from .seeded_db import seeded_cursor
except ImportError:   # collected with test/ as the rootdir
    from seeded_db import seeded_cursor

CTL, RCC, WCT = 100, 200, 300


def _body(attrs) -> bytes:
    """A long-header comps BODY carrying ``attrs`` as its ext tail."""
    tail = b"".join(struct.pack("<II", aid, len(v)) + v for aid, v in attrs)
    return (struct.pack("<IIHHH", 1, 2, 3, 0x6A, 7) + bytes(60)
            + struct.pack("<II", len(tail), len(attrs) + 1) + tail)


def _cursor(wct_attr):
    return seeded_cursor(comps=[
        (CTL, 0, "MyController", 0, 256, _body([])),
        (RCC, CTL, "RxControllerCollection", 0, 256, _body([])),
        (WCT, RCC, "WallClockTime", 0, 256, _body([(0x1, wct_attr)])),
    ])


def _wct_image(tz, lta, size=181) -> bytes:
    buf = bytearray(size)
    if size >= 10:
        struct.pack_into("<H", buf, 8, tz)
    if size >= 20:
        struct.pack_into("<H", buf, 18, lta)
    return bytes(buf)


def test_nonzero_timezone_and_lta_decode():
    b = ControllerBuilder(_cursor(_wct_image(5, 1)), CTL)
    assert b._pass_time_sync_cst()[4:] == ("1", "5")


def test_zero_config_keeps_defaults():
    b = ControllerBuilder(_cursor(_wct_image(0, 0)), CTL)
    assert b._pass_time_sync_cst()[4:] == ("0", "0")


def test_unknown_lta_fails_closed():
    b = ControllerBuilder(_cursor(_wct_image(5, 7)), CTL)
    assert b._pass_time_sync_cst()[4:] == ("0", "0")


def test_short_image_fails_closed():
    b = ControllerBuilder(_cursor(_wct_image(5, 1, size=16)), CTL)
    assert b._pass_time_sync_cst()[4:] == ("0", "0")


def test_absent_record_keeps_defaults():
    cur = seeded_cursor(comps=[(CTL, 0, "MyController", 0, 256, _body([]))])
    b = ControllerBuilder(cur, CTL)
    assert b._pass_time_sync_cst()[4:] == ("0", "0")
