"""Unit tests for the length-keyed AXIS_VIRTUAL <Data Format="Axis"> tail.

The header (offsets 158..1182) is generation-invariant; only the tail differs
by blob length. Length 3424 is an older generation that predates
InterpolatedPositionConfiguration: the OEM emits neither it nor
AxisUpdateSchedule, so the renderer must omit both (tail = (None, None)),
while the 3430 generation still emits InterpolatedPositionConfiguration.
The AxisUpdateSchedule value, when present, is a u8 enum read at the
length-keyed offset (not hardcoded), so byte 0/1/2 -> Base/Alternate 1/2.
"""

import xml.etree.ElementTree as ET

from acd.l5x.elements import _render_axis_virtual, _AXIS_VIRTUAL_HEADER


def _attrs(blob, group_name):
    out = _render_axis_virtual(blob, group_name)
    assert out is not None
    return ET.fromstring(out).find("AxisParameters").attrib


def test_v3424_omits_interpolated_position_and_update_schedule():
    # A zeroed blob decodes to valid defaults (enum index 0 labels, 0.0 floats,
    # empty PositionUnits) -- enough to exercise the tail selection.
    attrs = _attrs(bytes(3424), "MG1")
    assert "InterpolatedPositionConfiguration" not in attrs
    assert "AxisUpdateSchedule" not in attrs
    # MotionGroup + every fixed header attr, and nothing else.
    assert attrs["MotionGroup"] == "MG1"
    assert len(attrs) == 1 + len(_AXIS_VIRTUAL_HEADER)


def test_v3430_still_emits_interpolated_position_config():
    # Regression guard: the newer generation keeps InterpolatedPositionConfig.
    attrs = _attrs(bytes(3430), "MG1")
    assert "InterpolatedPositionConfiguration" in attrs
    assert "AxisUpdateSchedule" not in attrs


def test_unknown_length_renders_nothing():
    # Fail-closed: an unmodelled length keeps today's no-<Data> behaviour.
    assert _render_axis_virtual(bytes(3425), "MG1") is None


def _blob_with_sched(length, aus_off, code):
    b = bytearray(length)
    b[aus_off] = code
    return bytes(b)


def test_axis_update_schedule_read_from_offset():
    # The value is READ from the length-keyed offset, not hardcoded to "Base".
    # 5476 -> aus_off 3488; 5843 -> aus_off 3520; 3654 -> aus_off 3440.
    for length, aus_off in ((5476, 3488), (5843, 3520), (3654, 3440)):
        assert _attrs(_blob_with_sched(length, aus_off, 0),
                      "MG1")["AxisUpdateSchedule"] == "Base"
        assert _attrs(_blob_with_sched(length, aus_off, 1),
                      "MG1")["AxisUpdateSchedule"] == "Alternate 1"
        assert _attrs(_blob_with_sched(length, aus_off, 2),
                      "MG1")["AxisUpdateSchedule"] == "Alternate 2"


def test_unmodelled_schedule_code_withholds_block():
    # Fail-closed: a schedule byte outside {0,1,2} withholds the whole <Data>
    # rather than guessing (unreachable in-corpus; domain is proven {0,1,2}).
    assert _render_axis_virtual(_blob_with_sched(5476, 3488, 7), "MG1") is None
