"""Unit tests for the length-keyed AXIS_VIRTUAL <Data Format="Axis"> tail.

The header (offsets 158..1182) is generation-invariant; only the tail differs
by blob length. Length 3424 is an older generation that predates
InterpolatedPositionConfiguration: the OEM emits neither it nor
AxisUpdateSchedule, so the renderer must omit both (tail = (None, False)),
while the 3430 generation still emits InterpolatedPositionConfiguration.
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
