"""Unit tests for the MotionSync RPI pass's per-axis classification.

The pass zeroes a ProductType-37/45 drive's MotionSync RPI only when the
project's axis layout fully resolves; _axis_sched_class is the decision table
that guards it. The 'unassigned' state (modid 0 + readable not-in-any-group
cid) is what lets a project with fully-unassigned axes keep its completeness,
while every unreadable/unknown state still aborts the pass.
"""

from acd.l5x.elements import _axis_sched_class

KNOWN = {51432, 63924}
GROUPS = {9248}


def test_linked_and_grouped_is_scheduled():
    assert _axis_sched_class(51432, 9248, KNOWN, GROUPS) == "scheduled"


def test_linked_with_unreadable_image_fails_toward_scheduled():
    assert _axis_sched_class(51432, None, KNOWN, GROUPS) == "scheduled"


def test_linked_but_ungrouped_leaves_drive_unscheduled():
    assert _axis_sched_class(63924, 0, KNOWN, GROUPS) == "ungrouped"


def test_fully_unassigned_axis_does_not_void_completeness():
    assert _axis_sched_class(0, 0, KNOWN, GROUPS) == "unassigned"


def test_unknown_modid_is_unresolved():
    assert _axis_sched_class(12345, 9248, KNOWN, GROUPS) == "unresolved"
    assert _axis_sched_class(None, None, KNOWN, GROUPS) == "unresolved"


def test_modid_zero_with_group_claim_is_unresolved():
    # An axis that claims a group but links no drive contradicts the layout.
    assert _axis_sched_class(0, 9248, KNOWN, GROUPS) == "unresolved"
    assert _axis_sched_class(0, None, KNOWN, GROUPS) == "unresolved"
