"""Unit tests for ``external_access_enum``.

Raw value 1 encodes "Undefined" (a component that predates ExternalAccess).
Only the AOI Parameter/LocalTag call sites opt in via ``undefined_ok``; every
other caller keeps the legacy default so unvalidated surfaces are unchanged.
"""

from acd.l5x.base import external_access_enum


def test_known_values_default_surface():
    assert external_access_enum(0) == "Read/Write"
    assert external_access_enum(2) == "Read Only"
    assert external_access_enum(3) == "None"
    # Unknown values fall back to the default.
    assert external_access_enum(7) == "Read/Write"


def test_raw_one_maps_to_undefined_only_when_opted_in():
    assert external_access_enum(1) == "Read/Write"
    assert external_access_enum(1, undefined_ok=True) == "Undefined"


def test_opt_in_does_not_disturb_other_values():
    assert external_access_enum(0, undefined_ok=True) == "Read/Write"
    assert external_access_enum(2, undefined_ok=True) == "Read Only"
    assert external_access_enum(3, undefined_ok=True) == "None"
