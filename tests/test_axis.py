"""Axis tests — the six axes are stable and well-formed."""
from posture.axis import Axis, AXES, AXIS_META, is_axis, all_axis_values


def test_six_axes():
    assert len(AXES()) == 6


def test_axis_values_are_strings():
    for a in AXES():
        assert isinstance(a.value, str)
        assert a.value  # non-empty


def test_axis_meta_covers_all_axes():
    for a in AXES():
        assert a in AXIS_META
        m = AXIS_META[a]
        assert m["desc"]
        assert m["key_kind"]
        assert m["status_set"]


def test_expected_axes_present():
    vals = {a.value for a in AXES()}
    assert vals == {"vulnerability", "configuration", "exposure",
                    "inventory", "threat", "trust"}


def test_is_axis():
    assert is_axis("vulnerability")
    assert not is_axis("weather")
    assert list(all_axis_values()) == [a.value for a in AXES()]