import pytest

from cicflowmeter.utils import get_statistics


def test_empty_list():
    assert get_statistics([]) == {
        "total": 0,
        "max": 0,
        "min": 0,
        "mean": 0,
        "std": 0,
    }


def test_single_observation():
    result = get_statistics([0.5])

    assert result["total"] == 0.5
    assert result["max"] == 0.5
    assert result["min"] == 0.5
    assert result["mean"] == 0.5
    assert result["std"] == 0


def test_multiple_observations():
    result = get_statistics([0.5, 1.0])

    assert result["total"] == 1.5
    assert result["max"] == 1.0
    assert result["min"] == 0.5
    assert result["mean"] == 0.75
    assert result["std"] == pytest.approx(0.25)
