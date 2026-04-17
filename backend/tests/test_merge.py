from datetime import datetime, timedelta

from app.merge import SOURCE_PRIORITY, _floor_minute


def test_floor_minute_zeros_seconds_and_micros() -> None:
    dt = datetime(2026, 4, 17, 9, 12, 34, 567)
    assert _floor_minute(dt) == datetime(2026, 4, 17, 9, 12)


def test_priority_order() -> None:
    assert SOURCE_PRIORITY["phone"] < SOURCE_PRIORITY["checkin"]
    assert SOURCE_PRIORITY["checkin"] < SOURCE_PRIORITY["manual"]
    assert SOURCE_PRIORITY["manual"] < SOURCE_PRIORITY["plan"]


def test_one_minute_delta() -> None:
    a = _floor_minute(datetime(2026, 4, 17, 9, 12, 34))
    b = a + timedelta(minutes=1)
    assert (b - a).total_seconds() == 60
