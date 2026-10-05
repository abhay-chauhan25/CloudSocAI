"""Smoke tests: prove the test harness runs and the backend package is importable."""

import app


def test_app_package_is_importable() -> None:
    assert app.__name__ == "app"


def test_app_package_has_description() -> None:
    assert app.__doc__
    assert "CloudSOC AI" in app.__doc__
