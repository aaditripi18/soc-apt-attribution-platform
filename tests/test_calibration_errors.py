"""B1.1 — minimal calibration package foundation (ADR-0006).

Verifies only that the new ``calibration`` package and its per-layer
fail-closed error type import and behave as the repository's error
convention requires. No ``CalibrationCase``, manifest, ``calibration_version``,
or deterministic-helper tests exist yet — those belong to B1.2+ and are
deliberately out of scope for this gate.
"""

from __future__ import annotations

import pytest


def test_calibration_package_imports() -> None:
    import attribution_platform.calibration as calibration

    assert calibration.CalibrationError is not None
    assert "CalibrationError" in calibration.__all__


def test_calibration_error_imports_from_errors_module() -> None:
    from attribution_platform.calibration import CalibrationError as FromPackage
    from attribution_platform.calibration.errors import CalibrationError as FromModule

    # The package re-export and the module definition are the same object.
    assert FromPackage is FromModule


def test_calibration_error_is_valuerror_subclass() -> None:
    from attribution_platform.calibration.errors import CalibrationError

    # Matches the per-layer fail-closed pattern (ValueError subclass), like
    # AttributionError / CorrelationError / DetectionError.
    assert issubclass(CalibrationError, ValueError)


def test_calibration_error_raises_and_is_catchable() -> None:
    from attribution_platform.calibration.errors import CalibrationError

    with pytest.raises(CalibrationError, match="boom"):
        raise CalibrationError("boom")

    # It is also catchable as a plain ValueError (fail-closed constructor idiom).
    with pytest.raises(ValueError, match="boom"):
        raise CalibrationError("boom")


def test_calibration_error_is_distinct_from_other_layer_errors() -> None:
    from attribution_platform.attribution.errors import AttributionError
    from attribution_platform.calibration.errors import CalibrationError

    # A distinct type per layer: a caller can tell which layer rejected input.
    # Neither is a subclass of the other, so catching one never catches the other.
    assert not issubclass(CalibrationError, AttributionError)
    assert not issubclass(AttributionError, CalibrationError)
