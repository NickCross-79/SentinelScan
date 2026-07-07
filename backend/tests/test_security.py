"""Target validation and the authorization gate."""

import pytest

from backend.app.core.security import TargetValidationError, validate_target


def test_authorization_gate_required():
    with pytest.raises(TargetValidationError):
        validate_target("192.168.1.0/24", authorized=False)


def test_private_range_allowed_when_authorized():
    assert validate_target("192.168.1.0/24", authorized=True) == "192.168.1.0/24"
    assert validate_target("127.0.0.1", authorized=True) == "127.0.0.1"


def test_public_range_blocked_by_default():
    with pytest.raises(TargetValidationError):
        validate_target("8.8.8.8", authorized=True)


def test_public_range_allowed_with_override():
    assert validate_target("8.8.8.8", authorized=True, allow_public=True) == "8.8.8.8"


def test_empty_target_rejected():
    with pytest.raises(TargetValidationError):
        validate_target("", authorized=True)
