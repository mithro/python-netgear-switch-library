import pytest

from netgear_switch import errors


def test_all_errors_subclass_base():
    for name in (
        "ConfigError",
        "CredentialError",
        "UnknownModelError",
        "UnsupportedCapabilityError",
        "WriteVerificationError",
    ):
        cls = getattr(errors, name)
        assert issubclass(cls, errors.NetgearSwitchError)


def test_write_verification_error_carries_before_after():
    err = errors.WriteVerificationError("mismatch", before=1, after=2)
    assert err.before == 1
    assert err.after == 2
    assert "mismatch" in str(err)


def test_base_is_catchable():
    with pytest.raises(errors.NetgearSwitchError):
        raise errors.UnsupportedCapabilityError("no MAC table on Plus switches")
