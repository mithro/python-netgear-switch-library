import os
import stat
import textwrap

import pytest

from netgear_switch import errors
from netgear_switch.config import (
    SwitchConfig,
    ensure_secure_file,
    load_inventory,
    resolve_secret,
)


def test_resolve_secret_literal_env_command_and_none():
    assert resolve_secret(None, env={}) is None
    assert resolve_secret("public", env={}) == "public"
    assert resolve_secret("${WC}", env={"WC": "s3cr3t"}) == "s3cr3t"

    def fake_runner(args, **kw):
        assert args == ["pass", "show", "netgear/x"]
        return __import__("types").SimpleNamespace(
            returncode=0, stdout="frompass\n", stderr=""
        )

    assert (
        resolve_secret("!pass show netgear/x", env={}, runner=fake_runner) == "frompass"
    )


def test_resolve_secret_missing_env_raises():
    with pytest.raises(errors.CredentialError):
        resolve_secret("${NOPE}", env={})


def test_resolve_secret_command_failure_raises():
    def failing(args, **kw):
        return __import__("types").SimpleNamespace(
            returncode=1, stdout="", stderr="boom"
        )

    with pytest.raises(errors.CredentialError):
        resolve_secret("!false", env={}, runner=failing)


def test_resolve_secret_missing_binary_raises_credential_error():
    with pytest.raises(errors.CredentialError):
        resolve_secret("!definitely-not-a-real-binary-xyzzy --flag", env={})


def _write(tmp_path, body, mode=0o600):
    p = tmp_path / "inv.toml"
    p.write_text(textwrap.dedent(body))
    os.chmod(p, mode)
    return p


def test_load_inventory_parses_switches(tmp_path):
    p = _write(
        tmp_path,
        """
        [switches.sw-a]
        model = "gsm7252ps"
        host = "10.1.5.20"
        snmp.community = "public"
        snmp.write_community = "${WC}"
        protected_ports = [9, 10]

        [switches.sw-b]
        model = "gs110emx"
        host = "10.1.5.25"
        http.password = "${PW}"
        nsdp.interface = "eth0"
        """,
    )
    inv = load_inventory(p, env={"WC": "w", "PW": "p"})
    assert set(inv) == {"sw-a", "sw-b"}
    a = inv["sw-a"]
    assert isinstance(a, SwitchConfig)
    assert a.model.key == "gsm7252ps"
    assert a.snmp_community == "public"
    assert a.protected_ports == frozenset({9, 10})
    assert a.snmp_write_community(env={"WC": "w"}) == "w"
    assert inv["sw-b"].nsdp_interface == "eth0"
    assert inv["sw-b"].http_password(env={"PW": "p"}) == "p"


def test_load_inventory_unknown_model_raises(tmp_path):
    p = _write(
        tmp_path,
        """
        [switches.bad]
        model = "nope"
        host = "1.2.3.4"
        """,
    )
    with pytest.raises(errors.NetgearSwitchError):
        load_inventory(p, env={})


def test_literal_secret_requires_secure_permissions(tmp_path):
    p = _write(
        tmp_path,
        """
        [switches.sw]
        model = "gsm7252ps"
        host = "10.1.5.20"
        snmp.write_community = "literalsecret"
        """,
        mode=0o644,
    )
    with pytest.raises(errors.ConfigError):
        load_inventory(p, env={})


def test_ensure_secure_file_accepts_600(tmp_path):
    p = tmp_path / "ok"
    p.write_text("x")
    os.chmod(p, 0o600)
    ensure_secure_file(p)  # no raise


def test_ensure_secure_file_rejects_world_readable(tmp_path):
    p = tmp_path / "bad"
    p.write_text("x")
    os.chmod(p, stat.S_IRUSR | stat.S_IWUSR | stat.S_IROTH)
    with pytest.raises(errors.ConfigError):
        ensure_secure_file(p)


def test_non_string_secret_is_config_error_not_silent(tmp_path):
    p = _write(
        tmp_path,
        """
        [switches.sw]
        model = "gsm7252ps"
        host = "10.1.5.20"
        snmp.write_community = 12345
        """,
        mode=0o644,
    )
    with pytest.raises(errors.ConfigError):
        load_inventory(p, env={})


def test_protected_ports_rejects_booleans(tmp_path):
    p = _write(
        tmp_path,
        """
        [switches.sw]
        model = "gsm7252ps"
        host = "10.1.5.20"
        protected_ports = [true, 9]
        """,
    )
    with pytest.raises(errors.ConfigError):
        load_inventory(p, env={})
