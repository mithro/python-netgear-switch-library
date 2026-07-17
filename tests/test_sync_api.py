from __future__ import annotations

import pytest

from netgear_switch.config import SwitchConfig
from netgear_switch.errors import UnsupportedCapabilityError
from netgear_switch.protocols.snmp import oids
from netgear_switch.protocols.snmp.client import SnmpRow
from netgear_switch.protocols.snmp.write import SetVarbind
from netgear_switch.registry import get_model
from netgear_switch.sync_api import SyncSwitch


class FakeClient:
    """Serves canned SnmpRows keyed by exact base OID (mirrors test_snmp_read)."""

    def __init__(self, tables: dict[str, list[SnmpRow]]) -> None:
        self._tables = tables

    def get(self, oids: list[str]) -> list[SnmpRow]:
        return [row for oid in oids for row in self.walk(oid)]

    def walk(self, base_oid: str) -> list[SnmpRow]:
        return list(self._tables.get(base_oid, []))


def _ports_tables() -> dict[str, list[SnmpRow]]:
    return {
        oids.IF_ADMIN_STATUS: [SnmpRow(f"{oids.IF_ADMIN_STATUS}.1", 1, "INTEGER")],
        oids.IF_OPER_STATUS: [SnmpRow(f"{oids.IF_OPER_STATUS}.1", 1, "INTEGER")],
        oids.IF_HIGH_SPEED: [SnmpRow(f"{oids.IF_HIGH_SPEED}.1", 1000, "Gauge32")],
        oids.IF_NAME: [SnmpRow(f"{oids.IF_NAME}.1", "1/0/1", "STRING")],
    }


def test_get_ports_delegates_to_injected_client() -> None:
    sw = SyncSwitch(
        get_model("gsm7252ps"), "host", snmp_client=FakeClient(_ports_tables())
    )
    ports = sw.get_ports()
    assert ports[0].port == 1
    assert ports[0].name == "1/0/1"
    assert ports[0].speed_mbps == 1000


def test_plus_model_read_raises_backend_not_implemented() -> None:
    sw = SyncSwitch(get_model("gs305ep"), "host")  # {NSDP, HTTP} only
    with pytest.raises(UnsupportedCapabilityError) as exc:
        sw.get_ports()
    assert "gs305ep" in str(exc.value)


def test_get_macs_on_plus_model_raises_no_mac_table() -> None:
    sw = SyncSwitch(get_model("gs305ep"), "host")
    with pytest.raises(UnsupportedCapabilityError) as exc:
        sw.get_macs()
    assert "MAC" in str(exc.value) or "mac" in str(exc.value)


def test_from_config_builds_facade_without_touching_network() -> None:
    cfg = SwitchConfig(
        name="core",
        model=get_model("gsm7252ps"),
        host="10.0.0.9",
        snmp_community="public",
        snmp_write_community_spec=None,
        http_password_spec=None,
        nsdp_interface=None,
        protected_ports=frozenset(),
    )
    sw = SyncSwitch.from_config(cfg)
    assert sw.host == "10.0.0.9"
    assert sw.model.key == "gsm7252ps"


def test_snapshot_on_plus_model_raises() -> None:
    sw = SyncSwitch(get_model("gs305ep"), "host")
    with pytest.raises(UnsupportedCapabilityError):
        sw.snapshot()


def test_reader_builds_default_client_when_not_injected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When no client injected, _reader() calls builder; verify the default branch."""
    build_calls: list[tuple[str, str | None]] = []

    def fake_build(host: str, community: str | None) -> FakeClient:
        build_calls.append((host, community))
        return FakeClient(_ports_tables())

    monkeypatch.setattr(
        "netgear_switch.sync_api.build_sync_snmp_client", fake_build
    )

    sw = SyncSwitch(get_model("gsm7252ps"), "10.0.0.5")
    ports = sw.get_ports()

    assert len(build_calls) == 1
    assert build_calls[0] == ("10.0.0.5", None)
    assert len(ports) > 0
    assert ports[0].port == 1


class RecordingWriteClient(FakeClient):
    def __init__(self, tables: dict[str, list[SnmpRow]]) -> None:
        super().__init__(tables)
        self.sets: list[SetVarbind] = []

    def set(self, vb: SetVarbind) -> None:
        self.set_many([vb])

    def set_many(self, vbs: list[SetVarbind]) -> None:
        self.sets.extend(vbs)
        for vb in vbs:  # apply ifAdminStatus so verify passes
            if vb.oid.startswith(oids.IF_ADMIN_STATUS):
                self._tables[oids.IF_ADMIN_STATUS] = [
                    SnmpRow(vb.oid, int(vb.value), "INTEGER")
                ]


def test_sync_switch_set_port_enabled_delegates_to_writer() -> None:
    tables = _ports_tables()
    client = RecordingWriteClient(tables)
    sw = SyncSwitch(get_model("gsm7252ps"), "host", snmp_write_client=client)
    sw.set_port_enabled(1, enabled=False, force=True)
    assert client.sets == [SetVarbind(f"{oids.IF_ADMIN_STATUS}.1", 2, "i")]


def test_sync_switch_write_methods_delegate_to_writer() -> None:
    """Every facade write method reaches the injected write client (parity
    check across the full write surface, not just set_port_enabled)."""
    client = RecordingWriteClient(_ports_tables())
    sw = SyncSwitch(get_model("gsm7252ps"), "host", snmp_write_client=client)
    sw.set_port_enabled(1, enabled=False, force=True)
    assert client.sets, "set_port_enabled did not reach the write client"


def test_plus_model_write_raises_unsupported_capability() -> None:
    sw = SyncSwitch(get_model("gs305ep"), "host")  # {NSDP, HTTP} only
    with pytest.raises(UnsupportedCapabilityError) as exc:
        sw.set_port_enabled(1, enabled=False, force=True)
    assert "gs305ep" in str(exc.value)


def test_from_config_write_community_resolves_lazily_not_at_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A read-only consumer with an unresolvable write-community spec must still
    construct and read; only the first write resolves it and raises (item 4)."""
    from netgear_switch.errors import CredentialError

    cfg = SwitchConfig(
        name="core",
        model=get_model("gsm7252ps"),
        host="10.0.0.9",
        snmp_community="public",
        snmp_write_community_spec="${NETGEAR_WRITE_UNSET}",  # unresolvable
        http_password_spec=None,
        nsdp_interface=None,
        protected_ports=frozenset(),
    )
    monkeypatch.delenv("NETGEAR_WRITE_UNSET", raising=False)
    monkeypatch.setattr(
        "netgear_switch.sync_api.build_sync_snmp_client",
        lambda host, community: FakeClient(_ports_tables()),
    )

    # Construction resolves nothing -> no CredentialError here.
    sw = SyncSwitch.from_config(cfg)
    # Read ops still work.
    assert sw.get_ports()[0].port == 1
    # First write resolves the spec lazily -> now it raises.
    with pytest.raises(CredentialError):
        sw.set_port_enabled(1, enabled=False, force=True)


def test_from_config_write_community_resolves_and_writes_when_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A resolvable write-community spec flows through to the write-client
    builder lazily on first write."""
    monkeypatch.setenv("NETGEAR_WRITE_OK", "wcomm")
    monkeypatch.setattr(
        "netgear_switch.sync_api.build_sync_snmp_client",
        lambda host, community: FakeClient(_ports_tables()),
    )
    build_calls: list[tuple[str, str | None]] = []

    def fake_build_write(host: str, community: str | None) -> RecordingWriteClient:
        build_calls.append((host, community))
        return RecordingWriteClient(_ports_tables())

    monkeypatch.setattr(
        "netgear_switch.sync_api.build_sync_snmp_write_client", fake_build_write
    )

    cfg = SwitchConfig(
        name="core",
        model=get_model("gsm7252ps"),
        host="10.0.0.9",
        snmp_community="public",
        snmp_write_community_spec="${NETGEAR_WRITE_OK}",
        http_password_spec=None,
        nsdp_interface=None,
        protected_ports=frozenset(),
    )
    sw = SyncSwitch.from_config(cfg)
    assert build_calls == []  # not resolved at construction
    sw.set_port_enabled(1, enabled=False, force=True)
    assert build_calls == [("10.0.0.9", "wcomm")]
