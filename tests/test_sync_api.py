from __future__ import annotations

import pytest

from netgear_switch.config import SwitchConfig
from netgear_switch.errors import UnsupportedCapabilityError
from netgear_switch.models import VlanMode
from netgear_switch.protocols.snmp import oids
from netgear_switch.protocols.snmp.client import SnmpRow
from netgear_switch.protocols.snmp.write import SetVarbind, encode_port_bitmap
from netgear_switch.registry import get_model
from netgear_switch.snmp_write import PoeCycleTimeouts
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


_WRITE_VLAN = 10  # pre-existing VLAN used by set_vlan_membership
_NEW_VLAN = 999  # created then deleted by create_vlan/delete_vlan


def _all_writes_tables() -> dict[str, list[SnmpRow]]:
    """Seed tables for every facade write method's happy path on port 1,
    coherent enough that each op's post-write verification passes."""
    tables = _ports_tables()
    tables.update({
        oids.PETH_PSE_PORT_TABLE: [
            SnmpRow(f"{oids.PETH_PSE_PORT_TABLE}.3.1.1", 1, "INTEGER"),
            SnmpRow(f"{oids.PETH_PSE_PORT_TABLE}.6.1.1", 3, "INTEGER"),
        ],
        oids.DOT1Q_PVID: [SnmpRow(f"{oids.DOT1Q_PVID}.1", 1, "Gauge32")],
        oids.DOT1Q_VLAN_STATIC_NAME: [
            SnmpRow(
                f"{oids.DOT1Q_VLAN_STATIC_NAME}.{_WRITE_VLAN}", "existing", "STRING"
            )
        ],
        oids.DOT1Q_VLAN_STATIC_EGRESS: [
            SnmpRow(
                f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.{_WRITE_VLAN}",
                encode_port_bitmap((1,)), "Hex-STRING",
            )
        ],
        oids.DOT1Q_VLAN_STATIC_UNTAGGED: [
            SnmpRow(
                f"{oids.DOT1Q_VLAN_STATIC_UNTAGGED}.{_WRITE_VLAN}",
                encode_port_bitmap((1,)), "Hex-STRING",
            )
        ],
        oids.IP_ADENT_ADDR: [
            SnmpRow(f"{oids.IP_ADENT_ADDR}.10.1.5.20", "10.1.5.20", "IpAddress")
        ],
        oids.IP_ADENT_NETMASK: [
            SnmpRow(f"{oids.IP_ADENT_NETMASK}.10.1.5.20", "255.255.255.0", "IpAddress")
        ],
        oids.IP_ROUTE_DEST: [
            SnmpRow(f"{oids.IP_ROUTE_DEST}.0.0.0.0", "0.0.0.0", "IpAddress")
        ],
        oids.IP_ROUTE_NEXTHOP: [
            SnmpRow(f"{oids.IP_ROUTE_NEXTHOP}.0.0.0.0", "10.1.5.1", "IpAddress")
        ],
    })
    return tables


class AllWritesRecordingClient(FakeClient):
    """Coherently applies every write op's SET(s) into the read tables, so
    each of the nine facade write methods' post-write verification passes
    without touching real network (Fix 1: full delegation coverage)."""

    def __init__(self, tables: dict[str, list[SnmpRow]]) -> None:
        super().__init__(tables)
        self.sets: list[SetVarbind] = []
        vo = oids.vendor_oids(get_model("gsm7252ps"))
        self._mgmt_addr_oid = vo.mgmt_write_addr_unverified
        self._mgmt_netmask_oid = vo.mgmt_write_netmask_unverified
        self._mgmt_gateway_oid = vo.mgmt_write_gateway_unverified
        self._mgmt_addr = "10.1.5.20"

    def set(self, vb: SetVarbind) -> None:
        self.set_many([vb])

    def set_many(self, vbs: list[SetVarbind]) -> None:
        self.sets.extend(vbs)
        for vb in vbs:
            self._apply(vb)

    def _apply(self, vb: SetVarbind) -> None:
        pse_admin_prefix = f"{oids.PETH_PSE_PORT_TABLE}.3.1."
        if vb.oid.startswith(pse_admin_prefix):
            port = int(vb.oid.rsplit(".", 1)[1])
            on = int(vb.value) == 1
            pse = oids.PETH_PSE_PORT_TABLE
            self._tables[pse] = [
                SnmpRow(f"{pse}.3.1.{port}", 1 if on else 2, "INTEGER"),
                SnmpRow(f"{pse}.6.1.{port}", 3 if on else 1, "INTEGER"),
            ]
            self._tables[oids.IF_OPER_STATUS] = [
                SnmpRow(f"{oids.IF_OPER_STATUS}.{port}", 1 if on else 2, "INTEGER")
            ]
        elif vb.oid.startswith(oids.IF_ADMIN_STATUS):
            self._tables[oids.IF_ADMIN_STATUS] = [
                SnmpRow(vb.oid, int(vb.value), "INTEGER")
            ]
        elif vb.oid.startswith(oids.DOT1Q_PVID):
            self._tables[oids.DOT1Q_PVID] = [SnmpRow(vb.oid, int(vb.value), "Gauge32")]
        elif vb.oid.startswith(oids.DOT1Q_VLAN_STATIC_EGRESS):
            self._tables[oids.DOT1Q_VLAN_STATIC_EGRESS] = [
                SnmpRow(vb.oid, vb.value, "Hex-STRING")
            ]
        elif vb.oid.startswith(oids.DOT1Q_VLAN_STATIC_UNTAGGED):
            self._tables[oids.DOT1Q_VLAN_STATIC_UNTAGGED] = [
                SnmpRow(vb.oid, vb.value, "Hex-STRING")
            ]
        elif vb.oid.startswith(oids.DOT1Q_VLAN_STATIC_ROW_STATUS):
            vid = vb.oid.rsplit(".", 1)[1]
            if int(vb.value) == oids.ROW_STATUS_DESTROY:
                self._tables[oids.DOT1Q_VLAN_STATIC_NAME] = [
                    r for r in self._tables.get(oids.DOT1Q_VLAN_STATIC_NAME, [])
                    if not r.oid.endswith(f".{vid}")
                ]
            # CREATE_AND_GO: the paired NAME SET in the same batch supplies
            # the actual row, so there is nothing to apply here.
        elif vb.oid.startswith(oids.DOT1Q_VLAN_STATIC_NAME):
            vid = vb.oid.rsplit(".", 1)[1]
            kept = [
                r for r in self._tables.get(oids.DOT1Q_VLAN_STATIC_NAME, [])
                if not r.oid.endswith(f".{vid}")
            ]
            self._tables[oids.DOT1Q_VLAN_STATIC_NAME] = [
                *kept, SnmpRow(vb.oid, vb.value, "STRING")
            ]
        elif vb.oid == self._mgmt_addr_oid:
            self._mgmt_addr = str(vb.value)
            self._tables[oids.IP_ADENT_ADDR] = [
                SnmpRow(f"{oids.IP_ADENT_ADDR}.{vb.value}", vb.value, "IpAddress")
            ]
        elif vb.oid == self._mgmt_netmask_oid:
            self._tables[oids.IP_ADENT_NETMASK] = [
                SnmpRow(
                    f"{oids.IP_ADENT_NETMASK}.{self._mgmt_addr}", vb.value, "IpAddress"
                )
            ]
        elif vb.oid == self._mgmt_gateway_oid:
            self._tables[oids.IP_ROUTE_NEXTHOP] = [
                SnmpRow(f"{oids.IP_ROUTE_NEXTHOP}.0.0.0.0", vb.value, "IpAddress")
            ]


def test_sync_switch_write_methods_delegate_to_writer() -> None:
    """Every one of the nine facade write methods reaches the injected write
    client: a full round trip (SET issued, post-write verification passes)
    for set_poe, set_port_enabled, set_pvid, set_vlan_membership,
    create_vlan, delete_vlan, cycle_poe, clear_poe_fault, and set_mgmt_ip."""
    client = AllWritesRecordingClient(_all_writes_tables())
    sw = SyncSwitch(get_model("gsm7252ps"), "host", snmp_write_client=client)
    tiny = PoeCycleTimeouts(off_timeout=1, on_timeout=1, poll_interval=0)
    vo = oids.vendor_oids(get_model("gsm7252ps"))

    sw.set_poe(1, on=False, force=True)
    assert SetVarbind(f"{oids.PETH_PSE_PORT_TABLE}.3.1.1", 2, "i") in client.sets

    sw.set_port_enabled(1, enabled=False, force=True)
    assert SetVarbind(f"{oids.IF_ADMIN_STATUS}.1", 2, "i") in client.sets

    sw.set_pvid(1, 20, force=True)
    assert SetVarbind(f"{oids.DOT1Q_PVID}.1", 20, "u") in client.sets

    sw.set_vlan_membership(_WRITE_VLAN, 2, VlanMode.TAGGED, force=True)
    assert any(
        s.oid == f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.{_WRITE_VLAN}" for s in client.sets
    )

    sw.create_vlan(_NEW_VLAN, "temp-vlan", force=True)
    assert (
        f"{oids.DOT1Q_VLAN_STATIC_NAME}.{_NEW_VLAN}", "s", "temp-vlan"
    ) in {(s.oid, s.type_letter, s.value) for s in client.sets}

    sw.delete_vlan(_NEW_VLAN, force=True)
    assert SetVarbind(
        f"{oids.DOT1Q_VLAN_STATIC_ROW_STATUS}.{_NEW_VLAN}",
        oids.ROW_STATUS_DESTROY, "i",
    ) in client.sets

    sw.cycle_poe(1, force=True, timeouts=tiny)
    admin_sets = [
        s.value for s in client.sets if s.oid == f"{oids.PETH_PSE_PORT_TABLE}.3.1.1"
    ]
    assert admin_sets[-2:] == [2, 1]  # off then on

    sw.clear_poe_fault(1, force=True, timeouts=tiny)
    admin_sets = [
        s.value for s in client.sets if s.oid == f"{oids.PETH_PSE_PORT_TABLE}.3.1.1"
    ]
    assert admin_sets[-2:] == [2, 1]  # off then on

    sw.set_mgmt_ip("10.9.9.9", "255.255.255.0", "10.9.9.1", force=True)
    assert SetVarbind(vo.mgmt_write_addr_unverified, "10.9.9.9", "a") in client.sets
    assert SetVarbind(
        vo.mgmt_write_netmask_unverified, "255.255.255.0", "a"
    ) in client.sets
    assert SetVarbind(vo.mgmt_write_gateway_unverified, "10.9.9.1", "a") in client.sets


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


def test_write_community_resolver_invoked_at_most_once_across_writes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fix 2: the write-community resolver is resolved once on the first
    write, then cached -- a second write must NOT re-invoke the resolver
    (e.g. a ``!command`` write-community spec must not re-exec its
    subprocess on every single write)."""
    calls = 0

    def counting_resolver() -> str | None:
        nonlocal calls
        calls += 1
        return "wcomm"

    monkeypatch.setattr(
        "netgear_switch.sync_api.build_sync_snmp_write_client",
        lambda host, community: RecordingWriteClient(_ports_tables()),
    )

    sw = SyncSwitch(
        get_model("gsm7252ps"), "host",
        snmp_write_community_resolver=counting_resolver,
    )
    sw.set_port_enabled(1, enabled=False, force=True)
    sw.set_port_enabled(1, enabled=True, force=True)
    assert calls == 1


def test_resolve_write_community_explicit_value_wins_over_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An explicit ``snmp_write_community`` is used as-is on the first write,
    without even consulting the resolver closure."""
    build_calls: list[tuple[str, str | None]] = []

    def fake_build_write(host: str, community: str | None) -> RecordingWriteClient:
        build_calls.append((host, community))
        return RecordingWriteClient(_ports_tables())

    monkeypatch.setattr(
        "netgear_switch.sync_api.build_sync_snmp_write_client", fake_build_write
    )

    def unused_resolver() -> str | None:
        raise AssertionError("resolver must not run when an explicit value is set")

    sw = SyncSwitch(
        get_model("gsm7252ps"), "host",
        snmp_write_community="explicit-comm",
        snmp_write_community_resolver=unused_resolver,
    )
    sw.set_port_enabled(1, enabled=False, force=True)
    assert build_calls == [("host", "explicit-comm")]


def test_resolve_write_community_defaults_to_none_without_community_or_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No explicit community and no resolver -> the write client is built
    with ``community=None`` (neither is configured)."""
    build_calls: list[tuple[str, str | None]] = []

    def fake_build_write(host: str, community: str | None) -> RecordingWriteClient:
        build_calls.append((host, community))
        return RecordingWriteClient(_ports_tables())

    monkeypatch.setattr(
        "netgear_switch.sync_api.build_sync_snmp_write_client", fake_build_write
    )

    sw = SyncSwitch(get_model("gsm7252ps"), "host")
    sw.set_port_enabled(1, enabled=False, force=True)
    assert build_calls == [("host", None)]
