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


def test_plus_model_read_routes_to_nsdp() -> None:
    # gs305ep has {NSDP, HTTP} only; now that NSDP is wired, get_ports() must
    # route to the injected NSDP client rather than raise (superseded the old
    # "backend not implemented" stub-era assertion now that Task 10 wires NSDP).
    from netgear_switch.protocols.nsdp.protocol import NSDPPacket, Op, Tag

    class FakeNsdp:
        def read(self, tags: object) -> NSDPPacket:
            pkt = NSDPPacket(
                op=Op.READ_RESPONSE, client_mac=b"\x00" * 6, server_mac=b"\xaa" * 6
            )
            pkt.add_tlv(Tag.MODEL, b"GS305EP")
            pkt.add_tlv(Tag.PORT_COUNT, b"\x05")
            pkt.add_tlv(Tag.PORT_STATUS, b"\x01\x05\x01")
            return pkt

    sw = SyncSwitch(get_model("gs305ep"), "host", nsdp_client=FakeNsdp())
    ports = sw.get_ports()
    assert ports[0].speed_mbps == 1000


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


def test_snapshot_on_plus_model_uses_nsdp_and_skips_unsupported_sections() -> None:
    # snapshot() is backend-tolerant: macs/lldp/sensors are ops NEITHER NSDP
    # NOR HTTP can serve on gs305ep, so they aggregate as empty instead of
    # raising. poe is an NSDP gap that HTTP DOES serve (Task 9 per-op
    # routing), so with an HTTP client available it populates too, instead of
    # skipping as it did before HTTP was wired.
    from netgear_switch.protocols.nsdp.protocol import NSDPPacket, Op, Tag

    class FakeNsdp:
        def read(self, tags: object) -> NSDPPacket:
            pkt = NSDPPacket(
                op=Op.READ_RESPONSE, client_mac=b"\x00" * 6, server_mac=b"\xaa" * 6
            )
            pkt.add_tlv(Tag.MODEL, b"GS305EP")
            pkt.add_tlv(Tag.PORT_COUNT, b"\x05")
            pkt.add_tlv(Tag.PORT_STATUS, b"\x01\x05\x01")
            return pkt

    class FakeHttp:
        def login(self) -> None: ...
        def get_page(self, path: str) -> str:
            if path == "/getPoePortStatus.cgi":
                return (
                    '<tr class="portID"><td>1</td><td>Delivering</td>'
                    '<td>12800</td></tr>'
                )
            return "<input name='hash' value='h'>"
        def post_form(self, path: str, data: dict[str, str]) -> str:
            return ""

    sw = SyncSwitch(
        get_model("gs305ep"), "host", nsdp_client=FakeNsdp(), http_client=FakeHttp()
    )
    data = sw.snapshot()
    assert len(data.ports) == 1
    assert data.macs == ()
    assert data.lldp == ()
    assert data.sensors == ()
    assert len(data.poe) == 1
    assert data.poe[0].power_mw == 12800


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
    # NSDP has no per-port admin-enable tag, so the NsdpWriter refuses (without
    # ever touching the client -- DummyNsdp asserts it is never called);
    # per-op routing then falls through to HTTP, whose writer ALSO has no
    # grounded port-enable endpoint and refuses too (without ever resolving an
    # HTTP password -- construction never even reaches the wire). The last
    # UnsupportedCapabilityError raised (HTTP's) is what the caller sees.
    class DummyNsdp:
        def read(self, tags: object) -> None:
            raise AssertionError("must not be called")

        def write(self, tlvs: object, *, password: str) -> None:
            raise AssertionError("must not be called")

    sw = SyncSwitch(
        get_model("gs305ep"), "host",  # {NSDP, HTTP} only
        nsdp_write_client=DummyNsdp(), nsdp_password="admin",
    )
    with pytest.raises(UnsupportedCapabilityError) as exc:
        sw.set_port_enabled(1, enabled=False, force=True)
    assert "port-enable" in str(exc.value)


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


def test_sync_switch_plus_model_reads_over_nsdp() -> None:
    from netgear_switch.protocols.nsdp.protocol import NSDPPacket, Op, Tag

    class FakeNsdp:
        def read(self, tags):
            pkt = NSDPPacket(op=Op.READ_RESPONSE, client_mac=b"\x00" * 6,
                             server_mac=b"\xaa" * 6)
            pkt.add_tlv(Tag.MODEL, b"GS110EMX")
            pkt.add_tlv(Tag.PORT_COUNT, b"\x0a")
            pkt.add_tlv(Tag.PORT_STATUS, b"\x01\x05\x01")
            return pkt

        def write(self, tlvs, *, password):  # unused here
            return NSDPPacket(op=Op.WRITE_RESPONSE, client_mac=b"\x00" * 6)

    sw = SyncSwitch(get_model("gs110emx"), "10.1.5.20", nsdp_client=FakeNsdp())
    assert sw.get_ports()[0].speed_mbps == 1000
    # A Plus model has no MAC table: facade guard raises before the reader.
    with pytest.raises(UnsupportedCapabilityError):
        sw.get_macs()


def test_sync_switch_plus_set_pvid_over_nsdp() -> None:
    from netgear_switch.protocols.nsdp.protocol import NSDPPacket, Op, Tag

    class RecordingNsdp:
        def __init__(self) -> None:
            self.pvids = {1: 1}
            self.writes: list[str] = []

        def read(self, tags):
            import struct
            pkt = NSDPPacket(op=Op.READ_RESPONSE, client_mac=b"\x00" * 6,
                             server_mac=b"\xaa" * 6)
            pkt.add_tlv(Tag.MODEL, b"GS110EMX")
            pkt.add_tlv(Tag.PORT_COUNT, b"\x0a")
            for p, v in self.pvids.items():
                pkt.add_tlv(Tag.PORT_PVID, bytes([p]) + struct.pack(">H", v))
            return pkt

        def write(self, tlvs, *, password):
            import struct
            self.writes.append(password)
            for t in tlvs:
                if t.tag == Tag.PORT_PVID:
                    self.pvids[t.value[0]] = struct.unpack_from(">H", t.value, 1)[0]
            return NSDPPacket(op=Op.WRITE_RESPONSE, client_mac=b"\x00" * 6, result=0)

    client = RecordingNsdp()
    sw = SyncSwitch(get_model("gs110emx"), "10.1.5.20",
                    nsdp_write_client=client, nsdp_client=client,
                    nsdp_password="admin")
    sw.set_pvid(1, 90)
    assert client.pvids[1] == 90
    assert client.writes == ["admin"]


# --- Task 9: per-op three-way backend routing (SNMP > NSDP > HTTP) ---------


def test_gs305ep_poe_routes_to_http_ports_stay_nsdp() -> None:
    # Per-op routing: PoE is an NSDP gap → served by HTTP; the facade must fall
    # through NSDP (which raises UnsupportedCapabilityError for get_poe) to HTTP.
    from netgear_switch.registry import get_model
    from netgear_switch.sync_api import SyncSwitch

    class _HttpSess:
        def login(self) -> None: ...
        def get_page(self, path: str) -> str:
            if path == "/getPoePortStatus.cgi":
                return (
                    '<tr class="portID"><td>1</td><td>Delivering</td>'
                    '<td>12800</td></tr>'
                )
            return "<input name='hash' value='h'>"
        def post_form(self, path: str, data: dict[str, str]) -> str:
            return ""

    # NsdpReader.get_poe() raises UnsupportedCapabilityError WITHOUT touching its
    # client, so a bare object() is a safe stand-in for the (unused) NSDP client.
    sw = SyncSwitch(
        get_model("gs305ep"), "sw.example",
        nsdp_client=object(), nsdp_password="x", http_client=_HttpSess(),
    )
    poe = sw.get_poe()
    assert poe[0].port == 1
    assert poe[0].power_mw == 12800  # came from HTTP, proving NSDP→HTTP fallback


def test_gsm7228ps_http_gated_off_for_read_and_write() -> None:
    # Guard the intent: gsm7228ps is SNMP-authoritative; its HTTP backend must
    # never participate in read/write dispatch (HTTP is reserved for firmware/
    # reboot). Proven by _reader_for/_writer_for(Backend.HTTP) refusing.
    from netgear_switch.errors import UnsupportedCapabilityError
    from netgear_switch.registry import Backend, get_model
    from netgear_switch.sync_api import SyncSwitch

    sw = SyncSwitch(get_model("gsm7228ps"), "h")
    with pytest.raises(UnsupportedCapabilityError):
        sw._reader_for(Backend.HTTP)
    with pytest.raises(UnsupportedCapabilityError):
        sw._writer_for(Backend.HTTP)


def test_http_password_resolved_lazily(monkeypatch: pytest.MonkeyPatch) -> None:
    from netgear_switch.config import SwitchConfig
    from netgear_switch.registry import get_model
    from netgear_switch.sync_api import SyncSwitch

    cfg = SwitchConfig(
        name="p", model=get_model("gs305ep"), host="h",
        snmp_community=None, snmp_write_community_spec=None,
        http_password_spec="${MISSING_HTTP_PW}", nsdp_interface=None,
        protected_ports=frozenset(),
    )
    # Construction must NOT raise even though the spec is unresolvable.
    sw = SyncSwitch.from_config(cfg, env={})
    assert sw.model.key == "gs305ep"


def test_http_client_closed_after_http_routed_op(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # HTTP is the only one of the three backends holding a persistent
    # connection (SNMP/NSDP build fresh per call and need no teardown); the
    # facade must close any HttpClient IT builds, via context-manager exit.
    from netgear_switch.registry import get_model
    from netgear_switch.sync_api import SyncSwitch

    class _SpyHttpClient:
        def __init__(self) -> None:
            self.closed = False

        def login(self) -> None: ...

        def get_page(self, path: str) -> str:
            if path == "/getPoePortStatus.cgi":
                return (
                    '<tr class="portID"><td>1</td><td>Delivering</td>'
                    '<td>12800</td></tr>'
                )
            return "<input name='hash' value='h'>"

        def post_form(self, path: str, data: dict[str, str]) -> str:
            return ""

        def close(self) -> None:
            self.closed = True

    spy = _SpyHttpClient()
    monkeypatch.setattr(
        "netgear_switch.sync_api.build_sync_http_client",
        lambda host, password, model: spy,
    )

    with SyncSwitch(
        get_model("gs305ep"), "sw.example",
        nsdp_client=object(), nsdp_password="x", http_password="secret",
    ) as sw:
        poe = sw.get_poe()
        assert poe[0].port == 1
        assert spy.closed is False  # still in use inside the `with` block

    assert spy.closed is True  # torn down on context-manager exit


def test_injected_http_client_is_never_closed_by_facade() -> None:
    # An HttpSession the caller injected is the caller's to close, not ours;
    # `close()` must never touch it.
    from netgear_switch.registry import get_model
    from netgear_switch.sync_api import SyncSwitch

    class _HttpSess:
        def login(self) -> None: ...

        def get_page(self, path: str) -> str:
            if path == "/getPoePortStatus.cgi":
                return (
                    '<tr class="portID"><td>1</td><td>Delivering</td>'
                    '<td>12800</td></tr>'
                )
            return "<input name='hash' value='h'>"

        def post_form(self, path: str, data: dict[str, str]) -> str:
            return ""

        def close(self) -> None:
            raise AssertionError("facade must never close a caller-injected client")

    with SyncSwitch(
        get_model("gs305ep"), "sw.example",
        nsdp_client=object(), nsdp_password="x", http_client=_HttpSess(),
    ) as sw:
        sw.get_poe()
    # __exit__ ran close() above; no AssertionError means the injected
    # session's close() was correctly never invoked.


def test_delete_vlan_guards_protected_member_before_http_fallback() -> None:
    # NsdpWriter.delete_vlan ALWAYS raises UnsupportedCapabilityError (NSDP has
    # no VLAN lifecycle ops), so on a {NSDP, HTTP} model delete_vlan always
    # falls through to HttpWriter -- which does NOT itself guard protected
    # member ports on delete (only per-port ops carry its internal `_guard`;
    # see HttpWriter.delete_vlan's docstring: "guarded per-member elsewhere").
    # The facade must supply that missing safety rail itself, BEFORE HTTP is
    # ever touched.
    import struct

    from netgear_switch.errors import ProtectedPortError
    from netgear_switch.protocols.nsdp.protocol import NSDPPacket, Op, Tag
    from netgear_switch.registry import get_model
    from netgear_switch.sync_api import SyncSwitch

    class FakeNsdp:
        def read(self, tags: object) -> NSDPPacket:
            pkt = NSDPPacket(
                op=Op.READ_RESPONSE, client_mac=b"\x00" * 6, server_mac=b"\xaa" * 6
            )
            pkt.add_tlv(Tag.MODEL, b"GS305EP")
            pkt.add_tlv(Tag.PORT_COUNT, b"\x05")
            pkt.add_tlv(
                Tag.VLAN_MEMBERS,
                struct.pack(">H", 90) + bytes([0b1000_0000, 0]) + bytes([0, 0]),
            )  # vlan 90 has protected port 1 as an untagged member
            return pkt

        def write(self, tlvs: object, *, password: str) -> None:
            raise AssertionError("NSDP has no VLAN lifecycle; must not be written")

    class _RaisingHttpSess:
        def login(self) -> None:
            raise AssertionError("guard must refuse before HTTP is ever touched")

        def get_page(self, path: str) -> str:
            raise AssertionError("guard must refuse before HTTP is ever touched")

        def post_form(self, path: str, data: dict[str, str]) -> str:
            raise AssertionError("guard must refuse before HTTP is ever touched")

    sw = SyncSwitch(
        get_model("gs305ep"), "sw.example",
        nsdp_client=FakeNsdp(), http_client=_RaisingHttpSess(),
        protected_ports=frozenset({1}),
    )
    with pytest.raises(ProtectedPortError):
        sw.delete_vlan(90)  # force=False: must refuse, never reach HTTP
