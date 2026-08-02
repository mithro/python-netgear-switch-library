from __future__ import annotations

import asyncio

import pytest

from netgear_switch.aio_api import AsyncSwitch, async_detect_model
from netgear_switch.config import SwitchConfig
from netgear_switch.errors import UnsupportedCapabilityError
from netgear_switch.models import VlanMode
from netgear_switch.protocols.snmp import oids
from netgear_switch.protocols.snmp.client import SnmpRow
from netgear_switch.protocols.snmp.write import SetVarbind, encode_port_bitmap
from netgear_switch.registry import get_model
from netgear_switch.snmp_write import PoeCycleTimeouts
from snmp_fakes import walk_by_prefix


class FakeAsyncClient:
    """Async twin of Task 2's FakeClient: identical lookup, async methods."""

    def __init__(self, tables: dict[str, list[SnmpRow]]) -> None:
        self._tables = tables

    async def get(self, oids: list[str]) -> list[SnmpRow]:
        rows: list[SnmpRow] = []
        for oid in oids:
            rows.extend(await self.walk(oid))
        return rows

    async def walk(self, base_oid: str) -> list[SnmpRow]:
        return walk_by_prefix(self._tables, base_oid)


def _ports_tables() -> dict[str, list[SnmpRow]]:
    return {
        oids.IF_ADMIN_STATUS: [SnmpRow(f"{oids.IF_ADMIN_STATUS}.1", 1, "INTEGER")],
        oids.IF_OPER_STATUS: [SnmpRow(f"{oids.IF_OPER_STATUS}.1", 1, "INTEGER")],
        oids.IF_HIGH_SPEED: [SnmpRow(f"{oids.IF_HIGH_SPEED}.1", 1000, "Gauge32")],
        oids.IF_NAME: [SnmpRow(f"{oids.IF_NAME}.1", "1/0/1", "STRING")],
    }


def test_get_ports_delegates_to_injected_async_client() -> None:
    sw = AsyncSwitch(
        get_model("gsm7252ps"), "host", snmp_client=FakeAsyncClient(_ports_tables())
    )
    ports = asyncio.run(sw.get_ports())
    assert ports[0].port == 1
    assert ports[0].name == "1/0/1"
    assert ports[0].speed_mbps == 1000


def test_plus_model_read_routes_to_nsdp() -> None:
    # gs305ep has {NSDP, HTTP} only; now that NSDP is wired, get_ports() must
    # route to the injected NSDP client rather than raise (superseded the old
    # "backend not implemented" stub-era assertion now that Task 10 wires NSDP).
    from netgear_switch.protocols.nsdp.protocol import NSDPPacket, Op, Tag

    class FakeAsyncNsdp:
        async def read(self, tags: object) -> NSDPPacket:
            pkt = NSDPPacket(
                op=Op.READ_RESPONSE, client_mac=b"\x00" * 6, server_mac=b"\xaa" * 6
            )
            pkt.add_tlv(Tag.MODEL, b"GS305EP")
            pkt.add_tlv(Tag.PORT_COUNT, b"\x05")
            pkt.add_tlv(Tag.PORT_STATUS, b"\x01\x05\x01")
            return pkt

    sw = AsyncSwitch(get_model("gs305ep"), "host", nsdp_client=FakeAsyncNsdp())
    ports = asyncio.run(sw.get_ports())
    assert ports[0].speed_mbps == 1000


def test_get_macs_on_plus_model_raises_no_mac_table() -> None:
    sw = AsyncSwitch(get_model("gs305ep"), "host")
    with pytest.raises(UnsupportedCapabilityError):
        asyncio.run(sw.get_macs())


def test_snapshot_on_plus_model_uses_nsdp_and_skips_unsupported_sections() -> None:
    # Mirror of the sync test: snapshot() describes ONE backend and tolerates
    # that backend's gaps (macs/lldp/sensors AND poe are all things NSDP cannot
    # serve on gs305ep). poe is NOT filled in from HTTP behind the caller's back
    # any more -- see test_gs305ep_poe_needs_an_explicit_http_backend.
    from netgear_switch.protocols.nsdp.protocol import NSDPPacket, Op, Tag

    class FakeAsyncNsdp:
        async def read(self, tags: object) -> NSDPPacket:
            pkt = NSDPPacket(
                op=Op.READ_RESPONSE, client_mac=b"\x00" * 6, server_mac=b"\xaa" * 6
            )
            pkt.add_tlv(Tag.MODEL, b"GS305EP")
            pkt.add_tlv(Tag.PORT_COUNT, b"\x05")
            pkt.add_tlv(Tag.PORT_STATUS, b"\x01\x05\x01")
            return pkt

    class FakeAsyncHttp:
        async def login(self) -> None: ...
        async def get_page(self, path: str) -> str:
            if path == "/getPoePortStatus.cgi":
                return (
                    '<tr class="portID"><td>1</td><td>Delivering</td>'
                    "<td>12800</td></tr>"
                )
            return "<input name='hash' value='h'>"

        async def post_form(self, path: str, data: dict[str, str]) -> str:
            return ""

    sw = AsyncSwitch(
        get_model("gs305ep"),
        "host",
        nsdp_client=FakeAsyncNsdp(),
        http_client=FakeAsyncHttp(),
    )
    data = asyncio.run(sw.snapshot())
    assert len(data.ports) == 1
    assert data.macs == ()
    assert data.lldp == ()
    assert data.sensors == ()
    assert data.poe == ()  # NSDP has no PoE status; nothing substitutes for it


def test_from_config_builds_facade_without_touching_network() -> None:
    """Async from_config mirrors sync test: builds facade without network access."""
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
    sw = AsyncSwitch.from_config(cfg)
    assert sw.host == "10.0.0.9"
    assert sw.model.key == "gsm7252ps"


def test_reader_builds_default_client_when_not_injected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When no client injected, _reader() calls builder; verify the default branch."""
    build_calls: list[tuple[str, str | None]] = []

    def fake_build(host: str, community: str | None) -> FakeAsyncClient:
        build_calls.append((host, community))
        return FakeAsyncClient(_ports_tables())

    monkeypatch.setattr("netgear_switch.aio_api.build_async_snmp_client", fake_build)

    sw = AsyncSwitch(get_model("gsm7252ps"), "10.0.0.5")
    ports = asyncio.run(sw.get_ports())

    assert len(build_calls) == 1
    assert build_calls[0] == ("10.0.0.5", None)
    assert len(ports) > 0
    assert ports[0].port == 1


class RecordingAsyncWriteClient(FakeAsyncClient):
    def __init__(self, tables: dict[str, list[SnmpRow]]) -> None:
        super().__init__(tables)
        self.sets: list[SetVarbind] = []

    async def set(self, vb: SetVarbind) -> None:
        await self.set_many([vb])

    async def set_many(self, vbs: list[SetVarbind]) -> None:
        self.sets.extend(vbs)
        for vb in vbs:  # apply ifAdminStatus so verify passes
            if vb.oid.startswith(oids.IF_ADMIN_STATUS):
                self._tables[oids.IF_ADMIN_STATUS] = [
                    SnmpRow(vb.oid, int(vb.value), "INTEGER")
                ]


def test_async_switch_set_port_enabled_delegates_to_writer() -> None:
    tables = _ports_tables()
    client = RecordingAsyncWriteClient(tables)
    sw = AsyncSwitch(get_model("gsm7252ps"), "host", snmp_write_client=client)
    asyncio.run(sw.set_port_enabled(1, enabled=False, force=True))
    assert client.sets == [SetVarbind(f"{oids.IF_ADMIN_STATUS}.1", 2, "i")]


_WRITE_VLAN = 10  # pre-existing VLAN used by set_vlan_membership
_NEW_VLAN = 999  # created then deleted by create_vlan/delete_vlan


def _all_writes_tables() -> dict[str, list[SnmpRow]]:
    """Async twin of the sync facade test's table seed (see test_sync_api.py):
    every facade write method's happy path on port 1, coherent enough that
    each op's post-write verification passes."""
    tables = _ports_tables()
    tables.update(
        {
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
                    encode_port_bitmap((1,)),
                    "Hex-STRING",
                )
            ],
            oids.DOT1Q_VLAN_STATIC_UNTAGGED: [
                SnmpRow(
                    f"{oids.DOT1Q_VLAN_STATIC_UNTAGGED}.{_WRITE_VLAN}",
                    encode_port_bitmap((1,)),
                    "Hex-STRING",
                )
            ],
            oids.IP_ADENT_ADDR: [
                SnmpRow(f"{oids.IP_ADENT_ADDR}.10.1.5.20", "10.1.5.20", "IpAddress")
            ],
            oids.IP_ADENT_NETMASK: [
                SnmpRow(
                    f"{oids.IP_ADENT_NETMASK}.10.1.5.20", "255.255.255.0", "IpAddress"
                )
            ],
            oids.IP_ROUTE_DEST: [
                SnmpRow(f"{oids.IP_ROUTE_DEST}.0.0.0.0", "0.0.0.0", "IpAddress")
            ],
            oids.IP_ROUTE_NEXTHOP: [
                SnmpRow(f"{oids.IP_ROUTE_NEXTHOP}.0.0.0.0", "10.1.5.1", "IpAddress")
            ],
        }
    )
    return tables


class AllWritesRecordingAsyncClient(FakeAsyncClient):
    """Async twin of ``AllWritesRecordingClient`` (test_sync_api.py): applies
    every write op's SET(s) into the read tables coherently, so each of the
    nine facade write methods' post-write verification passes (Fix 1)."""

    def __init__(self, tables: dict[str, list[SnmpRow]]) -> None:
        super().__init__(tables)
        self.sets: list[SetVarbind] = []
        vo = oids.vendor_oids(get_model("gsm7252ps"))
        self._mgmt_addr_oid = vo.mgmt_write_addr_unverified
        self._mgmt_netmask_oid = vo.mgmt_write_netmask_unverified
        self._mgmt_gateway_oid = vo.mgmt_write_gateway_unverified
        self._mgmt_addr = "10.1.5.20"

    async def set(self, vb: SetVarbind) -> None:
        await self.set_many([vb])

    async def set_many(self, vbs: list[SetVarbind]) -> None:
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
                    r
                    for r in self._tables.get(oids.DOT1Q_VLAN_STATIC_NAME, [])
                    if not r.oid.endswith(f".{vid}")
                ]
            # CREATE_AND_GO: the paired NAME SET in the same batch supplies
            # the actual row, so there is nothing to apply here.
        elif vb.oid.startswith(oids.DOT1Q_VLAN_STATIC_NAME):
            vid = vb.oid.rsplit(".", 1)[1]
            kept = [
                r
                for r in self._tables.get(oids.DOT1Q_VLAN_STATIC_NAME, [])
                if not r.oid.endswith(f".{vid}")
            ]
            self._tables[oids.DOT1Q_VLAN_STATIC_NAME] = [
                *kept,
                SnmpRow(vb.oid, vb.value, "STRING"),
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


def test_async_switch_write_methods_delegate_to_writer() -> None:
    """Async mirror of the sync facade delegation test: every one of the nine
    facade write methods reaches the injected async write client with a full
    round trip (SET issued, post-write verification passes)."""
    client = AllWritesRecordingAsyncClient(_all_writes_tables())
    sw = AsyncSwitch(get_model("gsm7252ps"), "host", snmp_write_client=client)
    tiny = PoeCycleTimeouts(off_timeout=1, on_timeout=1, poll_interval=0)
    vo = oids.vendor_oids(get_model("gsm7252ps"))

    async def _run() -> None:
        await sw.set_poe(1, on=False, force=True)
        assert SetVarbind(f"{oids.PETH_PSE_PORT_TABLE}.3.1.1", 2, "i") in client.sets

        await sw.set_port_enabled(1, enabled=False, force=True)
        assert SetVarbind(f"{oids.IF_ADMIN_STATUS}.1", 2, "i") in client.sets

        # _WRITE_VLAN, not an arbitrary id: set_pvid refuses a PVID pointing at
        # a VLAN the switch does not have (see the sync twin).
        await sw.set_pvid(1, _WRITE_VLAN, force=True)
        assert SetVarbind(f"{oids.DOT1Q_PVID}.1", _WRITE_VLAN, "u") in client.sets

        await sw.set_vlan_membership(_WRITE_VLAN, 2, VlanMode.TAGGED, force=True)
        assert any(
            s.oid == f"{oids.DOT1Q_VLAN_STATIC_EGRESS}.{_WRITE_VLAN}"
            for s in client.sets
        )

        await sw.create_vlan(_NEW_VLAN, "temp-vlan", force=True)
        assert (f"{oids.DOT1Q_VLAN_STATIC_NAME}.{_NEW_VLAN}", "s", "temp-vlan") in {
            (s.oid, s.type_letter, s.value) for s in client.sets
        }

        await sw.delete_vlan(_NEW_VLAN, force=True)
        assert (
            SetVarbind(
                f"{oids.DOT1Q_VLAN_STATIC_ROW_STATUS}.{_NEW_VLAN}",
                oids.ROW_STATUS_DESTROY,
                "i",
            )
            in client.sets
        )

        await sw.cycle_poe(1, force=True, timeouts=tiny)
        admin_sets = [
            s.value for s in client.sets if s.oid == f"{oids.PETH_PSE_PORT_TABLE}.3.1.1"
        ]
        assert admin_sets[-2:] == [2, 1]  # off then on

        await sw.clear_poe_fault(1, force=True, timeouts=tiny)
        admin_sets = [
            s.value for s in client.sets if s.oid == f"{oids.PETH_PSE_PORT_TABLE}.3.1.1"
        ]
        assert admin_sets[-2:] == [2, 1]  # off then on

        await sw.set_mgmt_ip("10.9.9.9", "255.255.255.0", "10.9.9.1", force=True)
        assert SetVarbind(vo.mgmt_write_addr_unverified, "10.9.9.9", "a") in client.sets
        assert (
            SetVarbind(vo.mgmt_write_netmask_unverified, "255.255.255.0", "a")
            in client.sets
        )
        assert (
            SetVarbind(vo.mgmt_write_gateway_unverified, "10.9.9.1", "a") in client.sets
        )

    asyncio.run(_run())


def test_plus_model_write_raises_unsupported_capability() -> None:
    # gs305ep's DEFAULT backend is NSDP, and NSDP cannot serve a per-port
    # admin-enable, so the AsyncNsdpWriter refuses -- without ever touching the
    # client (DummyAsyncNsdp asserts it is never called). There is no
    # cross-backend fallback any more, so that refusal is what the caller sees,
    # and it must carry the measurement rather than a bare claim (see the sync
    # twin in test_sync_api.py).
    class DummyAsyncNsdp:
        async def read(self, tags: object) -> None:
            raise AssertionError("must not be called")

        async def write(self, tlvs: object, *, password: str) -> None:
            raise AssertionError("must not be called")

    sw = AsyncSwitch(
        get_model("gs305ep"),
        "host",  # {NSDP, HTTP} only
        nsdp_write_client=DummyAsyncNsdp(),
        nsdp_password="admin",
    )
    with pytest.raises(UnsupportedCapabilityError) as exc:
        asyncio.run(sw.set_port_enabled(1, enabled=False, force=True))
    message = str(exc.value)
    assert "admin-enable over NSDP is UNPROVEN" in message
    assert "GS110EMX fw 1.0.2.8" in message  # names what was measured, and where
    assert "Use the HTTP backend" in message  # and where the capability does live


def test_from_config_write_community_resolves_lazily_not_at_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Async mirror of the sync lazy-write-community test (review item 4):
    from_config must not resolve/raise at construction; only the first
    awaited write resolves the spec and raises."""
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
        "netgear_switch.aio_api.build_async_snmp_client",
        lambda host, community: FakeAsyncClient(_ports_tables()),
    )

    # Construction resolves nothing -> no CredentialError here.
    sw = AsyncSwitch.from_config(cfg)
    # Read ops still work.
    ports = asyncio.run(sw.get_ports())
    assert ports[0].port == 1
    # First awaited write resolves the spec lazily -> now it raises.
    with pytest.raises(CredentialError):
        asyncio.run(sw.set_port_enabled(1, enabled=False, force=True))


def test_from_config_write_community_resolves_and_writes_when_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A resolvable write-community spec flows through to the async
    write-client builder lazily on first write."""
    monkeypatch.setenv("NETGEAR_WRITE_OK", "wcomm")
    monkeypatch.setattr(
        "netgear_switch.aio_api.build_async_snmp_client",
        lambda host, community: FakeAsyncClient(_ports_tables()),
    )
    build_calls: list[tuple[str, str | None]] = []

    def fake_build_write(host: str, community: str | None) -> RecordingAsyncWriteClient:
        build_calls.append((host, community))
        return RecordingAsyncWriteClient(_ports_tables())

    monkeypatch.setattr(
        "netgear_switch.aio_api.build_async_snmp_write_client", fake_build_write
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
    sw = AsyncSwitch.from_config(cfg)
    assert build_calls == []  # not resolved at construction
    asyncio.run(sw.set_port_enabled(1, enabled=False, force=True))
    assert build_calls == [("10.0.0.9", "wcomm")]


def test_write_community_resolver_invoked_at_most_once_across_writes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Async mirror of the sync memoization test (Fix 2): the write-community
    resolver is resolved once on the first write, then cached -- a second
    write must NOT re-invoke the resolver."""
    calls = 0

    def counting_resolver() -> str | None:
        nonlocal calls
        calls += 1
        return "wcomm"

    monkeypatch.setattr(
        "netgear_switch.aio_api.build_async_snmp_write_client",
        lambda host, community: RecordingAsyncWriteClient(_ports_tables()),
    )

    sw = AsyncSwitch(
        get_model("gsm7252ps"),
        "host",
        snmp_write_community_resolver=counting_resolver,
    )
    asyncio.run(sw.set_port_enabled(1, enabled=False, force=True))
    asyncio.run(sw.set_port_enabled(1, enabled=True, force=True))
    assert calls == 1


def test_resolve_write_community_explicit_value_wins_over_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Async mirror: an explicit ``snmp_write_community`` is used as-is on
    the first write, without even consulting the resolver closure."""
    build_calls: list[tuple[str, str | None]] = []

    def fake_build_write(host: str, community: str | None) -> RecordingAsyncWriteClient:
        build_calls.append((host, community))
        return RecordingAsyncWriteClient(_ports_tables())

    monkeypatch.setattr(
        "netgear_switch.aio_api.build_async_snmp_write_client", fake_build_write
    )

    def unused_resolver() -> str | None:
        raise AssertionError("resolver must not run when an explicit value is set")

    sw = AsyncSwitch(
        get_model("gsm7252ps"),
        "host",
        snmp_write_community="explicit-comm",
        snmp_write_community_resolver=unused_resolver,
    )
    asyncio.run(sw.set_port_enabled(1, enabled=False, force=True))
    assert build_calls == [("host", "explicit-comm")]


def test_resolve_write_community_defaults_to_none_without_community_or_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Async mirror: no explicit community and no resolver -> the write
    client is built with ``community=None``."""
    build_calls: list[tuple[str, str | None]] = []

    def fake_build_write(host: str, community: str | None) -> RecordingAsyncWriteClient:
        build_calls.append((host, community))
        return RecordingAsyncWriteClient(_ports_tables())

    monkeypatch.setattr(
        "netgear_switch.aio_api.build_async_snmp_write_client", fake_build_write
    )

    sw = AsyncSwitch(get_model("gsm7252ps"), "host")
    asyncio.run(sw.set_port_enabled(1, enabled=False, force=True))
    assert build_calls == [("host", None)]


def test_async_switch_plus_model_reads_over_nsdp() -> None:
    from netgear_switch.protocols.nsdp.protocol import NSDPPacket, Op, Tag

    class FakeAsyncNsdp:
        async def read(self, tags):
            pkt = NSDPPacket(
                op=Op.READ_RESPONSE, client_mac=b"\x00" * 6, server_mac=b"\xaa" * 6
            )
            pkt.add_tlv(Tag.MODEL, b"GS110EMX")
            pkt.add_tlv(Tag.PORT_COUNT, b"\x0a")
            pkt.add_tlv(Tag.PORT_STATUS, b"\x01\x05\x01")
            return pkt

        async def write(self, tlvs, *, password):  # unused here
            return NSDPPacket(op=Op.WRITE_RESPONSE, client_mac=b"\x00" * 6)

    async def _run() -> None:
        sw = AsyncSwitch(
            get_model("gs110emx"), "10.1.5.20", nsdp_client=FakeAsyncNsdp()
        )
        ports = await sw.get_ports()
        assert ports[0].speed_mbps == 1000
        # A Plus model has no MAC table: facade guard raises before the reader.
        with pytest.raises(UnsupportedCapabilityError):
            await sw.get_macs()

    asyncio.run(_run())


def test_async_upload_certificate_scp_raises_cli_is_synchronous() -> None:
    """upload_certificate_scp is CLI/SCP-based; the async facade has no CLI
    backend (CLI is synchronous), so the method EXISTS for API-surface parity
    with SyncSwitch but honestly raises UnsupportedCapabilityError -- mirroring
    how async CLI reads/writes are rejected, never a silent AttributeError."""

    async def _run() -> None:
        sw = AsyncSwitch(get_model("m4300-16x"), "10.1.5.20")
        with pytest.raises(UnsupportedCapabilityError, match="synchronous"):
            await sw.upload_certificate_scp(
                scp_source="user@host", scp_password="pw", remote_dir="/tmp"
            )

    asyncio.run(_run())


def test_async_switch_plus_set_pvid_over_nsdp() -> None:
    from netgear_switch.protocols.nsdp.protocol import NSDPPacket, Op, Tag

    class RecordingAsyncNsdp:
        def __init__(self) -> None:
            self.pvids = {1: 1}
            self.writes: list[str] = []

        async def read(self, tags):
            import struct

            pkt = NSDPPacket(
                op=Op.READ_RESPONSE, client_mac=b"\x00" * 6, server_mac=b"\xaa" * 6
            )
            pkt.add_tlv(Tag.MODEL, b"GS110EMX")
            pkt.add_tlv(Tag.PORT_COUNT, b"\x0a")
            # VLAN 90 exists here -- see the sync twin: set_pvid refuses a PVID
            # pointing at a VLAN the device does not have.
            pkt.add_tlv(
                Tag.VLAN_MEMBERS, struct.pack(">H", 90) + b"\x80\x00" + b"\x00\x00"
            )
            for p, v in self.pvids.items():
                pkt.add_tlv(Tag.PORT_PVID, bytes([p]) + struct.pack(">H", v))
            return pkt

        async def write(self, tlvs, *, password):
            import struct

            self.writes.append(password)
            for t in tlvs:
                if t.tag == Tag.PORT_PVID:
                    self.pvids[t.value[0]] = struct.unpack_from(">H", t.value, 1)[0]
            return NSDPPacket(op=Op.WRITE_RESPONSE, client_mac=b"\x00" * 6, result=0)

    async def _run() -> None:
        client = RecordingAsyncNsdp()
        sw = AsyncSwitch(
            get_model("gs110emx"),
            "10.1.5.20",
            nsdp_write_client=client,
            nsdp_client=client,
            nsdp_password="admin",
        )
        await sw.set_pvid(1, 90)
        assert client.pvids[1] == 90
        assert client.writes == ["admin"]

    asyncio.run(_run())


# --- explicit backend selection: NO silent protocol substitution ------------


def test_gs305ep_poe_needs_an_explicit_http_backend() -> None:
    # Async mirror of the sync test: PoE is a genuine NSDP gap, NSDP is this
    # model's default backend, so the op RAISES (naming NSDP and pointing at
    # HTTP) instead of quietly answering over a protocol the caller did not ask
    # for. Requesting HTTP explicitly works.
    from netgear_switch.errors import UnsupportedCapabilityError
    from netgear_switch.registry import Backend, get_model

    class _AsyncHttpSess:
        async def login(self) -> None: ...
        async def get_page(self, path: str) -> str:
            if path == "/getPoePortStatus.cgi":
                return (
                    '<tr class="portID"><td>1</td><td>Delivering</td>'
                    "<td>12800</td></tr>"
                )
            return "<input name='hash' value='h'>"

        async def post_form(self, path: str, data: dict[str, str]) -> str:
            return ""

    async def _run() -> None:
        # AsyncNsdpReader.get_poe() raises UnsupportedCapabilityError WITHOUT
        # touching its client, so a bare object() is a safe NSDP stand-in.
        sw = AsyncSwitch(
            get_model("gs305ep"),
            "sw.example",
            nsdp_client=object(),
            nsdp_password="x",
            http_client=_AsyncHttpSess(),
        )
        with pytest.raises(UnsupportedCapabilityError) as exc:
            await sw.get_poe()
        assert "NSDP" in str(exc.value)
        assert "HTTP" in str(exc.value)
        poe = await sw.get_poe(backend=Backend.HTTP)
        assert poe[0].port == 1
        assert poe[0].power_mw == 12800

    asyncio.run(_run())


def test_async_requested_backend_is_never_substituted() -> None:
    from netgear_switch.errors import UnsupportedCapabilityError
    from netgear_switch.registry import Backend, get_model

    async def _run() -> None:
        sw = AsyncSwitch(get_model("gs305ep"), "sw.example", nsdp_client=object())
        with pytest.raises(UnsupportedCapabilityError) as exc:
            await sw.get_ports(backend=Backend.SNMP)
        assert "no SNMP backend" in str(exc.value)

    asyncio.run(_run())


def test_async_default_backend_resolution_is_deterministic() -> None:
    from netgear_switch.registry import Backend, get_model

    assert AsyncSwitch(get_model("gs305ep"), "h").resolve_backend() is Backend.NSDP
    assert AsyncSwitch(get_model("gsm7252ps"), "h").resolve_backend() is Backend.SNMP
    sw = AsyncSwitch(get_model("gsm7252ps"), "h")
    assert sw.resolve_backend(Backend.HTTP) is Backend.HTTP


def test_gsm7228ps_http_reads_grounded_and_join_dispatch() -> None:
    # gsm7228ps (the S3300-52X) HTTP reads were GROUNDED 2026-07-30 against real
    # hardware (10.1.5.11), so its HTTP backend now participates in read
    # dispatch behind SNMP (like gsm7252ps/m4300): _reader_for/_writer_for(HTTP)
    # yield working objects rather than refusing. SNMP stays preferred.
    from netgear_switch.registry import Backend, get_model

    sw = AsyncSwitch(get_model("gsm7228ps"), "h", http_password="x")
    assert sw._reader_for(Backend.HTTP) is not None
    assert sw._writer_for(Backend.HTTP) is not None


def test_http_password_resolved_lazily() -> None:
    from netgear_switch.config import SwitchConfig
    from netgear_switch.registry import get_model

    cfg = SwitchConfig(
        name="p",
        model=get_model("gs305ep"),
        host="h",
        snmp_community=None,
        snmp_write_community_spec=None,
        http_password_spec="${MISSING_HTTP_PW}",
        nsdp_interface=None,
        protected_ports=frozenset(),
    )
    # Construction must NOT raise even though the spec is unresolvable.
    sw = AsyncSwitch.from_config(cfg, env={})
    assert sw.model.key == "gs305ep"


def test_http_client_closed_after_http_routed_op(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # HTTP is the only one of the three backends holding a persistent
    # connection; the facade must aclose() any AsyncHttpClient IT builds, via
    # async-context-manager exit.
    from netgear_switch.registry import get_model

    class _SpyAsyncHttpClient:
        def __init__(self) -> None:
            self.closed = False

        async def login(self) -> None: ...

        async def get_page(self, path: str) -> str:
            if path == "/getPoePortStatus.cgi":
                return (
                    '<tr class="portID"><td>1</td><td>Delivering</td>'
                    "<td>12800</td></tr>"
                )
            return "<input name='hash' value='h'>"

        async def post_form(self, path: str, data: dict[str, str]) -> str:
            return ""

        async def aclose(self) -> None:
            self.closed = True

    spy = _SpyAsyncHttpClient()
    monkeypatch.setattr(
        "netgear_switch.aio_api.build_async_http_client",
        lambda host, password, model: spy,
    )

    async def _run() -> None:
        async with AsyncSwitch(
            get_model("gs305ep"),
            "sw.example",
            nsdp_client=object(),
            nsdp_password="x",
            http_password="secret",
        ) as sw:
            from netgear_switch.registry import Backend

            # Explicit HTTP: PoE over the web UI is asked for, never substituted.
            poe = await sw.get_poe(backend=Backend.HTTP)
            assert poe[0].port == 1
            assert spy.closed is False  # still in use inside `async with`
        assert spy.closed is True  # torn down on async-context-manager exit

    asyncio.run(_run())


def test_injected_http_client_is_never_closed_by_facade() -> None:
    # An AsyncHttpSession the caller injected is the caller's to close, not
    # ours; `aclose()` must never touch it.
    from netgear_switch.registry import get_model

    class _AsyncHttpSess:
        async def login(self) -> None: ...

        async def get_page(self, path: str) -> str:
            if path == "/getPoePortStatus.cgi":
                return (
                    '<tr class="portID"><td>1</td><td>Delivering</td>'
                    "<td>12800</td></tr>"
                )
            return "<input name='hash' value='h'>"

        async def post_form(self, path: str, data: dict[str, str]) -> str:
            return ""

        async def aclose(self) -> None:
            raise AssertionError("facade must never close a caller-injected client")

    async def _run() -> None:
        async with AsyncSwitch(
            get_model("gs305ep"),
            "sw.example",
            nsdp_client=object(),
            nsdp_password="x",
            http_client=_AsyncHttpSess(),
        ) as sw:
            from netgear_switch.registry import Backend

            await sw.get_poe(backend=Backend.HTTP)

    asyncio.run(_run())


def test_delete_vlan_guards_protected_member_before_http_fallback() -> None:
    # Async mirror: AsyncNsdpWriter.delete_vlan ALWAYS raises
    # UnsupportedCapabilityError (NSDP has no VLAN lifecycle ops), so on a
    # {NSDP, HTTP} model delete_vlan always falls through to AsyncHttpWriter --
    # which does NOT itself guard protected member ports on delete. The
    # facade must supply that missing safety rail itself, before HTTP is ever
    # touched.
    import struct

    from netgear_switch.errors import ProtectedPortError
    from netgear_switch.protocols.nsdp.protocol import NSDPPacket, Op, Tag
    from netgear_switch.registry import get_model

    class FakeAsyncNsdp:
        async def read(self, tags: object) -> NSDPPacket:
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

        async def write(self, tlvs: object, *, password: str) -> None:
            raise AssertionError("NSDP has no VLAN lifecycle; must not be written")

    class _RaisingAsyncHttpSess:
        async def login(self) -> None:
            raise AssertionError("guard must refuse before HTTP is ever touched")

        async def get_page(self, path: str) -> str:
            raise AssertionError("guard must refuse before HTTP is ever touched")

        async def post_form(self, path: str, data: dict[str, str]) -> str:
            raise AssertionError("guard must refuse before HTTP is ever touched")

    async def _run() -> None:
        sw = AsyncSwitch(
            get_model("gs305ep"),
            "sw.example",
            nsdp_client=FakeAsyncNsdp(),
            http_client=_RaisingAsyncHttpSess(),
            protected_ports=frozenset({1}),
        )
        with pytest.raises(ProtectedPortError):
            await sw.delete_vlan(90)  # force=False: must refuse, never reach HTTP

    asyncio.run(_run())


# --- Task 2: model detection (async_detect_model / AsyncSwitch.identify) ---


def _system_info_tables(sys_descr: str) -> dict[str, list[SnmpRow]]:
    return {
        oids.SYS_DESCR: [SnmpRow(oids.SYS_DESCR, sys_descr, "STRING")],
        oids.SYS_OBJECT_ID: [
            SnmpRow(oids.SYS_OBJECT_ID, "1.3.6.1.4.1.4526.10.100.14", "OID")
        ],
    }


def test_async_detect_model_matches_registered_model() -> None:
    client = FakeAsyncClient(_system_info_tables("NETGEAR GSM7252PS"))
    detected = asyncio.run(async_detect_model("10.0.0.9", client=client))
    assert detected.key == "gsm7252ps"
    assert detected.matched is True


def test_async_detect_model_unregistered_model_is_none() -> None:
    client = FakeAsyncClient(_system_info_tables("NETGEAR M7300-28G"))
    detected = asyncio.run(async_detect_model("10.0.0.9", client=client))
    assert detected.key is None
    assert detected.matched is False


def test_async_detect_model_builds_default_client_when_not_injected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    build_calls: list[tuple[str, str | None]] = []

    def fake_build(host: str, community: str | None) -> FakeAsyncClient:
        build_calls.append((host, community))
        return FakeAsyncClient(_system_info_tables("NETGEAR GSM7252PS"))

    monkeypatch.setattr("netgear_switch.aio_api.build_async_snmp_client", fake_build)

    detected = asyncio.run(async_detect_model("10.0.0.9", community="public"))
    assert build_calls == [("10.0.0.9", "public")]
    assert detected.key == "gsm7252ps"


def test_async_switch_identify_bypasses_model_snmp_gate() -> None:
    # Mirrors SyncSwitch.identify's test: must work even when self.model has
    # no SNMP backend at all.
    client = FakeAsyncClient(_system_info_tables("NETGEAR GS110EMX"))
    sw = AsyncSwitch(get_model("gs110emx"), "host", snmp_client=client)
    detected = asyncio.run(sw.identify())
    assert detected.key == "gs110emx"


def test_async_switch_identify_reflects_device_not_bound_model() -> None:
    client = FakeAsyncClient(_system_info_tables("NETGEAR GS110EMX"))
    sw = AsyncSwitch(get_model("gsm7252ps"), "host", snmp_client=client)
    detected = asyncio.run(sw.identify())
    assert detected.key == "gs110emx"
