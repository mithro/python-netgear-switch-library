from __future__ import annotations

import asyncio
import json

import pytest

pytest.importorskip("mcp", reason="the [mcp] extra is required for the MCP server")

from netgear_switch.errors import ConfigError, UnsupportedCapabilityError
from netgear_switch.mcp import server as mod
from netgear_switch.models import IpMode, MgmtIpConfig, VLANInfo
from netgear_switch.protocols.nsdp.protocol import (
    NSDPPacket,
    Op,
    Tag,
)
from netgear_switch.registry import Backend, get_model
from netgear_switch.sync_api import SyncSwitch

_READ_TOOLS = {
    "get_ports",
    "get_stats",
    "get_vlans",
    "get_pvids",
    "get_macs",
    "get_lldp",
    "get_sensors",
    "get_poe",
    "get_mgmt_ip",
    "identify",
    "list_switches",
    "snapshot",
    "get_device",
}
_WRITE_TOOLS = {
    "set_pvid",
    "set_port_enabled",
    "set_poe",
    "set_vlan_membership",
    "create_vlan",
    "delete_vlan",
    "cycle_poe",
    "clear_poe_fault",
    "set_mgmt_ip",
}


def _tool_names(env: dict[str, str]) -> set[str]:
    srv = mod.build_server(env=env)
    return {t.name for t in asyncio.run(srv.list_tools())}


def test_writes_are_gated_off_by_default() -> None:
    names = _tool_names({})
    assert _READ_TOOLS.issubset(names)
    assert names.isdisjoint(_WRITE_TOOLS)  # no write tool registered


def test_writes_registered_when_opted_in() -> None:
    names = _tool_names({"NGSW_MCP_ALLOW_WRITES": "1"})
    assert _READ_TOOLS.issubset(names)
    assert _WRITE_TOOLS.issubset(names)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("1", True),
        ("true", True),
        ("YES", True),
        ("on", True),
        ("0", False),
        ("", False),
        ("off", False),
        ("maybe", False),
    ],
)
def test_writes_enabled_parsing(value: str, expected: bool) -> None:
    assert mod.writes_enabled({"NGSW_MCP_ALLOW_WRITES": value}) is expected


def test_jsonable_serializes_models_tree() -> None:
    vlan = VLANInfo(
        vlan_id=90,
        name="iot",
        member_ports=frozenset({2, 1, 3}),
        tagged_ports=frozenset({1}),
        untagged_ports=frozenset({2, 3}),
    )
    out = mod._jsonable([vlan])
    assert out == [
        {
            "vlan_id": 90,
            "name": "iot",
            "member_ports": [1, 2, 3],  # frozenset -> sorted list
            "tagged_ports": [1],
            "untagged_ports": [2, 3],
        }
    ]
    mgmt = MgmtIpConfig(
        mode=IpMode.STATIC,
        address="10.1.5.25",
        netmask="255.255.255.0",
        gateway="10.1.5.1",
        base_mac="AA:BB:CC:DD:EE:FF",
    )
    assert mod._jsonable(mgmt)["mode"] == "static"  # enum -> value


def test_read_wraps_unsupported_capability() -> None:
    def boom():
        raise UnsupportedCapabilityError("no MAC table on a Plus switch")

    res = mod._read("get_macs", boom)
    assert res == {
        "unsupported": True,
        "op": "get_macs",
        "detail": "no MAC table on a Plus switch",
    }


def test_read_wraps_library_error() -> None:
    from netgear_switch.protocols.nsdp.client import NsdpError

    def boom():
        raise NsdpError("timed out")

    assert mod._read("get_ports", boom) == {"error": "timed out", "op": "get_ports"}


def test_resolve_requires_a_selector() -> None:
    with pytest.raises(ConfigError, match="either"):
        mod._resolve(
            switch=None,
            host=None,
            model=None,
            config=None,
            community=None,
            http_password=None,
            nsdp_interface=None,
            env={},
        )


def test_list_inventory_switches(tmp_path) -> None:
    inv = tmp_path / "inv.toml"
    inv.write_text(
        '[switches.core]\nmodel = "gsm7252ps"\nhost = "10.1.5.20"\n'
        '[switches.plus]\nmodel = "gs110emx"\nhost = "10.1.5.25"\n'
    )
    got = mod.list_inventory_switches(str(inv), {})
    assert {s["name"] for s in got} == {"core", "plus"}
    assert {"name": "plus", "model": "gs110emx", "host": "10.1.5.25"} in got


def test_list_inventory_requires_a_path() -> None:
    with pytest.raises(ConfigError, match="NGSW_INVENTORY"):
        mod.list_inventory_switches(None, {})


class _CannedNsdp:
    """Returns one canned READ_RESPONSE for a gs110emx (includes MODEL, which
    every per-op read requests -- see nsdp_read._with_model)."""

    def read(self, tags):
        pkt = NSDPPacket(
            op=Op.READ_RESPONSE,
            client_mac=b"\x00" * 6,
            server_mac=b"\xbc\xa5\x11\xb8\xec\xf1",
        )
        pkt.add_tlv(Tag.MODEL, b"GS110EMX")
        pkt.add_tlv(Tag.PORT_COUNT, b"\x0a")
        pkt.add_tlv(Tag.PORT_STATUS, b"\x01\x05\x01")  # port 1 gigabit
        pkt.add_tlv(Tag.PORT_STATUS, b"\x02\x00\x01")  # port 2 down
        pkt.add_tlv(Tag.IP_ADDRESS, b"\x0a\x01\x05\x19")  # 10.1.5.25
        pkt.add_tlv(Tag.NETMASK, b"\xff\xff\xff\x00")
        pkt.add_tlv(Tag.GATEWAY, b"\x0a\x01\x05\x01")
        pkt.add_tlv(Tag.DHCP_MODE, b"\x00")
        return pkt


def _call(srv, name, args) -> list:
    result = asyncio.run(srv.call_tool(name, args))
    # Newer FastMCP returns a (content, structured) tuple for typed-return
    # tools and a bare content list otherwise; normalise to the content list.
    content = result[0] if isinstance(result, tuple) else result
    texts = [c.text for c in content if getattr(c, "type", None) == "text"]
    return [json.loads(t) for t in texts]


def test_get_ports_end_to_end_against_a_mock(monkeypatch) -> None:
    """A read tool, driven through the real FastMCP machinery, returns the
    reader's data as JSON -- proving the server wraps the library faithfully."""

    def fake_resolve(_ns, *, env=None, prompt=None):
        return SyncSwitch(get_model("gs110emx"), "10.1.5.25", nsdp_client=_CannedNsdp())

    monkeypatch.setattr(mod, "resolve_switch", fake_resolve)
    srv = mod.build_server(env={})
    ports = _call(srv, "get_ports", {"host": "10.1.5.25", "model": "gs110emx"})
    by_port = {p["port"]: p for p in ports}
    assert by_port[1]["link_up"] is True
    assert by_port[1]["speed_mbps"] == 1000
    assert by_port[2]["link_up"] is False

    mgmt = _call(srv, "get_mgmt_ip", {"host": "10.1.5.25", "model": "gs110emx"})[0]
    assert mgmt["address"] == "10.1.5.25"
    assert mgmt["base_mac"] == "BC:A5:11:B8:EC:F1"


def test_unsupported_op_returns_structured_result(monkeypatch) -> None:
    """gs110emx has no MAC table over any backend -> the tool reports it
    honestly rather than fabricating an empty list."""

    def fake_resolve(_ns, *, env=None, prompt=None):
        return SyncSwitch(get_model("gs110emx"), "10.1.5.25", nsdp_client=_CannedNsdp())

    monkeypatch.setattr(mod, "resolve_switch", fake_resolve)
    srv = mod.build_server(env={})
    res = _call(srv, "get_macs", {"host": "10.1.5.25", "model": "gs110emx"})[0]
    assert res["unsupported"] is True
    assert res["op"] == "get_macs"


def test_write_tool_reaches_the_switch_when_enabled(monkeypatch) -> None:
    """With writes enabled, set_pvid drives the library write path; a Plus
    model with no reachable write backend surfaces that honestly, not silently."""
    calls: list[tuple] = []

    class _RecordingSwitch:
        # `backend` is RECORDED, not merely tolerated: the tool must thread the
        # caller's protocol choice through to the library. Dropping it would
        # silently run the op over the model's default backend, which is exactly
        # the quiet protocol substitution CLAUDE.md principle 1 forbids.
        def set_pvid(self, port, vlan, *, force, backend=None):
            calls.append((port, vlan, force, backend))

    monkeypatch.setattr(
        mod, "resolve_switch", lambda _ns, *, env=None, prompt=None: _RecordingSwitch()
    )
    srv = mod.build_server(env={"NGSW_MCP_ALLOW_WRITES": "1"})
    res = _call(
        srv,
        "set_pvid",
        {
            "host": "10.1.5.25",
            "model": "gs110emx",
            "port": 3,
            "vlan": 90,
            "force": True,
        },
    )[0]
    assert res == {"ok": True, "op": "set_pvid"}
    # No backend named -> None, i.e. "use the model's documented default".
    assert calls == [(3, 90, True, None)]

    # An explicitly named backend must arrive as the Backend enum member.
    calls.clear()
    res = _call(
        srv,
        "set_pvid",
        {
            "host": "10.1.5.25",
            "model": "gs110emx",
            "port": 3,
            "vlan": 90,
            "force": True,
            "backend": "http",
        },
    )[0]
    assert res == {"ok": True, "op": "set_pvid"}
    assert calls == [(3, 90, True, Backend.HTTP)]

    # An unknown backend fails LOUDLY -- it propagates as a tool error naming the
    # bad value and the valid ones, rather than being ignored and quietly running
    # the op over the default backend.
    calls.clear()
    with pytest.raises(Exception, match="carrier-pigeon") as exc:
        _call(
            srv,
            "set_pvid",
            {
                "host": "10.1.5.25",
                "model": "gs110emx",
                "port": 3,
                "vlan": 90,
                "force": True,
                "backend": "carrier-pigeon",
            },
        )
    assert "snmp" in str(exc.value)  # lists what IS valid
    assert calls == []  # and the write never reached the switch


# Public SyncSwitch methods that deliberately get NO MCP tool: connection
# lifecycle and raw HTTP primitives, none of which are switch operations.
_NOT_MCP_EXPOSED = {
    "login",
    "get_page",
    "post_form",
    "close",
    "from_config",
    # Introspection, not an operation: "which backend would an op with this
    # argument run on?". Every real op instead takes an optional `backend`
    # argument (exposing THAT over MCP is a separate, open follow-up).
    "resolve_backend",
}
# SyncSwitch method -> MCP tool name, where the two differ.
_RENAMED = {"nsdp_device": "get_device"}


def test_every_switch_operation_has_an_mcp_tool() -> None:
    """Coverage guard: every read/write op on SyncSwitch must be reachable over
    MCP. Without this, adding an API method silently leaves MCP behind."""
    import inspect

    from netgear_switch.sync_api import SyncSwitch

    ops = {
        name
        for name, member in inspect.getmembers(SyncSwitch)
        if not name.startswith("_")
        and callable(member)
        and name not in _NOT_MCP_EXPOSED
    }
    tools = _tool_names({"NGSW_MCP_ALLOW_WRITES": "1"})
    missing = {op for op in ops if _RENAMED.get(op, op) not in tools}
    assert not missing, f"SyncSwitch ops with no MCP tool: {sorted(missing)}"


def test_new_write_tools_reach_the_switch(monkeypatch) -> None:
    """cycle_poe / clear_poe_fault / set_mgmt_ip drive the library write path."""
    calls: list[tuple] = []

    class _Recording:
        # Each accepts `backend` because every write tool now threads the
        # caller's protocol choice through (see the set_pvid test for the
        # assertions on its value).
        def cycle_poe(self, port, *, force, backend=None):
            calls.append(("cycle_poe", port, force))

        def clear_poe_fault(self, port, *, force, backend=None):
            calls.append(("clear_poe_fault", port, force))

        def set_mgmt_ip(self, address, netmask, gateway, *, force, backend=None):
            calls.append(("set_mgmt_ip", address, netmask, gateway, force))

    monkeypatch.setattr(
        mod, "resolve_switch", lambda _ns, *, env=None, prompt=None: _Recording()
    )
    srv = mod.build_server(env={"NGSW_MCP_ALLOW_WRITES": "1"})
    sel = {"host": "h", "model": "gs110emx", "force": True}
    assert _call(srv, "cycle_poe", {**sel, "port": 4})[0] == {
        "ok": True,
        "op": "cycle_poe",
    }
    assert _call(srv, "clear_poe_fault", {**sel, "port": 5})[0]["ok"] is True
    assert (
        _call(
            srv,
            "set_mgmt_ip",
            {
                **sel,
                "address": "10.1.5.9",
                "netmask": "255.255.255.0",
                "gateway": "10.1.5.1",
            },
        )[0]["ok"]
        is True
    )
    assert calls == [
        ("cycle_poe", 4, True),
        ("clear_poe_fault", 5, True),
        ("set_mgmt_ip", "10.1.5.9", "255.255.255.0", "10.1.5.1", True),
    ]


def test_upload_certificate_tool_reaches_the_switch(monkeypatch) -> None:
    """upload_certificate drives the library write path with the PEMs + force."""
    calls: list[tuple] = []

    class _Recording:
        def upload_certificate(self, cert_pem, key_pem, *, force):
            calls.append((cert_pem, key_pem, force))

    monkeypatch.setattr(
        mod, "resolve_switch", lambda _ns, *, env=None, prompt=None: _Recording()
    )
    srv = mod.build_server(env={"NGSW_MCP_ALLOW_WRITES": "1"})
    res = _call(
        srv,
        "upload_certificate",
        {
            "host": "h",
            "model": "gsm7228ps",
            "cert_pem": "CERT",
            "key_pem": "KEY",
            "force": True,
        },
    )[0]
    assert res == {"ok": True, "op": "upload_certificate"}
    assert calls == [("CERT", "KEY", True)]


def test_upload_certificate_tool_reports_not_implemented(monkeypatch) -> None:
    """A known-but-unimplemented mechanism (m4300 SCP) surfaces as
    ``not_implemented`` -- never ``unsupported`` (the hardware CAN do it) and
    never an uncaught stack trace."""

    class _M4300Like:
        def upload_certificate(self, cert_pem, key_pem, *, force):
            raise NotImplementedError("uses SCP file-copy to the switch")

    monkeypatch.setattr(
        mod, "resolve_switch", lambda _ns, *, env=None, prompt=None: _M4300Like()
    )
    srv = mod.build_server(env={"NGSW_MCP_ALLOW_WRITES": "1"})
    res = _call(
        srv,
        "upload_certificate",
        {
            "host": "h",
            "model": "m4300-24x",
            "cert_pem": "C",
            "key_pem": "K",
            "force": True,
        },
    )[0]
    assert res["not_implemented"] is True
    assert res["op"] == "upload_certificate"
    assert "unsupported" not in res


def test_set_vlan_membership_rejects_bad_mode(monkeypatch) -> None:
    monkeypatch.setattr(
        mod, "resolve_switch", lambda _ns, *, env=None, prompt=None: object()
    )
    srv = mod.build_server(env={"NGSW_MCP_ALLOW_WRITES": "1"})
    res = _call(
        srv,
        "set_vlan_membership",
        {"host": "h", "model": "gs110emx", "vlan": 90, "port": 1, "mode": "bogus"},
    )[0]
    assert "invalid mode" in res["error"]
