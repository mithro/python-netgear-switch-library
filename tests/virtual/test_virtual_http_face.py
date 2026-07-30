from __future__ import annotations

import asyncio

import httpx
import pytest

from http_specs import reads_verified
from netgear_switch.http_read import AsyncHttpReader, HttpReader
from netgear_switch.models import IpMode, PoEDetect
from netgear_switch.protocols.http.endpoints import http_spec
from netgear_switch.registry import get_model
from netgear_switch.transport.http.client import AsyncHttpClient, HttpClient
from netgear_switch.virtual.faces.http import VirtualHttpFace
from netgear_switch.virtual.seed import seed_gs305ep
from netgear_switch.virtual.server import VirtualSwitch

# Fail this module's tests if they leak a socket/thread ResourceWarning, and
# also (belt-and-suspenders) if pytest re-emits a leaked-resource finalizer
# warning as PytestUnraisableExceptionWarning -- see
# test_stop_closes_listening_socket_deterministically below for why the
# ResourceWarning filter alone is not a reliable leak detector for this face.
pytestmark = pytest.mark.filterwarnings(
    "error::ResourceWarning", "error::pytest.PytestUnraisableExceptionWarning"
)

_SPEC = http_spec(get_model("gs305ep"))


@pytest.fixture
def face():
    state = seed_gs305ep()
    f = VirtualHttpFace(state, _SPEC, password="password")
    port = f.start()
    try:
        yield f, port, state
    finally:
        f.stop()


def test_login_read_write_reread(face) -> None:
    _f, port, state = face
    client = HttpClient(f"127.0.0.1:{port}", "password", _SPEC)
    try:
        client.login()
        poe = client.get_page("/getPoePortStatus.cgi")
        from netgear_switch.protocols.http import parse

        assert parse.parse_poe_status(poe)[0].detect is PoEDetect.DELIVERING
        # Turn PoE port 2 off via the CGI, then re-read.
        page = client.get_page("/PoEPortConfig.cgi")
        h = parse.parse_csrf_hash(page)
        client.post_form(
            "/PoEPortConfig.cgi",
            {"ACTION": "Apply", "portID": "1", "ADMIN_MODE": "0", "hash": h},
        )
        assert state.poe[2].admin is False
    finally:
        client.close()


def test_wrong_password_rejected(face) -> None:
    _f, port, _ = face
    from netgear_switch.errors import HttpAuthError

    client = HttpClient(f"127.0.0.1:{port}", "wrong", _SPEC)
    with pytest.raises(HttpAuthError):
        client.login()
    client.close()


def test_unsupported_path_404s(face) -> None:
    """A path this model's spec doesn't advertise must 404, not fabricate a
    generic 200 OK page (the gs110emx dashboard path, not one of gs305ep's
    populated spec fields)."""
    _f, port, _ = face
    resp = httpx.get(f"http://127.0.0.1:{port}/iss/specific/sysInfo.html")
    assert resp.status_code == 404


def test_stop_closes_listening_socket_deterministically(face) -> None:
    """``stop()`` must close the listening socket synchronously, not leave it
    for GC to finalize.

    A reviewer proved that ``-W error::ResourceWarning`` does NOT reliably
    catch this leak: CPython reports an unclosed socket via a GC finalizer,
    which pytest re-emits as ``PytestUnraisableExceptionWarning`` (a
    ``UserWarning`` subclass, not a ``ResourceWarning``) -- the
    ``error::ResourceWarning`` filter never matches it, so a run with
    ``server_close()`` deleted from ``stop()`` still passed. This assertion
    is deterministic instead: it inspects the real OS-level file descriptor
    on the server's listening socket and fails immediately if it is still
    open after ``stop()`` returns, regardless of whether/when GC runs or
    which warning category (if any) a finalizer happens to raise.
    """
    f, _port, _state = face
    server = f._server
    assert server is not None
    assert server.socket.fileno() != -1  # sanity: open while running
    f.stop()
    assert server.socket.fileno() == -1


def test_gs110emx_has_its_own_bindable_http_face() -> None:
    """gs110emx's registry entry is ``{NSDP, HTTP}`` (see registry.py), not
    NSDP-only, and its HTTP face serves the FULL NSDP read surface
    (ports/stats/VLANs/PVIDs/mgmt-IP -- see ``protocols/http/endpoints.py``).
    Prove the gs110emx face binds, serves its login page, gates its known
    paths, and can complete a full token-session (Gambit, not cookie)
    ``HttpClient`` login + read of every grounded page."""
    spec = http_spec(get_model("gs110emx"))
    sw = VirtualSwitch(model="gs110emx")
    sw.start()
    try:
        assert sw.http_port != 0

        resp = httpx.get(f"http://127.0.0.1:{sw.http_port}{spec.login_path}")
        assert resp.status_code == 200

        # gs110emx (EMx, no PoE) leaves poe_config_path None -- gs305ep's PoE
        # CGI path is not in gs110emx's known-path set, so it must 404.
        assert spec.poe_config_path is None
        resp = httpx.get(f"http://127.0.0.1:{sw.http_port}/PoEPortConfig.cgi")
        assert resp.status_code == 404
        # HTTP now covers the full NSDP read surface (real URLs, live 2026-07-21).
        assert spec.dashboard_path == "/iss/specific/port_settings.html"

        client = HttpClient(f"127.0.0.1:{sw.http_port}", "password", spec)
        try:
            client.login()
            for path in (
                spec.stats_path,
                spec.sysinfo_path,
                spec.dashboard_path,
                spec.pvid_path,
                spec.vlan_config_path,
            ):
                assert path is not None
                assert client.get_page(path)
        finally:
            client.close()
    finally:
        sw.stop()


def test_gs110emx_wrong_password_rejected() -> None:
    """Token-session (Gambit) twin of ``test_wrong_password_rejected``: a
    bad password must yield no (or an empty) Gambit token, and the client
    must raise ``HttpAuthError`` rather than treat an empty token as a
    session (see transport/http/client.py::_extract_session_token)."""
    from netgear_switch.errors import HttpAuthError

    spec = http_spec(get_model("gs110emx"))
    sw = VirtualSwitch(model="gs110emx")
    sw.start()
    try:
        client = HttpClient(f"127.0.0.1:{sw.http_port}", "wrong", spec)
        with pytest.raises(HttpAuthError):
            client.login()
        client.close()
    finally:
        sw.stop()


def test_gs110emx_http_reader_end_to_end() -> None:
    """Full stack, no hardware: VirtualSwitch("gs110emx") -> token-session
    (Gambit) login via HttpClient -> HttpReader.get_stats()/get_mgmt_ip()
    over the real parse.parse_interface_stats/parse_sysinfo path. Asserts
    against virtual/seed.py::seed_gs110emx's seeded values, proving the
    mock's byte-faithful pages (web_gs110emx.py) round-trip through the
    same parsers a real device's pages would."""
    sw = VirtualSwitch(model="gs110emx")
    sw.start()
    try:
        spec = http_spec(get_model("gs110emx"))
        client = HttpClient(f"127.0.0.1:{sw.http_port}", "password", spec)
        try:
            reader = HttpReader(client, get_model("gs110emx"))
            stats = {s.port: s for s in reader.get_stats()}
            # Counters transcribed from gs110emx_interface_stats.html: the
            # traffic is on 6/8/9/10 and ports 1-5/7 really are zero.
            assert stats[1].rx_bytes == 0
            assert stats[6].tx_bytes == 70_892_018_242
            assert stats[9].rx_bytes == 2_963_140_428_936
            assert stats[1].rx_errors == 0

            mgmt = reader.get_mgmt_ip()
            assert mgmt.address == "10.1.5.25"
            assert mgmt.netmask == "255.255.255.0"
            assert mgmt.gateway == "10.1.5.1"
            assert mgmt.mode is IpMode.STATIC
            # Uppercased (VirtualSwitchState.nsdp_mac is the same bytes the
            # SNMP/NSDP mock faces serve, so this must match their casing).
            assert mgmt.base_mac == "BC:A5:11:B8:EC:F1"
        finally:
            client.close()
    finally:
        sw.stop()


def test_gs110emx_async_http_reader_end_to_end() -> None:
    """Async twin of ``test_gs110emx_http_reader_end_to_end`` -- sync/async
    parity over the same token-session flow."""

    async def run() -> None:
        sw = VirtualSwitch(model="gs110emx")
        sw.start()
        try:
            spec = http_spec(get_model("gs110emx"))
            client = AsyncHttpClient(f"127.0.0.1:{sw.http_port}", "password", spec)
            try:
                reader = AsyncHttpReader(client, get_model("gs110emx"))
                stats = {s.port: s for s in await reader.get_stats()}
                assert stats[9].rx_bytes == 2_963_140_428_936
                mgmt = await reader.get_mgmt_ip()
                assert mgmt.address == "10.1.5.25"
                assert mgmt.mode is IpMode.STATIC
            finally:
                await client.aclose()
        finally:
            sw.stop()

    asyncio.run(run())


# --- gsm7252ps: the XE FASTPATH face ---------------------------------------

_GSM7252PS_SPEC = http_spec(get_model("gsm7252ps"))


@pytest.fixture
def xe_face():
    from netgear_switch.virtual.seed import seed_gsm7252ps

    state = seed_gsm7252ps()
    f = VirtualHttpFace(state, _GSM7252PS_SPEC, password="password")
    port = f.start()
    try:
        yield f, port, state
    finally:
        f.stop()


def test_xe_face_login_requires_username_and_password(xe_face) -> None:
    """The real gsm7252ps cheetah form posts uname AND pwd, and validates
    both. A transport that dropped the username would fail on hardware, so
    the mock must reject it too."""
    _f, port, _state = xe_face
    client = HttpClient(f"127.0.0.1:{port}", "password", _GSM7252PS_SPEC)
    try:
        client.login()  # sends uname=admin + pwd=password
    finally:
        client.close()

    bad = httpx.post(
        f"http://127.0.0.1:{port}/base/cheetah_login.html",
        data={"pwd": "password"},  # no uname
    )
    assert "Set-Cookie" not in bad.headers


def test_xe_face_serves_every_read_op_from_state(xe_face) -> None:
    """The mock renders the real XE cell format, so the SAME parsers that read
    the hardware captures read it back -- ports/stats/PVIDs/VLANs/MACs/PoE/
    LLDP/sensors/mgmt-IP, all from one VirtualSwitchState."""
    _f, port, state = xe_face
    with reads_verified("gsm7252ps"):
        client = HttpClient(f"127.0.0.1:{port}", "password", _GSM7252PS_SPEC)
        try:
            client.login()
            reader = HttpReader(client, get_model("gsm7252ps"))
            ports = {p.port: p for p in reader.get_ports()}
            # the web UI lists ONLY physical ports: the state's CPU/lag
            # interfaces (ifIndex 417/418) must not appear
            assert set(ports) == set(range(1, 53))
            assert ports[1].link_up is state.ports[1].link
            assert ports[1].speed_mbps == state.ports[1].speed

            assert dict(reader.get_pvids()) == {
                p: v for p, v in state.pvids.items() if p <= 52
            }
            assert {v.vlan_id for v in reader.get_vlans()} == set(state.vlans)
            assert {s.port for s in reader.get_stats()} == set(range(1, 53))
            assert {p.port for p in reader.get_poe()} == set(state.poe)
            assert len(reader.get_macs()) == len(state.macs)
            assert len(reader.get_lldp()) == len(state.lldp)

            mgmt = reader.get_mgmt_ip()
            assert mgmt.address == state.mgmt.address
            assert mgmt.base_mac == "E0:91:F5:0C:D6:DB"
            # the page has no DHCP indicator: never guessed from the state
            assert mgmt.mode is IpMode.UNKNOWN

            # The HTTP sysInfo sensor set is the real web-UI one (temperatures
            # + fan/PSU health), DIFFERENT from this device's SNMP set (fan RPM
            # + PSU watts). Names/values are the captured page's own.
            sensors = {(s.kind, s.name): s.value for s in reader.get_sensors()}
            assert sensors[("temperature", "System")] == 29.0
            assert sensors[("temperature", "CPU")] == 49.0
            # the "MAC" temperature row reads N/A on this unit -> skipped
            assert ("temperature", "MAC") not in sensors
            # fans report health text, not RPM; the unpopulated Fan4/Fan5 slots
            # render the page's "NA" text and are skipped, not reported as failed
            assert sensors[("fan", "Fan1/PWR")] == 1.0
            assert ("fan", "Fan4") not in sensors
            # RPS + Power Module operational flags from the Device Status table
            assert sensors[("power", "RPS")] == 1.0
        finally:
            client.close()


def test_xe_face_404s_a_path_the_spec_does_not_serve(xe_face) -> None:
    """This model's spec has no reboot/logout/PoE-config page, and the face
    must 404 rather than fabricate a 200 for one."""
    _f, port, _state = xe_face
    assert httpx.get(f"http://127.0.0.1:{port}/device_reboot.cgi").status_code == 404


# --- gs728tpp: the GoAhead ``wcd`` XML-API face ----------------------------

_GS728TPP_SPEC = http_spec(get_model("gs728tpp"))


@pytest.fixture
def goahead_face():
    from netgear_switch.virtual.seed import seed_gs728tpp

    state = seed_gs728tpp()
    f = VirtualHttpFace(state, _GS728TPP_SPEC, password="password")
    port = f.start()
    try:
        yield f, port, state
    finally:
        f.stop()


def test_goahead_face_xml_api_login_and_wrong_password(goahead_face) -> None:
    """The GoAhead login is GET / (302 -> session path) then a System.xml GET;
    the client stores the session path and a wrong password is rejected."""
    from netgear_switch.errors import HttpAuthError

    _f, port, _state = goahead_face
    client = HttpClient(f"127.0.0.1:{port}", "password", _GS728TPP_SPEC)
    try:
        client.login()
        assert client._session_path  # captured from the 302 redirect
    finally:
        client.close()

    bad = HttpClient(f"127.0.0.1:{port}", "wrong", _GS728TPP_SPEC)
    with pytest.raises(HttpAuthError):
        bad.login()
    bad.close()


def test_goahead_reads_verified_but_gate_still_fires(goahead_face) -> None:
    """gs728tpp ships reads_verified=True after the 2026-07-29 live cross-verify
    (10.2.5.10), so HttpReader constructs. The honesty gate itself is still
    exercised here: forcing an unverified spec variant must refuse construction."""
    import dataclasses

    from netgear_switch.errors import UnsupportedCapabilityError
    from netgear_switch.protocols.http import endpoints

    _f, port, _state = goahead_face
    client = HttpClient(f"127.0.0.1:{port}", "password", _GS728TPP_SPEC)
    try:
        client.login()
        # Shipped spec is verified -> constructs fine.
        HttpReader(client, get_model("gs728tpp"))
        # Gate mechanism: an unverified variant of the SAME spec must refuse.
        original = endpoints._SPECS["gs728tpp"]
        endpoints._SPECS["gs728tpp"] = dataclasses.replace(
            original, reads_verified=False
        )
        try:
            with pytest.raises(UnsupportedCapabilityError):
                HttpReader(client, get_model("gs728tpp"))
        finally:
            endpoints._SPECS["gs728tpp"] = original
    finally:
        client.close()


def test_goahead_face_serves_every_read_op_from_state(goahead_face) -> None:
    """The mock renders the real wcd XML, so the SAME parse_goahead_* parsers
    that read the hardware captures read it back -- ports/pvids/vlans/poe/macs/
    lldp/sensors/mgmt-IP, all from one VirtualSwitchState (== the SNMP seed)."""
    from netgear_switch.models import IpMode, PoEDetect

    _f, port, state = goahead_face
    with reads_verified("gs728tpp"):
        client = HttpClient(f"127.0.0.1:{port}", "password", _GS728TPP_SPEC)
        try:
            client.login()
            reader = HttpReader(client, get_model("gs728tpp"))

            ports = {p.port: p for p in reader.get_ports()}
            assert set(ports) == set(range(1, 29))  # physical g1..g28 only
            for p, sim in state.ports.items():
                assert ports[p].link_up is sim.link
                assert ports[p].speed_mbps == (sim.speed if sim.link else None)

            assert dict(reader.get_pvids()) == state.pvids

            vlans = {v.vlan_id: v for v in reader.get_vlans()}
            assert set(vlans) == set(state.vlans)
            for vid, sim in state.vlans.items():
                assert vlans[vid].member_ports == frozenset(sim.member)
                assert vlans[vid].untagged_ports == frozenset(sim.untagged)
                assert vlans[vid].tagged_ports == frozenset(sim.member - sim.untagged)

            poe = {p.port: p for p in reader.get_poe()}
            assert set(poe) == set(state.poe)
            assert poe[1].detect is PoEDetect.SEARCHING

            assert len(reader.get_macs()) == len(state.macs)
            assert {n.local_port for n in reader.get_lldp()} == {2, 24, 26, 28}

            sensors = {(s.kind, s.name): s.value for s in reader.get_sensors()}
            assert sensors[("fan", "Fan1")] == 1.0
            assert ("fan", "Fan3") not in sensors  # absent slot skipped
            assert sensors[("power", "Main PS")] == 1.0

            mgmt = reader.get_mgmt_ip()
            assert (mgmt.address, mgmt.netmask, mgmt.gateway) == (
                state.mgmt.address,
                state.mgmt.netmask,
                state.mgmt.gateway,
            )
            assert mgmt.mode is IpMode.UNKNOWN
            # base_mac now read from the SystemInfo page (DeviceBasicInfo/
            # MacAddre), uppercased -> parity with the SNMP base MAC.
            assert mgmt.base_mac == ":".join(f"{b:02X}" for b in state.nsdp_mac)
        finally:
            client.close()


def test_goahead_get_stats_unsupported(goahead_face) -> None:
    """Per-port statistics are behind an unresolvable JS nav indirection on this
    UI, so get_stats over HTTP must raise UnsupportedCapabilityError (SNMP is
    the source), never fabricate counters."""
    from netgear_switch.errors import UnsupportedCapabilityError

    _f, port, _state = goahead_face
    with reads_verified("gs728tpp"):
        client = HttpClient(f"127.0.0.1:{port}", "password", _GS728TPP_SPEC)
        try:
            client.login()
            reader = HttpReader(client, get_model("gs728tpp"))
            with pytest.raises(UnsupportedCapabilityError):
                reader.get_stats()
        finally:
            client.close()


def test_goahead_face_404s_unknown_wcd_query(goahead_face) -> None:
    """A wcd query this face does not serve must 404, not fabricate a page.
    Sends a valid session cookie so this exercises the unknown-query 404 path,
    not the unauthenticated-redirect path (see test below)."""
    _f, port, _state = goahead_face
    resp = httpx.get(
        f"http://127.0.0.1:{port}/cs0000face/wcd?{{file=/nope/Bogus.xml}}{{X}}",
        headers={"Cookie": "sessionID=virtualsid"},
    )
    assert resp.status_code == 404


def test_goahead_face_refuses_unauthenticated_wcd_read(goahead_face) -> None:
    """Fidelity: real hardware redirects an unauthenticated wcd read to login.
    The mock must do the same (302), so the suite would catch a client that
    tried to read before logging in. A valid session cookie is served normally."""
    _f, port, _state = goahead_face
    url = (
        f"http://127.0.0.1:{port}/cs0000face/wcd?"
        "{file=/System/Management/IPConf_master.xml}{IPv4InterfaceList}"
    )
    # No cookie -> refused with a redirect, NOT served.
    refused = httpx.get(url, follow_redirects=False)
    assert refused.status_code == 302
    # Same query WITH the post-login session cookie -> served.
    served = httpx.get(url, headers={"Cookie": "sessionID=virtualsid"})
    assert served.status_code == 200
    assert "IPv4InterfaceList" in served.text


def test_goahead_async_reader_end_to_end(goahead_face) -> None:
    """Async twin: sync/async parity over the XML_API login + wcd reads."""

    async def run() -> None:
        _f, port, state = goahead_face
        with reads_verified("gs728tpp"):
            client = AsyncHttpClient(f"127.0.0.1:{port}", "password", _GS728TPP_SPEC)
            try:
                reader = AsyncHttpReader(client, get_model("gs728tpp"))
                ports = {p.port: p for p in await reader.get_ports()}
                assert set(ports) == set(range(1, 29))
                assert dict(await reader.get_pvids()) == state.pvids
                mgmt = await reader.get_mgmt_ip()
                assert mgmt.address == state.mgmt.address
            finally:
                await client.aclose()

    asyncio.run(run())


# --- gsm7228ps: the S3300-52X XE FASTPATH face -----------------------------
# The S3300 shares the gsm7252ps XE cell grid for ports/stats/PVIDs/PoE/LLDP,
# but its MAC table (shifted columns, escaped 1/gN names), VLAN membership
# (1/gN/1/xgN egress names) and sysInfo (base MAC only, no live sensors) get
# S3300-specific handling. Expected values are the same switch's real SNMP
# capture (tests/fixtures/captures/gsm7228ps.json).
import json as _json  # noqa: E402
from pathlib import Path as _Path  # noqa: E402

_GSM7228PS_SPEC = http_spec(get_model("gsm7228ps"))
_S3300_CAPTURE = _json.loads(
    (
        _Path(__file__).parent.parent / "fixtures" / "captures" / "gsm7228ps.json"
    ).read_text()
)["snapshot"]


@pytest.fixture
def s3300_face():
    from netgear_switch.virtual.seed import seed_gsm7228ps

    state = seed_gsm7228ps()
    f = VirtualHttpFace(state, _GSM7228PS_SPEC, password="password")
    port = f.start()
    try:
        yield f, port, state
    finally:
        f.stop()


def test_s3300_face_serves_grounded_reads_matching_snmp_capture(s3300_face) -> None:
    """Full stack, no hardware: VirtualSwitch("gsm7228ps") HTTP face -> cheetah
    login -> HttpReader reproduces the seven grounded reads, cross-checked
    against the real SNMP capture. get_sensors raises Unsupported (the S3300
    sysInfo has no live fan/temp table -- SNMP only)."""
    from netgear_switch.errors import UnsupportedCapabilityError

    _f, port, _state = s3300_face
    cap = _S3300_CAPTURE
    client = HttpClient(f"127.0.0.1:{port}", "password", _GSM7228PS_SPEC)
    try:
        client.login()
        reader = HttpReader(client, get_model("gsm7228ps"))

        # (1) ports -- port set + admin/link/speed match SNMP
        ports = {p.port: p for p in reader.get_ports()}
        assert set(ports) == set(range(1, 53))
        for cp in cap["ports"]:
            assert ports[cp["port"]].link_up is cp["link_up"]
            assert ports[cp["port"]].speed_mbps == cp["speed_mbps"]

        # (2) stats -- port set (counters are volatile, not parity-pinned)
        assert {s.port for s in reader.get_stats()} == set(range(1, 53))

        # (3) pvids -- exact
        assert dict(reader.get_pvids()) == {p[0]: p[1] for p in cap["pvids"]}

        # (4) vlans -- IDs + physical membership match SNMP (lag ifIndexes the
        # SNMP capture lists on VLAN 1 are rendered "lag N" and omitted by both)
        vlans = {v.vlan_id: v for v in reader.get_vlans()}
        cv = {v["vlan_id"]: v for v in cap["vlans"]}
        assert set(vlans) == set(cv) == {1, 5, 21, 121, 4089}
        for vid, v in vlans.items():
            assert set(v.member_ports) == {
                p for p in cv[vid]["member_ports"] if p <= 52
            }
        assert vlans[5].name == "net"

        # (5) poe -- port set + admin + power_mw match; delivering ports stable
        poe = {p.port: p for p in reader.get_poe()}
        cpoe = {p["port"]: p for p in cap["poe"]}
        assert set(poe) == set(cpoe)
        for port_no, cp in cpoe.items():
            assert poe[port_no].admin_enabled is cp["admin_enabled"]
            assert poe[port_no].power_mw == cp["power_mw"]
            if cp["power_mw"] > 0:
                assert poe[port_no].detect is PoEDetect.DELIVERING

        # (6) lldp -- both neighbours, chassis/sysname match
        lldp = {n.local_port: n for n in reader.get_lldp()}
        assert set(lldp) == {n["local_port"] for n in cap["lldp"]}
        for cn in cap["lldp"]:
            assert lldp[cn["local_port"]].remote_chassis_id == cn["remote_chassis_id"]
            assert lldp[cn["local_port"]].remote_sys_name == cn["remote_sys_name"]

        # (7) macs -- the 17 PHYSICAL entries (SNMP's 18th is the switch's own
        # base MAC on the CPU ifIndex, which the FDB parser omits)
        macs = {(m.mac, m.port, m.vlan_id) for m in reader.get_macs()}
        assert macs == {
            (m["mac"], m["port"], m["vlan_id"]) for m in cap["macs"] if m["port"] <= 52
        }
        assert "08:BD:43:6B:B8:D8" not in {m for m, _p, _v in macs}

        # mgmt-IP over HTTP is base-MAC only (SNMP is authoritative for address)
        mgmt = reader.get_mgmt_ip()
        assert mgmt.mode is IpMode.UNKNOWN
        assert mgmt.address is None
        assert mgmt.base_mac == cap["mgmt_ip"]["base_mac"] == "08:BD:43:6B:B8:D8"

        # sensors -- unsupported over HTTP (no live fan/temp table); SNMP only
        with pytest.raises(UnsupportedCapabilityError):
            reader.get_sensors()
    finally:
        client.close()


def test_s3300_face_login_requires_username_and_password(s3300_face) -> None:
    """The S3300 cheetah form posts uname=admin + pwd, and the mock validates
    both -- a transport that dropped the username would fail on hardware."""
    _f, port, _state = s3300_face
    client = HttpClient(f"127.0.0.1:{port}", "password", _GSM7228PS_SPEC)
    try:
        client.login()  # uname=admin + pwd=password
    finally:
        client.close()
    bad = httpx.post(
        f"http://127.0.0.1:{port}/base/cheetah_login.html",
        data={"pwd": "password"},  # no uname
    )
    assert "Set-Cookie" not in bad.headers


def test_s3300_face_404s_a_path_the_spec_does_not_serve(s3300_face) -> None:
    """The S3300 spec has no reboot/logout/PoE-config page; the face must 404
    rather than fabricate a 200."""
    _f, port, _state = s3300_face
    assert httpx.get(f"http://127.0.0.1:{port}/device_reboot.cgi").status_code == 404
