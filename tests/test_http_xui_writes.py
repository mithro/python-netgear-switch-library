"""HTTP writes on the managed FASTPATH "XUI" pages, driven against the mock.

Covers the three ops that used to raise ``UnsupportedCapabilityError`` for every
model -- ``set_port_enabled``, ``set_mgmt_ip`` and ``clear_poe_fault`` -- plus
the PoE admin write that shares their page. Every wire detail asserted here was
measured on real hardware on 2026-07-30 (gsm7252ps 10.1.5.22, gsm7228ps/S3300
10.1.5.11, m4300-24x 10.1.5.13, m4300-16x 10.1.5.20:49152); the mock reproduces
it, so a regression in either the page shape or the form builder fails here.
"""

from __future__ import annotations

import asyncio
import pathlib

import pytest

from netgear_switch.errors import (
    HttpError,
    ProtectedPortError,
    UnsupportedCapabilityError,
)
from netgear_switch.http_read import HttpReader
from netgear_switch.http_write import AsyncHttpWriter, HttpWriter
from netgear_switch.models import IpMode, PoEDetect
from netgear_switch.protocols.http import forms, parse
from netgear_switch.protocols.http.endpoints import http_spec
from netgear_switch.registry import get_model
from netgear_switch.transport.http.client import AsyncHttpClient, HttpClient
from netgear_switch.virtual.faces.http import VirtualHttpFace
from netgear_switch.virtual.seed import (
    seed_gsm7228ps,
    seed_gsm7252ps,
    seed_m4300_16x,
    seed_m4300_24x,
)

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "http"

_SEEDS = {
    "gsm7252ps": seed_gsm7252ps,
    "gsm7228ps": seed_gsm7228ps,
    "m4300-24x": seed_m4300_24x,
    "m4300-16x": seed_m4300_16x,
}
# The managed models whose PoE FORM accepts writes -- all of them except
# m4300-24x, which has no PoE hardware at all. gsm7252ps used to be excluded on
# the (wrong) grounds that its page "refuses every write"; the refusal was a
# missing list-unit field in OUR body, fixed and live-verified 2026-07-31 on
# 10.1.5.22 port 1/0/35.
POE_WRITABLE = ("gsm7252ps", "gsm7228ps", "m4300-16x")


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


class _Live:
    """A running virtual HTTP face plus a logged-in library client."""

    def __init__(self, key: str) -> None:
        self.key = key
        self.model = get_model(key)
        self.state = _SEEDS[key]()
        self.spec = http_spec(self.model)
        self.face = VirtualHttpFace(self.state, self.spec, password="password")
        self.port = self.face.start()
        self.client = HttpClient(f"127.0.0.1:{self.port}", "password", self.spec)

    def writer(self) -> HttpWriter:
        return HttpWriter(self.client, self.model)

    def reader(self) -> HttpReader:
        return HttpReader(self.client, self.model)

    def ports_page(self) -> parse.XuiListPage:
        assert self.spec.port_config_path is not None
        return parse.parse_xui_list_page(
            self.client.get_page(self.spec.port_config_path)
        )

    def admin(self, port: int) -> bool:
        names = (f"1/0/{port}", f"1/g{port}", f"1/xg{port}")
        row = next(r for r in self.ports_page().rows if r.field("v_1_2_1") in names)
        return row.field("v_1_2_6") == "Enable"

    def close(self) -> None:
        self.client.close()
        self.face.stop()


@pytest.fixture(params=sorted(_SEEDS))
def managed(request: pytest.FixtureRequest):
    live = _Live(request.param)
    try:
        yield live
    finally:
        live.close()


@pytest.fixture(params=POE_WRITABLE)
def poe_managed(request: pytest.FixtureRequest):
    live = _Live(request.param)
    try:
        yield live
    finally:
        live.close()


@pytest.fixture
def xe():
    live = _Live("gsm7252ps")
    try:
        yield live
    finally:
        live.close()


# --- set_port_enabled -------------------------------------------------------


def test_set_port_enabled_round_trip(managed) -> None:
    """Disable -> verify -> enable -> verify, exactly the sequence run live on
    all four switches (each on a link-down, undescribed port)."""
    assert managed.admin(2) is True
    managed.writer().set_port_enabled(2, enabled=False)
    assert managed.admin(2) is False
    managed.writer().set_port_enabled(2, enabled=True)
    assert managed.admin(2) is True


def test_set_port_enabled_touches_only_the_target_row(xe) -> None:
    """The live proof this pins: after the apply, a full re-read of the table
    showed the target row changed and every other row byte-identical."""
    before = {r.prefix: dict(r.fields) for r in xe.ports_page().rows}
    xe.writer().set_port_enabled(7, enabled=False)
    after = {r.prefix: dict(r.fields) for r in xe.ports_page().rows}
    changed = {p for p, fields in after.items() if fields != before[p]}
    assert changed == {"1.6.52."}  # 0-based row 6 == port 7


def test_set_port_enabled_finds_the_smart_firmware_ifname() -> None:
    """The S3300 names its ports ``1/g12``/``1/xg49``, not ``1/0/12``. The row
    is located by MATCHING the device's own cell, so both spellings work; a
    writer that computed ``row = port - 1`` would address the wrong row on any
    page whose row order is not port order (the PoE page of a 52-port switch has
    48 rows)."""
    live = _Live("gsm7228ps")
    try:
        rows = live.ports_page().rows
        assert rows[0].field("v_1_2_1") == "1/g1"
        assert rows[48].field("v_1_2_1") == "1/xg49"
        live.writer().set_port_enabled(49, enabled=False)
        assert live.admin(49) is False
    finally:
        live.close()


def test_set_port_enabled_rejects_a_port_the_page_does_not_render() -> None:
    live = _Live("m4300-24x")
    try:
        with pytest.raises(UnsupportedCapabilityError, match="not on this page"):
            live.writer().set_port_enabled(99, enabled=False)
    finally:
        live.close()


def test_set_port_enabled_needs_the_row_checkbox(xe) -> None:
    """The firmware applies ONLY rows whose ``gecb`` checkbox is submitted, and
    the mock reproduces that. Dropping it must leave the device untouched --
    which is why the writer verifies after writing instead of trusting the 200."""
    page = xe.ports_page()
    row = page.rows[1]
    body = forms.xui_row_apply_form(
        page, row, {"v_1_2_6": "Disable"}, button="v_2_1_2"
    )
    assert row.checkbox is not None
    del body[row.checkbox]
    xe.client.post_form(page.action, body)
    assert xe.admin(2) is True  # unchanged: the row was not selected


def test_set_port_enabled_surfaces_the_switchs_refusal(xe) -> None:
    """These pages answer HTTP 200 when they REFUSE, via err_flag=1 + err_msg.
    A bad value must come back as the switch's own message, not as success."""
    page = xe.ports_page()
    html = xe.client.post_form(
        page.action,
        forms.xui_row_apply_form(
            page, page.rows[0], {"v_1_2_6": "Bogus"}, button="v_2_1_2"
        ),
    )
    assert parse.parse_fastpath_err(html) == (
        "Error! Failed to Set 'Admin <br/> Mode' with 'Bogus'"
    )


def test_set_port_enabled_async_matches_sync(xe) -> None:
    async def run() -> None:
        client = AsyncHttpClient(f"127.0.0.1:{xe.port}", "password", xe.spec)
        await client.login()
        writer = AsyncHttpWriter(client, xe.model)
        await writer.set_port_enabled(3, enabled=False)
        assert xe.state.ports[3].admin is False
        await writer.set_port_enabled(3, enabled=True)
        await client.aclose()

    asyncio.run(run())
    assert xe.admin(3) is True


# --- clear_poe_fault / set_poe ----------------------------------------------


def test_clear_poe_fault_rearms_detection(poe_managed) -> None:
    """The page's hidden write-only ``v_1_2_20`` = "Reset" column, driven by its
    RESET button, re-runs PD detection -- so a faulted port leaves FAULT."""
    port = min(poe_managed.state.poe)
    poe_managed.state.poe[port].detect = 6  # a fault code
    poe_managed.writer().clear_poe_fault(port)
    detect = {p.port: p.detect for p in poe_managed.reader().get_poe()}
    assert detect[port] is not PoEDetect.FAULT


def test_clear_poe_fault_uses_the_pages_own_reset_button_label(poe_managed) -> None:
    """``v_2_1_3`` reads "RESET" on the gsm72xx pages and "Power Cycle Port(s)"
    on the M4300s (live 2026-07-30), so the value is echoed from the page."""
    assert poe_managed.spec.poe_config_path is not None
    page = parse.parse_xui_list_page(
        poe_managed.client.get_page(poe_managed.spec.poe_config_path)
    )
    expected = (
        "Power Cycle Port(s)" if poe_managed.key.startswith("m4300") else "RESET"
    )
    assert page.buttons["v_2_1_3"] == expected


def test_set_poe_round_trip_over_http(poe_managed) -> None:
    port = min(poe_managed.state.poe)
    writer, reader = poe_managed.writer(), poe_managed.reader()
    writer.set_poe(port, on=False)
    assert {p.port: p.admin_enabled for p in reader.get_poe()}[port] is False
    writer.set_poe(port, on=True)
    assert {p.port: p.admin_enabled for p in reader.get_poe()}[port] is True


def _poe_page(live: _Live) -> parse.XuiListPage:
    assert live.spec.poe_config_path is not None
    return parse.parse_xui_list_page(live.client.get_page(live.spec.poe_config_path))


def test_xui_pages_expose_their_list_navigation_block(managed) -> None:
    """Every XUI list page carries a ``urlListUnit`` field in its ``deftestme``
    navigation rows, and the parser must surface it -- it is what scopes an
    apply. Real captures of all four switches put ``v_1_1_1``/``v_1_3_1`` there
    (aliased by the page's own
    ``xeData["xalias_urlListUnit"] = "1_1_1|1_3_1|3_1_1|3_4_1"``)."""
    nav = managed.ports_page().nav
    assert nav["v_1_1_1"] == "1"
    assert nav["v_1_3_1"] == "1"
    # The global "apply to all rows" row is NOT navigation: echoing its empty
    # cells back is itself refused on hardware.
    assert not any(name.startswith("v_g_") for name in nav)


def test_poe_apply_carries_the_pages_list_unit(poe_managed) -> None:
    """The body the writer POSTs must contain the page's own list-unit field.

    This is the whole gsm7252ps bug: without it, 10.1.5.22 answered HTTP 200 +
    err_flag=1 with one 'Failed to Set' line per read-write column, even for a
    body that changed nothing."""
    page = _poe_page(poe_managed)
    body = forms.xui_row_apply_form(
        page, page.rows[0], {"v_1_2_2": "Disable"}, button="v_2_1_2"
    )
    assert body["v_1_1_1"] == "1"
    assert body["v_1_3_1"] == "1"


def test_gsm7252ps_poe_refuses_an_apply_with_no_list_unit(xe) -> None:
    """The mock reproduces the REFUSAL, not just the success.

    Live 2026-07-31 on 10.1.5.22 port 1/0/35: the same body without
    ``v_1_1_1``/``v_1_3_1`` came back err_flag=1 listing every read-write column
    it carried, and the port did not change. A writer that regressed the nav
    block must fail here rather than quietly stop working against hardware."""
    page = _poe_page(xe)
    row = page.rows[0]
    before = xe.state.poe[min(xe.state.poe)].admin
    body = forms.xui_row_apply_form(
        page, row, {"v_1_2_2": "Disable"}, button="v_2_1_2", omit=("v_1_2_20",)
    )
    for name in ("v_1_1_1", "v_1_3_1"):
        del body[name]
    html = xe.client.post_form(page.action, body)
    assert parse.parse_fastpath_err(html) == (
        "Error! Failed to Set 'Admin <br/> Mode' with 'Disable'"
    )
    assert xe.state.poe[min(xe.state.poe)].admin is before  # nothing changed


def test_gsm7252ps_poe_refusal_names_every_rw_column_in_the_body(xe) -> None:
    """The refusal lists one line per read-write column PRESENT in the body --
    which is how the Port Reset column was identified as a separate offender:
    dropping ``v_1_2_20`` removed exactly its line (live, 10.1.5.22)."""
    page = _poe_page(xe)
    body = forms.xui_row_apply_form(
        page, page.rows[0], {"v_1_2_2": "Disable"}, button="v_2_1_2"
    )
    for name in ("v_1_1_1", "v_1_3_1"):
        del body[name]
    err = parse.parse_fastpath_err(xe.client.post_form(page.action, body))
    assert err is not None
    assert err.splitlines() == [
        "Error! Failed to Set 'Admin <br/> Mode' with 'Disable'",
        "Error! Failed to Set 'Port Reset' with 'Reset'",
    ]


def test_siblings_accept_a_poe_apply_with_no_list_unit() -> None:
    """The counter-example, encoded so the mock cannot over-correct: gsm7228ps
    and m4300-16x render a per-row hidden ``v_1_2_21`` "Unit" key, so their rows
    are self-identifying and the apply lands with no page-level unit at all
    (live 2026-07-30 on 10.1.5.11 and 10.1.5.20:49152)."""
    for key in ("gsm7228ps", "m4300-16x"):
        live = _Live(key)
        try:
            page = _poe_page(live)
            body = forms.xui_row_apply_form(
                page,
                page.rows[0],
                {"v_1_2_2": "Disable"},
                button="v_2_1_2",
                omit=("v_1_2_20",),
            )
            for name in ("v_1_1_1", "v_1_3_1"):
                del body[name]
            html = live.client.post_form(page.action, body)
            assert parse.parse_fastpath_err(html) is None, key
            assert live.state.poe[min(live.state.poe)].admin is False, key
        finally:
            live.close()


def test_poe_apply_does_not_carry_the_write_only_reset_column(poe_managed) -> None:
    """APPLY's own shed list (``xeData.xa_2_1_2[14] = "1_2_20|g_1_2_20"``)
    disables the write-only Port Reset action, so a browser never submits it on
    an apply -- an apply must not double as a power cycle."""
    page = _poe_page(poe_managed)
    row = page.rows[0]
    body = forms.xui_row_apply_form(
        page,
        row,
        {"v_1_2_2": "Disable"},
        button="v_2_1_2",
        omit=("v_1_2_20",),
    )
    assert row.prefix + "v_1_2_20" in row.fields  # the page DOES render it
    assert row.prefix + "v_1_2_20" not in body


def test_poe_reset_does_not_carry_the_config_columns(poe_managed) -> None:
    """RESET's shed list disables ``1_2_2..1_2_18`` (``1_2_19`` too on the
    gsm7228ps/M4300 pages), so a power cycle must not rewrite Admin Mode."""
    page = _poe_page(poe_managed)
    row = page.rows[0]
    body = forms.xui_row_apply_form(
        page,
        row,
        {"v_1_2_20": "Reset"},
        button="v_2_1_3",
        omit=tuple(f"v_1_2_{n}" for n in range(2, 20)),
    )
    assert body[row.prefix + "v_1_2_20"] == "Reset"
    assert row.prefix + "v_1_2_2" not in body
    assert body[row.prefix + "v_1_2_1"] == row.field("v_1_2_1")  # key kept


def test_m4300_24x_has_no_poe_page_at_all() -> None:
    """Not a missing implementation: on the real 24X the page IS served (HTTP
    200, 28152 bytes, correct title, full button set) and simply has ZERO rows,
    because the SKU has no PSE ports."""
    live = _Live("m4300-24x")
    try:
        with pytest.raises(UnsupportedCapabilityError):
            live.writer().clear_poe_fault(1)
    finally:
        live.close()


# --- set_mgmt_ip ------------------------------------------------------------


def test_get_mgmt_ip_reads_the_models_own_page(managed) -> None:
    """Every managed model now serves address + mask + gateway + method over
    HTTP -- including gsm7228ps, whose spec used to claim its mgmt IP was
    unreachable this way, and the M4300s, whose /v1/ipConfiguration.html reads
    0.0.0.0 (their real page is mgmtVlanIpv4Configuration.html)."""
    cfg = managed.reader().get_mgmt_ip()
    assert cfg.address == managed.state.mgmt.address
    assert cfg.netmask == managed.state.mgmt.netmask
    assert cfg.gateway == managed.state.mgmt.gateway
    assert cfg.base_mac is not None


def test_set_mgmt_ip_needs_force(managed) -> None:
    with pytest.raises(ProtectedPortError):
        managed.writer().set_mgmt_ip("10.9.9.9", "255.255.255.0", "10.9.9.1")
    assert managed.state.mgmt.address != "10.9.9.9"


def test_set_mgmt_ip_applies_and_verifies(managed) -> None:
    """UNVERIFIED-LIVE by design: applying this to any reachable switch would
    move its management address and drop the session mid-write. The wire shape
    is grounded in each model's captured page (see XuiMgmtIpFields); this drives
    it end-to-end against the mock, including the read-back verification."""
    managed.writer().set_mgmt_ip(
        "10.9.9.9", "255.255.0.0", "10.9.0.1", force=True
    )
    cfg = managed.reader().get_mgmt_ip()
    assert (cfg.address, cfg.netmask, cfg.gateway) == (
        "10.9.9.9",
        "255.255.0.0",
        "10.9.0.1",
    )
    assert cfg.mode is IpMode.STATIC  # an explicit address is a STATIC address


def test_set_mgmt_ip_surfaces_a_refused_address() -> None:
    """The page validates the address and answers 200 + err_flag=1 with its own
    message (it publishes that string as ``xeValData.xv_1_1_1_635``). The writer
    must raise it, never treat the 200 as success."""
    live = _Live("m4300-16x")
    try:
        with pytest.raises(HttpError, match="switch refused"):
            live.writer().set_mgmt_ip(
                "10.9.9.999", "255.255.0.0", "10.9.0.1", force=True
            )
        assert live.state.mgmt.address != "10.9.9.999"
    finally:
        live.close()


def test_set_mgmt_ip_async_matches_sync(xe) -> None:
    async def run() -> None:
        client = AsyncHttpClient(f"127.0.0.1:{xe.port}", "password", xe.spec)
        await client.login()
        await AsyncHttpWriter(client, xe.model).set_mgmt_ip(
            "10.8.8.8", "255.255.255.0", "10.8.8.1", force=True
        )
        await client.aclose()

    asyncio.run(run())
    assert xe.state.mgmt.address == "10.8.8.8"
    assert xe.state.mgmt.gateway == "10.8.8.1"


# --- gs110emx: the same op, a genuinely different mechanism ----------------


def _emx():
    from netgear_switch.virtual.seed import seed_gs110emx

    model = get_model("gs110emx")
    state = seed_gs110emx()
    spec = http_spec(model)
    face = VirtualHttpFace(state, spec, password="password")
    port = face.start()
    client = HttpClient(f"127.0.0.1:{port}", "password", spec)
    client.login()
    return model, state, face, client


def test_gs110emx_set_port_enabled_round_trip() -> None:
    """This model's page has NO admin column: disabling a port means posting its
    "Physical Mode" as Disable (``PORT_CTRL_MODE=3``) and the reply is a bare
    ``SUCCESS`` body. LIVE-VERIFIED on a real GS110EMX (10.1.5.26, 2026-07-31)
    on port 7 -- link-down, no description."""
    model, state, face, client = _emx()
    try:
        writer, reader = HttpWriter(client, model), HttpReader(client, model)
        assert {p.port: p.admin_enabled for p in reader.get_ports()}[3] is True
        writer.set_port_enabled(3, enabled=False)
        assert state.ports[3].admin is False
        assert {p.port: p.admin_enabled for p in reader.get_ports()}[3] is False
        writer.set_port_enabled(3, enabled=True)
        assert {p.port: p.admin_enabled for p in reader.get_ports()}[3] is True
    finally:
        client.close()
        face.stop()


def test_gs110emx_port_no_must_be_semicolon_terminated() -> None:
    """``saveSelectedPorts()`` builds ``PORT_NO`` as ``"<n>;"``. A bare "3" is
    answered HTTP 200 and applies NOTHING -- caught on real hardware
    (10.1.5.25) by the writer's verify-after-write, and reproduced by the mock
    so the builder cannot regress to a bare number without this failing."""
    model, state, face, client = _emx()
    try:
        body = forms.gs110emx_port_admin_form(
            port=3, enabled=False, flow_control_mode="4"
        )
        assert body["PORT_NO"] == "3;"
        client.post_form("/iss/specific/port_settings.html", {**body, "PORT_NO": "3"})
        assert state.ports[3].admin is True  # nothing selected -> nothing applied
        del model
    finally:
        client.close()
        face.stop()


def test_gs110emx_rejects_a_port_it_does_not_render() -> None:
    model, _state, face, client = _emx()
    try:
        with pytest.raises(UnsupportedCapabilityError, match="not on this page"):
            HttpWriter(client, model).set_port_enabled(99, enabled=False)
    finally:
        client.close()
        face.stop()


def test_gs110emx_poe_and_mgmt_ip_write_stay_honest() -> None:
    """This model genuinely has no PoE (its own JS lists 39 pages and none is a
    PoE page; poe.html/poe_config.html both 404 -- live 2026-07-31), so PoE
    writes must raise. Its mgmt-IP page is a Plus-class sysInfo form, NOT a
    FASTPATH XUI one, so set_mgmt_ip is not yet implemented for it and says so
    rather than POSTing a guessed body."""
    model, _state, face, client = _emx()
    try:
        writer = HttpWriter(client, model)
        with pytest.raises(UnsupportedCapabilityError):
            writer.clear_poe_fault(1)
        with pytest.raises(UnsupportedCapabilityError, match="management-IP form"):
            writer.set_mgmt_ip("10.9.9.9", "255.255.255.0", "10.9.9.1", force=True)
    finally:
        client.close()
        face.stop()


# --- the write-form builders + page parsers (pure, fixture-grounded) --------


def test_xui_row_apply_form_refuses_a_column_the_row_does_not_render() -> None:
    page = parse.parse_xui_list_page(_fixture("gsm7252ps_portsConfiguration.html"))
    with pytest.raises(KeyError, match="v_1_2_99"):
        forms.xui_row_apply_form(
            page, page.rows[0], {"v_1_2_99": "x"}, button="v_2_1_2"
        )


def test_xui_row_apply_form_carries_only_the_target_row() -> None:
    page = parse.parse_xui_list_page(_fixture("gsm7252ps_portsConfiguration.html"))
    body = forms.xui_row_apply_form(
        page, page.rows[35], {"v_1_2_6": "Disable"}, button="v_2_1_2"
    )
    assert body["1.35.52.v_1_2_6"] == "Disable"
    assert body["1.35.52.gecb5"] == "on"
    assert body["submit_flag"] == "8"  # the firmware's xui_operation_submit
    assert body["v_2_1_2"] == "APPLY"
    # No other row is mentioned at all -- a firmware that ignored checkboxes
    # still could not touch another port through this body.
    assert not [k for k in body if k.startswith("1.") and not k.startswith("1.35.")]


def test_xui_form_apply_form_echoes_the_pages_csrf_token() -> None:
    """The M4300-16X answers 403 to a POST that drops its per-page CSRFToken, so
    the builder starts from the page's own fields."""
    page = parse.parse_xui_form_page(
        _fixture("m4300_16x_mgmtVlanIpv4Configuration.html")
    )
    body = forms.xui_form_apply_form(page, {"v_1_6_1": "10.0.0.9"}, button="v_3_1_1")
    assert body["CSRFToken"] == page.fields["CSRFToken"]
    assert body["v_1_6_1"] == "10.0.0.9"
    assert body["submit_flag"] == "8"
    assert body["v_3_1_1"] == "Apply"


def test_fixture_ports_pages_carry_the_measured_row_naming() -> None:
    """Per-firmware row/checkbox naming, straight off the live pages. These
    differ on every SKU, which is exactly why the writer scrapes them."""
    expected = {
        "gsm7252ps_portsConfiguration.html": ("1.0.52.", "1.0.52.gecb5", "1/0/1"),
        "gsm7228ps_portsConfiguration.html": ("1.0.52.", "1.0.52.gecb10", "1/g1"),
        "m4300_ports.html": ("1.0.24.", "1.0.24.gecb_1_2", "1/0/1"),
        "m4300_16x_portsConfiguration.html": (
            "1.0.16.",
            "1.0.16.gecb_1_2",
            "1/0/1",
        ),
    }
    for name, (prefix, checkbox, ifname) in expected.items():
        page = parse.parse_xui_list_page(_fixture(name), page=name)
        assert page.rows[0].prefix == prefix, name
        assert page.rows[0].checkbox == checkbox, name
        assert page.rows[0].field("v_1_2_1") == ifname, name
        assert page.rows[0].field("v_1_2_6") == "Enable", name
        assert page.buttons["v_2_1_2"].upper() == "APPLY", name


def test_fixture_poe_page_has_the_write_only_reset_column() -> None:
    page = parse.parse_xui_list_page(
        _fixture("gsm7252ps_poeInterfaceConfiguration.html")
    )
    assert len(page.rows) == 48
    assert page.rows[0].field("v_1_2_20") == "Reset"
    assert page.buttons["v_2_1_3"] == "RESET"


def test_fixture_m4300_16x_poe_page_labels_reset_differently() -> None:
    page = parse.parse_xui_list_page(
        _fixture("m4300_16x_poeInterfaceConfiguration.html")
    )
    assert len(page.rows) == 16
    assert page.buttons["v_2_1_3"] == "Power Cycle Port(s)"


def test_fixture_m4300_24x_poe_page_is_present_but_has_no_rows() -> None:
    """THE captured proof that the -24X's missing PoE is a device fact and not a
    missing implementation. A 404 would have meant "page not found"; this is a
    **200** of exactly 28152 bytes, with the correct title and the page's full
    button set, that simply contains ZERO ``<TR p="...">`` rows -- because the
    SKU has no PSE ports. Its sibling -16X serves the same URL with 16."""
    html = _fixture("m4300_24x_poeInterfaceConfiguration.html")
    assert len(html) == 28152
    assert "<TITLE>NETGEAR -  PoE Port Configuration</TITLE>" in html
    page = parse.parse_xui_list_page(html)
    assert page.rows == ()
    assert page.buttons["v_2_1_3"] == "Power Cycle Port(s)"
    assert (
        len(parse.parse_xui_list_page(
            _fixture("m4300_16x_poeInterfaceConfiguration.html")
        ).rows)
        == 16
    )


def test_fixture_gsm7228ps_ip_page_is_not_a_button_page() -> None:
    """``v_2_1_1`` on this page is the Management VLAN ID, NOT a button -- the
    reason button detection is scoped to the page's own xuiButtonsDiv instead of
    guessing from the field name."""
    page = parse.parse_xui_form_page(_fixture("gsm7228ps_ipConfiguration.html"))
    assert page.fields["v_2_1_1"] == "5"
    assert set(page.buttons) == {"v_3_1_1", "v_3_1_2"}
    assert page.fields["v_1_1_1"] == "10.1.5.11"
