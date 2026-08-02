"""Per-model web-UI endpoint/CGI definitions (pure data).

Each ``HttpModelSpec`` records how one model logs in and which page each read
op scrapes. ``scheme_verified``/``reads_verified`` mark whether that model's
flows are grounded in captured prior art or still
``UNVERIFIED-pending-capture``:

- ``gs305ep`` (Plus PoE): login, dashboard/stats, PoE, VLAN/PVID, and reboot
  endpoints are GROUNDED in ``py_netgear_plus/models.py`` (GS30xSeries /
  GS30xEPxSeries: ``CRYPT_FUNCTION="merge_hash"``, ``LOGIN_TEMPLATE``,
  PoE/VLAN CGI paths) and in ``rcfiles/bin/netgear-smp-vlan`` (identical
  ``merge`` hash scheme observed on GS105PE; ``8021qCf.cgi`` /
  ``8021qMembe.cgi`` / ``portPVID.cgi`` field shapes and wire codes). Both
  ``scheme_verified`` and ``reads_verified`` are ``True``.
- ``gsm7228ps`` (Smart Managed Pro / S3300-52X): the plaintext cheetah login
  form is GROUNDED in ``certbot-hook-netgear-switches/netgear-updater.py``
  (``S3300Updater``), so ``scheme_verified`` is ``True``. Its read pages are the
  SAME Cheetah XE grid as the sibling ``gsm7252ps`` and are GROUNDED in real
  captures of the live switch (``tests/fixtures/http/gsm7228ps_*.html``);
  ports/stats/PVIDs/VLANs/PoE/LLDP reuse the ``parse_xe_*`` parsers, while the
  MAC table (shifted columns, escaped ``1/gN`` port names) and sensors
  (unsupported over HTTP) get S3300-specific handling -- see
  ``HtmlDialect.S3300``. ``reads_verified`` is ``True`` (HTTP cross-verified vs
  SNMP on 10.1.5.11); SNMP remains authoritative for the full sensor set. Its
  management IP is NOT "unreachable over HTTP" as this file once claimed --
  ``/ipConfiguration.html`` serves it, and more of it than SNMP does (see
  ``mgmt_ip_path`` below).
- ``gs110emx`` (Plus EMx / Gambit): GROUNDED in real captures from a physical
  GS110EMX (``tests/fixtures/http/gs110emx_*.html``). The scheme is
  ``merge_hash_md5(password, rand)`` (identical function to ``gs305ep``) POSTed
  as ``LoginPassword`` to ``/redirect.html`` (``rand`` scraped from ``GET /``,
  not from the POST target itself -- see ``login_post_path``); the response
  carries a ``Gambit`` TOKEN (not a cookie -- no ``Set-Cookie`` is ever sent)
  that every subsequent request must carry (``session_token_field``).
  HTTP covers the FULL NSDP read surface here (ports/stats/VLANs/PVIDs/
  mgmt-IP): an earlier probe guessed ``/iss/specific/{vlan,port,pvid}.html``,
  got 404s and WRONGLY concluded "NSDP-only" -- the real URLs
  (``port_settings``/``vlan_pvidsetting``/``Cf8021q``/``vlanMembership``) live
  only as JS string literals and were found live 2026-07-21. ``poe_*`` stay
  ``None`` (this model genuinely has no PoE, confirmed 404), as do
  ``reboot_path``/``logout_path`` (never captured, not guessed).
  CAVEAT on ``reads_verified=True``: only VLAN 1's membership page was
  captured, so the per-VLAN ``vlanIdSel`` select is live-confirmed but
  fixture-proven for VLAN 1 only.
- ``gs105pe`` (Plus, 5-port): LIVE-VERIFIED on a real GS105PE (10.1.5.30,
  2026-07-21) -- registry ``verified=True``, and BOTH ``scheme_verified`` and
  ``reads_verified`` are ``True``, grounded in six real captures
  (``tests/fixtures/http/gs105pe_*.html``). The merge-hash login is shared with
  ``gs305ep``, but the READ paths are NOT: the gs305ep copies were partly wrong
  (``dashboard.cgi`` and ``getPoePortStatus.cgi`` both 404 on real hardware).
  Port status is ``status.cgi`` and device identity/mgmt-IP is
  ``switch_info.cgi``; see ``HtmlDialect.GS105PE`` for the parser set.
- ``gsm7252ps`` (Fully Managed / XE FASTPATH): the cheetah login
  (``uname``+``pwd`` -> SID cookie) was validated LIVE on 10.1.5.22, so
  ``scheme_verified`` is ``True``. Its read pages sit at the ROOT prefix and
  are grounded in real captures of that switch, covering EVERY read op
  including sensors and mgmt-IP (``sysInfo.html``). ``reads_verified`` is
  ``True``: the HTTP reader output was cross-verified against SNMP on the live
  switch (10.1.5.22) -- ports/PVIDs match, mgmt-IP is an exact match, and every
  read op returns real data.
"""

from __future__ import annotations

import dataclasses
import enum
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING

from ...errors import UnsupportedCapabilityError
from ...registry import Backend

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ...registry import SwitchModel


class LoginScheme(enum.Enum):
    MERGE_HASH_CGI = "merge_hash_cgi"  # Plus SID scheme (gs305ep) — GROUNDED
    GAMBIT = "gambit"  # EMx merge-hash + token (gs110emx) — GROUNDED
    CHEETAH_FORM = "cheetah_form"  # Pro/S3300 (gsm7228ps) — plaintext form
    CHEETAH_V1 = "cheetah_v1"  # M4300 /v1 — uname+pwd + Referer CSRF
    # GS728TPP GoAhead XML-API (grounded in certbot-hook GS728TPPUpdater): a
    # THREE-step handshake, not a form POST -- GET / returns a 302 redirect to a
    # per-session path, then a GET of ``<sess>/System.xml?action=login&user=..&
    # password=..`` returns ``<statusCode>0</statusCode>`` and a ``sessionID``
    # RESPONSE HEADER (never a Set-Cookie), which the client then sets as the
    # ``sessionID`` cookie alongside ``userStatus=ok``/``usernme=<user>``. Every
    # subsequent read is a GET under that session path (see transport client).
    XML_API = "xml_api"


class HtmlDialect(enum.Enum):
    """Which family of HTML the model's read pages are written in, selecting the
    whole parser set ``http_read.py`` uses for ports/stats/PVIDs/VLAN-list.

    The two families genuinely differ in wire shape: the gs305ep CGI pages use
    closed ``<tr class="portID">...</tr>`` rows and ``8021qCf.cgi`` VLAN
    checkboxes, whereas the real GS110EMX firmware never closes a port row and
    lists VLANs as ``<tr class="vlanID tableTr">`` rows (all GROUNDED in
    captures under ``tests/fixtures/http/``). One dialect field per model beats
    a separate shape flag per read op.
    """

    STANDARD = "standard"  # gs305ep CGI: closed portID rows, vlanck checkboxes
    GS110EMX = "gs110emx"  # real GS110EMX: open portID rows, Advanced-802.1Q list
    GS105PE = "gs105pe"  # real GS105PE: status.cgi layout, hidden-input counters
    M4300 = "m4300"  # real M4300 Cheetah /v1: xid hidden inputs + field comments
    # "auto-generated by XE" FASTPATH pages (real GSM7252PS): the same hidden-
    # input cells as M4300 but with NO <!-- field --> comments, so fields are
    # addressed by COLUMN COORDINATE instead of by name (see parse.parse_xe_rows).
    # Named for the firmware family rather than the SKU because the encoding is
    # a FASTPATH/XE trait -- but it is so far VALIDATED ONLY against gsm7252ps
    # captures; another XE model's column maps must be re-checked, not assumed.
    XE_FASTPATH = "xe_fastpath"
    # S3300-52X-PoE+ (Smart Managed Pro, gsm7228ps): the SAME Cheetah XE grid as
    # gsm7252ps for ports/stats/PVIDs/VLANs/PoE/LLDP (parse_xe_*), but three
    # pages differ and get their own handling. (1) The basicAddressTable columns
    # are SHIFTED (VLAN in v_1_2_2, not v_1_2_1) and the port ifName is
    # HTML-entity-escaped in the Smart firmware's "1/gN"/"1/xgN" form
    # (parse_s3300_macs). (2) Its sysInfo exposes only the Base MAC Address, so
    # that is all get_mgmt_ip takes from it (parse_s3300_mgmt); the IPv4
    # address/netmask/gateway/method come from /ipConfiguration.html instead.
    # This used to say those "live on a JS-menu-only page unreachable here" --
    # WRONG, and corrected live 2026-07-30 (see the _GSM7228PS spec below).
    # (3) That sysInfo carries no live fan/temp sensor table, so get_sensors is
    # unsupported over HTTP (SNMP is the only source). LIVE-verified on the real
    # S3300-52X (10.1.5.11), cross-checked vs SNMP.
    S3300 = "s3300"
    # GS728TPP GoAhead ``wcd`` XML API (real captures, tmp/gs728tpp_ground_truth
    # .json): every read is a ``GET <sess>/wcd?{file=/path/X.xml}{Object}..``
    # whose response is a template of ``BIND=`` placeholders followed by a
    # trailing ``<DeviceConfiguration>`` data block of ``<Object type="section">``
    # elements (scalars, or repeated ``<Interface>``/``<Entry>``/``<VLAN>`` rows).
    # The parsers extract ONLY that data block and read it as XML -- see
    # parse.parse_goahead_*. Structured XML, NOT the HTML-scraping the other
    # dialects do.
    GOAHEAD_XML = "goahead_xml"


def dialect_has_csrf_hash(dialect: HtmlDialect) -> bool:
    """Whether this dialect's pages carry an ``<input name="hash">`` CSRF token.

    ``http_write`` scrapes that token before every form post, so a dialect
    without one cannot be driven by those writers at all.

    MEASURED 2026-08-02, not inferred. Live probes found NO hash on any write
    page of gsm7252ps (10.1.5.22: vlanStatus, poeInterfaceConfiguration,
    portPvidConfiguration, vlan_port_cfg, portsConfiguration) nor of gs110emx
    (10.1.5.25: Cf8021q, vlan_pvidsetting). Only the Plus ``.cgi`` pages have
    it -- the surface ``HttpWriter`` was originally written against.

    ONE definition, read by the capability oracle AND by the virtual switch, so
    the mock can never emit a token the hardware lacks. That divergence is
    exactly how HTTP ``create_vlan`` passed the entire test suite while failing
    on all four FASTPATH switches.
    """
    return dialect in {HtmlDialect.STANDARD, HtmlDialect.GS105PE}



@dataclass(frozen=True)
class XuiMgmtIpFields:
    """Which fields of a FASTPATH XUI management-IP page carry what.

    Deliberately PER MODEL, never shared by dialect. The two Cheetah families
    put the same information on different pages under different names, and one
    page name that looks shared is not:

    * gsm7252ps / gsm7228ps: ``/ipConfiguration.html`` -- address ``v_1_1_1``,
      mask ``v_1_2_1``, gateway ``v_1_3_1``, protocol ``v_1_18_1`` (the hidden
      twin of the visible radio, which is ``v_1_8_1`` on gsm7252ps but
      ``v_1_4_1`` on gsm7228ps -- the same name means different things on the
      two boxes, so only the hidden one is used).
    * m4300-24x / m4300-16x: ``/v1/mgmtVlanIpv4Configuration.html`` -- address
      ``v_1_6_1``, mask ``v_1_7_1``, gateway ``v_1_71_1``, DHCP/static
      ``v_1_5_3`` (``Enable`` = DHCP, ``Disable`` = Manual, per the page's own
      ``xeData["xew_1_5_3_Enable"] = "DHCP"``). Their ``/v1/ipConfiguration.html``
      exists and answers 200, but it is the SERVICE-PORT interface and reads
      ``0.0.0.0/0.0.0.0`` on both SKUs (live 2026-07-30) -- reading mgmt-IP from
      it would report the switch as unaddressed.
    * gsm7252ps/gsm7228ps 404 on ``/mgmtVlanIpv4Configuration.html`` (live
      2026-07-30), which is exactly why this is not one shared constant.
    """

    address: str
    netmask: str
    gateway: str
    # The field carrying the addressing METHOD, plus the two values it takes.
    mode: str
    static_value: str
    dhcp_value: str
    # The page's APPLY button field (``v_3_1_1`` on both families). Its VALUE is
    # read off the page, since the label differs (``APPLY`` vs ``Apply``).
    apply_button: str


_GSM72XX_MGMT_IP_FIELDS = XuiMgmtIpFields(
    address="v_1_1_1",
    netmask="v_1_2_1",
    gateway="v_1_3_1",
    mode="v_1_18_1",
    static_value="None",  # allWebEnums e_v_1_18_1 = ["None","Bootp","DHCP"]
    dhcp_value="DHCP",
    apply_button="v_3_1_1",
)
_M4300_MGMT_IP_FIELDS = XuiMgmtIpFields(
    address="v_1_6_1",
    netmask="v_1_7_1",
    gateway="v_1_71_1",
    mode="v_1_5_3",
    static_value="Disable",  # xew_1_5_3_Disable = "Manual"
    dhcp_value="Enable",  # xew_1_5_3_Enable = "DHCP"
    apply_button="v_3_1_1",
)


@dataclass(frozen=True)
class HttpModelSpec:
    model_key: str
    scheme: LoginScheme
    scheme_verified: bool
    login_path: str
    password_field: str
    # Cookie session (SID-style): the name of the auth cookie the client
    # must see after login. Left "" (unused) for a token-session model --
    # see `session_token_field` below; the two are mutually exclusive.
    cookie_name: str
    needs_rand: bool
    dashboard_path: str | None
    stats_path: str | None
    poe_config_path: str | None
    poe_status_path: str | None
    vlan_config_path: str | None
    vlan_membership_path: str | None
    pvid_path: str | None
    reboot_path: str | None
    logout_path: str | None
    is_epx_poe: bool
    reads_verified: bool
    # Token session (GS110EMX Gambit): the form/query-param NAME the session
    # token is carried under on every request (e.g. "Gambit") once the login
    # POST response has yielded one. ``None`` (the default) means this model
    # uses the older cookie session instead -- see ``cookie_name`` above and
    # ``transport/http/client.py``'s ``_check_authed``/token handling.
    session_token_field: str | None = None
    # The login POST target, when it differs from ``login_path`` (the GET
    # page the ``rand`` nonce/login form is scraped from). ``None`` means
    # POST goes to ``login_path`` itself (gs305ep/gsm7228ps); GS110EMX GETs
    # ``/`` for `rand` but POSTs the hashed password to ``/redirect.html``.
    login_post_path: str | None = None
    # Device identity + management-IP config page (GS110EMX sysInfo.html).
    # ``None`` means this model has no such HTTP page (gs305ep/gsm7228ps
    # read this via NSDP/SNMP instead).
    sysinfo_path: str | None = None
    # Dedicated management-IP query, for a model whose mgmt-IP lives on a
    # DIFFERENT page than ``sysinfo_path``. On the GS728TPP GoAhead API the
    # ``sysinfo_path`` wcd query serves device identity + box sensors, but the
    # IPv4 interface/gateway config is a SEPARATE ``IPConf_master.xml`` wcd
    # query -- so ``get_mgmt_ip`` reads this field instead of ``sysinfo_path``
    # for the GOAHEAD_XML dialect. ``None`` (the default) means mgmt-IP is read
    # from ``sysinfo_path`` (every other model), or is unsupported when that is
    # ``None`` too.
    mgmt_ip_path: str | None = None
    # Which HTML family this model's read pages use -- see HtmlDialect. Selects
    # the ports/stats/PVID/VLAN-list parser set. Defaults to the gs305ep CGI
    # shape every model but gs110emx uses.
    html_dialect: HtmlDialect = HtmlDialect.STANDARD
    # MAC/FDB table page. None = this model exposes no FDB over HTTP (every
    # Plus switch; only the M4300 managed UI has one).
    mac_table_path: str | None = None
    # Username field name for schemes that need one (M4300 /v1 posts BOTH
    # uname and pwd). None = password-only login.
    username_field: str | None = None
    # Default username sent with ``username_field``.
    username: str = "admin"
    # Whether every request must carry a ``Referer: http://<host>/`` header.
    # The M4300 /v1 UI answers 403 to any request without it (a CSRF guard).
    needs_referer: bool = False
    # LLDP neighbour table page. None = this model's web UI exposes no LLDP
    # neighbour data (every Plus switch; the M4300 /v1 UI has only LLDP-MED
    # remote data, which carries no chassis/port-id table) -> get_lldp raises
    # rather than returning a fabricated empty list.
    lldp_path: str | None = None
    # HTTPS SSL-certificate upload (multipart POST). Populated only for a model
    # with a GROUNDED web-UI upload flow -- today only gsm7228ps/S3300, grounded
    # in certbot-hook-netgear-switches/netgear-updater.py::S3300Updater
    # (upload_certificate, lines ~625-706): the combined cert+key PEM is POSTed
    # to ``cert_upload_path`` as the file field ``cert_upload_file_field``
    # (``.v_1_3_1_handle``), alongside the fixed form fields in
    # ``cert_upload_form_fields``. All three None/empty means this model exposes
    # no cert-upload flow through this library; HttpWriter.upload_certificate
    # then raises UnsupportedCapabilityError (or, for a model whose real
    # mechanism is known but not yet implemented, NotImplementedError -- see
    # http_write.CERT_UPLOAD_KNOWN_UNIMPLEMENTED).
    cert_upload_path: str | None = None
    cert_upload_file_field: str | None = None
    # default_factory (not a bare MappingProxyType default): Python 3.11's
    # dataclass rejects an unhashable mappingproxy as a field default
    # ("mutable default ... use default_factory"); 3.12 tolerated it, which is
    # why local 3.12 runs missed it. The factory keeps the empty-immutable-map
    # default while staying 3.11-compatible.
    cert_upload_form_fields: Mapping[str, str] = dataclasses.field(
        default_factory=lambda: MappingProxyType({})
    )
    # Transport: whether this model's web UI is HTTPS (self-signed cert -- the
    # facade passes ``secure`` to the client, which leaves verify_tls off). The
    # M4300-16X-PoE moves its Cheetah "Main UI" to HTTPS; every other model so
    # far is plain HTTP. ``False`` (the default) = http://.
    secure: bool = False
    # The POST target of the VLAN-membership form, when it differs from the GET
    # page in ``vlan_membership_path`` (mirrors ``login_post_path``). ``None``
    # means the page POSTs back to itself -- every Plus-class model
    # (``8021qMembe.cgi``, ``vlanMembership.html``).
    #
    # LIVE-DISCOVERED 2026-07-30 on all four FASTPATH switches: the managed
    # "VLAN Membership" page GETs ``switching/dot1q/vlan_port_cfg.html`` but its
    # ``<form ACTION=...>`` is the sibling ``switching/dot1q/vlan_port_cfg_rw.html``
    # -- used for BOTH reads (``submt=0``, the VLAN <select>'s own onChange path)
    # and applies (``submt=16``). See ``parse.parse_fastpath_membership``.
    vlan_membership_post_path: str | None = None
    # Non-standard web-UI TCP port. ``None`` (the default) = the URL's implicit
    # 80/443. The M4300-16X-PoE serves its Cheetah UI on 49152; the facade forms
    # the host as ``<ip>:<web_port>`` when this is set.
    web_port: int | None = None
    # The per-port ADMIN-MODE page (``set_port_enabled``). On every FASTPATH
    # model this is the same ``portsConfiguration.html`` the reader scrapes for
    # port status, but it is a SEPARATE field on purpose: "the page I read
    # status from" and "the page I write admin mode to" are different questions,
    # and a model whose write page moves (or whose write form has to be
    # discovered separately, as on the Plus CGIs) must be able to say so without
    # dragging its read path along. ``None`` = not discovered for this model,
    # and ``set_port_enabled`` says which model and which page it is missing.
    port_config_path: str | None = None
    # Which fields of ``mgmt_ip_path`` carry address/mask/gateway/method, for a
    # model whose mgmt-IP page is a FASTPATH XUI form. ``None`` for the Plus/
    # GoAhead models, whose mgmt-IP pages are a different shape entirely.
    mgmt_ip_fields: XuiMgmtIpFields | None = None


# The managed (FASTPATH/Cheetah) "VLAN Membership" page, shared by every managed
# model in this file -- gsm7252ps, gsm7228ps/S3300 and both M4300 SKUs (the M4300s
# serve it under their ``/v1`` prefix). LIVE-DISCOVERED 2026-07-30, and it is NOT
# guessable: fifteen plausible FASTPATH names were probed on 10.1.5.22 and every
# one 404'd --
#     GET /vlanMembership.html            -> HTTP 404
#     GET /vlanMemberConfiguration.html   -> HTTP 404
#     GET /vlanPortConfiguration.html     -> HTTP 404
#     GET /vlanPortSummary.html           -> HTTP 404   (+11 more)
# while ``/vlanConfiguration.html`` DOES exist but is the VLAN create/delete page
# (no per-port Participation/Tagging anywhere in its 23104 bytes). The real URL is
# a leaf of the JS nav tree, ``GET /base/js/ng_sideNav.js``:
#     str+=FrthLvl("lvl2","VLAN Membership",
#                        "switching/dot1q/vlan_port_cfg.html","none");
# The page GETs ``vlan_port_cfg.html`` and its form POSTs to the ``_rw.html`` twin,
# which serves BOTH reads (``submt=0``) and applies (``submt=16``) -- see
# ``parse.parse_fastpath_membership`` and ``forms.fastpath_membership_form``.
# Deliberately NOT a per-model literal: the same relative path was confirmed live
# on all four SKUs, so a divergence would be a real finding, not a typo.
_FASTPATH_VLAN_MEMBERSHIP = "/switching/dot1q/vlan_port_cfg.html"
_FASTPATH_VLAN_MEMBERSHIP_RW = "/switching/dot1q/vlan_port_cfg_rw.html"
_M4300_VLAN_MEMBERSHIP = f"/v1{_FASTPATH_VLAN_MEMBERSHIP}"
_M4300_VLAN_MEMBERSHIP_RW = f"/v1{_FASTPATH_VLAN_MEMBERSHIP_RW}"

# The FASTPATH XUI write pages. Every one of these was fetched live on all four
# managed switches on 2026-07-30 and answered 200 with the expected <TITLE>; the
# ``/v1`` prefix is the M4300s' and is applied per model below, never assumed.
#
# The mgmt-IP page is where the two families genuinely diverge, so there is NO
# shared constant for it -- see XuiMgmtIpFields' docstring for the measured
# 404s/0.0.0.0s that make one impossible.
_FASTPATH_PORT_CONFIG = "/portsConfiguration.html"
_FASTPATH_POE_CONFIG = "/poeInterfaceConfiguration.html"
_GSM72XX_MGMT_IP = "/ipConfiguration.html"
_M4300_MGMT_IP = "/v1/mgmtVlanIpv4Configuration.html"


# GROUNDED: py_netgear_plus/models.py GS30xSeries/GS30xEPxSeries
# (CRYPT_FUNCTION="merge_hash", ALLOWED_COOKIE_TYPES=["SID"],
# check_login_form_rand=True, LOGIN_TEMPLATE url=/login.cgi
# params={password:_password_hash}; PoE/VLAN CGI paths) plus
# rcfiles/bin/netgear-smp-vlan (identical merge-hash login observed on
# GS105PE; 8021qCf.cgi/8021qMembe.cgi/portPVID.cgi field shapes and the
# 1=Untagged/2=Tagged/3=Excluded membership wire codes). Fully grounded.
#
# sysinfo_path is STILL None, deliberately. The obvious move is to copy
# gs105pe's ``/switch_info.cgi`` -- gs305ep and gs105pe do share the login
# scheme -- but copying gs305ep's read paths ONTO gs105pe is exactly what went
# wrong before (``dashboard.cgi`` and ``getPoePortStatus.cgi`` both 404'd on the
# real GS105PE), so the inference is known-unreliable in this very pair. It
# could not be settled here: all three gs305ep/gs105pe units in this fleet
# (poe-micro1/2/3 @ 10.1.5.28/.29/.30) were POWERED OFF on 2026-07-30 -- no
# ICMP, no NSDP unicast, and no answer to an NSDP discovery broadcast on the
# 10.1.5.0/24 segment. Discover it live rather than guessing.
_GS305EP = HttpModelSpec(
    model_key="gs305ep",
    scheme=LoginScheme.MERGE_HASH_CGI,
    scheme_verified=True,
    login_path="/login.cgi",
    password_field="password",
    cookie_name="SID",
    needs_rand=True,
    dashboard_path="/dashboard.cgi",
    stats_path="/portStatistics.cgi",
    poe_config_path="/PoEPortConfig.cgi",
    poe_status_path="/getPoePortStatus.cgi",
    vlan_config_path="/8021qCf.cgi",
    vlan_membership_path="/8021qMembe.cgi",
    pvid_path="/portPVID.cgi",
    reboot_path="/device_reboot.cgi",
    logout_path="/logout.cgi",
    is_epx_poe=True,
    reads_verified=True,
)

# GROUNDED: live capture from a physical GS110EMX (see
# tests/fixtures/http/gs110emx_*.html). GET / for `rand` -> POST
# LoginPassword=merge_hash_md5(pw, rand) to /redirect.html -> response carries
# a Gambit TOKEN (no cookie) that every subsequent request carries as
# ?Gambit=<token> (GET) or a form field (POST).
#
# HTTP covers the FULL NSDP read surface on this model (2026-07-21 live
# discovery, correcting an earlier absence-of-evidence error): the real page
# URLs live only as string literals in /frame.js, so an earlier probe that
# guessed /iss/specific/{vlan,port,pvid}.html got 404 and WRONGLY concluded
# "NSDP-only". The real URLs are ports=port_settings.html, PVIDs=
# vlan_pvidsetting.html, VLAN list=Cf8021q.html (Advanced 802.1Q), VLAN
# membership=vlanMembership.html (same `hiddenMem`/VLAN_ID scheme as gs305ep).
# poe_*_path stay None -- gs110emx genuinely has NO PoE (confirmed 404).
# reboot_path/logout_path were never captured and stay None rather than guessed.
#
# reads_verified=True covers ports/stats/PVIDs/VLANs/mgmt-IP. Caveat: within
# sysInfo.html, only the STATIC-IP case was directly observed; parse_sysinfo's
# DHCP branch is inferred from the same <select>'s option ordering, never
# captured from a real DHCP-configured device -- see HttpSysInfo's docstring.
#
# mac_table_path / lldp_path / poe_status_path stay None, and that is now
# ENUMERATED rather than assumed. This firmware builds its whole menu from
# ``GET /frame.js``, whose string literals name every page the UI can reach --
# all 37 of them, fetched live from 10.1.5.25 (fw 1.0.2.8, 2026-07-30):
#   Basic8021q, Cf8021q, GPL, cable_diagnostics, cos_configuration,
#   default_settings, getstatus, httpdownload, igs_conf, interface_stats,
#   lacp_cfg, lacp_port_cfg, lag_membership, lag_settings, lbdt_configuration,
#   password, plusconf, portBasedAdvanced, portBasedBasic, port_monitorconfig,
#   port_ratectrl, port_settings, powerSaving, registration, restore, save,
#   stormControl_interface, support, sysInfo, sys_reload, userGuide,
#   vlanMembership, vlan_pvidsetting, voice_vlan_cfg, voice_vlan_oui,
#   voice_vlan_port_cfg (+ /help.html)
# There is no MAC address table page, no LLDP page, no sensor page and no PoE
# page in that list -- so get_macs/get_lldp/get_sensors/get_poe have nothing to
# scrape here, matching the NSDP tag sweep, which found no such tag either.
#
# PORT ADMIN over HTTP, for whoever wires ``HttpWriter.set_port_enabled``: this
# model has no "Admin Status" column at all -- disabling a port is done by
# setting its SPEED to "Disable". ``dashboard_path`` (port_settings.html) is
# both the read page and the write target. Its own JS
# (``function.js::sendPortStatusForm``) POSTs form-encoded:
#     Gambit=<token>&PORT_NO=<n>;&PORT_DESCRIPTION=<urlencoded>
#     &PORT_CTRL_MODE=<m>&PORT_CTRL_DUPLEX=<d>&PORT_CTRL_SPEED=<s>
#     &FLOW_CONTROL_MODE=<f>&ACTION=apply
# where PORT_NO is a SEMICOLON-terminated list ("5;", "5;7;"), the visible
# PHYSICAL_MODE select maps 1=Auto ->(1,0,0), 6=Disable ->(3,0,0), 2..5 = fixed
# 10/100 speeds, FLOW_CONTROL_MODE is 1=Disable / 4=Enable, and the response
# body is the literal string "SUCCESS". VERIFIED live on 10.1.5.25 (2026-07-30):
# the POST is accepted and answers SUCCESS. (A first attempt sent PORT_NO=5
# without the semicolon; the switch still answered SUCCESS but applied nothing --
# so a caller MUST check the page afterwards, not the response body.)
_GS110EMX = HttpModelSpec(
    model_key="gs110emx",
    scheme=LoginScheme.GAMBIT,
    scheme_verified=True,
    login_path="/",
    login_post_path="/redirect.html",
    password_field="LoginPassword",
    cookie_name="",  # unused: token session (see session_token_field)
    needs_rand=True,
    dashboard_path="/iss/specific/port_settings.html",
    # Same page, but a genuinely different write mechanism from the FASTPATH
    # grid: it has no admin column, so an admin change is its "Physical Mode"
    # select posted as PORT_CTRL_MODE (see forms.gs110emx_port_admin_form).
    # LIVE-VERIFIED 2026-07-31 on 10.1.5.25.
    port_config_path="/iss/specific/port_settings.html",
    stats_path="/iss/specific/interface_stats.html",
    sysinfo_path="/iss/specific/sysInfo.html",
    poe_config_path=None,
    poe_status_path=None,  # confirmed 404 -- no PoE on this model
    vlan_config_path="/iss/specific/Cf8021q.html",
    vlan_membership_path="/iss/specific/vlanMembership.html",
    pvid_path="/iss/specific/vlan_pvidsetting.html",
    # LIVE-DISCOVERED 2026-07-31 on 10.1.5.25, the same way the FASTPATH VLAN
    # page was found -- by harvesting the firmware's OWN page literals out of
    # /homepage.html + /frame.js + /function.js + /script.js (39 of them) rather
    # than guessing URLs. Both confirmed by fetching them:
    #     GET /iss/specific/sys_reload.html -> 200, <title>Device Restart</title>
    #     GET /iss/specific/logout.html     -> 200, and it really does end the
    #                                          session (every later read then
    #                                          returned the 298-byte login page)
    reboot_path="/iss/specific/sys_reload.html",
    logout_path="/iss/specific/logout.html",
    # ENUMERATED ABSENT, not merely uncaptured -- and reached independently by
    # two investigations that agree:
    #   * the 39 page literals harvested above contain no PoE, LLDP or MAC/FDB
    #     page at all, and the plausible names probed on top of that
    #     (poe.html, poe_config.html, lldp.html, lldp_neighbors.html,
    #     mac_table.html, fdb.html, address_table.html) each answered HTTP 404
    #     with the firmware's 649-byte not-found body;
    #   * the NSDP tag-space survey of this same model found no MAC/LLDP/sensor
    #     tag either (see nsdp_read), so the data is absent from BOTH protocols.
    # Leaving these None is therefore the measured answer, not a gap.
    mac_table_path=None,
    lldp_path=None,
    is_epx_poe=False,
    reads_verified=True,
    session_token_field="Gambit",
    html_dialect=HtmlDialect.GS110EMX,
)

# Login is GROUNDED: certbot-hook-netgear-switches/netgear-updater.py
# S3300Updater posts plaintext pwd= to /base/cheetah_login.html and reads
# back a SID cookie. The read pages are the SAME Cheetah XE grid as the sibling
# gsm7252ps (uname=admin + plaintext pwd -> SID cookie, root-prefix pages), and
# were LIVE-VERIFIED on the real S3300-52X (10.1.5.11, 2026-07-30): ports/
# stats/PVIDs/VLANs/PoE/LLDP parse with the shared parse_xe_* parsers and equal
# SNMP (ports=52, vlans=5, pvids=52, poe=48, stats=52, lldp=2). Three reads use
# S3300-specific handling (HtmlDialect.S3300): the MAC table has shifted columns
# and escaped 1/gN port names (parse_s3300_macs -> 17 physical entries; SNMP
# additionally reports the switch's own base MAC on the CPU ifIndex, an entry
# the FDB parsers skip on every FASTPATH model), mgmt-IP exposes only the base
# MAC over HTTP (parse_s3300_mgmt; SNMP is authoritative for the address), and
# sensors are unsupported over HTTP (sysInfo has no live fan/temp table -- SNMP
# only). reads_verified=True. HTTPS cert upload is unchanged (grounded in
# S3300Updater.upload_certificate).
_GSM7228PS = HttpModelSpec(
    model_key="gsm7228ps",
    scheme=LoginScheme.CHEETAH_FORM,
    scheme_verified=True,
    login_path="/base/cheetah_login.html",
    password_field="pwd",
    username_field="uname",
    username="admin",
    cookie_name="SID",
    needs_rand=False,
    dashboard_path="/portsConfiguration.html",
    port_config_path=_FASTPATH_PORT_CONFIG,
    stats_path="/portStatistics.html",
    sysinfo_path="/base/system/management/sysInfo.html",
    # LIVE-DISCOVERED 2026-07-30 on the real S3300-52X (10.1.5.11), correcting
    # the note this spec used to carry ("the IPv4 mgmt address lives on a
    # JS-menu-only page unreachable here"). It is NOT unreachable:
    #     GET /ipConfiguration.html -> HTTP 200, 8859 bytes,
    #     <TITLE>NetGear - IPv4 Network Interface Configuration</TITLE>
    #     v_1_1_1="10.1.5.11" v_1_2_1="255.255.255.0" v_1_3_1="10.1.5.1"
    #     v_1_18_1="DHCP"
    # which is the switch's real management address, gateway and method -- more
    # than SNMP reports. (Its sibling page ``/mgmtVlanIpv4Configuration.html``
    # 404s here; that one is M4300-only.) The base MAC still comes from sysInfo,
    # which is the only page that carries it on this model.
    mgmt_ip_path=_GSM72XX_MGMT_IP,
    mgmt_ip_fields=_GSM72XX_MGMT_IP_FIELDS,
    mac_table_path="/basicAddressTable.html",
    lldp_path="/lldpRemoteInventory.html",
    poe_config_path="/poeInterfaceConfiguration.html",
    poe_status_path="/poeInterfaceConfiguration.html",
    vlan_config_path="/vlanStatus.html",
    # LIVE-DISCOVERED 2026-07-30 on the real S3300-52X (10.1.5.11) -- see
    # _FASTPATH_VLAN_MEMBERSHIP below. GET returned 47740 bytes titled
    # "VLAN Configuration" with the "VLAN Membership" section header, a vlanId
    # <select> listing 1/5/21/121/4089, hiddenTagged=""/hiddenUnTagged=
    # "1&#x2F;0&#x2F;49,..." and a 78-slot hiddenMem (52 ports + 26 LAGs).
    vlan_membership_path=_FASTPATH_VLAN_MEMBERSHIP,
    vlan_membership_post_path=_FASTPATH_VLAN_MEMBERSHIP_RW,
    pvid_path="/portPvidConfiguration.html",
    reboot_path=None,
    logout_path=None,
    is_epx_poe=False,
    reads_verified=True,
    html_dialect=HtmlDialect.S3300,
    # HTTPS SSL-cert upload IS grounded even though reads are not: copied
    # field-for-field from S3300Updater.upload_certificate (netgear-updater.py
    # lines ~648-678). The file field is ``.v_1_3_1_handle`` (a combined
    # cert+key PEM as certificate.pem, application/octet-stream); the rest are
    # the fixed hidden form fields that page submits.
    cert_upload_path="/http_file_download.html/a1",
    cert_upload_file_field=".v_1_3_1_handle",
    cert_upload_form_fields=MappingProxyType(
        {
            "v_1_1_3": "HTTP",
            "v_1_1_2": "SSL Server Certificate PEM File",
            "v_1_2_1": "",
            "v_1_3_2": " not in progress",
            "v_1_3_3": "",
            "v_1_3_4": "",
            "v_1_9_1": "image1",
            "v_1_9_5": "",
            "v_1_9_2": "1",
            "v_1_9_3": "Enable",
            "v_1_19_1": "32",
            "v_1_20_1": "",
            "v_1_200_1": "",
            "v_2_3_1": " not in progress",
            "v_2_4_3": "None",
            "v_2_4_2": " not in progress",
            "v_4_1_1": "",
            "submit_flag": "8",
            "submit_target": "http_file_download.html",
            "err_flag": "0",
            "err_msg": "",
            "clazz_information": "http_file_download.html",
        }
    ),
)

# gs105pe (Plus, 5-port, NSDP+HTTP) -- LIVE-VERIFIED 2026-07-21 against real
# units (poe-micro2/3 @ 10.1.5.29/.30); registry verified=True. The login
# SCHEME is byte-identical to gs305ep's (GET /login.cgi for `rand`, POST
# password=MD5(merge(pw, rand)) back to /login.cgi, SID cookie back) and was
# confirmed live -> scheme_verified=True. The READ paths are NOT gs305ep's:
# those copies were partly WRONG on real hardware (dashboard.cgi and
# getPoePortStatus.cgi both 404). Corrected against six real captures in
# tests/fixtures/http/gs105pe_*.html -> reads_verified=True. See
# HtmlDialect.GS105PE for the parser set this selects.
_GS105PE = HttpModelSpec(
    model_key="gs105pe",
    scheme=LoginScheme.MERGE_HASH_CGI,
    scheme_verified=True,
    login_path="/login.cgi",
    password_field="password",
    cookie_name="SID",
    needs_rand=True,
    # LIVE-DISCOVERED 2026-07-21 on a real GS105PE (10.1.5.30). The paths
    # previously copied from gs305ep were PARTLY WRONG: dashboard.cgi and
    # getPoePortStatus.cgi both 404 on real hardware. Port status is
    # status.cgi, and device identity/mgmt-IP is switch_info.cgi.
    dashboard_path="/status.cgi",
    stats_path="/portStatistics.cgi",
    sysinfo_path="/switch_info.cgi",
    poe_config_path=None,
    # CONFIRMED 404: this model is PoE pass-through, not a PSE -- no PoE
    # status page exists (matches its registry poe_port_count=0).
    poe_status_path=None,
    vlan_config_path="/8021qCf.cgi",
    vlan_membership_path="/8021qMembe.cgi",
    pvid_path="/portPVID.cgi",
    reboot_path="/device_reboot.cgi",
    logout_path="/logout.cgi",
    is_epx_poe=False,
    reads_verified=True,
    html_dialect=HtmlDialect.GS105PE,
)

# LIVE-VERIFIED 2026-07-21 against a real M4300-24X (10.1.5.13). The read-page
# URLs were NOT statically discoverable -- the Cheetah /v1 menu is built at
# runtime in JS -- and were recovered by driving a real browser and harvesting
# every menu leaf's ``SetLinkPage('<page>')`` handler; the URL prefix is
# ``/v1/``. Login is uname+pwd (plaintext) to /v1/base/cheetah_login.html, and
# EVERY subsequent request must carry a Referer header or the switch answers
# 403 (``needs_referer``). Page values live in the raw HTML as
# semantically-commented hidden inputs -- see HtmlDialect.M4300 and
# ``parse.parse_cheetah_rows``.
#
# Deliberately absent: ``poe_*`` (the M4300-24X has no PoE) and any LLDP
# neighbour page -- this UI exposes only LLDP-MED remote data
# (medRemoteDevInfo.html), which carries no chassis/port-id neighbour table,
# so ``get_lldp`` stays honestly unsupported over HTTP and SNMP remains the
# source for it.
_M4300 = HttpModelSpec(
    model_key="m4300-24x",
    scheme=LoginScheme.CHEETAH_V1,
    scheme_verified=True,
    login_path="/",
    login_post_path="/v1/base/cheetah_login.html",
    password_field="pwd",
    username_field="uname",
    cookie_name="SID",
    needs_rand=False,
    needs_referer=True,
    dashboard_path="/v1/portsConfiguration.html",
    port_config_path=f"/v1{_FASTPATH_PORT_CONFIG}",
    stats_path="/v1/portStatistics.html",
    sysinfo_path="/v1/base/system/management/sysInfo.html",
    # LIVE-MEASURED 2026-07-30 on BOTH M4300 SKUs (10.1.5.13 and
    # 10.1.5.20:49152). The management address is on the MANAGEMENT-VLAN page,
    # not the network-interface page:
    #     GET /v1/ipConfiguration.html            -> 200, v_1_1_1="0.0.0.0"
    #                                                    v_1_2_1="0.0.0.0"
    #                                                    v_1_3_1="0.0.0.0"
    #     GET /v1/mgmtVlanIpv4Configuration.html  -> 200, v_1_6_1="10.1.5.13"
    #                                                    v_1_7_1="255.255.255.0"
    #                                                    v_1_71_1="10.1.5.1"
    # i.e. ipConfiguration describes the (unused) service port. Reading mgmt-IP
    # from it would have reported both switches as 0.0.0.0. The base MAC still
    # comes from sysInfo -- this page's ``v_4_4_1`` is the management
    # INTERFACE's MAC (8C:3B:AD:6B:BB:E3), one off from the switch's base MAC
    # (…:E0), so using it would break parity with SNMP's
    # dot1dBaseBridgeAddress.
    mgmt_ip_path=_M4300_MGMT_IP,
    mgmt_ip_fields=_M4300_MGMT_IP_FIELDS,
    mac_table_path="/v1/basicAddressTable.html",
    # CORRECTION, live 2026-07-31 on BOTH SKUs. This spec used to say the M4300
    # web UI "exposes only LLDP-MED remote data (medRemoteDevInfo.html), which
    # carries no chassis/port-id neighbour table", and get_lldp raised. That was
    # absence of evidence: the real neighbour page is the SAME
    # ``lldpRemoteInventory.html`` the XE models use, and it was found the same
    # way the VLAN page was -- by reading the firmware's own nav tree
    # (``GET /v1/base/js/ng_sideNav.js``, 463 page literals) instead of guessing.
    #     GET /v1/lldpRemoteInventory.html -> 200, 26425 bytes,
    #     <TITLE>NETGEAR -  LLDP Remote Device Inventory</TITLE>, 11 rows
    # and parse_xe_lldp reads it EXACTLY equal to SNMP's lldpRemTable on both
    # switches (11/11 neighbours on the -24X, 4/4 on the -16X: same local port,
    # remote sysName and chassis id for every entry).
    lldp_path="/v1/lldpRemoteInventory.html",
    # LIVE-MEASURED 2026-07-30 on the M4300-24X (10.1.5.13): this SKU has NO
    # PoE, and the proof is a 200 rather than a 404 --
    #     GET /v1/poeInterfaceConfiguration.html -> HTTP 200, 28152 bytes,
    #     <TITLE>NETGEAR -  PoE Port Configuration</TITLE>, the full button set
    #     (Refresh / Power Cycle Port(s) / Cancel / Apply) and ZERO <TR p="...">
    #     rows.
    # The page is present and correct; the switch simply has no PSE ports. The
    # 16X below serves the same URL with 16 rows. Left None here so every PoE op
    # raises UnsupportedCapabilityError naming this model rather than POSTing
    # into a table that cannot contain the port.
    poe_config_path=None,
    poe_status_path=None,
    vlan_config_path="/v1/vlanStatus.html",
    # LIVE-DISCOVERED 2026-07-30 on the real M4300-24X (10.1.5.13) -- see
    # _FASTPATH_VLAN_MEMBERSHIP. GET returned 65449 bytes titled "VLAN
    # Configuration"; its form ACTION is /v1/switching/dot1q/vlan_port_cfg_rw.html,
    # the vlanId <select> lists all 14 VLANs, and VLAN 1 reads back
    # hiddenTagged="1&#x2F;0&#x2F;5," / hiddenUnTagged="1/0/1,1/0/2,1/0/7,1/0/8,
    # 0/13/1,..." over a 152-slot hiddenMem (24 ports + 128 LAGs).
    vlan_membership_path=_M4300_VLAN_MEMBERSHIP,
    vlan_membership_post_path=_M4300_VLAN_MEMBERSHIP_RW,
    pvid_path="/v1/portPvidConfiguration.html",
    reboot_path=None,  # never captured -- not guessed
    logout_path=None,
    is_epx_poe=False,
    reads_verified=True,
    html_dialect=HtmlDialect.M4300,
)

# INHERITED, NOT INDEPENDENTLY CAPTURED. The M4300-16X runs the same FASTPATH
# firmware image and therefore the same Cheetah /v1 web UI as the 24X, so the
# login scheme and page URLs carry over -- but NO M4300-16X web session was
# ever captured, and no fixture or test exercises this SKU's HTTP path. The
# verified flags below are inherited from the 24X and mean "verified for this
# firmware family", NOT "captured from a 16X". Treat a 16X-specific HTTP
# surprise (different port count, PoE pages the 24X lacks) as unverified until
# someone captures one.
# reads_verified=False (unlike the 24x): the M4300-16X-PoE runs the AV-era
# two-UI firmware where the FASTPATH "Main UI" (Cheetah) is moved OFF port 80 to
# HTTPS on port 49152 (port 80/443 serve the Vue "AV UI" instead). Confirmed live
# on 10.1.5.20 (2026-07-30): port 80 -> <title>network</title> (Vue), port 49152 ->
# <TITLE>NETGEAR M4300-16X</TITLE> (Cheetah). This inherited-from-24x spec targets
# http://<host>/v1/... (the AV-UI port) and so does NOT work against the real 16x
# -- login POSTs 404, and :49152 resets a plaintext-http connect (it is HTTPS).
# The 16x is otherwise fully live-verified over SNMP + CLI. Wiring 16x HTTP needed
# HTTPS-on-49152 transport support (done) + the SIDSSL cookie + a poe_status_path
# (the 16x IS PoE, unlike the 24x) -- all done + live cross-verified below.
_M4300_16X = dataclasses.replace(
    _M4300,
    model_key="m4300-16x",
    # LIVE cross-verified 2026-07-30 on the real M4300-16X-PoE (10.1.5.20:49152):
    # every HTTP read (ports/stats/PVIDs/VLANs/MACs/mgmt-IP + PoE) matches SNMP.
    reads_verified=True,
    # The real 16X Cheetah "Main UI" is HTTPS on :49152 (see the note above). The
    # login flow + /v1/ read paths are inherited from the 24X, but the HTTPS
    # variant names its session cookie SIDSSL (not SID) -- confirmed live: the
    # login POST sets SIDSSL and it authenticates every read page.
    cookie_name="SIDSSL",
    # Per-port PoE: the 16X (unlike the non-PoE 24X) serves the FASTPATH
    # poeInterfaceConfiguration.html under /v1/. Its cell format is byte-identical
    # to the gsm7252ps XE page, so _parse_poe routes the M4300 dialect through
    # parse_xe_poe (16 PSE rows, live-verified == pethPsePortTable).
    poe_status_path=f"/v1{_FASTPATH_POE_CONFIG}",
    # Same page, and it WRITES: live-proven 2026-07-30 on 10.1.5.20:49152 by
    # setting port 1/0/15's Port Priority Low -> High -> Low through this form
    # and reading each change back (err_flag=0 both times).
    poe_config_path=f"/v1{_FASTPATH_POE_CONFIG}",
    secure=True,
    web_port=49152,
)
# VLAN-membership note for the 16X specifically (the paths are inherited from the
# 24X above, but the 16X needed a TRANSPORT fix before any of them could be
# POSTed): this firmware answers ``403 Forbidden`` to EVERY POST -- including
# POSTs to pages whose GET returns 200 -- unless an ``Origin`` header accompanies
# the ``Referer``. Isolated live 2026-07-30 on 10.1.5.20:49152 (Referer alone ->
# 403 "403 Forbidden\r\n"; + Origin -> 200 with the real VLAN 4 page; Origin
# without Referer -> 403 again). Fixed in
# ``transport/http/client.py::_referer_headers``. Its membership page also carries
# a per-page ``CSRFToken`` hidden field the 24X does not have; the form builder
# echoes back whatever the page rendered, so both SKUs work from one code path.
# LIVE-VERIFIED 2026-07-30 (10.1.5.20:49152): 63503-byte page, 16-port grid,
# 145-slot hiddenMem, VLAN 4 -> tagged 9,10,12..16 / untagged 11.

# gsm7252ps (Fully Managed, 52-port/48-PoE, SNMP+HTTP). The LOGIN is
# LIVE-VALIDATED against the real switch 10.1.5.22 (2026-07-22): the Cheetah
# form POSTs uname=admin + plaintext pwd to /base/cheetah_login.html and gets
# an SID cookie back -- same scheme as gsm7228ps, but this UI also validates
# the username, hence username_field. No Referer guard (unlike the M4300 /v1
# UI): plain GETs of the read pages succeed.
#
# The READ pages live at the ROOT prefix -- not /base/ and not /v1/ -- and are
# GROUNDED in real captures of that switch (tests/fixtures/http/gsm7252ps_*.
# html), including the sysInfo page that serves get_sensors (get_mgmt_ip moved
# to ipConfiguration.html -- see mgmt_ip_path below). Their HTML is the
# XE_FASTPATH dialect (see HtmlDialect), NOT the M4300's: the M4300 parsers
# return zero rows on these pages.
#
# reads_verified is True: the HTTP reader was cross-verified against SNMP on
# the live switch (10.1.5.22) -- see the reads_verified=True line below. Every
# read op this model supports has a page here; there is no
# UnsupportedCapabilityError carve-out.
# vlan_membership_path is None because vlanStatus.html carries each VLAN's
# egress list inline (as on the M4300), and reboot/logout were never captured.
_GSM7252PS = HttpModelSpec(
    model_key="gsm7252ps",
    scheme=LoginScheme.CHEETAH_FORM,
    scheme_verified=True,
    login_path="/base/cheetah_login.html",
    password_field="pwd",
    username_field="uname",
    username="admin",
    cookie_name="SID",
    needs_rand=False,
    dashboard_path="/portsConfiguration.html",
    port_config_path=_FASTPATH_PORT_CONFIG,
    stats_path="/portStatistics.html",
    sysinfo_path="/base/system/management/sysInfo.html",
    # LIVE 2026-07-30 (10.1.5.22): ipConfiguration.html reports the mgmt address,
    # mask, gateway AND the addressing method (v_1_18_1="DHCP"), which the
    # sysInfo page this used to read does not -- sysInfo carries no gateway and
    # no DHCP/static indicator, so get_mgmt_ip reported IpMode.UNKNOWN and
    # gateway=None where SNMP has both. (mgmtVlanIpv4Configuration.html, the
    # M4300's page, 404s here.)
    mgmt_ip_path=_GSM72XX_MGMT_IP,
    mgmt_ip_fields=_GSM72XX_MGMT_IP_FIELDS,
    mac_table_path="/basicAddressTable.html",
    lldp_path="/lldpRemoteInventory.html",
    # LIVE-VERIFIED 2026-07-31 on 10.1.5.22, port 1/0/35 (link-down, undescribed,
    # PoE "Searching"): set_poe Enable->Disable->Enable, each apply answering
    # err_flag=0 and each state read back off the page.
    #
    # This entry was previously None with a note claiming the form "REFUSES every
    # write" -- it does not, and the refusal was ours. The page answered HTTP 200
    # + err_flag=1 with one "Error! Failed to Set '<column>' with '<value>'" line
    # per read-write column (Admin Mode, Port Priority, Power Limit Type, Power
    # Limit, Detection Type, Timer Schedule, Port Reset), even for a body that
    # changed nothing, because the POST omitted the page's own list-scope field.
    # This firmware's PoE rows carry NO hidden Unit key column, unlike
    # gsm7228ps's and both M4300s' (which render ``v_1_2_21``, ``xk_1_2_21=1``,
    # ``xeleName="Unit"``) -- so the row is not self-identifying here and the
    # firmware takes the list scope from the page-level ``urlListUnit`` field
    # instead. Adding ``v_1_1_1`` alone, or its alias ``v_1_3_1`` alone, made the
    # byte-identical write succeed; adding only the ``v_1_1_2`` type filter did
    # not. That is why the same builder worked on the siblings and on this
    # switch's own portsConfiguration page: only this page needs the scope field.
    # See ``XuiListPage.nav`` / ``forms.xui_row_apply_form``.
    poe_config_path=_FASTPATH_POE_CONFIG,
    poe_status_path=_FASTPATH_POE_CONFIG,
    vlan_config_path="/vlanStatus.html",
    # LIVE-DISCOVERED 2026-07-30 on the real GSM7252PS (10.1.5.22) -- see
    # _FASTPATH_VLAN_MEMBERSHIP for how (and after which 404s). GET returned
    # 46700 bytes titled "VLAN Configuration" carrying the "VLAN Membership"
    # section, and for VLAN 1: hiddenTagged="1/0/6",
    # hiddenUnTagged="1/0/8,...,1/0/52,0/3/1..0/3/64", a 116-slot hiddenMem
    # (52 ports + 64 LAGs) and the older ``grey_[btu].gif`` port grid.
    vlan_membership_path=_FASTPATH_VLAN_MEMBERSHIP,
    vlan_membership_post_path=_FASTPATH_VLAN_MEMBERSHIP_RW,
    pvid_path="/portPvidConfiguration.html",
    reboot_path=None,  # never captured -- not guessed
    logout_path=None,
    is_epx_poe=False,
    reads_verified=True,  # live HTTP<->SNMP cross-verified 2026-07-23
    html_dialect=HtmlDialect.XE_FASTPATH,
)

# gs728tpp (Smart Managed Pro, 28-port/24-PoE+, SNMP+HTTP). The LOGIN is the
# GoAhead XML API (LoginScheme.XML_API), GROUNDED in
# certbot-hook-netgear-switches/netgear-updater.py's GS728TPPUpdater AND in real
# captures of the live switch 10.2.5.10 (tmp/gs728tpp_ground_truth.json): GET /
# 302-redirects to a per-session path, GET ``<sess>/System.xml?action=login&
# user=admin&password=..`` returns ``<statusCode>0</statusCode>`` + a sessionID
# response header, and every read is a GET ``<sess>/wcd?{file=..}{Object}..``
# returning a ``<DeviceConfiguration>`` XML data block -- so scheme_verified is
# True. The read PARSERS are grounded in those same captures but have NOT yet
# been live cross-verified against SNMP, so reads_verified is False (the honesty
# gate keeps HttpReader refusing to construct until the live cross-verify flips
# it -- exactly as gsm7252ps did before its own verify).
#
# The read-op "paths" are the wcd QUERIES (the transport prefixes the captured
# session path); the HTML dialect is GOAHEAD_XML. get_mgmt_ip reads a SEPARATE
# IPConf wcd query (mgmt_ip_path), since sysinfo_path here serves device
# identity + box sensors. stats_path is None: per-port statistics are behind an
# unresolvable JS nav indirection on this UI (SwitchStatistics.htm is CPU-only),
# so get_stats honestly raises UnsupportedCapabilityError -- SNMP is the source
# for per-port counters on this model.
_GS728TPP = HttpModelSpec(
    model_key="gs728tpp",
    scheme=LoginScheme.XML_API,
    scheme_verified=True,
    login_path="/",
    password_field="password",
    username_field="user",
    username="admin",
    cookie_name="sessionID",
    needs_rand=False,
    dashboard_path=(
        "wcd?{file=/Switching/Ports/portConfiguration_master_jq.htm}{Standard802_3List}"
    ),
    stats_path=None,  # per-port stats unavailable via HTTP -> get_stats raises
    sysinfo_path=(
        "wcd?{file=/System/Management/SystemInfo_master_745.xml}"
        "{DeviceBasicInfo}{TimeSetting}{DiagnosticsUnitList}"
    ),
    mgmt_ip_path=(
        "wcd?{file=/System/Management/IPConf_master.xml}"
        "{IPv4InterfaceList}{IPv4GatewayList}"
    ),
    poe_config_path=None,
    poe_status_path=(
        "wcd?{file=/System/PoE/PoeInterfaceConf_master.xml}{PoEPSEInterfaceList}"
    ),
    vlan_config_path=("wcd?{file=/Switching/VLAN/VlanConfBasic_master.xml}{VLANList}"),
    # VLAN membership is derived from the per-port JoinVLANList carried inline in
    # the PVID page (VLANInterfaceList), so there is no separate membership POST.
    vlan_membership_path=None,
    pvid_path=(
        "wcd?{file=/Switching/VLAN/PortPvidConf_master_745.xml}{VLANInterfaceList}"
    ),
    mac_table_path=(
        "wcd?{file=/Switching/Address Table/DynamicAddresses_master.xml}"
        "{ForwardingTable}"
    ),
    lldp_path=(
        "wcd?{file=/System/LLDP/NeighborsInformation_master.xml}{LLDPMEDNeighborList}"
    ),
    reboot_path=None,
    logout_path=None,
    is_epx_poe=False,
    # HTTPS SSL-cert upload IS a distinct XML-API flow (NOT the gsm7228ps
    # multipart form): the writer POSTs a raw ``SSLCryptoCertificateImportList``
    # XML body to the session-path-prefixed ``wcd`` endpoint (see
    # http_write._cert_upload_xml). Grounded in
    # certbot-hook-netgear-switches/netgear-updater.py::GS728TPPUpdater
    # (upload_certificate/_build_cert_xml). ``cert_upload_file_field`` stays
    # None -- there is no multipart file part -- and the dialect (GOAHEAD_XML)
    # is what routes upload_certificate to the XML path.
    cert_upload_path="wcd",
    # LIVE-VERIFIED 2026-07-29 against the real GS728TPP (10.2.5.10, via the
    # ten64 jump host): every parse_goahead_* was run on a FRESH live wcd fetch
    # and cross-checked against the switch's actual known config -- 28 ports
    # g1..g28 with correct link/speed, 24 PoE ports, real VLAN names (net/pwr/
    # store/iot/guest...), PVIDs, per-port membership, 135 MAC entries, 4 real
    # LLDP neighbors (reterm1 + ten64 x3), Fan1/Fan2/Main+Redundant PS sensors,
    # mgmt-IP 10.2.5.10/24 gw 10.2.5.1. (Cross-checked vs the switch's ground
    # truth rather than vs SNMP, since this model's SNMP OID family is itself
    # UNVERIFIED-pending-capture -- see registry.py.) get_stats stays unsupported.
    reads_verified=True,
    html_dialect=HtmlDialect.GOAHEAD_XML,
)

_SPECS: dict[str, HttpModelSpec] = {
    s.model_key: s
    for s in (
        _GS305EP,
        _GS110EMX,
        _GSM7228PS,
        _GS105PE,
        _M4300,
        _M4300_16X,
        _GSM7252PS,
        _GS728TPP,
    )
}

HTTP_SPECS: Mapping[str, HttpModelSpec] = MappingProxyType(_SPECS)


def http_spec(model: SwitchModel) -> HttpModelSpec:
    """Return the web-UI spec for ``model`` or raise if it has no HTTP backend."""
    if Backend.HTTP not in model.backends:
        raise UnsupportedCapabilityError(f"model {model.key!r} has no HTTP backend")
    try:
        return _SPECS[model.key]
    except KeyError:
        raise UnsupportedCapabilityError(
            f"model {model.key!r} has an HTTP backend but no endpoint spec"
        ) from None
