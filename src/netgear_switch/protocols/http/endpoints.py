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
- ``gsm7228ps`` (Smart Managed Pro / S3300): the plaintext cheetah login form
  is GROUNDED in ``certbot-hook-netgear-switches/netgear-updater.py``
  (``S3300Updater``), so ``scheme_verified`` is ``True``. SNMP is the
  preferred read/write path for this model; no web-UI read/write flow has
  been captured, so ``reads_verified`` is ``False`` and the reader/writer
  refuse rather than fabricate.
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
    MERGE_HASH_CGI = "merge_hash_cgi"   # Plus SID scheme (gs305ep) — GROUNDED
    GAMBIT = "gambit"                   # EMx merge-hash + token (gs110emx) — GROUNDED
    CHEETAH_FORM = "cheetah_form"       # Pro/S3300 (gsm7228ps) — plaintext form
    CHEETAH_V1 = "cheetah_v1"           # M4300 /v1 — uname+pwd + Referer CSRF
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
    # GS728TPP GoAhead ``wcd`` XML API (real captures, tmp/gs728tpp_ground_truth
    # .json): every read is a ``GET <sess>/wcd?{file=/path/X.xml}{Object}..``
    # whose response is a template of ``BIND=`` placeholders followed by a
    # trailing ``<DeviceConfiguration>`` data block of ``<Object type="section">``
    # elements (scalars, or repeated ``<Interface>``/``<Entry>``/``<VLAN>`` rows).
    # The parsers extract ONLY that data block and read it as XML -- see
    # parse.parse_goahead_*. Structured XML, NOT the HTML-scraping the other
    # dialects do.
    GOAHEAD_XML = "goahead_xml"


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
    # Non-standard web-UI TCP port. ``None`` (the default) = the URL's implicit
    # 80/443. The M4300-16X-PoE serves its Cheetah UI on 49152; the facade forms
    # the host as ``<ip>:<web_port>`` when this is set.
    web_port: int | None = None


# GROUNDED: py_netgear_plus/models.py GS30xSeries/GS30xEPxSeries
# (CRYPT_FUNCTION="merge_hash", ALLOWED_COOKIE_TYPES=["SID"],
# check_login_form_rand=True, LOGIN_TEMPLATE url=/login.cgi
# params={password:_password_hash}; PoE/VLAN CGI paths) plus
# rcfiles/bin/netgear-smp-vlan (identical merge-hash login observed on
# GS105PE; 8021qCf.cgi/8021qMembe.cgi/portPVID.cgi field shapes and the
# 1=Untagged/2=Tagged/3=Excluded membership wire codes). Fully grounded.
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
    stats_path="/iss/specific/interface_stats.html",
    sysinfo_path="/iss/specific/sysInfo.html",
    poe_config_path=None,
    poe_status_path=None,  # confirmed 404 -- no PoE on this model
    vlan_config_path="/iss/specific/Cf8021q.html",
    vlan_membership_path="/iss/specific/vlanMembership.html",
    pvid_path="/iss/specific/vlan_pvidsetting.html",
    reboot_path=None,  # never captured -- not guessed
    logout_path=None,  # never captured -- not guessed
    is_epx_poe=False,
    reads_verified=True,
    session_token_field="Gambit",
    html_dialect=HtmlDialect.GS110EMX,
)

# Login is GROUNDED: certbot-hook-netgear-switches/netgear-updater.py
# S3300Updater posts plaintext pwd= to /base/cheetah_login.html and reads
# back a SID cookie. SNMP is the preferred read/write path for this model;
# no web-UI read/write flow has been captured, so reads/writes are
# UNVERIFIED-pending-capture and only login + reboot/logout are populated.
_GSM7228PS = HttpModelSpec(
    model_key="gsm7228ps",
    scheme=LoginScheme.CHEETAH_FORM,
    scheme_verified=True,
    login_path="/base/cheetah_login.html",
    password_field="pwd",
    cookie_name="SID",
    needs_rand=False,
    dashboard_path=None,
    stats_path=None,
    poe_config_path=None,
    poe_status_path=None,
    vlan_config_path=None,
    vlan_membership_path=None,
    pvid_path=None,
    reboot_path=None,
    logout_path=None,
    is_epx_poe=False,
    reads_verified=False,
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
    stats_path="/v1/portStatistics.html",
    sysinfo_path="/v1/base/system/management/sysInfo.html",
    mac_table_path="/v1/basicAddressTable.html",
    poe_config_path=None,
    poe_status_path=None,
    vlan_config_path="/v1/vlanStatus.html",
    vlan_membership_path=None,  # vlanStatus carries the egress list inline
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
# The 16x is otherwise fully live-verified over SNMP + CLI. Wiring 16x HTTP needs
# HTTPS-on-49152 transport support + a poe_status_path (the 16x IS PoE, unlike the
# 24x) -- a dedicated slice; until then HTTP stays gated so the facade uses the
# verified SNMP/CLI backends and never a broken web path.
_M4300_16X = dataclasses.replace(
    _M4300,
    model_key="m4300-16x",
    reads_verified=False,
    # The real 16X Cheetah "Main UI" is HTTPS on :49152 (see the note above).
    # The login flow + /v1/ read paths are inherited unchanged from the 24X;
    # only the transport (https + non-standard port) differs. reads_verified
    # stays False -- the controller live-verifies before flipping it. No
    # poe_status_path yet: per-port PoE is a 16X-only page, a separate slice
    # after live-verification.
    secure=True,
    web_port=49152,
)

# gsm7252ps (Fully Managed, 52-port/48-PoE, SNMP+HTTP). The LOGIN is
# LIVE-VALIDATED against the real switch 10.1.5.22 (2026-07-22): the Cheetah
# form POSTs uname=admin + plaintext pwd to /base/cheetah_login.html and gets
# an SID cookie back -- same scheme as gsm7228ps, but this UI also validates
# the username, hence username_field. No Referer guard (unlike the M4300 /v1
# UI): plain GETs of the read pages succeed.
#
# The READ pages live at the ROOT prefix -- not /base/ and not /v1/ -- and are
# GROUNDED in real captures of that switch (tests/fixtures/http/gsm7252ps_*.
# html), including the sysInfo page that serves BOTH get_sensors and
# get_mgmt_ip. Their HTML is the XE_FASTPATH dialect (see HtmlDialect), NOT
# the M4300's: the M4300 parsers return zero rows on these pages.
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
    stats_path="/portStatistics.html",
    sysinfo_path="/base/system/management/sysInfo.html",
    mac_table_path="/basicAddressTable.html",
    lldp_path="/lldpRemoteInventory.html",
    poe_config_path=None,  # never captured -- not guessed
    poe_status_path="/poeInterfaceConfiguration.html",
    vlan_config_path="/vlanStatus.html",
    vlan_membership_path=None,  # vlanStatus carries the egress list inline
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
        "wcd?{file=/Switching/Ports/portConfiguration_master_jq.htm}"
        "{Standard802_3List}"
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
    vlan_config_path=(
        "wcd?{file=/Switching/VLAN/VlanConfBasic_master.xml}{VLANList}"
    ),
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
        "wcd?{file=/System/LLDP/NeighborsInformation_master.xml}"
        "{LLDPMEDNeighborList}"
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
        _GS305EP, _GS110EMX, _GSM7228PS, _GS105PE, _M4300, _M4300_16X, _GSM7252PS,
        _GS728TPP,
    )
}

HTTP_SPECS: Mapping[str, HttpModelSpec] = MappingProxyType(_SPECS)


def http_spec(model: SwitchModel) -> HttpModelSpec:
    """Return the web-UI spec for ``model`` or raise if it has no HTTP backend."""
    if Backend.HTTP not in model.backends:
        raise UnsupportedCapabilityError(
            f"model {model.key!r} has no HTTP backend"
        )
    try:
        return _SPECS[model.key]
    except KeyError:
        raise UnsupportedCapabilityError(
            f"model {model.key!r} has an HTTP backend but no endpoint spec"
        ) from None
