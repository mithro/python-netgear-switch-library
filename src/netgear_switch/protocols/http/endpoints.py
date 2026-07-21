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
- ``gs110emx`` (Plus EMx / Gambit): login + the ``sysInfo``/``interface_stats``
  reads are GROUNDED in a real capture from a physical GS110EMX (see
  ``tests/fixtures/http/gs110emx_{login,redirect,sysinfo,interface_stats}.html``).
  The scheme is ``merge_hash_md5(password, rand)`` (identical function to
  ``gs305ep``) POSTed as ``LoginPassword`` to ``/redirect.html`` (``rand``
  scraped from ``GET /``, not from the POST target itself -- see
  ``login_post_path``); the response carries a ``Gambit`` TOKEN (not a
  cookie -- no ``Set-Cookie`` is ever sent) that every subsequent request
  must carry (``session_token_field``). Live capture proved
  ``/iss/specific/{vlan,port,poePortStatus,neighbor,dashboard}.html`` all
  404 -- gs110emx has no PoE and serves ports/VLANs/PVIDs via NSDP, not
  HTTP, so those spec fields stay honestly ``None``. ``scheme_verified`` and
  ``reads_verified`` are ``True`` for exactly this grounded surface
  (login + ``sysinfo_path`` + ``stats_path``); ``reboot_path``/
  ``logout_path`` were never captured and stay ``None`` rather than guessed.
- ``gs105pe`` (Plus, 5-port, spec-only -- registered ``verified=False`` in
  ``registry.py``, no capture exists): the login SCHEME is well-grounded
  (``rcfiles/bin/netgear-smp-vlan`` shows a GS105PE session byte-identical to
  ``gs305ep``'s), but the read-endpoint paths below are copied from
  ``gs305ep``'s spec as a same-family shape guess, never confirmed against a
  real GS105PE response -- both ``scheme_verified`` and ``reads_verified``
  stay ``False`` accordingly.
"""
from __future__ import annotations

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
    # Which HTML family this model's read pages use -- see HtmlDialect. Selects
    # the ports/stats/PVID/VLAN-list parser set. Defaults to the gs305ep CGI
    # shape every model but gs110emx uses.
    html_dialect: HtmlDialect = HtmlDialect.STANDARD


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
)

# gs105pe (Plus, 5-port, NSDP+HTTP -- see registry.py's entry for the
# port/PoE-count honesty notes) is registered verified=False: NO capture
# exists for this model. The login SCHEME itself is well-grounded --
# rcfiles/bin/netgear-smp-vlan's GS105PE session flow is byte-identical to
# gs305ep's (GET /login.cgi for `rand`, POST password=MD5(merge(pw, rand))
# back to /login.cgi, SID cookie back) -- but this entry deliberately still
# marks scheme_verified=False/reads_verified=False rather than claim
# verification: the *read* endpoints below (dashboard/stats/PoE/VLAN paths)
# are copied from gs305ep's spec as a same-family SHAPE guess, not confirmed
# against an actual GS105PE response, and per-task honesty policy this
# registration must not claim more than that. See gs305ep's own docstring
# entry above for the grounded VLAN CGI paths this reuses.
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

_SPECS: dict[str, HttpModelSpec] = {
    s.model_key: s for s in (_GS305EP, _GS110EMX, _GSM7228PS, _GS105PE)
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
