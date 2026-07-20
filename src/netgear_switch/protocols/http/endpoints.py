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


class StatsPageShape(enum.Enum):
    """Which HTML row-shape ``http_read.py``'s ``_parse_stats`` must parse a
    model's ``stats_path`` page with.

    Previously keyed off ``session_token_field is not None`` as a proxy for
    "this is gs110emx" -- that happened to work only because gs110emx is
    currently the one and only token-session model, but a FUTURE token-session
    model with an ordinary (closed-``<tr>``) stats page would have been
    silently misparsed by that proxy. A dedicated field says exactly what it
    means.
    """

    STANDARD = "standard"  # closed <tr class="portID">...</tr> (gs305ep)
    GS110EMX_OPEN_ROW = "gs110emx_open_row"  # real hardware never closes the row


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
    # Which HTML row-shape stats_path uses -- see StatsPageShape. Defaults to
    # the ordinary closed-<tr> shape every model but gs110emx uses.
    stats_page_shape: StatsPageShape = StatsPageShape.STANDARD


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
# tests/fixtures/http/gs110emx_{login,redirect,sysinfo,interface_stats}.html).
# GET / for `rand` -> POST LoginPassword=merge_hash_md5(pw, rand) to
# /redirect.html -> response carries a Gambit TOKEN (no cookie) that every
# subsequent request carries as ?Gambit=<token> (GET) or a form field
# (POST). Confirmed-404 endpoints (/iss/specific/{vlan,port,poePortStatus,
# neighbor,dashboard}.html) stay None -- gs110emx has no PoE and serves
# ports/VLANs/PVIDs via NSDP, not HTTP. reboot_path/logout_path were never
# captured and stay None rather than guessed.
#
# reads_verified=True covers exactly the grounded surface above -- but within
# sysInfo.html specifically, only the STATIC-IP case (the real capture's own
# `data-select-value="0"`) was directly observed; parse_sysinfo's DHCP branch
# (`data-select-value="1"` -> IpMode.DHCP) is inferred from the same
# <select>'s option ordering, never itself captured from a real
# DHCP-configured device -- see HttpSysInfo's docstring. Don't read
# reads_verified=True as a claim that the DHCP branch was independently
# verified; it wasn't.
_GS110EMX = HttpModelSpec(
    model_key="gs110emx",
    scheme=LoginScheme.GAMBIT,
    scheme_verified=True,
    login_path="/",
    login_post_path="/redirect.html",
    password_field="LoginPassword",
    cookie_name="",  # unused: token session (see session_token_field)
    needs_rand=True,
    dashboard_path=None,  # confirmed 404 -- no HTTP port-status page
    stats_path="/iss/specific/interface_stats.html",
    sysinfo_path="/iss/specific/sysInfo.html",
    poe_config_path=None,
    poe_status_path=None,  # confirmed 404 -- no PoE on this model
    vlan_config_path=None,  # confirmed 404 -- VLANs are NSDP-only here
    vlan_membership_path=None,  # confirmed 404
    pvid_path=None,  # confirmed 404
    reboot_path=None,  # never captured -- not guessed
    logout_path=None,  # never captured -- not guessed
    is_epx_poe=False,
    reads_verified=True,
    session_token_field="Gambit",
    stats_page_shape=StatsPageShape.GS110EMX_OPEN_ROW,
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

_SPECS: dict[str, HttpModelSpec] = {
    s.model_key: s for s in (_GS305EP, _GS110EMX, _GSM7228PS)
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
