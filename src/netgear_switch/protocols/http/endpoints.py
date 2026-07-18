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
- ``gs110emx`` (Plus EMx / Gambit): the login hash function and Gambit-token
  extraction are NOT grounded in a captured session (only partially
  corroborated by ``py_netgear_plus/models.py`` EMxSeries/GS110EMX). Both
  ``scheme_verified`` and ``reads_verified`` are ``False``.
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
    GAMBIT = "gambit"                   # EMx scheme (gs110emx) — UNVERIFIED
    CHEETAH_FORM = "cheetah_form"       # Pro/S3300 (gsm7228ps) — plaintext form


@dataclass(frozen=True)
class HttpModelSpec:
    model_key: str
    scheme: LoginScheme
    scheme_verified: bool
    login_path: str
    password_field: str
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

# UNVERIFIED-pending-capture: Gambit login hash + /iss/specific pages not
# grounded in a captured session. Endpoints from py_netgear_plus EMxSeries.
_GS110EMX = HttpModelSpec(
    model_key="gs110emx",
    scheme=LoginScheme.GAMBIT,
    scheme_verified=False,
    login_path="/homepage.html",
    password_field="LoginPassword",
    cookie_name="gambitCookie",
    needs_rand=True,
    dashboard_path="/iss/specific/sysInfo.html",
    stats_path="/iss/specific/interface_stats.html",
    poe_config_path=None,
    poe_status_path=None,
    vlan_config_path=None,
    vlan_membership_path=None,
    pvid_path=None,
    reboot_path=None,
    logout_path="/iss/specific/logout.html",
    is_epx_poe=False,
    reads_verified=False,
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
