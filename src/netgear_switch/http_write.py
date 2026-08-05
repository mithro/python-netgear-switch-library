"""Model-driven web-UI write operations with verify-after-write + guards.

Parallel to ``snmp_write.py``. Every mutating op: (1) enforces
``protected_ports`` on disruptive ports unless ``force=True``; (2) GETs the
target page to scrape the fresh CSRF ``hash``; (3) POSTs the encoded form;
(4) re-GETs and re-parses to confirm the change actually took — raising
``WriteVerificationError(before, after)`` on divergence, NEVER silently
succeeding.

``set_port_enabled``, ``set_mgmt_ip`` and ``clear_poe_fault`` used to raise
``UnsupportedCapabilityError`` for EVERY model. They were missing
implementations, not device limitations, and are now built:

* ``set_port_enabled`` — the managed models' ``portsConfiguration.html`` Admin
  Mode column (LIVE-VERIFIED on all four: gsm7252ps, gsm7228ps, m4300-24x,
  m4300-16x), and the GS110EMX's differently-shaped ``port_settings.html``
  Physical Mode POST (LIVE-VERIFIED on 10.1.5.26).
* ``clear_poe_fault`` — the managed PoE page's hidden write-only "Port Reset"
  column driven by its RESET button (LIVE-VERIFIED on gsm7252ps, gsm7228ps and
  m4300-16x), and the Plus UI's ``PoEPortConfig.cgi`` reset.
* ``set_mgmt_ip`` — each managed model's own management-IP form. The APPLY is
  deliberately NOT live-verified: doing so would move a real switch's
  management address and drop the session mid-write. See the method docstring
  for exactly what is and is not proven.

Where an op still raises for a model, the refusal names captured device output:
the M4300-24X's PoE page has zero rows because the SKU has no PSE, and the
GS110EMX has no PoE page at all. gsm7252ps used to be on that list -- its PoE
form was recorded as answering ``err_flag=1`` to every write -- and it did not
belong there: the body was missing the page's own list-unit field, and once it
rides along the write lands (see ``endpoints.py`` and
``forms.xui_row_apply_form``).

VLAN membership on the MANAGED (FASTPATH/Cheetah) models — gsm7252ps,
gsm7228ps/S3300 and both M4300 SKUs — goes through
``_set_fastpath_membership`` against the live-discovered
``switching/dot1q/vlan_port_cfg_rw.html`` endpoint; the Plus-class models keep
the ``8021qMembe.cgi`` path. That is a fifth step for these pages: they answer
HTTP 200 even when they REFUSE the write, reporting it in a hidden
``err_flag``/``err_msg`` pair, so the apply response is checked for that before
verification (see ``_raise_on_fastpath_err_flag``) and the switch's own message
is what the caller gets.
"""

from __future__ import annotations

import asyncio
import re
import time
from types import MappingProxyType
from typing import TYPE_CHECKING
from xml.sax.saxutils import escape as _xml_escape

from .errors import (
    HttpError,
    HttpUnexpectedPageError,
    ProtectedPortError,
    UnsupportedCapabilityError,
    WriteVerificationError,
)
from .http_read import _parse_poe, fastpath_membership_paths
from .models import VlanMode, poe_cycle_complete
from .protocols.http import forms, goahead, parse
from .protocols.http.endpoints import HtmlDialect, http_spec
from .protocols.http.session import MultipartFile

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping

    from .models import PoEStatus, PortSpeed
    from .protocols.http.endpoints import HttpModelSpec, XuiMgmtIpFields
    from .protocols.http.session import AsyncHttpSession, HttpSession
    from .protocols.http.types import FastpathMembership, XuiListPage, XuiRow
    from .registry import SwitchModel
    from .snmp_write import PoeCycleTimeouts


# Models whose real SSL-certificate upload mechanism is KNOWN but is NOT an HTTP
# form -- it is the FASTPATH ``copy scp://`` file-copy, implemented in this
# library as ``SyncSwitch.upload_certificate_scp`` (these keys are exactly the
# FASTPATH members of ``registry.SCP_CERT_PROFILES``). Keyed by registry model
# key -> a human name for the mechanism. The HTTP writer deliberately raises
# NotImplementedError here, NOT UnsupportedCapabilityError: the hardware
# genuinely CAN load a certificate (just not over this HTTP interface), so
# claiming it is unsupported / has no known mechanism would be a false
# statement -- see ``_reject_known_unimplemented_cert_upload``.
CERT_UPLOAD_KNOWN_UNIMPLEMENTED: Mapping[str, str] = MappingProxyType(
    {
        # The M4300 FASTPATH image takes the cert over SCP (``copy scp://.../
        # cert ...``), not an HTTP form -- a different transport entirely.
        "m4300-24x": "SCP file-copy to the switch (FastpathScpUpdater)",
        "m4300-16x": "SCP file-copy to the switch (FastpathScpUpdater)",
        # gsm7252ps is ALSO a FASTPATH SCP cert switch (in SCP_CERT_PROFILES):
        # its cert upload IS implemented, just over SCP not HTTP. The HTTP
        # writer must therefore NOT claim "no known mechanism" -- it points at
        # the SCP path, exactly like m4300.
        "gsm7252ps": "SCP file-copy to the switch (copy scp://)",
        # NOTE: gs728tpp used to live here, but its GoAhead XML-API upload is now
        # IMPLEMENTED -- see ``_cert_upload_xml`` and ``upload_certificate``'s
        # GOAHEAD_XML dispatch below.
    }
)

# The filename real S3300 firmware is sent (S3300Updater posts the combined
# cert+key PEM as ``certificate.pem``).
_CERT_FILENAME = "certificate.pem"


def _reject_known_unimplemented_cert_upload(model_key: str) -> None:
    """Raise NotImplementedError if ``model_key``'s cert-upload mechanism is
    known-but-unimplemented (see ``CERT_UPLOAD_KNOWN_UNIMPLEMENTED``)."""
    mechanism = CERT_UPLOAD_KNOWN_UNIMPLEMENTED.get(model_key)
    if mechanism is not None:
        raise NotImplementedError(
            f"SSL-certificate upload for {model_key!r} uses {mechanism}, which "
            "this HTTP writer does not perform; use "
            "SyncSwitch.upload_certificate_scp instead"
        )


def _combine_cert_key_pem(cert_pem: str, key_pem: str) -> str:
    """Concatenate the certificate and private-key PEMs into the single file
    S3300 firmware expects (mirrors S3300Updater: ``cert + b"\\n" + key``)."""
    return f"{cert_pem.rstrip(chr(10))}\n{key_pem}"


def _cert_upload_multipart(
    spec: HttpModelSpec, cert_pem: str, key_pem: str
) -> tuple[str, dict[str, str], MultipartFile]:
    """Return the (path, form fields, file part) for ``spec``'s grounded
    SSL-cert upload, or raise UnsupportedCapabilityError if it has none.

    Pure; shared by the sync and async writers so the wire shape (the exact
    field map + combined-PEM file) cannot drift between the two codebases.
    """
    if spec.cert_upload_path is None or spec.cert_upload_file_field is None:
        raise UnsupportedCapabilityError(
            f"model {spec.model_key!r} has no known SSL-certificate upload mechanism"
        )
    payload = MultipartFile(
        field=spec.cert_upload_file_field,
        filename=_CERT_FILENAME,
        content=_combine_cert_key_pem(cert_pem, key_pem).encode(),
        content_type="application/octet-stream",
    )
    return spec.cert_upload_path, dict(spec.cert_upload_form_fields), payload


def _rsa_pkcs1_pair(key_pem: str) -> tuple[str, str]:
    """Convert an RSA private key PEM to the PKCS#1 "traditional" pair the
    GS728TPP GoAhead API requires: ``(private_key_pkcs1, public_key_pkcs1)``.

    Mirrors GS728TPPUpdater._convert_to_rsa_format, but uses the ``cryptography``
    library instead of shelling out to ``openssl rsa -traditional`` /
    ``-RSAPublicKey_out``. The switch accepts ONLY RSA keys, so a non-RSA key
    (EC/Ed25519/DSA) raises ``ValueError`` with a clear message rather than
    posting a body the switch would reject.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    try:
        private_key = serialization.load_pem_private_key(
            key_pem.encode(), password=None
        )
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"could not parse the private key as an unencrypted PEM: {exc}"
        ) from exc
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError(
            "GS728TPP SSL-certificate upload requires an RSA private key; got "
            f"{type(private_key).__name__}"
        )
    private_pkcs1 = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pkcs1 = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1,
        )
        .decode()
    )
    return private_pkcs1.strip(), public_pkcs1.strip()


def _build_gs728tpp_cert_xml(cert_pem: str, public_pem: str, private_pem: str) -> str:
    """Build the ``SSLCryptoCertificateImportList`` XML body (mirrors
    GS728TPPUpdater._build_cert_xml, XML-escaping each PEM block)."""

    def esc(text: str) -> str:
        return _xml_escape(text, {'"': "&quot;", "'": "&apos;"})

    return (
        "<?xml version='1.0' encoding='utf-8'?>"
        "<DeviceConfiguration>"
        '<SSLCryptoCertificateImportList action="set">'
        "<Entry><instance>1</instance>"
        f"<certificate>{esc(cert_pem)}</certificate>"
        f"<publicKey>{esc(public_pem)}</publicKey>"
        f"<privateKey>{esc(private_pem)}</privateKey>"
        "</Entry></SSLCryptoCertificateImportList>"
        "</DeviceConfiguration>"
    )


def _cert_upload_xml(
    spec: HttpModelSpec, cert_pem: str, key_pem: str
) -> tuple[str, str]:
    """Return the ``(path, xml_body)`` for ``spec``'s GoAhead XML-API SSL-cert
    upload, or raise UnsupportedCapabilityError if it has no upload endpoint.

    Pure; shared by the sync and async writers so the wire shape (the exact XML
    envelope + PKCS#1 conversion) cannot drift between the two codebases. Raises
    ``ValueError`` (via ``_rsa_pkcs1_pair``) for a non-RSA key.
    """
    if spec.cert_upload_path is None:
        raise UnsupportedCapabilityError(
            f"model {spec.model_key!r} has no known SSL-certificate upload mechanism"
        )
    private_pkcs1, public_pkcs1 = _rsa_pkcs1_pair(key_pem)
    body = _build_gs728tpp_cert_xml(cert_pem.strip(), public_pkcs1, private_pkcs1)
    return spec.cert_upload_path, body


_UPLOAD_STATUS_RE = re.compile(r"<statusCode>(\d+)</statusCode>")
_UPLOAD_STATUS_STRING_RE = re.compile(r"<statusString>([^<]*)</statusString>")


def _check_multipart_cert_response(text: str) -> None:
    """Raise ``HttpError`` unless an S3300 multipart cert-upload response
    reports success.

    The S3300 http_file_download page returns HTTP 200 even on a rejected
    certificate -- the real outcome is in the page BODY (mirrors the certbot
    hook's own check, live-confirmed on 10.1.5.11: a good upload renders
    "SSL PEM Server Certificate file download through HTTP is completed
    successfully"). Anything else (an error string, or the marker missing
    entirely) is surfaced rather than silently swallowed, so a bad cert/key or
    a wrong-endpoint POST can never look like success.
    """
    low = text.lower()
    if "completed successfully" in low:
        return
    err = re.search(r"(error[^<>\n]{0,80})", text, re.IGNORECASE)
    reason = err.group(1).strip() if err else "no 'completed successfully' marker"
    raise HttpError(f"S3300 SSL-certificate upload was not accepted: {reason}")


def _check_goahead_upload_response(text: str) -> None:
    """Raise ``HttpError`` if a GoAhead cert-upload response is not success.

    Success is ``<statusCode>0</statusCode>`` (mirrors GS728TPPUpdater); a
    non-zero code surfaces the ``<statusString>`` the switch returned.
    """
    match = _UPLOAD_STATUS_RE.search(text)
    if match is None:
        raise HttpError(
            "GS728TPP cert upload: response carried no <statusCode> "
            "(unexpected page -- not logged in, or wrong endpoint?)"
        )
    if match.group(1) != "0":
        detail = _UPLOAD_STATUS_STRING_RE.search(text)
        reason = detail.group(1) if detail else "unknown error"
        raise HttpError(
            f"GS728TPP cert upload failed (statusCode={match.group(1)}): {reason}"
        )


def _require_csrf_dialect(spec: HttpModelSpec, model_key: str, op: str) -> None:
    """Refuse a hash-scraping write on a dialect whose pages carry no token.

    This is a CAPABILITY refusal, not a surprise, so it raises
    UnsupportedCapabilityError rather than HttpUnexpectedPageError: the writer
    is built on the Plus form, and MEASURED probes of gsm7252ps and gs110emx
    found no ``<input name="hash">`` anywhere in their write pages. Saying so by
    type is what lets the facade, the capability table and the caller agree --
    and what stops a bare "unexpected page" from reading like a transient fault.
    """
    from .protocols.http.endpoints import dialect_has_csrf_hash

    if not dialect_has_csrf_hash(spec.html_dialect):
        raise UnsupportedCapabilityError(
            f"model {model_key!r} web UI carries no CSRF 'hash' token, which "
            f"the HTTP {op} writer requires"
        )


def _csrf(html: str) -> str:
    token = parse.parse_csrf_hash(html)
    if token is None:
        raise HttpUnexpectedPageError("no CSRF 'hash' token on page before write")
    return token


def _require_path(model_key: str, path: str | None, op: str) -> str:
    """Return ``path`` or raise honestly if this model's spec has none for ``op``.

    The message says the SPEC has no path rather than "the web UI does not expose
    it", because those are different claims and only the per-model spec entry
    knows which one applies. Some Nones in ``endpoints.py`` are MEASURED absences
    (the gs110emx really has no PoE/LLDP/MAC page -- its own JS publishes 39
    pages, none of them those, and seven probed names each 404), while others are
    simply undiscovered, usually because the switch was unreachable. Asserting a
    device limitation for the second kind is what CLAUDE.md principle 4 forbids,
    so the wording sends the reader to the spec entry, where the evidence -- or
    its absence -- is recorded.
    """
    if path is None:
        raise UnsupportedCapabilityError(
            f"model {model_key!r} has no {op} page in its HTTP endpoint spec "
            "(see protocols/http/endpoints.py for whether that is a measured "
            "absence or an undiscovered page)"
        )
    return path


def _is_fastpath_dialect(spec: HttpModelSpec) -> bool:
    """True for the managed FASTPATH/Cheetah models (gsm7252ps, gsm7228ps/S3300
    and both M4300 SKUs), whose VLAN membership lives on
    ``switching/dot1q/vlan_port_cfg.html`` rather than a Plus-class
    ``8021qMembe.cgi``. Mirrors ``http_read._is_fastpath_dialect``."""
    return spec.html_dialect in (
        HtmlDialect.M4300,
        HtmlDialect.XE_FASTPATH,
        HtmlDialect.S3300,
    )


def _is_xml_api_dialect(spec: HttpModelSpec) -> bool:
    """True for a UI that writes by POSTing an XML body to one endpoint.

    Only the GS728TPP's GoAhead ``wcd`` API today. Kept as a predicate rather
    than an inline dialect comparison so the dispatch reads the same way as
    ``_is_fastpath_dialect`` and a second XML-API model joins in one place.
    """
    return spec.html_dialect is HtmlDialect.GOAHEAD_XML


def _check_goahead_status(text: str, what: str) -> None:
    """Raise ``HttpError`` unless a ``wcd`` write reported success.

    Success is ``<statusCode>0</statusCode>`` -- the same convention the
    GS728TPP certificate upload already checks (it mirrors GS728TPPUpdater).
    A missing statusCode means the POST did not reach a write handler at all
    (not logged in, or wrong endpoint), which must never read as success.
    """
    match = _UPLOAD_STATUS_RE.search(text)
    if match is None:
        raise HttpError(
            f"{what}: response carried no <statusCode> (unexpected page -- "
            "not logged in, or wrong endpoint?)"
        )
    if match.group(1) != "0":
        detail = _UPLOAD_STATUS_STRING_RE.search(text)
        reason = detail.group(1) if detail else "unknown error"
        raise HttpError(f"{what} failed (statusCode={match.group(1)}): {reason}")


def _raise_on_fastpath_err_flag(html: str, what: str) -> None:
    """Surface the switch's OWN rejection of a FASTPATH apply.

    These pages answer HTTP 200 even when they refuse the write and report it in
    two hidden fields the page's ``check_error()`` JS pops up:
    ``err_flag=1`` plus a human ``err_msg``. Without this check the only symptom
    was the generic verify-after-write failure, which hides the reason -- and the
    reason is what a caller needs.

    LIVE example (M4300-24X 10.1.5.13, 2026-07-30): applying membership for a
    port whose ``switchport mode`` is ``access`` returns

        err_flag=1
        err_msg='Unable to set VLAN membership for VLAN ( 4004 )'

    i.e. the FASTPATH precondition that a port only accepts explicit VLAN
    participation while in ``general`` mode. That is a device requirement to be
    reported, not a library limitation to be papered over.
    """
    flag = parse.parse_fastpath_err(html)
    if flag is None:
        return
    raise HttpError(f"switch refused {what}: {flag}")


def _require_fastpath_membership_for(
    page: FastpathMembership, vlan: int, path: str
) -> None:
    """Refuse to act on a membership page showing a DIFFERENT VLAN.

    Without this a rejected VLAN-select POST (the firmware answers by
    re-rendering whichever VLAN was already showing) would have this writer
    apply the caller's change to the WRONG VLAN.
    """
    if page.vlan_id is not None and page.vlan_id != vlan:
        raise HttpUnexpectedPageError(
            f"{path}: asked for VLAN {vlan} but the page shows VLAN "
            f"{page.vlan_id} -- refusing to write to the wrong VLAN"
        )


# FASTPATH XUI column coordinates, read off each page's OWN header row (and
# corroborated by the firmware's per-field metadata, e.g.
# ``xeData.xeleName_1_2_6 = "Admin <br/> Mode"``). Live-confirmed on all four
# managed switches 2026-07-30: the header cell ``id=1_2_6`` reads "Admin Mode"
# on gsm7252ps/gsm7228ps/m4300-24x/m4300-16x alike.
_XUI_PORT_ADMIN = "v_1_2_6"
_XUI_PORT_IFNAME = "v_1_2_1"
# poeInterfaceConfiguration.html. Column 20 is a HIDDEN, WRITE-ONLY enum the
# page never displays -- ``xeData.xp_1_2_20 = "write-only"``,
# ``xeData.xeleName_1_2_20 = "Port Reset"``,
# ``allWebEnums[...] = [ "None","Reset" ]`` -- and the RESET button's action
# array (``xeData.xa_2_1_3``) enables exactly ``1_2_20|g_1_2_20`` while
# disabling every config column, which is how the one page serves both APPLY
# and RESET.
_XUI_POE_IFNAME = "v_1_2_1"
_XUI_POE_ADMIN = "v_1_2_2"
_XUI_POE_RESET = "v_1_2_20"
_XUI_POE_RESET_VALUE = "Reset"
# The two buttons' own shed lists, read off the firmware's
# ``/scripts/_xe_poeInterfaceConfiguration.js`` (fetched live 2026-07-31 from
# gsm7252ps 10.1.5.22 and gsm7228ps 10.1.5.11). Index 14 of a button's action
# array is its DISABLE set and index 15 its ENABLE set -- ``xuiShed(2, ...)``
# sets ``disabled=true``, so a browser does not submit those inputs for that
# button:
#
#   xeData.xa_2_1_2 (APPLY) disable = "1_2_20|g_1_2_20"
#   xeData.xa_2_1_3 (RESET) disable = "1_2_2|1_2_3|...|1_2_18|g_1_2_2|...|g_1_2_18"
#
# So APPLY submits the config columns without the write-only Port Reset action,
# and RESET submits the Port Reset action without the config columns. Sending
# both at once is what the gsm7252ps error message called out by name -- its
# refusal listed 'Admin <br/> Mode' AND 'Port Reset' together, and dropping
# ``v_1_2_20`` from the apply removed exactly the 'Port Reset' line (live
# 2026-07-31, 10.1.5.22 port 1/0/35).
#
# The RESET set is the UNION of the two firmwares' lists: gsm7252ps stops at
# ``1_2_18`` (its Timer Schedule column 19 and Temperature column 22 stay
# enabled) while gsm7228ps/m4300 also disable ``1_2_19``. A column a row does not
# render is ignored by the builder, so one tuple serves every model.
_XUI_POE_APPLY_OMITS = (_XUI_POE_RESET,)
_XUI_POE_RESET_OMITS = tuple(f"v_1_2_{n}" for n in range(2, 20))
# ``Enable``/``Disable`` are the wire values of both admin-mode columns
# (rendered verbatim in the cells on every model).
_XUI_ENABLE = "Enable"
_XUI_DISABLE = "Disable"


def _xui_enabled(value: bool) -> str:
    return _XUI_ENABLE if value else _XUI_DISABLE


def _fastpath_ifnames(port: int) -> tuple[str, ...]:
    """The ifName spellings a FASTPATH page may use for physical ``port``.

    Two are in live use and they are NOT interchangeable: the Fully-Managed and
    M4300 firmwares write ``1/0/36`` while the Smart-Managed-Pro S3300 writes
    ``1/g12`` (and ``1/xg49`` for its 10G ports). Both are tried rather than
    keyed off the dialect, because the row is then confirmed by MATCHING the
    device's own cell -- never by computing a row index from the port number,
    which would address the wrong row on any page whose row order differs from
    port order (the PoE page of a 52-port switch has only 48 rows).
    """
    return (f"1/0/{port}", f"1/g{port}", f"1/xg{port}")


def _find_xui_row(page: XuiListPage, port: int, column: str, what: str) -> XuiRow:
    """The row of ``page`` whose ``column`` names physical ``port``, or raise."""
    for ifname in _fastpath_ifnames(port):
        row = page.row_for(column, ifname)
        if row is not None:
            return row
    rendered = sorted(str(r.field(column)) for r in page.rows)
    raise UnsupportedCapabilityError(
        f"{what}: port {port} is not on this page (it renders {rendered!r})"
    )


def _check_gs110emx_apply(text: str, what: str) -> None:
    """Raise unless a GS110EMX AJAX apply answered ``SUCCESS``.

    That page's own JS keys off exactly this: ``if (resText != "SUCCESS")`` it
    renders the error. The response is a bare body on an HTTP 200, so without
    this check a rejected write would look like a successful one.
    """
    if text.strip().upper().startswith("SUCCESS"):
        return
    raise HttpError(f"switch refused {what}: {text.strip()[:200]!r}")


def _require_xui_mgmt_fields(spec: HttpModelSpec) -> tuple[str, XuiMgmtIpFields]:
    """``(page path, field map)`` for this model's mgmt-IP write, or raise."""
    if spec.mgmt_ip_path is None or spec.mgmt_ip_fields is None:
        raise UnsupportedCapabilityError(
            f"model {spec.model_key!r} has no known web management-IP form "
            "(no mgmt_ip_path/mgmt_ip_fields in its endpoint spec)"
        )
    return spec.mgmt_ip_path, spec.mgmt_ip_fields


def _mgmt_ip_changes(
    fields: XuiMgmtIpFields, address: str, netmask: str, gateway: str
) -> dict[str, str]:
    """The field overrides for a STATIC mgmt-IP apply.

    The method field is set FIRST in the dict on purpose -- these forms are
    ordinary urlencoded bodies, but the firmware's own page switches the address
    boxes from disabled to enabled when the method radio changes (the page's
    ``xa_1_5_3`` / ``xa_1_8_1`` action arrays), so a body that says "static" is
    what makes the three address fields meaningful at all. Sending the addresses
    while the method still says DHCP is the FASTPATH ordering mistake principle
    4 warns about.
    """
    return {
        fields.mode: fields.static_value,
        fields.address: address,
        fields.netmask: netmask,
        fields.gateway: gateway,
    }


def _poe_reset_button(page: XuiListPage, model_key: str) -> str:
    """The PoE page's reset/power-cycle button field.

    ``v_2_1_3`` on every managed model, but its LABEL differs (``RESET`` on the
    gsm72xx pages, ``Power Cycle Port(s)`` on both M4300s -- live 2026-07-30),
    which is why only the field name is a constant and the value is echoed from
    the page. Raises if the page has no such button rather than inventing one.
    """
    if "v_2_1_3" not in page.buttons:
        raise UnsupportedCapabilityError(
            f"model {model_key!r} PoE page has no reset button "
            f"(it renders {sorted(page.buttons)!r})"
        )
    return "v_2_1_3"


def _vlan_checkbox_index(html: str, vlan: int) -> int | None:
    for m in re.finditer(r'name="vlanck(\d+)"[^>]*value="(\d+)"', html):
        if int(m.group(2)) == vlan:
            return int(m.group(1))
    return None


class HttpWriter:
    def __init__(
        self,
        session: HttpSession,
        model: SwitchModel,
        *,
        protected_ports: frozenset[int] = frozenset(),
    ) -> None:
        self._spec = http_spec(model)
        self.session = session
        self.model = model
        self.protected_ports = protected_ports

    def _guard(self, port: int, force: bool) -> None:
        if port in self.protected_ports and not force:
            raise ProtectedPortError(
                f"port {port} is protected on {self.model.key!r}; pass force=True"
            )

    # --- GoAhead XML API (GS728TPP) ---------------------------------------
    #
    # Every write on this UI is one POST of an XML body to a single endpoint;
    # the object name and action verb inside the body select the operation.
    # See protocols/http/goahead.py for where that wire shape comes from.

    def _goahead_write(self, body: str, what: str) -> None:
        path = _require_path(
            self.model.key, self._spec.xml_write_path, "XML-API write endpoint"
        )
        _check_goahead_status(self.session.post_xml(path, body), what)

    def _goahead_membership(
        self,
    ) -> dict[int, tuple[frozenset[int], frozenset[int]]]:
        """``{vlan: (tagged, untagged)}`` as the switch reports it right now.

        Read from the per-port page the reader already uses: each port's inline
        JoinVLANList carries the complete membership, so this is the same view
        ``get_vlans`` is built from -- verification cannot pass against a
        different projection than the one callers see.
        """
        path = _require_path(
            self.model.key, self._spec.pvid_path, "port VLAN membership"
        )
        return parse.parse_goahead_port_vlan_membership(self.session.get_page(path))

    def _goahead_mode_of(self, vlan: int, port: int) -> VlanMode:
        tagged, untagged = self._goahead_membership().get(
            vlan, (frozenset(), frozenset())
        )
        if port in untagged:
            return VlanMode.UNTAGGED
        if port in tagged:
            return VlanMode.TAGGED
        return VlanMode.EXCLUDED

    def _goahead_vlan_ids(self) -> set[int]:
        path = _require_path(self.model.key, self._spec.vlan_config_path, "VLAN config")
        return set(parse.parse_goahead_vlan_names(self.session.get_page(path)))

    def _require_vlan_exists(self, vlan: int) -> None:
        """Refuse a PVID pointing at a VLAN this switch does not have.

        A precondition, so nothing is sent. The device will not catch it:
        MEASURED on the GS728TPP (10.2.5.10, firmware 6.0.1.30) an unknown PVID
        is ACCEPTED and reads back, creating no VLAN -- so verify-after-write
        passes while the port is left pointing at a VLAN that is not there.

        Skipped where this UI cannot enumerate VLANs at all (no vlan_config
        page): refusing on a list we cannot read would be worse than the risk.
        """
        if self._spec.vlan_config_path is None:
            return
        page = self.session.get_page(self._spec.vlan_config_path)
        known = (
            set(parse.parse_goahead_vlan_names(page))
            if _is_xml_api_dialect(self._spec)
            else set(parse.parse_vlan_ids(page))
        )
        if vlan not in known:
            raise HttpUnexpectedPageError(
                f"VLAN {vlan} does not exist (known: {sorted(known)})"
            )

    def _goahead_create_vlan(self, vlan: int, name: str) -> None:
        before = self._goahead_vlan_ids()
        self._goahead_write(goahead.vlan_create_body(vlan, name), f"create VLAN {vlan}")
        after = self._goahead_vlan_ids()
        if vlan not in after:
            raise WriteVerificationError(
                f"VLAN {vlan} was not created",
                before=sorted(before),
                after=sorted(after),
            )

    def _goahead_delete_vlan(self, vlan: int) -> None:
        before = self._goahead_vlan_ids()
        self._goahead_write(goahead.vlan_delete_body(vlan), f"delete VLAN {vlan}")
        after = self._goahead_vlan_ids()
        if vlan in after:
            raise WriteVerificationError(
                f"VLAN {vlan} was not deleted",
                before=sorted(before),
                after=sorted(after),
            )

    def _goahead_poe_rearm(
        self,
        port: int,
        *,
        timeouts: PoeCycleTimeouts | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Power-cycle ``port`` by driving its adminEnable off then on.

        This UI publishes NO PoE reset control -- ``Behaviour/UnitsPoe.js`` has
        no reset/cycle/reboot action and the page's only buttons are Refresh,
        Cancel and Apply -- so a power cycle is an admin re-arm of the same
        field. That is not an invention: it is the mechanism SnmpWriter already
        uses on agents with no reset column, and it is what the switch itself
        can be made to do.

        Two SEPARATE writes, each verified, then a poll for the port to come
        back, using the same recovery rule as every other backend
        (``models.poe_cycle_complete``).
        """
        from .snmp_write import PoeCycleTimeouts

        limits = timeouts or PoeCycleTimeouts()
        before = self._poe_status(port)
        self._goahead_poe_admin(port, on=False)
        self._goahead_poe_admin(port, on=True)
        deadline = clock() + limits.on_timeout
        while not poe_cycle_complete(before, self._poe_status(port)):
            if clock() >= deadline:
                raise WriteVerificationError(
                    f"PoE port {port} did not come back after the power cycle "
                    f"within {limits.on_timeout}s",
                    before=before,
                    after=self._poe_status(port),
                )
            sleep(limits.poll_interval)

    def _poe_status(self, port: int) -> PoEStatus | None:
        path = _require_path(self.model.key, self._spec.poe_status_path, "PoE status")
        rows = _parse_poe(self._spec, self.session.get_page(path))
        return next((r for r in rows if r.port == port), None)

    def _goahead_poe_admin(self, port: int, on: bool) -> None:
        before = self._poe_admin(port)
        self._goahead_write(
            goahead.poe_admin_body(goahead.port_interface_name(port), on),
            f"PoE port {port} admin -> {on}",
        )
        after = self._poe_admin(port)
        if after != on:
            raise WriteVerificationError(
                f"PoE port {port} did not read back as on={on}",
                before=before,
                after=after,
            )

    def _set_goahead_port_enabled(self, path: str, port: int, enabled: bool) -> None:
        """Port admin state through the ports page's ``Standard802_3List``.

        ``path`` is the page the state is read back from -- the same one
        ``get_ports`` uses -- while the write itself goes to the single wcd
        endpoint like every other write on this UI.
        """
        before = next(
            (
                p.admin_enabled
                for p in parse.parse_goahead_ports(self.session.get_page(path))
                if p.port == port
            ),
            None,
        )
        self._goahead_write(
            goahead.port_config_body(
                goahead.port_interface_name(port), port, admin_enabled=enabled
            ),
            f"port {port} admin -> {enabled}",
        )
        after = next(
            (
                p.admin_enabled
                for p in parse.parse_goahead_ports(self.session.get_page(path))
                if p.port == port
            ),
            None,
        )
        if after is not enabled:
            raise WriteVerificationError(
                f"port {port} did not read back as enabled={enabled}",
                before=before,
                after=after,
            )

    def set_port_description(
        self, port: int, description: str, *, force: bool = False
    ) -> None:
        """Label a port through the ports page's ``interfaceDescription``.

        XML-API only for now: that page carries the field and the read side
        already parses it. The FASTPATH XUI port pages have a description column
        too, but its cell id has not been captured, and guessing one would post
        into an unknown cell.
        """
        self._guard(port, force)
        if not _is_xml_api_dialect(self._spec):
            raise UnsupportedCapabilityError(
                f"model {self.model.key!r}: no HTTP port-description write is "
                "built for this web UI dialect"
            )
        path = _require_path(
            self.model.key, self._spec.dashboard_path, "the ports page"
        )

        def described(body: str) -> str | None:
            rows = parse.parse_goahead_ports(body)
            return next((p.description for p in rows if p.port == port), None)

        before = described(self.session.get_page(path))
        self._goahead_write(
            goahead.port_config_body(
                goahead.port_interface_name(port), port, description=description
            ),
            f"port {port} description",
        )
        after = described(self.session.get_page(path))
        want = description or None
        if after != want:
            raise WriteVerificationError(
                f"description for port {port} did not read back as {want!r}",
                before=before,
                after=after,
            )

    def _set_goahead_membership(self, vlan: int, port: int, mode: VlanMode) -> None:
        before = self._goahead_mode_of(vlan, port)
        self._goahead_write(
            goahead.vlan_membership_body(vlan, goahead.port_interface_name(port), mode),
            f"VLAN {vlan} membership for port {port} -> {mode.value}",
        )
        after = self._goahead_mode_of(vlan, port)
        if after is not mode:
            raise WriteVerificationError(
                f"VLAN {vlan} port {port} did not read back as {mode.value}",
                before=before,
                after=after,
            )

    def set_poe(self, port: int, on: bool, *, force: bool = False) -> None:
        # The XML-API check comes BEFORE the page requirement: that UI has no
        # per-op write page at all (one wcd endpoint, the body selects the op),
        # so demanding ``poe_config_path`` would refuse a write that works.
        if _is_xml_api_dialect(self._spec):
            self._guard(port, force)
            self._goahead_poe_admin(port, on)
            return
        path = _require_path(
            self.model.key, self._spec.poe_config_path, "web PoE config"
        )
        self._guard(port, force)
        if _is_fastpath_dialect(self._spec):
            self._xui_poe_admin(path, port, on)
            return
        before = self._poe_admin(port)
        page = self.session.get_page(path)
        form = forms.poe_apply_form(
            port=port, on=on, is_epx=self._spec.is_epx_poe, csrf_hash=_csrf(page)
        )
        self.session.post_form(path, form)
        after = self._poe_admin(port)
        if after != on:
            raise WriteVerificationError(
                f"PoE port {port} did not read back as on={on}",
                before=before,
                after=after,
            )

    def _xui_poe_admin(self, path: str, port: int, on: bool) -> None:
        """FASTPATH PoE admin mode through ``poeInterfaceConfiguration.html``.

        LIVE-PROVEN on gsm7228ps 10.1.5.11 (port ``1/g12``), m4300-16x
        10.1.5.20:49152 (port 1/0/15) 2026-07-30 and gsm7252ps 10.1.5.22 (port
        1/0/35) 2026-07-31, by driving this exact form builder through a real
        change and reading it back.

        The gsm7252ps needed two corrections the other two firmwares tolerated,
        both of them the page's own doing rather than the device's: its list
        ``nav`` block must ride along (see ``forms.xui_row_apply_form``), and the
        write-only Port Reset column must NOT (see ``_XUI_POE_APPLY_OMITS``).
        """
        page = parse.parse_xui_list_page(self.session.get_page(path), page=path)
        row = _find_xui_row(page, port, _XUI_POE_IFNAME, f"{self.model.key!r} PoE")
        before = row.field(_XUI_POE_ADMIN)
        applied = self.session.post_form(
            page.action,
            forms.xui_row_apply_form(
                page,
                row,
                {_XUI_POE_ADMIN: _xui_enabled(on)},
                button="v_2_1_2",
                omit=_XUI_POE_APPLY_OMITS,
            ),
        )
        _raise_on_fastpath_err_flag(applied, f"PoE port {port} admin -> {on}")
        after = self._poe_admin(port)
        if after != on:
            raise WriteVerificationError(
                f"PoE port {port} did not read back as on={on} on {path}",
                before=before,
                after=after,
            )

    def cycle_poe(
        self,
        port: int,
        *,
        force: bool = False,
        timeouts: PoeCycleTimeouts | None = None,
    ) -> None:
        if _is_xml_api_dialect(self._spec):
            # This UI has no reset control at all, so a cycle is an admin
            # re-arm -- and unlike the reset-button dialects it CAN be verified,
            # so the timeouts are honoured rather than discarded.
            self._guard(port, force)
            self._goahead_poe_rearm(port, timeouts=timeouts)
            return
        # timeouts accepted-but-unused: matches SnmpWriter/NsdpWriter so the
        # facade's SnmpWriter | NsdpWriter | HttpWriter union call site typechecks.
        del timeouts
        path = _require_path(
            self.model.key, self._spec.poe_config_path, "web PoE config"
        )
        self._guard(port, force)
        if _is_fastpath_dialect(self._spec):
            self._xui_poe_reset(path, port)
            return
        page = self.session.get_page(path)
        self.session.post_form(
            path, forms.poe_reset_form(port=port, csrf_hash=_csrf(page))
        )

    def clear_poe_fault(
        self,
        port: int,
        *,
        force: bool = False,
        timeouts: PoeCycleTimeouts | None = None,
    ) -> None:
        """Clear a PoE fault on ``port`` by re-running the port's PoE detection.

        On the managed FASTPATH models this is the page's own hidden write-only
        "Port Reset" column driven by its RESET button -- the same mechanism the
        CLI backend uses (``poe reset``) and the same one ``SnmpWriter`` emulates
        with an admin off/on re-arm. On the Plus-class CGI UI it is the
        ``PoEPortConfig.cgi`` reset form, identical to ``cycle_poe``: a Plus
        switch has no separate "clear fault" action, the fault clears when
        detection re-runs.
        """
        if _is_xml_api_dialect(self._spec):
            # Same admin re-arm as cycle_poe -- this UI has no separate
            # clear-fault action either, and a fault clears when detection
            # re-runs (exactly as on the Plus CGI UI).
            self._guard(port, force)
            self._goahead_poe_rearm(port, timeouts=timeouts)
            return
        del timeouts  # accepted-but-unused; uniform writer surface (see cycle_poe).
        path = _require_path(
            self.model.key, self._spec.poe_config_path, "web PoE config"
        )
        self._guard(port, force)
        if _is_fastpath_dialect(self._spec):
            self._xui_poe_reset(path, port)
            return
        page = self.session.get_page(path)
        self.session.post_form(
            path, forms.poe_reset_form(port=port, csrf_hash=_csrf(page))
        )

    def _xui_poe_reset(self, path: str, port: int) -> None:
        """Press the FASTPATH PoE page's per-port RESET for ``port``.

        No verify-after-write, and that is not an omission: ``v_1_2_20`` is a
        WRITE-ONLY field (``xeData.xp_1_2_20 = "write-only"``) that re-runs PD
        detection -- it has no persistent state to read back, exactly like
        ``cycle_poe`` on every other backend. What IS checked is the page's own
        ``err_flag``/``err_msg``, so a refusal is raised rather than swallowed.

        The body carries the Port Reset action WITHOUT the config columns, which
        is what the RESET button's own shed list says (``_XUI_POE_RESET_OMITS``):
        a reset must not double as a rewrite of Admin Mode / priority / limits.
        """
        page = parse.parse_xui_list_page(self.session.get_page(path), page=path)
        row = _find_xui_row(page, port, _XUI_POE_IFNAME, f"{self.model.key!r} PoE")
        applied = self.session.post_form(
            page.action,
            forms.xui_row_apply_form(
                page,
                row,
                {_XUI_POE_RESET: _XUI_POE_RESET_VALUE},
                button=_poe_reset_button(page, self.model.key),
                omit=_XUI_POE_RESET_OMITS,
            ),
        )
        _raise_on_fastpath_err_flag(applied, f"PoE reset of port {port}")

    def set_pvid(self, port: int, vlan: int, *, force: bool = False) -> None:
        self._guard(port, force)
        path = _require_path(self.model.key, self._spec.pvid_path, "port PVIDs")
        self._require_vlan_exists(vlan)
        if _is_xml_api_dialect(self._spec):
            before = dict(parse.parse_goahead_pvids(self.session.get_page(path)))
            self._goahead_write(
                goahead.pvid_body(goahead.port_interface_name(port), vlan),
                f"PVID for port {port} -> {vlan}",
            )
            now = dict(parse.parse_goahead_pvids(self.session.get_page(path)))
            if now.get(port) != vlan:
                raise WriteVerificationError(
                    f"PVID for port {port} did not read back as {vlan}",
                    before=before.get(port),
                    after=now.get(port),
                )
            return
        page = self.session.get_page(path)
        self.session.post_form(
            path, forms.pvid_form(port=port, vlan=vlan, csrf_hash=_csrf(page))
        )
        after = dict(parse.parse_pvids(self.session.get_page(path)))
        if after.get(port) != vlan:
            raise WriteVerificationError(
                f"PVID for port {port} did not read back as {vlan}",
                before=None,
                after=after.get(port),
            )

    def set_vlan_membership(
        self, vlan: int, port: int, mode: VlanMode, *, force: bool = False
    ) -> None:
        self._guard(port, force)
        if _is_fastpath_dialect(self._spec):
            self._set_fastpath_membership(vlan, port, mode)
            return
        if _is_xml_api_dialect(self._spec):
            self._set_goahead_membership(vlan, port, mode)
            return
        path = _require_path(
            self.model.key, self._spec.vlan_membership_path, "VLAN membership"
        )
        html = self.session.post_form(path, {"VLAN_ID": str(vlan)})
        states = parse.parse_membership(html, self.model.port_count)
        states[port] = mode
        hidden = forms.membership_hidden_mem(states, self.model.port_count)
        self.session.post_form(
            path,
            forms.membership_form(vlan=vlan, hidden_mem=hidden, csrf_hash=_csrf(html)),
        )
        verify = self.session.post_form(path, {"VLAN_ID": str(vlan)})
        after = parse.parse_membership(verify, self.model.port_count)
        if after.get(port) is not mode:
            raise WriteVerificationError(
                f"VLAN {vlan} port {port} did not read back as {mode.value}",
                before=states.get(port),
                after=after.get(port),
            )

    def _set_fastpath_membership(self, vlan: int, port: int, mode: VlanMode) -> None:
        """Set one port's participation in ``vlan`` on the managed FASTPATH web UI.

        Wire flow, all live-confirmed (see ``parse.parse_fastpath_membership``):

        1. Read the VLAN's membership page (GET, then the browser's own
           ``submt=0`` re-render POST if another VLAN is showing).
        2. Replace ONLY this port's code in the ``hiddenMem`` string the device
           rendered -- every other slot, including the LAG pseudo-interfaces this
           library does not model, is preserved verbatim.
        3. POST it back with ``submt=16`` (what the page's own ``submitform()``
           sets), ``hiddenTagged``/``hiddenUnTagged`` cleared exactly as
           ``resethidden()`` does.
        4. Re-read and verify.

        Verification reads the page's ``configured`` view (``hiddenMem``), NOT its
        ``hiddenTagged``/``hiddenUnTagged`` egress lists. That is not a weaker
        check, it is the only correct one: those lists are the CURRENT
        (operational) view, and a port that is configured into a VLAN but not
        currently participating is absent from them -- live-proven on gsm7252ps
        VLAN 1, where ``1/0/50``/``1/0/51`` are ``Configured: Include`` yet
        ``Current: Exclude``. Verifying against the current view would report a
        successful write as failed for exactly the link-down ports a caller is
        most likely to be configuring.
        """
        get_path, post_path = fastpath_membership_paths(self._spec, self.model.key)
        before = self._read_fastpath_membership(vlan, get_path, post_path)
        hidden = parse.fastpath_hidden_mem_with(before, port, mode)
        applied = self.session.post_form(
            post_path,
            forms.fastpath_membership_form(
                before, vlan=vlan, hidden_mem=hidden, apply=True
            ),
        )
        _raise_on_fastpath_err_flag(applied, f"VLAN {vlan} port {port} -> {mode.value}")
        after = self._read_fastpath_membership(vlan, get_path, post_path)
        if after.configured.get(port) is not mode:
            raise WriteVerificationError(
                f"VLAN {vlan} port {port} did not read back as {mode.value} on "
                f"{post_path} (hiddenMem slot "
                f"{before.port_slots.get(port)})",
                before=before.configured.get(port),
                after=after.configured.get(port),
            )

    def _read_fastpath_membership(
        self, vlan: int, get_path: str, post_path: str
    ) -> FastpathMembership:
        page = parse.parse_fastpath_membership(self.session.get_page(get_path))
        if page.vlan_id == vlan:
            return page
        body = forms.fastpath_membership_form(page, vlan=vlan)
        shown = parse.parse_fastpath_membership(self.session.post_form(post_path, body))
        _require_fastpath_membership_for(shown, vlan, post_path)
        return shown

    def create_vlan(self, vlan: int, name: str, *, force: bool = False) -> None:
        if _is_xml_api_dialect(self._spec):
            del force
            self._goahead_create_vlan(vlan, name)
            return
        _require_csrf_dialect(self._spec, self.model.key, "create_vlan")
        del name, force  # web UI 8021qCf.cgi has no VLAN-name field (GROUNDED).
        path = _require_path(self.model.key, self._spec.vlan_config_path, "VLAN config")
        page = self.session.get_page(path)
        self.session.post_form(
            path, forms.vlan_add_form(vlan=vlan, csrf_hash=_csrf(page))
        )
        after = parse.parse_vlan_ids(self.session.get_page(path))
        if vlan not in after:
            raise WriteVerificationError(
                f"VLAN {vlan} was not created", before=None, after=after
            )

    def delete_vlan(self, vlan: int, *, force: bool = False) -> None:
        if _is_xml_api_dialect(self._spec):
            del force  # membership disruptiveness is guarded per-member elsewhere
            self._goahead_delete_vlan(vlan)
            return
        _require_csrf_dialect(self._spec, self.model.key, "delete_vlan")
        del force  # VLAN delete disruptiveness is guarded per-member elsewhere.
        path = _require_path(self.model.key, self._spec.vlan_config_path, "VLAN config")
        page = self.session.get_page(path)
        idx = _vlan_checkbox_index(page, vlan)
        if idx is None:
            raise HttpUnexpectedPageError(f"VLAN {vlan} not present to delete")
        self.session.post_form(
            path,
            forms.vlan_delete_form(
                vlan=vlan, checkbox_index=idx, csrf_hash=_csrf(page)
            ),
        )
        after = parse.parse_vlan_ids(self.session.get_page(path))
        if vlan in after:
            raise WriteVerificationError(
                f"VLAN {vlan} was not deleted", before=None, after=after
            )

    def reboot(self, *, force: bool = False) -> None:
        # Capability check BEFORE the force gate: a model with no reboot endpoint
        # must raise the (accurate) UnsupportedCapabilityError, not ProtectedPortError.
        reboot_path = _require_path(
            self.model.key, self._spec.reboot_path, "web reboot"
        )
        if not force:
            raise ProtectedPortError("reboot is disruptive; pass force=True")
        landing = self._spec.vlan_config_path or self._spec.dashboard_path
        page = self.session.get_page(
            _require_path(self.model.key, landing, "web reboot")
        )
        self.session.post_form(reboot_path, forms.reboot_form(csrf_hash=_csrf(page)))

    def set_port_enabled(
        self, port: int, enabled: bool, *, force: bool = False
    ) -> None:
        """Set port ``port``'s admin mode through ``portsConfiguration.html``.

        LIVE-VERIFIED 2026-07-30 on ALL FOUR managed switches, each on a
        link-down, undescribed port, as disable -> re-read -> enable -> re-read:
        gsm7252ps 10.1.5.22 port 36, gsm7228ps 10.1.5.11 port 12 (``1/g12``),
        m4300-24x 10.1.5.13 port 16, m4300-16x 10.1.5.20:49152 port 15. In every
        case the apply answered ``err_flag=0`` and a full re-read of the table
        showed the target row's Admin Mode cell changed and EVERY other cell of
        every other row byte-identical.
        """
        self._guard(port, force)
        if _is_xml_api_dialect(self._spec):
            # No per-op write page (see set_poe); the state is read back from
            # the same ports page ``get_ports`` uses.
            self._set_goahead_port_enabled(
                _require_path(
                    self.model.key, self._spec.dashboard_path, "the ports page"
                ),
                port,
                enabled,
            )
            return
        path = _require_path(
            self.model.key, self._spec.port_config_path, "the port-configuration page"
        )
        if self._spec.html_dialect is HtmlDialect.GS110EMX:
            self._set_gs110emx_port_enabled(path, port, enabled)
            return
        page = parse.parse_xui_list_page(self.session.get_page(path), page=path)
        row = _find_xui_row(
            page, port, _XUI_PORT_IFNAME, f"{self.model.key!r} port configuration"
        )
        before = row.field(_XUI_PORT_ADMIN)
        applied = self.session.post_form(
            page.action,
            forms.xui_row_apply_form(
                page,
                row,
                {_XUI_PORT_ADMIN: _xui_enabled(enabled)},
                button="v_2_1_2",
            ),
        )
        _raise_on_fastpath_err_flag(applied, f"port {port} admin mode -> {enabled}")
        after = _find_xui_row(
            parse.parse_xui_list_page(self.session.get_page(path), page=path),
            port,
            _XUI_PORT_IFNAME,
            f"{self.model.key!r} port configuration",
        ).field(_XUI_PORT_ADMIN)
        if after != _xui_enabled(enabled):
            raise WriteVerificationError(
                f"port {port} admin mode did not read back as "
                f"{_xui_enabled(enabled)!r} on {path}",
                before=before,
                after=after,
            )

    def _set_gs110emx_port_enabled(self, path: str, port: int, enabled: bool) -> None:
        """Port admin mode on the GS110EMX's ``port_settings.html``.

        A different mechanism from the FASTPATH grid, so it gets its own path
        rather than a shared one that happens to fit: this page has no admin
        column at all -- disabling a port means POSTing its Physical Mode as
        ``Disable`` (``PORT_CTRL_MODE=3``), and the reply is a bare ``SUCCESS``
        body, not a re-rendered page. See ``forms.gs110emx_port_admin_form``.

        LIVE-VERIFIED 2026-07-31 on a real GS110EMX (10.1.5.26) against port 7
        (link-down, no description): disable -> re-read -> enable -> re-read,
        each step confirmed by re-reading the page.
        """
        rows = parse.parse_gs110emx_port_form_fields(self.session.get_page(path))
        if port not in rows:
            raise UnsupportedCapabilityError(
                f"{self.model.key!r} port configuration: port {port} is not on "
                f"this page (it renders {sorted(rows)!r})"
            )
        before = parse.parse_gs110emx_port_status(self.session.get_page(path))
        was = next((p.admin_enabled for p in before if p.port == port), None)
        self.session.post_form(
            path,
            forms.gs110emx_port_admin_form(
                port=port,
                enabled=enabled,
                flow_control_mode=rows[port].get("FLOW_CONTROL_MODE", "0"),
            ),
        )
        after = parse.parse_gs110emx_port_status(self.session.get_page(path))
        got = next((p.admin_enabled for p in after if p.port == port), None)
        if got is not enabled:
            raise WriteVerificationError(
                f"port {port} admin mode did not read back as {enabled} on {path}",
                before=was,
                after=got,
            )

    def set_mgmt_ip(
        self, address: str, netmask: str, gateway: str, *, force: bool = False
    ) -> None:
        """Set the switch's STATIC management address through its web UI.

        The page and field names are per model (see ``XuiMgmtIpFields``), both
        live-captured 2026-07-30. Disruptive by definition -- it moves the
        address the caller is talking to -- so it needs ``force=True``, and the
        capability is resolved BEFORE the force gate exactly like ``reboot``.

        **The APPLY on this page is UNVERIFIED against live hardware, and
        deliberately so.** Every other write in this file was proven by doing it
        to a real switch and reading it back; this one was not, because applying
        it to any of the four reachable switches would have moved that switch's
        management address, dropped the session mid-write and risked stranding a
        device on a network nobody could reach. What IS verified live on all
        four: the page exists and is the right one, its field names/values are
        the device's own (read back through ``get_mgmt_ip``), and the surrounding
        machinery -- the ``submit_flag=8`` apply flag, the whole-form echo, the
        button field, the ``err_flag`` refusal check -- is the same machinery
        proven by ``set_port_enabled`` and ``set_vlan_membership`` on these exact
        pages. The verify-after-write below is therefore real: if the switch
        refuses, the caller is told.
        """
        path, fields = _require_xui_mgmt_fields(self._spec)
        if not force:
            raise ProtectedPortError(
                "set_mgmt_ip moves the address this session is using and can "
                "leave the switch unreachable; pass force=True"
            )
        page = parse.parse_xui_form_page(self.session.get_page(path), page=path)
        applied = self.session.post_form(
            page.action,
            forms.xui_form_apply_form(
                page,
                _mgmt_ip_changes(fields, address, netmask, gateway),
                button=fields.apply_button,
            ),
        )
        _raise_on_fastpath_err_flag(applied, f"management IP -> {address}/{netmask}")
        after = parse.parse_xui_form_page(self.session.get_page(path), page=path)
        got = (
            after.fields.get(fields.address),
            after.fields.get(fields.netmask),
            after.fields.get(fields.gateway),
        )
        if got != (address, netmask, gateway):
            raise WriteVerificationError(
                f"management IP did not read back as {address}/{netmask} via "
                f"{gateway} on {path}",
                before=(
                    page.fields.get(fields.address),
                    page.fields.get(fields.netmask),
                    page.fields.get(fields.gateway),
                ),
                after=got,
            )

    def upload_certificate(
        self, cert_pem: str, key_pem: str, *, force: bool = False
    ) -> None:
        """Upload an HTTPS SSL server certificate (combined cert+key PEM).

        GROUNDED for gsm7228ps/S3300 (multipart form) and gs728tpp (GoAhead
        XML-API) -- see endpoints.py and ``_cert_upload_xml``. A model whose
        real mechanism is a non-HTTP SCP copy (m4300/gsm7252ps) raises
        NotImplementedError pointing at ``upload_certificate_scp``; a model with
        no known mechanism raises
        UnsupportedCapabilityError. Disruptive (replaces the running
        certificate), so ``force=True`` is required -- capability is resolved
        BEFORE the force gate, mirroring ``reboot``.
        """
        _reject_known_unimplemented_cert_upload(self.model.key)
        if self._spec.html_dialect is HtmlDialect.GOAHEAD_XML:
            path, body = _cert_upload_xml(self._spec, cert_pem, key_pem)
            if not force:
                raise ProtectedPortError(
                    "SSL-certificate upload replaces the switch's running "
                    "certificate and is disruptive; pass force=True"
                )
            _check_goahead_upload_response(self.session.post_xml(path, body))
            return
        path, fields, payload = _cert_upload_multipart(self._spec, cert_pem, key_pem)
        if not force:
            raise ProtectedPortError(
                "SSL-certificate upload replaces the switch's running "
                "certificate and is disruptive; pass force=True"
            )
        _check_multipart_cert_response(
            self.session.post_multipart(path, fields, payload)
        )

    def _poe_admin(self, port: int) -> bool:
        path = _require_path(self.model.key, self._spec.poe_status_path, "PoE status")
        # Dialect-aware, via the READER's own dispatcher: the FASTPATH PoE page
        # is an XE grid, not a Plus ``portID``-row CGI, so hard-coding
        # parse_poe_status here made verify-after-write raise
        # HttpUnexpectedPageError on every managed model.
        rows = _parse_poe(self._spec, self.session.get_page(path))
        for r in rows:
            if r.port == port:
                return r.admin_enabled
        return False

    def set_hostname(self, name: str, *, force: bool = False) -> None:
        """Set the host name, where this dialect's identity page carries one.

        Implemented for the GoAhead XML API only: ``DeviceBasicInfo/deviceName``
        is the host name there (MEASURED -- it reads byte-for-byte what SNMP
        reports through sysName). The other dialects' identity pages either
        carry no such field or have no captured write form, and are refused by
        name rather than returned empty: an empty answer here would be
        indistinguishable from a switch that genuinely has none.
        """
        del force  # renaming cannot strand a switch; reversible by writing back
        if not _is_xml_api_dialect(self._spec):
            raise UnsupportedCapabilityError(
                f"model {self.model.key!r}: this backend does not expose a "
                "host-name write"
            )
        path = _require_path(
            self.model.key, self._spec.sysinfo_path, "the system-information page"
        )
        before = parse.parse_goahead_hostname(self.session.get_page(path))
        # DeviceBasicInfo is a SCALAR section, so the body carries the field
        # directly rather than a repeated <Entry>. The page's own JS rejects
        # '&' in this field client-side; the value is XML-escaped here, and the
        # switch's verdict is what the statusCode check reports.
        self._goahead_write(
            goahead.write_body("DeviceBasicInfo", "set", [{"deviceName": name}]),
            f"hostname -> {name!r}",
        )
        after = parse.parse_goahead_hostname(self.session.get_page(path))
        if after != name:
            raise WriteVerificationError(
                f"hostname did not read back as {name!r}", before=before, after=after
            )

    def set_port_speed(
        self, port: int, speed: PortSpeed, *, force: bool = False
    ) -> None:
        """Set a port's speed/duplex through the ports page's admin fields.

        XML-API only. That page's ``Standard802_3List`` carries
        ``autoNegotiationAdminEnabled``/``speedAdmin``/``duplexAdminMode``, the
        read side already parses them, and the exact encoding is transcribed
        from the page's own submit JS (see ``goahead.port_speed_body``). The
        FASTPATH XUI port pages have a Speed control too, but its cell id has
        not been captured, and guessing one would post into an unknown cell.

        A rate the page's own dropdown does not offer is refused by name.
        That list is device evidence, not a house rule: the ``slctPortSpeed``
        ``<option>`` set is 10/100 half-or-full, 1000 FULL ONLY, and Auto. Note
        this UI DOES offer a forced 1000 where the FASTPATH CLI does not --
        which is exactly why that refusal lives in ``CliWriter`` and not in
        ``PortSpeed``.

        Disruptive -- applying a speed bounces the link -- so it honours
        ``protected_ports``.
        """
        self._guard(port, force)
        if not _is_xml_api_dialect(self._spec):
            raise UnsupportedCapabilityError(
                f"model {self.model.key!r}: no HTTP speed/duplex write form has "
                "been captured for this web UI dialect"
            )
        if (
            not speed.autonegotiate
            and (speed.speed_mbps, speed.full_duplex)
            not in goahead.GOAHEAD_FORCED_SPEEDS
        ):
            raise UnsupportedCapabilityError(
                f"model {self.model.key!r}: this web UI offers no "
                f"{speed} choice (its Speed control lists 10/100 half or full, "
                "1000 full, and Auto)"
            )
        path = _require_path(
            self.model.key, self._spec.dashboard_path, "the ports page"
        )

        def configured(body: str) -> PortSpeed | None:
            rows = parse.parse_goahead_ports(body)
            return next((p.speed_config for p in rows if p.port == port), None)

        before = configured(self.session.get_page(path))
        self._goahead_write(
            goahead.port_speed_body(goahead.port_interface_name(port), port, speed),
            f"port {port} speed -> {speed}",
        )
        after = configured(self.session.get_page(path))
        if after != speed:
            raise WriteVerificationError(
                f"speed for port {port} did not read back as {speed}",
                before=before,
                after=after,
            )

    def set_syslog_enabled(self, enabled: bool, *, force: bool = False) -> None:
        """This backend does not serve a remote-logging toggle.

        Refused by name rather than returned empty: an empty answer here
        would be indistinguishable from a switch that genuinely has none.
        """
        raise UnsupportedCapabilityError(
            f"model {self.model.key!r}: this backend does not expose "
            "a remote-logging toggle"
        )


class AsyncHttpWriter:
    def __init__(
        self,
        session: AsyncHttpSession,
        model: SwitchModel,
        *,
        protected_ports: frozenset[int] = frozenset(),
    ) -> None:
        self._spec = http_spec(model)
        self.session = session
        self.model = model
        self.protected_ports = protected_ports

    def _guard(self, port: int, force: bool) -> None:
        if port in self.protected_ports and not force:
            raise ProtectedPortError(
                f"port {port} is protected on {self.model.key!r}; pass force=True"
            )

    async def _poe_admin(self, port: int) -> bool:
        path = _require_path(self.model.key, self._spec.poe_status_path, "PoE status")
        rows = _parse_poe(self._spec, await self.session.get_page(path))
        for r in rows:
            if r.port == port:
                return r.admin_enabled
        return False

    # --- GoAhead XML API: async twins of SnmpWriter's -- see the sync writer
    # for where every body shape comes from. They exist because the capability
    # table does not distinguish sync from async: an op the sync writer can do
    # and the async one cannot would be a claim this codebase cannot honour.

    async def _goahead_write(self, body: str, what: str) -> None:
        path = _require_path(
            self.model.key, self._spec.xml_write_path, "XML-API write endpoint"
        )
        _check_goahead_status(await self.session.post_xml(path, body), what)

    async def _poe_status(self, port: int) -> PoEStatus | None:
        path = _require_path(self.model.key, self._spec.poe_status_path, "PoE status")
        rows = _parse_poe(self._spec, await self.session.get_page(path))
        return next((r for r in rows if r.port == port), None)

    async def _goahead_poe_admin(self, port: int, on: bool) -> None:
        before = await self._poe_admin(port)
        await self._goahead_write(
            goahead.poe_admin_body(goahead.port_interface_name(port), on),
            f"PoE port {port} admin -> {on}",
        )
        after = await self._poe_admin(port)
        if after != on:
            raise WriteVerificationError(
                f"PoE port {port} did not read back as on={on}",
                before=before,
                after=after,
            )

    async def _goahead_poe_rearm(
        self,
        port: int,
        *,
        timeouts: PoeCycleTimeouts | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        from .snmp_write import PoeCycleTimeouts

        limits = timeouts or PoeCycleTimeouts()
        before = await self._poe_status(port)
        await self._goahead_poe_admin(port, on=False)
        await self._goahead_poe_admin(port, on=True)
        deadline = clock() + limits.on_timeout
        while not poe_cycle_complete(before, await self._poe_status(port)):
            if clock() >= deadline:
                raise WriteVerificationError(
                    f"PoE port {port} did not come back after the power cycle "
                    f"within {limits.on_timeout}s",
                    before=before,
                    after=await self._poe_status(port),
                )
            await sleep(limits.poll_interval)

    async def _goahead_membership(
        self,
    ) -> dict[int, tuple[frozenset[int], frozenset[int]]]:
        path = _require_path(
            self.model.key, self._spec.pvid_path, "port VLAN membership"
        )
        return parse.parse_goahead_port_vlan_membership(
            await self.session.get_page(path)
        )

    async def _goahead_mode_of(self, vlan: int, port: int) -> VlanMode:
        tagged, untagged = (await self._goahead_membership()).get(
            vlan, (frozenset(), frozenset())
        )
        if port in untagged:
            return VlanMode.UNTAGGED
        return VlanMode.TAGGED if port in tagged else VlanMode.EXCLUDED

    async def set_port_description(
        self, port: int, description: str, *, force: bool = False
    ) -> None:
        """Async twin of ``HttpWriter.set_port_description`` -- see it."""
        self._guard(port, force)
        if not _is_xml_api_dialect(self._spec):
            raise UnsupportedCapabilityError(
                f"model {self.model.key!r}: no HTTP port-description write is "
                "built for this web UI dialect"
            )
        path = _require_path(
            self.model.key, self._spec.dashboard_path, "the ports page"
        )

        def described(body: str) -> str | None:
            rows = parse.parse_goahead_ports(body)
            return next((p.description for p in rows if p.port == port), None)

        before = described(await self.session.get_page(path))
        await self._goahead_write(
            goahead.port_config_body(
                goahead.port_interface_name(port), port, description=description
            ),
            f"port {port} description",
        )
        after = described(await self.session.get_page(path))
        want = description or None
        if after != want:
            raise WriteVerificationError(
                f"description for port {port} did not read back as {want!r}",
                before=before,
                after=after,
            )

    async def _set_goahead_membership(
        self, vlan: int, port: int, mode: VlanMode
    ) -> None:
        before = await self._goahead_mode_of(vlan, port)
        await self._goahead_write(
            goahead.vlan_membership_body(vlan, goahead.port_interface_name(port), mode),
            f"VLAN {vlan} membership for port {port} -> {mode.value}",
        )
        after = await self._goahead_mode_of(vlan, port)
        if after is not mode:
            raise WriteVerificationError(
                f"VLAN {vlan} port {port} did not read back as {mode.value}",
                before=before,
                after=after,
            )

    async def _goahead_vlan_ids(self) -> set[int]:
        path = _require_path(self.model.key, self._spec.vlan_config_path, "VLAN config")
        return set(parse.parse_goahead_vlan_names(await self.session.get_page(path)))

    async def _set_goahead_port_enabled(
        self, path: str, port: int, enabled: bool
    ) -> None:
        def admin_of(body: str) -> bool | None:
            rows = parse.parse_goahead_ports(body)
            return next((p.admin_enabled for p in rows if p.port == port), None)

        before = admin_of(await self.session.get_page(path))
        await self._goahead_write(
            goahead.port_config_body(
                goahead.port_interface_name(port), port, admin_enabled=enabled
            ),
            f"port {port} admin -> {enabled}",
        )
        after = admin_of(await self.session.get_page(path))
        if after is not enabled:
            raise WriteVerificationError(
                f"port {port} did not read back as enabled={enabled}",
                before=before,
                after=after,
            )

    async def set_poe(self, port: int, on: bool, *, force: bool = False) -> None:
        if _is_xml_api_dialect(self._spec):
            self._guard(port, force)
            await self._goahead_poe_admin(port, on)
            return
        path = _require_path(
            self.model.key, self._spec.poe_config_path, "web PoE config"
        )
        self._guard(port, force)
        if _is_fastpath_dialect(self._spec):
            await self._xui_poe_admin(path, port, on)
            return
        before = await self._poe_admin(port)
        page = await self.session.get_page(path)
        form = forms.poe_apply_form(
            port=port, on=on, is_epx=self._spec.is_epx_poe, csrf_hash=_csrf(page)
        )
        await self.session.post_form(path, form)
        after = await self._poe_admin(port)
        if after != on:
            raise WriteVerificationError(
                f"PoE port {port} did not read back as on={on}",
                before=before,
                after=after,
            )

    async def _xui_poe_admin(self, path: str, port: int, on: bool) -> None:
        """Async twin of ``HttpWriter._xui_poe_admin`` (see its docs)."""
        page = parse.parse_xui_list_page(await self.session.get_page(path), page=path)
        row = _find_xui_row(page, port, _XUI_POE_IFNAME, f"{self.model.key!r} PoE")
        before = row.field(_XUI_POE_ADMIN)
        applied = await self.session.post_form(
            page.action,
            forms.xui_row_apply_form(
                page,
                row,
                {_XUI_POE_ADMIN: _xui_enabled(on)},
                button="v_2_1_2",
                omit=_XUI_POE_APPLY_OMITS,
            ),
        )
        _raise_on_fastpath_err_flag(applied, f"PoE port {port} admin -> {on}")
        after = await self._poe_admin(port)
        if after != on:
            raise WriteVerificationError(
                f"PoE port {port} did not read back as on={on} on {path}",
                before=before,
                after=after,
            )

    async def cycle_poe(
        self,
        port: int,
        *,
        force: bool = False,
        timeouts: PoeCycleTimeouts | None = None,
    ) -> None:
        if _is_xml_api_dialect(self._spec):
            self._guard(port, force)
            await self._goahead_poe_rearm(port, timeouts=timeouts)
            return
        del timeouts  # accepted-but-unused; uniform writer surface (see sync).
        path = _require_path(
            self.model.key, self._spec.poe_config_path, "web PoE config"
        )
        self._guard(port, force)
        if _is_fastpath_dialect(self._spec):
            await self._xui_poe_reset(path, port)
            return
        page = await self.session.get_page(path)
        await self.session.post_form(
            path, forms.poe_reset_form(port=port, csrf_hash=_csrf(page))
        )

    async def clear_poe_fault(
        self,
        port: int,
        *,
        force: bool = False,
        timeouts: PoeCycleTimeouts | None = None,
    ) -> None:
        """Async twin of ``HttpWriter.clear_poe_fault`` (see its docs)."""
        if _is_xml_api_dialect(self._spec):
            self._guard(port, force)
            await self._goahead_poe_rearm(port, timeouts=timeouts)
            return
        del timeouts  # accepted-but-unused; uniform writer surface (see sync).
        path = _require_path(
            self.model.key, self._spec.poe_config_path, "web PoE config"
        )
        self._guard(port, force)
        if _is_fastpath_dialect(self._spec):
            await self._xui_poe_reset(path, port)
            return
        page = await self.session.get_page(path)
        await self.session.post_form(
            path, forms.poe_reset_form(port=port, csrf_hash=_csrf(page))
        )

    async def _xui_poe_reset(self, path: str, port: int) -> None:
        """Async twin of ``HttpWriter._xui_poe_reset`` (see its docs)."""
        page = parse.parse_xui_list_page(await self.session.get_page(path), page=path)
        row = _find_xui_row(page, port, _XUI_POE_IFNAME, f"{self.model.key!r} PoE")
        applied = await self.session.post_form(
            page.action,
            forms.xui_row_apply_form(
                page,
                row,
                {_XUI_POE_RESET: _XUI_POE_RESET_VALUE},
                button=_poe_reset_button(page, self.model.key),
                omit=_XUI_POE_RESET_OMITS,
            ),
        )
        _raise_on_fastpath_err_flag(applied, f"PoE reset of port {port}")

    async def _require_vlan_exists(self, vlan: int) -> None:
        """Async twin of ``HttpWriter._require_vlan_exists`` (see its docs)."""
        if self._spec.vlan_config_path is None:
            return
        page = await self.session.get_page(self._spec.vlan_config_path)
        known = (
            set(parse.parse_goahead_vlan_names(page))
            if _is_xml_api_dialect(self._spec)
            else set(parse.parse_vlan_ids(page))
        )
        if vlan not in known:
            raise HttpUnexpectedPageError(
                f"VLAN {vlan} does not exist (known: {sorted(known)})"
            )

    async def set_pvid(self, port: int, vlan: int, *, force: bool = False) -> None:
        self._guard(port, force)
        path = _require_path(self.model.key, self._spec.pvid_path, "port PVIDs")
        await self._require_vlan_exists(vlan)
        if _is_xml_api_dialect(self._spec):
            before = dict(parse.parse_goahead_pvids(await self.session.get_page(path)))
            await self._goahead_write(
                goahead.pvid_body(goahead.port_interface_name(port), vlan),
                f"PVID for port {port} -> {vlan}",
            )
            now = dict(parse.parse_goahead_pvids(await self.session.get_page(path)))
            if now.get(port) != vlan:
                raise WriteVerificationError(
                    f"PVID for port {port} did not read back as {vlan}",
                    before=before.get(port),
                    after=now.get(port),
                )
            return
        page = await self.session.get_page(path)
        await self.session.post_form(
            path, forms.pvid_form(port=port, vlan=vlan, csrf_hash=_csrf(page))
        )
        after = dict(parse.parse_pvids(await self.session.get_page(path)))
        if after.get(port) != vlan:
            raise WriteVerificationError(
                f"PVID for port {port} did not read back as {vlan}",
                before=None,
                after=after.get(port),
            )

    async def set_vlan_membership(
        self, vlan: int, port: int, mode: VlanMode, *, force: bool = False
    ) -> None:
        self._guard(port, force)
        if _is_fastpath_dialect(self._spec):
            await self._set_fastpath_membership(vlan, port, mode)
            return
        if _is_xml_api_dialect(self._spec):
            await self._set_goahead_membership(vlan, port, mode)
            return
        path = _require_path(
            self.model.key, self._spec.vlan_membership_path, "VLAN membership"
        )
        html = await self.session.post_form(path, {"VLAN_ID": str(vlan)})
        states = parse.parse_membership(html, self.model.port_count)
        states[port] = mode
        hidden = forms.membership_hidden_mem(states, self.model.port_count)
        await self.session.post_form(
            path,
            forms.membership_form(vlan=vlan, hidden_mem=hidden, csrf_hash=_csrf(html)),
        )
        verify = await self.session.post_form(path, {"VLAN_ID": str(vlan)})
        after = parse.parse_membership(verify, self.model.port_count)
        if after.get(port) is not mode:
            raise WriteVerificationError(
                f"VLAN {vlan} port {port} did not read back as {mode.value}",
                before=states.get(port),
                after=after.get(port),
            )

    async def _set_fastpath_membership(
        self, vlan: int, port: int, mode: VlanMode
    ) -> None:
        """Async twin of ``HttpWriter._set_fastpath_membership`` -- same wire flow
        and the same configured-view verification (see its docstring)."""
        get_path, post_path = fastpath_membership_paths(self._spec, self.model.key)
        before = await self._read_fastpath_membership(vlan, get_path, post_path)
        hidden = parse.fastpath_hidden_mem_with(before, port, mode)
        applied = await self.session.post_form(
            post_path,
            forms.fastpath_membership_form(
                before, vlan=vlan, hidden_mem=hidden, apply=True
            ),
        )
        _raise_on_fastpath_err_flag(applied, f"VLAN {vlan} port {port} -> {mode.value}")
        after = await self._read_fastpath_membership(vlan, get_path, post_path)
        if after.configured.get(port) is not mode:
            raise WriteVerificationError(
                f"VLAN {vlan} port {port} did not read back as {mode.value} on "
                f"{post_path} (hiddenMem slot {before.port_slots.get(port)})",
                before=before.configured.get(port),
                after=after.configured.get(port),
            )

    async def _read_fastpath_membership(
        self, vlan: int, get_path: str, post_path: str
    ) -> FastpathMembership:
        page = parse.parse_fastpath_membership(await self.session.get_page(get_path))
        if page.vlan_id == vlan:
            return page
        body = forms.fastpath_membership_form(page, vlan=vlan)
        shown = parse.parse_fastpath_membership(
            await self.session.post_form(post_path, body)
        )
        _require_fastpath_membership_for(shown, vlan, post_path)
        return shown

    async def create_vlan(self, vlan: int, name: str, *, force: bool = False) -> None:
        if _is_xml_api_dialect(self._spec):
            del force
            before = await self._goahead_vlan_ids()
            await self._goahead_write(
                goahead.vlan_create_body(vlan, name), f"create VLAN {vlan}"
            )
            after_ids = await self._goahead_vlan_ids()
            if vlan not in after_ids:
                raise WriteVerificationError(
                    f"VLAN {vlan} was not created",
                    before=sorted(before),
                    after=sorted(after_ids),
                )
            return
        _require_csrf_dialect(self._spec, self.model.key, "create_vlan")
        del name, force
        path = _require_path(self.model.key, self._spec.vlan_config_path, "VLAN config")
        page = await self.session.get_page(path)
        await self.session.post_form(
            path, forms.vlan_add_form(vlan=vlan, csrf_hash=_csrf(page))
        )
        after = parse.parse_vlan_ids(await self.session.get_page(path))
        if vlan not in after:
            raise WriteVerificationError(
                f"VLAN {vlan} was not created", before=None, after=after
            )

    async def delete_vlan(self, vlan: int, *, force: bool = False) -> None:
        if _is_xml_api_dialect(self._spec):
            del force
            before = await self._goahead_vlan_ids()
            await self._goahead_write(
                goahead.vlan_delete_body(vlan), f"delete VLAN {vlan}"
            )
            after_ids = await self._goahead_vlan_ids()
            if vlan in after_ids:
                raise WriteVerificationError(
                    f"VLAN {vlan} was not deleted",
                    before=sorted(before),
                    after=sorted(after_ids),
                )
            return
        _require_csrf_dialect(self._spec, self.model.key, "delete_vlan")
        del force
        path = _require_path(self.model.key, self._spec.vlan_config_path, "VLAN config")
        page = await self.session.get_page(path)
        idx = _vlan_checkbox_index(page, vlan)
        if idx is None:
            raise HttpUnexpectedPageError(f"VLAN {vlan} not present to delete")
        await self.session.post_form(
            path,
            forms.vlan_delete_form(
                vlan=vlan, checkbox_index=idx, csrf_hash=_csrf(page)
            ),
        )
        after = parse.parse_vlan_ids(await self.session.get_page(path))
        if vlan in after:
            raise WriteVerificationError(
                f"VLAN {vlan} was not deleted", before=None, after=after
            )

    async def reboot(self, *, force: bool = False) -> None:
        # Capability check BEFORE the force gate (see sync reboot).
        reboot_path = _require_path(
            self.model.key, self._spec.reboot_path, "web reboot"
        )
        if not force:
            raise ProtectedPortError("reboot is disruptive; pass force=True")
        landing = self._spec.vlan_config_path or self._spec.dashboard_path
        page = await self.session.get_page(
            _require_path(self.model.key, landing, "web reboot")
        )
        await self.session.post_form(
            reboot_path, forms.reboot_form(csrf_hash=_csrf(page))
        )

    async def set_port_enabled(
        self, port: int, enabled: bool, *, force: bool = False
    ) -> None:
        """Async twin of ``HttpWriter.set_port_enabled`` (see its docs)."""
        self._guard(port, force)
        if _is_xml_api_dialect(self._spec):
            await self._set_goahead_port_enabled(
                _require_path(
                    self.model.key, self._spec.dashboard_path, "the ports page"
                ),
                port,
                enabled,
            )
            return
        path = _require_path(
            self.model.key, self._spec.port_config_path, "the port-configuration page"
        )
        page = parse.parse_xui_list_page(await self.session.get_page(path), page=path)
        row = _find_xui_row(
            page, port, _XUI_PORT_IFNAME, f"{self.model.key!r} port configuration"
        )
        before = row.field(_XUI_PORT_ADMIN)
        applied = await self.session.post_form(
            page.action,
            forms.xui_row_apply_form(
                page,
                row,
                {_XUI_PORT_ADMIN: _xui_enabled(enabled)},
                button="v_2_1_2",
            ),
        )
        _raise_on_fastpath_err_flag(applied, f"port {port} admin mode -> {enabled}")
        after = _find_xui_row(
            parse.parse_xui_list_page(await self.session.get_page(path), page=path),
            port,
            _XUI_PORT_IFNAME,
            f"{self.model.key!r} port configuration",
        ).field(_XUI_PORT_ADMIN)
        if after != _xui_enabled(enabled):
            raise WriteVerificationError(
                f"port {port} admin mode did not read back as "
                f"{_xui_enabled(enabled)!r} on {path}",
                before=before,
                after=after,
            )

    async def set_mgmt_ip(
        self, address: str, netmask: str, gateway: str, *, force: bool = False
    ) -> None:
        """Async twin of ``HttpWriter.set_mgmt_ip`` -- INCLUDING its honesty
        caveat: the apply is unverified against live hardware, because verifying
        it would have moved a real switch's management address. See the sync
        twin's docstring for exactly what is and is not proven."""
        path, fields = _require_xui_mgmt_fields(self._spec)
        if not force:
            raise ProtectedPortError(
                "set_mgmt_ip moves the address this session is using and can "
                "leave the switch unreachable; pass force=True"
            )
        page = parse.parse_xui_form_page(await self.session.get_page(path), page=path)
        applied = await self.session.post_form(
            page.action,
            forms.xui_form_apply_form(
                page,
                _mgmt_ip_changes(fields, address, netmask, gateway),
                button=fields.apply_button,
            ),
        )
        _raise_on_fastpath_err_flag(applied, f"management IP -> {address}/{netmask}")
        after = parse.parse_xui_form_page(await self.session.get_page(path), page=path)
        got = (
            after.fields.get(fields.address),
            after.fields.get(fields.netmask),
            after.fields.get(fields.gateway),
        )
        if got != (address, netmask, gateway):
            raise WriteVerificationError(
                f"management IP did not read back as {address}/{netmask} via "
                f"{gateway} on {path}",
                before=(
                    page.fields.get(fields.address),
                    page.fields.get(fields.netmask),
                    page.fields.get(fields.gateway),
                ),
                after=got,
            )

    async def upload_certificate(
        self, cert_pem: str, key_pem: str, *, force: bool = False
    ) -> None:
        # Async twin of HttpWriter.upload_certificate -- same capability-before-
        # force ordering and same grounded wire shape (shared pure helpers).
        _reject_known_unimplemented_cert_upload(self.model.key)
        if self._spec.html_dialect is HtmlDialect.GOAHEAD_XML:
            path, body = _cert_upload_xml(self._spec, cert_pem, key_pem)
            if not force:
                raise ProtectedPortError(
                    "SSL-certificate upload replaces the switch's running "
                    "certificate and is disruptive; pass force=True"
                )
            _check_goahead_upload_response(await self.session.post_xml(path, body))
            return
        path, fields, payload = _cert_upload_multipart(self._spec, cert_pem, key_pem)
        if not force:
            raise ProtectedPortError(
                "SSL-certificate upload replaces the switch's running "
                "certificate and is disruptive; pass force=True"
            )
        _check_multipart_cert_response(
            await self.session.post_multipart(path, fields, payload)
        )

    async def set_hostname(self, name: str, *, force: bool = False) -> None:
        """This backend does not serve a host-name write.

        Refused by name rather than returned empty: an empty answer here
        would be indistinguishable from a switch that genuinely has none.
        """
        raise UnsupportedCapabilityError(
            f"model {self.model.key!r}: this backend does not expose a host-name write"
        )

    async def set_port_speed(
        self, port: int, speed: PortSpeed, *, force: bool = False
    ) -> None:
        """Async twin of ``HttpWriter.set_port_speed`` -- see it."""
        self._guard(port, force)
        if not _is_xml_api_dialect(self._spec):
            raise UnsupportedCapabilityError(
                f"model {self.model.key!r}: no HTTP speed/duplex write form has "
                "been captured for this web UI dialect"
            )
        if (
            not speed.autonegotiate
            and (speed.speed_mbps, speed.full_duplex)
            not in goahead.GOAHEAD_FORCED_SPEEDS
        ):
            raise UnsupportedCapabilityError(
                f"model {self.model.key!r}: this web UI offers no "
                f"{speed} choice (its Speed control lists 10/100 half or full, "
                "1000 full, and Auto)"
            )
        path = _require_path(
            self.model.key, self._spec.dashboard_path, "the ports page"
        )

        def configured(body: str) -> PortSpeed | None:
            rows = parse.parse_goahead_ports(body)
            return next((p.speed_config for p in rows if p.port == port), None)

        before = configured(await self.session.get_page(path))
        await self._goahead_write(
            goahead.port_speed_body(goahead.port_interface_name(port), port, speed),
            f"port {port} speed -> {speed}",
        )
        after = configured(await self.session.get_page(path))
        if after != speed:
            raise WriteVerificationError(
                f"speed for port {port} did not read back as {speed}",
                before=before,
                after=after,
            )

    async def set_syslog_enabled(self, enabled: bool, *, force: bool = False) -> None:
        """This backend does not serve a remote-logging toggle.

        Refused by name rather than returned empty: an empty answer here
        would be indistinguishable from a switch that genuinely has none.
        """
        raise UnsupportedCapabilityError(
            f"model {self.model.key!r}: this backend does not expose "
            "a remote-logging toggle"
        )
