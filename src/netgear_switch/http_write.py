"""Model-driven web-UI write operations with verify-after-write + guards.

Parallel to ``snmp_write.py``. Every mutating op: (1) enforces
``protected_ports`` on disruptive ports unless ``force=True``; (2) GETs the
target page to scrape the fresh CSRF ``hash``; (3) POSTs the encoded form;
(4) re-GETs and re-parses to confirm the change actually took — raising
``WriteVerificationError(before, after)`` on divergence, NEVER silently
succeeding. Web-UI-impossible/UNVERIFIED writes (port enable, mgmt-IP) raise
``UnsupportedCapabilityError`` honestly.
"""

from __future__ import annotations

import re
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
from .protocols.http import forms, parse
from .protocols.http.endpoints import HtmlDialect, http_spec
from .protocols.http.session import MultipartFile

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .models import VlanMode
    from .protocols.http.endpoints import HttpModelSpec
    from .protocols.http.session import AsyncHttpSession, HttpSession
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


def _csrf(html: str) -> str:
    token = parse.parse_csrf_hash(html)
    if token is None:
        raise HttpUnexpectedPageError("no CSRF 'hash' token on page before write")
    return token


def _require_path(model_key: str, path: str | None, op: str) -> str:
    """Return ``path`` or raise honestly if this model's spec has none for ``op``."""
    if path is None:
        raise UnsupportedCapabilityError(
            f"model {model_key!r} web UI does not expose {op}"
        )
    return path


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

    def set_poe(self, port: int, on: bool, *, force: bool = False) -> None:
        path = _require_path(
            self.model.key, self._spec.poe_config_path, "web PoE config"
        )
        self._guard(port, force)
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

    def cycle_poe(
        self,
        port: int,
        *,
        force: bool = False,
        timeouts: PoeCycleTimeouts | None = None,
    ) -> None:
        # timeouts accepted-but-unused: matches SnmpWriter/NsdpWriter so the
        # facade's SnmpWriter | NsdpWriter | HttpWriter union call site typechecks.
        del timeouts
        path = _require_path(
            self.model.key, self._spec.poe_config_path, "web PoE config"
        )
        self._guard(port, force)
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
        # Present so the facade's writer union has a uniform surface; the Plus
        # web UI has no grounded clear-PoE-fault endpoint (a fault clears on the
        # next PoEPortConfig apply/reset), so this is honestly unsupported.
        del port, force, timeouts
        raise UnsupportedCapabilityError(
            f"{self.model.key!r} web clear-PoE-fault is UNVERIFIED-pending-capture"
        )

    def set_pvid(self, port: int, vlan: int, *, force: bool = False) -> None:
        self._guard(port, force)
        path = _require_path(self.model.key, self._spec.pvid_path, "port PVIDs")
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

    def create_vlan(self, vlan: int, name: str, *, force: bool = False) -> None:
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
        del port, enabled, force
        raise UnsupportedCapabilityError(
            f"{self.model.key!r} web port-enable endpoint is UNVERIFIED-pending-capture"
        )

    def set_mgmt_ip(
        self, address: str, netmask: str, gateway: str, *, force: bool = False
    ) -> None:
        del address, netmask, gateway, force
        raise UnsupportedCapabilityError(
            f"{self.model.key!r} web mgmt-IP endpoint is UNVERIFIED-pending-capture"
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
        self.session.post_multipart(path, fields, payload)

    def _poe_admin(self, port: int) -> bool:
        path = _require_path(self.model.key, self._spec.poe_status_path, "PoE status")
        rows = parse.parse_poe_status(self.session.get_page(path))
        for r in rows:
            if r.port == port:
                return r.admin_enabled
        return False


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
        rows = parse.parse_poe_status(await self.session.get_page(path))
        for r in rows:
            if r.port == port:
                return r.admin_enabled
        return False

    async def set_poe(self, port: int, on: bool, *, force: bool = False) -> None:
        path = _require_path(
            self.model.key, self._spec.poe_config_path, "web PoE config"
        )
        self._guard(port, force)
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

    async def cycle_poe(
        self,
        port: int,
        *,
        force: bool = False,
        timeouts: PoeCycleTimeouts | None = None,
    ) -> None:
        del timeouts  # accepted-but-unused; uniform writer surface (see sync).
        path = _require_path(
            self.model.key, self._spec.poe_config_path, "web PoE config"
        )
        self._guard(port, force)
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
        del port, force, timeouts
        raise UnsupportedCapabilityError(
            f"{self.model.key!r} web clear-PoE-fault is UNVERIFIED-pending-capture"
        )

    async def set_pvid(self, port: int, vlan: int, *, force: bool = False) -> None:
        self._guard(port, force)
        path = _require_path(self.model.key, self._spec.pvid_path, "port PVIDs")
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

    async def create_vlan(self, vlan: int, name: str, *, force: bool = False) -> None:
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
        # Task 9 fix: was a plain (non-async) `def` -- inconsistent with every
        # other AsyncHttpWriter method and unsound under a facade call site
        # typed `Callable[[...], Awaitable[None]]` (mypy --strict caught the
        # union-type mismatch once the facade's generic per-op dispatcher
        # actually called it). Same immediate-refusal behaviour, now reachable
        # via `await` like its siblings.
        del port, enabled, force
        raise UnsupportedCapabilityError(
            f"{self.model.key!r} web port-enable endpoint is UNVERIFIED-pending-capture"
        )

    async def set_mgmt_ip(
        self, address: str, netmask: str, gateway: str, *, force: bool = False
    ) -> None:
        # Task 9 fix: see set_port_enabled above.
        del address, netmask, gateway, force
        raise UnsupportedCapabilityError(
            f"{self.model.key!r} web mgmt-IP endpoint is UNVERIFIED-pending-capture"
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
        await self.session.post_multipart(path, fields, payload)
