from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from netgear_switch.errors import (
    HttpError,
    ProtectedPortError,
    UnsupportedCapabilityError,
    WriteVerificationError,
)
from netgear_switch.http_write import AsyncHttpWriter, HttpWriter
from netgear_switch.models import VlanMode
from netgear_switch.registry import get_model

if TYPE_CHECKING:
    from netgear_switch.protocols.http.session import MultipartFile

_PORT_COUNT = 5  # gs305ep port_count
_WIRE_TO_MODE = {"1": VlanMode.UNTAGGED, "2": VlanMode.TAGGED, "3": VlanMode.EXCLUDED}
_MODE_TO_WIRE = {v: k for k, v in _WIRE_TO_MODE.items()}


def _run(coro):
    """Drive a coroutine to completion (no pytest-asyncio plugin configured)."""
    return asyncio.run(coro)


class _FakeGs305epState:
    """Shared PoE/PVID/VLAN state + page rendering behind the stateful fake
    sessions below (sync and async): records every POSTed field set and
    mutates its returned pages so a verify-after-write read reflects the
    write -- or, when ``honour_writes`` is False, deliberately does NOT
    reflect it, so the writer's verify step must raise.
    """

    def __init__(self, *, honour_writes: bool = True) -> None:
        self.poe_on = {1: True, 2: False, 3: False, 4: False}
        self.pvids = dict.fromkeys(range(1, _PORT_COUNT + 1), 1)
        self.vlan_members: dict[int, dict[int, VlanMode]] = {
            1: dict.fromkeys(range(1, _PORT_COUNT + 1), VlanMode.UNTAGGED)
        }
        self.vlan_ids: set[int] = {1}
        self.honour_writes = honour_writes
        self.posts: list[tuple[str, dict[str, str]]] = []

    def _render_get(self, path: str) -> str:
        if path == "/getPoePortStatus.cgi":
            rows = "".join(
                f'<tr class="portID"><td>{p}</td><td>'
                f"{'Delivering' if on else 'Disabled'}</td><td>0</td></tr>"
                for p, on in self.poe_on.items()
            )
            return f"<table>{rows}</table>"
        if path == "/portPVID.cgi":
            rows = "".join(
                f'<tr class="portID"><td>{p}</td>'
                f'<td sel="text">{p}</td><td sel="input">{v}</td></tr>'
                for p, v in self.pvids.items()
            )
            return f'<input name="hash" value="h"><table>{rows}</table>'
        if path == "/8021qCf.cgi":
            checks = "".join(
                f'<input name="vlanck{i}" value="{vid}">'
                for i, vid in enumerate(sorted(self.vlan_ids), start=1)
            )
            return f'<input name="hash" value="h">{checks}'
        return '<input name="hash" value="h">'

    def _render_post(self, path: str, data: dict[str, str]) -> str:
        self.posts.append((path, dict(data)))
        if path == "/PoEPortConfig.cgi":
            if data.get("ACTION") == "Apply" and self.honour_writes:
                port = int(data["portID"]) + 1
                self.poe_on[port] = data["ADMIN_MODE"] == "1"
            return "OK"
        if path == "/portPVID.cgi":
            if self.honour_writes:
                for key, val in data.items():
                    if key.startswith("port") and val == "checked":
                        port = int(key.removeprefix("port")) + 1
                        self.pvids[port] = int(data["pvid"])
            return "OK"
        if path == "/8021qMembe.cgi":
            vlan = int(data["VLAN_ID"])
            if "hiddenMem" in data:
                if self.honour_writes:
                    self.vlan_members[vlan] = {
                        i + 1: _WIRE_TO_MODE[ch]
                        for i, ch in enumerate(data["hiddenMem"][:_PORT_COUNT])
                    }
                return "OK"
            current = self.vlan_members.get(
                vlan, dict.fromkeys(range(1, _PORT_COUNT + 1), VlanMode.EXCLUDED)
            )
            hidden = "".join(
                _MODE_TO_WIRE[current.get(p, VlanMode.EXCLUDED)]
                for p in range(1, _PORT_COUNT + 1)
            )
            return (
                f'<input name="hash" value="h"><input id="hiddenMem" value="{hidden}">'
            )
        if path == "/8021qCf.cgi":
            if self.honour_writes:
                if data.get("ACTION") == "Add":
                    self.vlan_ids.add(int(data["ADD_VLANID"]))
                elif data.get("ACTION") == "Delete":
                    for key, val in data.items():
                        if key.startswith("vlanck"):
                            self.vlan_ids.discard(int(val))
            return "OK"
        return "OK"


class _StatefulSession(_FakeGs305epState):
    """Minimal stateful gs305ep session: PoE/PVID/VLAN state, drives verify."""

    def login(self) -> None:
        return None

    def get_page(self, path: str) -> str:
        return self._render_get(path)

    def post_form(self, path: str, data: dict[str, str]) -> str:
        return self._render_post(path, data)


class _AsyncStatefulSession(_FakeGs305epState):
    """Async mirror of ``_StatefulSession`` over the identical shared state,
    so sync and async writers are exercised against the same recorded
    behaviour and can never drift apart."""

    async def login(self) -> None:
        return None

    async def get_page(self, path: str) -> str:
        return self._render_get(path)

    async def post_form(self, path: str, data: dict[str, str]) -> str:
        return self._render_post(path, data)


# ---------------------------------------------------------------------------
# Sync PoE / mgmt-IP tests
# ---------------------------------------------------------------------------


def test_set_poe_verifies() -> None:
    sess = _StatefulSession()
    writer = HttpWriter(sess, get_model("gs305ep"))
    writer.set_poe(2, True)
    assert sess.poe_on[2] is True


def test_set_poe_write_not_reflected_raises_verification() -> None:
    sess = _StatefulSession(honour_writes=False)
    writer = HttpWriter(sess, get_model("gs305ep"))
    with pytest.raises(WriteVerificationError):
        writer.set_poe(2, True)


def test_protected_port_blocks_without_force() -> None:
    sess = _StatefulSession()
    writer = HttpWriter(sess, get_model("gs305ep"), protected_ports=frozenset({2}))
    with pytest.raises(ProtectedPortError):
        writer.set_poe(2, False)
    # force overrides.
    writer.set_poe(2, False, force=True)
    assert sess.poe_on[2] is False


def test_mgmt_ip_write_unsupported() -> None:
    writer = HttpWriter(_StatefulSession(), get_model("gs305ep"))
    with pytest.raises(UnsupportedCapabilityError):
        writer.set_mgmt_ip("10.0.0.2", "255.255.255.0", "10.0.0.1")


# ---------------------------------------------------------------------------
# Sync: PVID / VLAN membership / VLAN create-delete / PoE cycle & fault /
# reboot / port-enable.
# ---------------------------------------------------------------------------


def test_set_pvid_verifies() -> None:
    sess = _StatefulSession()
    writer = HttpWriter(sess, get_model("gs305ep"))
    writer.set_pvid(3, 20)
    assert sess.pvids[3] == 20
    assert sess.posts[-1] == (
        "/portPVID.cgi",
        {"port2": "checked", "pvid": "20", "hash": "h"},
    )


def test_set_pvid_write_not_reflected_raises_verification() -> None:
    sess = _StatefulSession(honour_writes=False)
    writer = HttpWriter(sess, get_model("gs305ep"))
    with pytest.raises(WriteVerificationError):
        writer.set_pvid(3, 20)


def test_set_vlan_membership_verifies() -> None:
    sess = _StatefulSession()
    writer = HttpWriter(sess, get_model("gs305ep"))
    writer.set_vlan_membership(1, 3, VlanMode.EXCLUDED)
    assert sess.vlan_members[1][3] is VlanMode.EXCLUDED
    apply_posts = [p for p in sess.posts if "hiddenMem" in p[1]]
    assert apply_posts[-1] == (
        "/8021qMembe.cgi",
        {"VLAN_ID": "1", "hiddenMem": "11311", "hash": "h"},
    )


def test_set_vlan_membership_write_not_reflected_raises_verification() -> None:
    sess = _StatefulSession(honour_writes=False)
    writer = HttpWriter(sess, get_model("gs305ep"))
    with pytest.raises(WriteVerificationError):
        writer.set_vlan_membership(1, 3, VlanMode.EXCLUDED)


def test_create_vlan_verifies() -> None:
    sess = _StatefulSession()
    writer = HttpWriter(sess, get_model("gs305ep"))
    writer.create_vlan(10, "irrelevant")
    assert 10 in sess.vlan_ids
    assert sess.posts[-1] == (
        "/8021qCf.cgi",
        {"ACTION": "Add", "ADD_VLANID": "10", "status": "Enable", "hash": "h"},
    )


def test_create_vlan_not_created_raises_verification() -> None:
    sess = _StatefulSession(honour_writes=False)
    writer = HttpWriter(sess, get_model("gs305ep"))
    with pytest.raises(WriteVerificationError):
        writer.create_vlan(10, "irrelevant")


def test_delete_vlan_verifies() -> None:
    sess = _StatefulSession()
    sess.vlan_ids.add(10)
    writer = HttpWriter(sess, get_model("gs305ep"))
    writer.delete_vlan(10)
    assert 10 not in sess.vlan_ids
    assert sess.posts[-1] == (
        "/8021qCf.cgi",
        {"ACTION": "Delete", "vlanck2": "10", "status": "Enable", "hash": "h"},
    )


def test_delete_vlan_not_removed_raises_verification() -> None:
    sess = _StatefulSession(honour_writes=False)
    sess.vlan_ids.add(10)
    writer = HttpWriter(sess, get_model("gs305ep"))
    with pytest.raises(WriteVerificationError):
        writer.delete_vlan(10)


def test_clear_poe_fault_posts_the_plus_reset_form() -> None:
    """A Plus switch has no separate clear-fault action: re-running detection
    IS the clear, which on this UI is PoEPortConfig.cgi's Reset -- exactly what
    ``cycle_poe`` posts. (This used to raise UnsupportedCapabilityError even
    though the mechanism was known and already implemented next door.)"""
    sess = _StatefulSession()
    writer = HttpWriter(sess, get_model("gs305ep"))
    writer.clear_poe_fault(2)
    assert sess.posts[-1] == (
        "/PoEPortConfig.cgi",
        {"ACTION": "Reset", "port1": "checked", "hash": "h"},
    )


def test_cycle_poe_posts_reset_form() -> None:
    sess = _StatefulSession()
    writer = HttpWriter(sess, get_model("gs305ep"))
    writer.cycle_poe(2)
    assert sess.posts[-1] == (
        "/PoEPortConfig.cgi",
        {"ACTION": "Reset", "port1": "checked", "hash": "h"},
    )
    # cycle_poe is POST-only/no verify BY DESIGN: admin state must be untouched.
    assert sess.poe_on[2] is False


def test_cycle_poe_respects_protected_port() -> None:
    sess = _StatefulSession()
    writer = HttpWriter(sess, get_model("gs305ep"), protected_ports=frozenset({2}))
    with pytest.raises(ProtectedPortError):
        writer.cycle_poe(2)


def test_reboot_requires_force() -> None:
    writer = HttpWriter(_StatefulSession(), get_model("gs305ep"))
    with pytest.raises(ProtectedPortError):
        writer.reboot()


def test_reboot_posts_form_with_force() -> None:
    sess = _StatefulSession()
    writer = HttpWriter(sess, get_model("gs305ep"))
    writer.reboot(force=True)
    assert sess.posts[-1] == ("/device_reboot.cgi", {"hash": "h"})


def test_set_port_enabled_is_unsupported() -> None:
    writer = HttpWriter(_StatefulSession(), get_model("gs305ep"))
    with pytest.raises(UnsupportedCapabilityError):
        writer.set_port_enabled(2, True)


# ---------------------------------------------------------------------------
# Async parity: AsyncHttpWriter had ZERO direct tests before this file.
# ---------------------------------------------------------------------------


def test_async_set_poe_verifies() -> None:
    sess = _AsyncStatefulSession()
    writer = AsyncHttpWriter(sess, get_model("gs305ep"))
    _run(writer.set_poe(2, True))
    assert sess.poe_on[2] is True


def test_async_set_poe_write_not_reflected_raises_verification() -> None:
    sess = _AsyncStatefulSession(honour_writes=False)
    writer = AsyncHttpWriter(sess, get_model("gs305ep"))
    with pytest.raises(WriteVerificationError):
        _run(writer.set_poe(2, True))


def test_async_protected_port_blocks_without_force() -> None:
    sess = _AsyncStatefulSession()
    writer = AsyncHttpWriter(sess, get_model("gs305ep"), protected_ports=frozenset({2}))
    with pytest.raises(ProtectedPortError):
        _run(writer.set_poe(2, False))
    _run(writer.set_poe(2, False, force=True))
    assert sess.poe_on[2] is False


def test_async_set_pvid_verifies() -> None:
    sess = _AsyncStatefulSession()
    writer = AsyncHttpWriter(sess, get_model("gs305ep"))
    _run(writer.set_pvid(3, 20))
    assert sess.pvids[3] == 20
    assert sess.posts[-1] == (
        "/portPVID.cgi",
        {"port2": "checked", "pvid": "20", "hash": "h"},
    )


def test_async_set_pvid_write_not_reflected_raises_verification() -> None:
    sess = _AsyncStatefulSession(honour_writes=False)
    writer = AsyncHttpWriter(sess, get_model("gs305ep"))
    with pytest.raises(WriteVerificationError):
        _run(writer.set_pvid(3, 20))


def test_async_set_vlan_membership_verifies() -> None:
    sess = _AsyncStatefulSession()
    writer = AsyncHttpWriter(sess, get_model("gs305ep"))
    _run(writer.set_vlan_membership(1, 3, VlanMode.EXCLUDED))
    assert sess.vlan_members[1][3] is VlanMode.EXCLUDED


def test_async_create_vlan_verifies() -> None:
    sess = _AsyncStatefulSession()
    writer = AsyncHttpWriter(sess, get_model("gs305ep"))
    _run(writer.create_vlan(10, "irrelevant"))
    assert 10 in sess.vlan_ids


def test_async_delete_vlan_verifies() -> None:
    sess = _AsyncStatefulSession()
    sess.vlan_ids.add(10)
    writer = AsyncHttpWriter(sess, get_model("gs305ep"))
    _run(writer.delete_vlan(10))
    assert 10 not in sess.vlan_ids


def test_async_clear_poe_fault_posts_the_plus_reset_form() -> None:
    sess = _AsyncStatefulSession()
    writer = AsyncHttpWriter(sess, get_model("gs305ep"))
    _run(writer.clear_poe_fault(2))
    assert sess.posts[-1] == (
        "/PoEPortConfig.cgi",
        {"ACTION": "Reset", "port1": "checked", "hash": "h"},
    )


def test_async_cycle_poe_posts_reset_form() -> None:
    sess = _AsyncStatefulSession()
    writer = AsyncHttpWriter(sess, get_model("gs305ep"))
    _run(writer.cycle_poe(2))
    assert sess.posts[-1] == (
        "/PoEPortConfig.cgi",
        {"ACTION": "Reset", "port1": "checked", "hash": "h"},
    )


def test_async_reboot_requires_force() -> None:
    writer = AsyncHttpWriter(_AsyncStatefulSession(), get_model("gs305ep"))
    with pytest.raises(ProtectedPortError):
        _run(writer.reboot())


def test_async_reboot_posts_form_with_force() -> None:
    sess = _AsyncStatefulSession()
    writer = AsyncHttpWriter(sess, get_model("gs305ep"))
    _run(writer.reboot(force=True))
    assert sess.posts[-1] == ("/device_reboot.cgi", {"hash": "h"})


def test_async_set_port_enabled_is_unsupported() -> None:
    writer = AsyncHttpWriter(_AsyncStatefulSession(), get_model("gs305ep"))
    with pytest.raises(UnsupportedCapabilityError):
        _run(writer.set_port_enabled(2, True))


def test_async_set_mgmt_ip_is_unsupported() -> None:
    writer = AsyncHttpWriter(_AsyncStatefulSession(), get_model("gs305ep"))
    with pytest.raises(UnsupportedCapabilityError):
        _run(writer.set_mgmt_ip("10.0.0.2", "255.255.255.0", "10.0.0.1"))


# ---------------------------------------------------------------------------
# SSL-certificate upload (gsm7228ps / S3300, grounded in
# certbot-hook-netgear-switches/netgear-updater.py::S3300Updater).
# ---------------------------------------------------------------------------

_CERT_PEM = "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----\n"
_KEY_PEM = "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n"
# The exact fixed form fields the S3300 cert-upload page submits (prior art
# lines ~655-678). The file field carries the combined cert+key PEM.
_EXPECTED_CERT_FORM = {
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


class _CertSpySession:
    """Records the single multipart POST the cert-upload writer drives."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, str], MultipartFile]] = []

    def login(self) -> None:
        return None

    def get_page(self, path: str) -> str:
        raise AssertionError(f"cert upload should not GET {path}")

    def post_form(self, path: str, data: dict[str, str]) -> str:
        raise AssertionError(f"cert upload should not post_form {path}")

    def post_multipart(
        self, path: str, data: dict[str, str], file: MultipartFile
    ) -> str:
        self.calls.append((path, dict(data), file))
        # Real S3300 success marker (upload_certificate now verifies it).
        return (
            "<html><body>SSL PEM Server Certificate file download through HTTP "
            "is completed successfully.</body></html>"
        )


class _AsyncCertSpySession(_CertSpySession):
    async def login(self) -> None:  # type: ignore[override]
        return None

    async def post_multipart(  # type: ignore[override]
        self, path: str, data: dict[str, str], file: MultipartFile
    ) -> str:
        self.calls.append((path, dict(data), file))
        # Real S3300 success marker (upload_certificate now verifies it).
        return (
            "<html><body>SSL PEM Server Certificate file download through HTTP "
            "is completed successfully.</body></html>"
        )


def test_upload_certificate_drives_grounded_multipart_post() -> None:
    sess = _CertSpySession()
    writer = HttpWriter(sess, get_model("gsm7228ps"))
    writer.upload_certificate(_CERT_PEM, _KEY_PEM, force=True)
    assert len(sess.calls) == 1
    path, data, file = sess.calls[0]
    assert path == "/http_file_download.html/a1"
    assert data == _EXPECTED_CERT_FORM
    assert file.field == ".v_1_3_1_handle"
    assert file.filename == "certificate.pem"
    assert file.content_type == "application/octet-stream"
    # Combined cert+key PEM, exactly as S3300Updater builds it.
    assert file.content == f"{_CERT_PEM.rstrip(chr(10))}\n{_KEY_PEM}".encode()


def test_upload_certificate_raises_when_switch_rejects() -> None:
    # The S3300 returns HTTP 200 even on a rejected cert -- the real outcome is
    # in the page body. upload_certificate must SURFACE a non-success body, never
    # silently swallow it (the certbot hook checks the same marker).
    class _RejectSession(_CertSpySession):
        def post_multipart(
            self, path: str, data: dict[str, str], file: MultipartFile
        ) -> str:
            return "<html><body>Error: invalid certificate file</body></html>"

    writer = HttpWriter(_RejectSession(), get_model("gsm7228ps"))
    with pytest.raises(HttpError, match="not accepted"):
        writer.upload_certificate(_CERT_PEM, _KEY_PEM, force=True)


def test_upload_certificate_requires_force() -> None:
    sess = _CertSpySession()
    writer = HttpWriter(sess, get_model("gsm7228ps"))
    with pytest.raises(ProtectedPortError):
        writer.upload_certificate(_CERT_PEM, _KEY_PEM)
    assert sess.calls == []  # nothing sent when force is withheld


def test_upload_certificate_m4300_is_not_implemented_not_unsupported() -> None:
    """m4300's cert mechanism (SCP) is KNOWN, so it must raise the clear
    NotImplementedError -- never UnsupportedCapabilityError, which would falsely
    claim the hardware cannot load a certificate."""
    sess = _CertSpySession()
    writer = HttpWriter(sess, get_model("m4300-24x"))
    with pytest.raises(NotImplementedError, match="SCP"):
        writer.upload_certificate(_CERT_PEM, _KEY_PEM, force=True)
    assert not isinstance(NotImplementedError, UnsupportedCapabilityError)
    assert sess.calls == []


def test_upload_certificate_gsm7252ps_is_not_implemented_points_to_scp() -> None:
    """Parity fix 3a: gsm7252ps DOES have a cert-upload mechanism (SCP, in
    SCP_CERT_PROFILES, reachable via SyncSwitch.upload_certificate_scp). The
    HTTP writer must therefore raise NotImplementedError naming SCP -- NOT
    UnsupportedCapabilityError claiming 'no known mechanism' -- exactly like
    m4300."""
    sess = _CertSpySession()
    writer = HttpWriter(sess, get_model("gsm7252ps"))
    with pytest.raises(NotImplementedError, match="SCP") as exc:
        writer.upload_certificate(_CERT_PEM, _KEY_PEM, force=True)
    # The message must point the caller at the real (implemented) SCP path,
    # never claim the capability is absent.
    assert "upload_certificate_scp" in str(exc.value)
    assert not isinstance(exc.value, UnsupportedCapabilityError)
    assert sess.calls == []


def test_async_upload_certificate_gsm7252ps_is_not_implemented() -> None:
    sess = _AsyncCertSpySession()
    writer = AsyncHttpWriter(sess, get_model("gsm7252ps"))
    with pytest.raises(NotImplementedError, match="SCP"):
        _run(writer.upload_certificate(_CERT_PEM, _KEY_PEM, force=True))


def test_upload_certificate_unknown_model_is_unsupported() -> None:
    """A model with an HTTP backend but NO known cert mechanism (gs305ep)
    honestly raises UnsupportedCapabilityError."""
    sess = _CertSpySession()
    writer = HttpWriter(sess, get_model("gs305ep"))
    with pytest.raises(UnsupportedCapabilityError):
        writer.upload_certificate(_CERT_PEM, _KEY_PEM, force=True)


def test_async_upload_certificate_drives_grounded_multipart_post() -> None:
    sess = _AsyncCertSpySession()
    writer = AsyncHttpWriter(sess, get_model("gsm7228ps"))
    _run(writer.upload_certificate(_CERT_PEM, _KEY_PEM, force=True))
    assert len(sess.calls) == 1
    path, data, file = sess.calls[0]
    assert path == "/http_file_download.html/a1"
    assert data == _EXPECTED_CERT_FORM
    assert file.field == ".v_1_3_1_handle"
    assert file.content == f"{_CERT_PEM.rstrip(chr(10))}\n{_KEY_PEM}".encode()


def test_async_upload_certificate_requires_force() -> None:
    sess = _AsyncCertSpySession()
    writer = AsyncHttpWriter(sess, get_model("gsm7228ps"))
    with pytest.raises(ProtectedPortError):
        _run(writer.upload_certificate(_CERT_PEM, _KEY_PEM))
    assert sess.calls == []


def test_async_upload_certificate_m4300_is_not_implemented() -> None:
    sess = _AsyncCertSpySession()
    writer = AsyncHttpWriter(sess, get_model("m4300-24x"))
    with pytest.raises(NotImplementedError, match="SCP"):
        _run(writer.upload_certificate(_CERT_PEM, _KEY_PEM, force=True))


# ---------------------------------------------------------------------------
# End-to-end: SyncSwitch.upload_certificate against the real virtual HTTP face,
# proving the multipart body reaches the mock and is recorded.
# ---------------------------------------------------------------------------


def test_sync_switch_upload_certificate_records_on_mock() -> None:
    from netgear_switch.protocols.http.endpoints import http_spec
    from netgear_switch.sync_api import SyncSwitch
    from netgear_switch.transport.http.client import HttpClient
    from netgear_switch.virtual.server import VirtualSwitch

    sw = VirtualSwitch(model="gsm7228ps")
    sw.start()
    try:
        spec = http_spec(get_model("gsm7228ps"))
        client = HttpClient(f"127.0.0.1:{sw.http_port}", "password", spec)
        switch = SyncSwitch(get_model("gsm7228ps"), "127.0.0.1", http_client=client)
        try:
            # force required, and the mock records the combined PEM it received.
            with pytest.raises(ProtectedPortError):
                switch.upload_certificate(_CERT_PEM, _KEY_PEM)
            assert sw.state.uploaded_cert is None
            switch.upload_certificate(_CERT_PEM, _KEY_PEM, force=True)
        finally:
            client.close()
        assert sw.state.uploaded_cert == f"{_CERT_PEM.rstrip(chr(10))}\n{_KEY_PEM}"
    finally:
        sw.stop()


# ---------------------------------------------------------------------------
# GS728TPP GoAhead XML-API SSL-cert upload (a distinct write path from the
# gsm7228ps multipart form): a raw SSLCryptoCertificateImportList XML body
# POSTed to the session-path-prefixed ``wcd`` endpoint, with the RSA private key
# converted to PKCS#1 "traditional" form. Grounded in GS728TPPUpdater.
# NOTE: this write path is exercised MOCK-ONLY; a live upload mutates a
# production switch and needs separate user permission.
# ---------------------------------------------------------------------------

# A wcd success response the mock/switch returns on a good import.
_GOAHEAD_OK = (
    '<?xml version="1.0" encoding="UTF-8" ?>'
    "<ResponseData><statusCode>0</statusCode></ResponseData>"
)


def _rsa_key_pem(bits: int = 2048) -> str:
    """A freshly generated RSA private key as an unencrypted PKCS#8 PEM (the
    input shape a real cert+key pair carries), for the XML-upload tests."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


class _XmlCertSpySession:
    """Records the single raw-XML POST the GoAhead cert-upload writer drives."""

    def __init__(self, response: str = _GOAHEAD_OK) -> None:
        self.calls: list[tuple[str, str]] = []
        self._response = response

    def login(self) -> None:
        return None

    def get_page(self, path: str) -> str:
        raise AssertionError(f"cert upload should not GET {path}")

    def post_form(self, path: str, data: dict[str, str]) -> str:
        raise AssertionError(f"cert upload should not post_form {path}")

    def post_multipart(
        self, path: str, data: dict[str, str], file: MultipartFile
    ) -> str:
        raise AssertionError("gs728tpp cert upload must be XML, not multipart")

    def post_xml(self, path: str, body: str) -> str:
        self.calls.append((path, body))
        return self._response


class _AsyncXmlCertSpySession(_XmlCertSpySession):
    async def login(self) -> None:  # type: ignore[override]
        return None

    async def post_xml(self, path: str, body: str) -> str:  # type: ignore[override]
        self.calls.append((path, body))
        return self._response


def test_upload_certificate_gs728tpp_drives_grounded_xml_post() -> None:
    key = _rsa_key_pem()
    sess = _XmlCertSpySession()
    writer = HttpWriter(sess, get_model("gs728tpp"))
    writer.upload_certificate(_CERT_PEM, key, force=True)
    assert len(sess.calls) == 1
    path, body = sess.calls[0]
    assert path == "wcd"
    assert '<SSLCryptoCertificateImportList action="set">' in body
    assert "<instance>1</instance>" in body
    # The RSA key was converted to PKCS#1 "traditional" form, and its PKCS#1
    # public key extracted -- NOT the PKCS#8 "BEGIN PRIVATE KEY" it came in as.
    assert "-----BEGIN RSA PRIVATE KEY-----" in body
    assert "-----BEGIN RSA PUBLIC KEY-----" in body
    assert "BEGIN PRIVATE KEY" not in body  # no leftover PKCS#8 wrapper
    assert "BEGIN CERTIFICATE" in body  # the cert PEM made it into the body


def test_upload_certificate_gs728tpp_requires_force() -> None:
    sess = _XmlCertSpySession()
    writer = HttpWriter(sess, get_model("gs728tpp"))
    with pytest.raises(ProtectedPortError):
        writer.upload_certificate(_CERT_PEM, _rsa_key_pem())
    assert sess.calls == []  # nothing sent when force is withheld


def test_upload_certificate_gs728tpp_rejects_non_rsa_key() -> None:
    """The switch accepts only RSA keys, so an EC key raises a clear ValueError
    BEFORE anything is posted."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    ec_key = (
        ec.generate_private_key(ec.SECP256R1())
        .private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        .decode()
    )
    sess = _XmlCertSpySession()
    writer = HttpWriter(sess, get_model("gs728tpp"))
    with pytest.raises(ValueError, match="RSA"):
        writer.upload_certificate(_CERT_PEM, ec_key, force=True)
    assert sess.calls == []


def test_upload_certificate_gs728tpp_surfaces_error_status() -> None:
    """A non-zero wcd statusCode surfaces the switch's statusString."""
    from netgear_switch.errors import HttpError

    sess = _XmlCertSpySession(
        response=(
            '<?xml version="1.0" ?><ResponseData><statusCode>7</statusCode>'
            "<statusString>invalid certificate</statusString></ResponseData>"
        )
    )
    writer = HttpWriter(sess, get_model("gs728tpp"))
    with pytest.raises(HttpError, match="invalid certificate"):
        writer.upload_certificate(_CERT_PEM, _rsa_key_pem(), force=True)


def test_async_upload_certificate_gs728tpp_drives_grounded_xml_post() -> None:
    sess = _AsyncXmlCertSpySession()
    writer = AsyncHttpWriter(sess, get_model("gs728tpp"))
    _run(writer.upload_certificate(_CERT_PEM, _rsa_key_pem(), force=True))
    assert len(sess.calls) == 1
    path, body = sess.calls[0]
    assert path == "wcd"
    assert "-----BEGIN RSA PRIVATE KEY-----" in body
    assert "-----BEGIN RSA PUBLIC KEY-----" in body


def test_async_upload_certificate_gs728tpp_requires_force() -> None:
    sess = _AsyncXmlCertSpySession()
    writer = AsyncHttpWriter(sess, get_model("gs728tpp"))
    with pytest.raises(ProtectedPortError):
        _run(writer.upload_certificate(_CERT_PEM, _rsa_key_pem()))
    assert sess.calls == []


def test_sync_switch_upload_certificate_gs728tpp_records_on_mock() -> None:
    """End-to-end: SyncSwitch.upload_certificate for gs728tpp drives the real
    GoAhead XML POST against the virtual face, which validates + records the
    received certificate (proving the XML body reaches the switch face)."""
    from netgear_switch.protocols.http.endpoints import http_spec
    from netgear_switch.sync_api import SyncSwitch
    from netgear_switch.transport.http.client import HttpClient
    from netgear_switch.virtual.server import VirtualSwitch

    sw = VirtualSwitch(model="gs728tpp")
    sw.start()
    try:
        spec = http_spec(get_model("gs728tpp"))
        client = HttpClient(f"127.0.0.1:{sw.http_port}", "password", spec)
        switch = SyncSwitch(get_model("gs728tpp"), "127.0.0.1", http_client=client)
        try:
            with pytest.raises(ProtectedPortError):
                switch.upload_certificate(_CERT_PEM, _rsa_key_pem())
            assert sw.state.uploaded_cert is None
            switch.upload_certificate(_CERT_PEM, _rsa_key_pem(), force=True)
        finally:
            client.close()
        # The face recorded the certificate PEM exactly as it arrived.
        assert sw.state.uploaded_cert == _CERT_PEM.strip()
    finally:
        sw.stop()
