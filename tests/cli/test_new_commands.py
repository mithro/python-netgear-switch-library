"""CLI tests for the operation-coverage subcommands: identify, nsdp-device,
cycle-poe, clear-poe-fault, upload-certificate."""

from __future__ import annotations

import io

from netgear_switch.cli import context
from netgear_switch.cli.main import main
from netgear_switch.errors import ProtectedPortError, UnsupportedCapabilityError
from netgear_switch.models import DetectedModel
from netgear_switch.protocols.nsdp.types import NsdpDevice
from netgear_switch.registry import get_model


def run(
    argv: list[str], switch: object, stdin: str = ""
) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(
        argv,
        switch_factory=lambda a, c: switch,
        stdin=io.StringIO(stdin),
        stdout=out,
        stderr=err,
    )
    return code, out.getvalue(), err.getvalue()


class RecordingSwitch:
    def __init__(
        self, host: str = "10.0.0.1", protected: set[int] | None = None
    ) -> None:
        self.model = get_model("gsm7252ps")
        self.host = host
        self.calls: list[tuple[object, ...]] = []
        self._protected = protected or set()

    def _check_protected(self, port: int, force: bool) -> None:
        if port in self._protected and not force:
            raise ProtectedPortError(f"port {port} is protected; pass force=True")

    def cycle_poe(self, port: int, *, force: bool = False) -> None:
        self._check_protected(port, force)
        self.calls.append(("cycle_poe", port, force))

    def clear_poe_fault(self, port: int, *, force: bool = False) -> None:
        self._check_protected(port, force)
        self.calls.append(("clear_poe_fault", port, force))

    def upload_certificate(
        self, cert_pem: str, key_pem: str, *, force: bool = False
    ) -> None:
        self.calls.append(("upload_certificate", cert_pem, key_pem, force))


# --- identify ------------------------------------------------------------


class IdentifySwitch(RecordingSwitch):
    def identify(self) -> DetectedModel:
        return DetectedModel(
            key="gsm7252ps",
            sys_descr="GSM7252PS ProSafe 48-port",
            sys_object_id="1.3.6.1.4.1.4526.100.1.1",
        )


def test_identify_prints_detected_model() -> None:
    code, out, _ = run(["identify"], IdentifySwitch())
    assert code == context.EXIT_OK
    assert "gsm7252ps" in out
    assert "GSM7252PS ProSafe 48-port" in out


def test_identify_json_shape() -> None:
    import json

    code, out, _ = run(["--json", "identify"], IdentifySwitch())
    assert code == context.EXIT_OK
    data = json.loads(out)
    assert data["key"] == "gsm7252ps"
    assert data["sys_object_id"] == "1.3.6.1.4.1.4526.100.1.1"


def test_identify_unmatched_key_is_not_a_guess() -> None:
    class Unmatched(RecordingSwitch):
        def identify(self) -> DetectedModel:
            return DetectedModel(
                key=None, sys_descr="Some Other Device", sys_object_id=None
            )

    code, out, _ = run(["identify"], Unmatched())
    assert code == context.EXIT_OK
    assert "(unmatched)" in out


# --- nsdp-device ---------------------------------------------------------


def test_nsdp_device_prints_record() -> None:
    class NsdpFake(RecordingSwitch):
        def nsdp_device(self) -> NsdpDevice:
            return NsdpDevice(
                model="GS308EP",
                mac="BC:A5:11:B8:EC:F1",
                hostname="switch1",
                ip="10.1.5.25",
                port_count=8,
            )

    code, out, _ = run(["nsdp-device"], NsdpFake())
    assert code == context.EXIT_OK
    assert "GS308EP" in out
    assert "BC:A5:11:B8:EC:F1" in out
    assert "10.1.5.25" in out


def test_nsdp_device_errors_honestly_on_non_nsdp_model() -> None:
    """A model without an NSDP backend surfaces UnsupportedCapabilityError as a
    clean CLI error, not a fabricated record nor a stack trace."""

    class NoNsdp(RecordingSwitch):
        def nsdp_device(self) -> NsdpDevice:
            raise UnsupportedCapabilityError(
                "model 'm4300-24x' has no NSDP backend"
            )

    code, out, err = run(["nsdp-device"], NoNsdp())
    assert code == context.EXIT_ERROR
    assert "error:" in err
    assert "no NSDP backend" in err
    assert "Traceback" not in err
    assert out == ""


# --- cycle-poe / clear-poe-fault -----------------------------------------


def test_cycle_poe_with_yes_reaches_facade() -> None:
    sw = RecordingSwitch()
    code, _o, _e = run(["cycle-poe", "5", "--yes"], sw)
    assert code == context.EXIT_OK
    assert sw.calls == [("cycle_poe", 5, False)]


def test_cycle_poe_dry_run_sends_nothing() -> None:
    sw = RecordingSwitch()
    code, out, _e = run(["cycle-poe", "5", "--dry-run"], sw)
    assert code == context.EXIT_OK
    assert "DRY-RUN" in out
    assert sw.calls == []


def test_cycle_poe_requires_confirmation() -> None:
    sw = RecordingSwitch()
    code, _o, err = run(["cycle-poe", "5"], sw, stdin="n\n")
    assert code == context.EXIT_ERROR
    assert "aborted" in err
    assert sw.calls == []


def test_cycle_poe_protected_refused_without_force() -> None:
    sw = RecordingSwitch(protected={9})
    code, _o, err = run(["cycle-poe", "9", "--yes"], sw)
    assert code == context.EXIT_PROTECTED
    assert "protected" in err
    assert "Traceback" not in err
    assert sw.calls == []


def test_cycle_poe_force_forwarded() -> None:
    sw = RecordingSwitch(protected={9})
    code, _o, _e = run(["cycle-poe", "9", "--yes", "--force"], sw)
    assert code == context.EXIT_OK
    assert sw.calls == [("cycle_poe", 9, True)]


def test_clear_poe_fault_with_yes_reaches_facade() -> None:
    sw = RecordingSwitch()
    code, _o, _e = run(["clear-poe-fault", "5", "--yes"], sw)
    assert code == context.EXIT_OK
    assert sw.calls == [("clear_poe_fault", 5, False)]


def test_clear_poe_fault_force_forwarded() -> None:
    sw = RecordingSwitch(protected={9})
    code, _o, _e = run(["clear-poe-fault", "9", "--yes", "--force"], sw)
    assert code == context.EXIT_OK
    assert sw.calls == [("clear_poe_fault", 9, True)]


# --- upload-certificate --------------------------------------------------


def _write_pems(tmp_path) -> tuple[str, str]:
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text(
        "-----BEGIN CERTIFICATE-----\nCERTDATA\n-----END CERTIFICATE-----\n"
    )
    key.write_text(
        "-----BEGIN PRIVATE KEY-----\nKEYDATA\n-----END PRIVATE KEY-----\n"
    )
    return str(cert), str(key)


def test_upload_certificate_reads_pems_and_reaches_facade(tmp_path) -> None:
    cert, key = _write_pems(tmp_path)
    sw = RecordingSwitch()
    code, _o, _e = run(
        ["upload-certificate", "--cert", cert, "--key", key, "--yes"], sw
    )
    assert code == context.EXIT_OK
    assert len(sw.calls) == 1
    op, cert_pem, key_pem, force = sw.calls[0]
    assert op == "upload_certificate"
    assert "CERTDATA" in cert_pem
    assert "KEYDATA" in key_pem
    assert force is False


def test_upload_certificate_force_forwarded(tmp_path) -> None:
    cert, key = _write_pems(tmp_path)
    sw = RecordingSwitch()
    code, _o, _e = run(
        ["upload-certificate", "--cert", cert, "--key", key, "--yes", "--force"], sw
    )
    assert code == context.EXIT_OK
    assert sw.calls[0][3] is True


def test_upload_certificate_dry_run_sends_nothing(tmp_path) -> None:
    cert, key = _write_pems(tmp_path)
    sw = RecordingSwitch()
    code, out, _e = run(
        ["upload-certificate", "--cert", cert, "--key", key, "--dry-run"], sw
    )
    assert code == context.EXIT_OK
    assert "DRY-RUN" in out
    assert sw.calls == []


def test_upload_certificate_missing_file_is_clean_error(tmp_path) -> None:
    sw = RecordingSwitch()
    code, _out, err = run(
        [
            "upload-certificate",
            "--cert",
            str(tmp_path / "nope.pem"),
            "--key",
            str(tmp_path / "also-nope.pem"),
            "--yes",
        ],
        sw,
    )
    assert code == context.EXIT_ERROR
    assert "error:" in err
    assert "Traceback" not in err
    assert sw.calls == []


def test_upload_certificate_not_implemented_is_clean_error(tmp_path) -> None:
    """A known-but-unimplemented mechanism (m4300 SCP, gs728tpp XML-API) raises
    NotImplementedError from the library; the CLI must report it cleanly, never
    as an uncaught stack trace."""
    cert, key = _write_pems(tmp_path)

    class NotImplementedSwitch(RecordingSwitch):
        def upload_certificate(
            self, cert_pem: str, key_pem: str, *, force: bool = False
        ) -> None:
            raise NotImplementedError(
                "SSL-certificate upload for 'm4300-24x' uses SCP file-copy to the "
                "switch; that mechanism is known but not yet implemented"
            )

    code, _o, err = run(
        ["upload-certificate", "--cert", cert, "--key", key, "--yes"],
        NotImplementedSwitch(),
    )
    assert code == context.EXIT_ERROR
    assert "error:" in err
    assert "not yet implemented" in err
    assert "Traceback" not in err
