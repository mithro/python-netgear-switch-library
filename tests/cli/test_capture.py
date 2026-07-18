from __future__ import annotations

import io
import json
import subprocess
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from netgear_switch.cli import context
from netgear_switch.cli.capture import CaptureRecord, default_raw_walk, run_capture
from netgear_switch.cli.main import main
from netgear_switch.errors import ConfigError
from netgear_switch.models import IpMode, MgmtIpConfig, PortStatus, SwitchData
from netgear_switch.registry import get_model

if TYPE_CHECKING:
    from pathlib import Path


class FakeSwitch:
    """Deliberately exposes only ``snapshot``/``model``/``host``: no set_*/create_*/
    delete_* method exists, so any attempt by ``run_capture`` to mutate the
    switch would fail with ``AttributeError`` rather than silently succeeding.
    """

    def __init__(self) -> None:
        self.model = get_model("gsm7252ps")
        self.host = "10.1.5.20"

    def snapshot(self) -> SwitchData:
        return SwitchData(
            model="gsm7252ps",
            host=self.host,
            ports=(PortStatus(1, "1/0/1", True, True, 1000),),
            mgmt_ip=MgmtIpConfig(
                IpMode.STATIC, "10.1.5.20", "255.255.255.0", "10.1.5.1"
            ),
        )


def test_run_capture_writes_snapshot_json(tmp_path: Path) -> None:
    out = tmp_path / "cap.json"
    record = run_capture(FakeSwitch(), out, snapshot_only=True)
    assert isinstance(record, CaptureRecord)
    data = json.loads(out.read_text())
    assert data["model"] == "gsm7252ps"
    assert data["host"] == "10.1.5.20"
    assert data["snapshot"]["ports"][0]["name"] == "1/0/1"
    assert data["raw_exchanges"] == []
    assert any("snapshot-only" in n for n in data["notes"])


def test_run_capture_records_injected_raw_walk(tmp_path: Path) -> None:
    out = tmp_path / "cap.json"
    walked: list[tuple[str, str]] = []

    def fake_walk(host: str, base: str) -> list[str]:
        walked.append((host, base))
        return ["OID.1 = INTEGER: 1", "OID.2 = STRING: x"]

    record = run_capture(FakeSwitch(), out, raw_walk=fake_walk)
    assert walked
    assert walked[0][0] == "10.1.5.20"
    assert record.raw_exchanges[0]["protocol"] == "snmp"
    data = json.loads(out.read_text())
    expected = ["OID.1 = INTEGER: 1", "OID.2 = STRING: x"]
    assert data["raw_exchanges"][0]["response"] == expected


def test_run_capture_notes_when_no_raw_backend(tmp_path: Path) -> None:
    record = run_capture(FakeSwitch(), tmp_path / "c.json")
    assert any("live-switch" in n for n in record.notes)
    assert record.raw_exchanges == []


def test_default_raw_walk_uses_injected_runner() -> None:
    def fake_runner(
        *args: object, **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=[], returncode=0, stdout="line1\nline2\n", stderr=""
        )

    lines = default_raw_walk("host", "1.3.6.1", runner=fake_runner)
    assert lines == ["line1", "line2"]


def test_run_capture_uses_injected_clock_deterministically(tmp_path: Path) -> None:
    out = tmp_path / "cap.json"
    fixed = datetime(2026, 7, 13, 12, 0, 0, tzinfo=UTC)

    record = run_capture(FakeSwitch(), out, snapshot_only=True, now=lambda: fixed)

    assert record.captured_at == "2026-07-13T12:00:00+00:00"
    data = json.loads(out.read_text())
    assert data["captured_at"] == "2026-07-13T12:00:00+00:00"


def test_run_capture_handles_raw_walk_exception_gracefully(tmp_path: Path) -> None:
    out = tmp_path / "cap.json"

    def failing_walk(host: str, base: str) -> list[str]:
        raise RuntimeError("boom")

    record = run_capture(FakeSwitch(), out, raw_walk=failing_walk)

    assert record.raw_exchanges[0]["protocol"] == "snmp"
    assert "error" in record.raw_exchanges[0]
    assert "response" not in record.raw_exchanges[0]
    assert any("failed" in n for n in record.notes)
    data = json.loads(out.read_text())
    assert "boom" in data["raw_exchanges"][0]["error"]


def test_run_capture_handles_missing_snmpbulkwalk_binary(tmp_path: Path) -> None:
    out = tmp_path / "cap.json"

    def missing_binary_runner(
        *args: object, **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError("snmpbulkwalk: command not found")

    def raw_walk_via_default(host: str, base: str) -> list[str]:
        return default_raw_walk(host, base, runner=missing_binary_runner)

    record = run_capture(FakeSwitch(), out, raw_walk=raw_walk_via_default)

    assert "error" in record.raw_exchanges[0]
    assert any("failed" in n for n in record.notes)


def test_default_raw_walk_raises_runtimeerror_on_nonzero_exit() -> None:
    def failing_runner(
        *args: object, **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="Timeout: No Response from host"
        )

    with pytest.raises(RuntimeError, match="Timeout: No Response from host"):
        default_raw_walk("host", "1.3.6.1", runner=failing_runner)


def test_default_raw_walk_propagates_timeout(tmp_path: Path) -> None:
    def timeout_runner(
        *args: object, **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd=["snmpbulkwalk"], timeout=30)

    def raw_walk_via_default(host: str, base: str) -> list[str]:
        return default_raw_walk(host, base, runner=timeout_runner)

    record = run_capture(
        FakeSwitch(), tmp_path / "cap.json", raw_walk=raw_walk_via_default
    )

    assert "error" in record.raw_exchanges[0]
    assert "TimeoutExpired" in record.raw_exchanges[0]["error"]


def test_run_capture_wraps_write_oserror_as_configerror(tmp_path: Path) -> None:
    """An unwritable output path (parent directory does not exist) must
    surface as a clean ``ConfigError`` naming the path -- never a bare
    ``OSError``/``FileNotFoundError`` traceback."""
    bad_path = tmp_path / "does-not-exist" / "cap.json"
    with pytest.raises(ConfigError, match=str(bad_path)):
        run_capture(FakeSwitch(), bad_path, snapshot_only=True)


def test_capture_command_with_unwritable_path_exits_cleanly_via_main(
    tmp_path: Path,
) -> None:
    bad_path = tmp_path / "does-not-exist" / "cap.json"
    buf, err = io.StringIO(), io.StringIO()
    code = main(
        ["capture", str(bad_path), "--snapshot-only"],
        switch_factory=lambda a, c: FakeSwitch(),
        stdout=buf,
        stderr=err,
    )
    assert code != context.EXIT_OK
    assert "Traceback" not in err.getvalue()
    assert "error:" in err.getvalue()


def test_capture_command_snapshot_only(tmp_path: Path) -> None:
    out = tmp_path / "cap.json"
    buf, err = io.StringIO(), io.StringIO()
    code = main(
        ["capture", str(out), "--snapshot-only"],
        switch_factory=lambda a, c: FakeSwitch(),
        stdout=buf,
        stderr=err,
    )
    assert code == context.EXIT_OK
    assert out.exists()
    assert "wrote capture" in buf.getvalue()
