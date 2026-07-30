"""``ngsw capture``: record a real switch's state + protocol exchanges.

Opt-in, live-switch, never run in CI. The state snapshot uses the public
``SyncSwitch.snapshot()`` (works against any backend); the reference raw walk
(``snmpbulkwalk`` output) requires live-switch access and is only recorded when
a ``raw_walk`` callable is supplied. Output is a JSON file used *for reference*
when hand-authoring fixtures (design spec Sec7.1) -- never committed as-is.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from netgear_switch.errors import ConfigError

from . import format as fmt

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path

    from netgear_switch.config import Runner
    from netgear_switch.sync_api import SyncSwitch

_WALK_TIMEOUT = 30


@dataclass
class CaptureRecord:
    model: str
    host: str
    captured_at: str
    snapshot: object
    raw_exchanges: list[dict[str, object]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def default_raw_walk(
    host: str,
    base: str,
    *,
    community: str = "public",
    runner: Runner = subprocess.run,
) -> list[str]:
    """Shell out to net-snmp's snmpbulkwalk (live hardware) for a reference walk.

    Never uses ``shell=True`` or string interpolation -- the argv is a fixed
    list, so there is no shell-injection surface even though ``host``/``base``
    are caller-controlled. A missing binary or a timeout propagates as the
    normal ``subprocess`` exception (``FileNotFoundError`` /
    ``subprocess.TimeoutExpired``); a nonzero exit is turned into a
    ``RuntimeError`` carrying the process's stderr. ``run_capture`` is
    responsible for catching these and recording an honest failure instead of
    crashing the whole capture.
    """
    result = runner(
        ["snmpbulkwalk", "-v2c", "-c", community, host, base],
        capture_output=True,
        text=True,
        timeout=_WALK_TIMEOUT,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"snmpbulkwalk exited {result.returncode}: {result.stderr.strip()}"
        )
    return result.stdout.splitlines()


def run_capture(
    switch: SyncSwitch,
    out_path: Path,
    *,
    snapshot_only: bool = False,
    raw_walk: Callable[[str, str], Sequence[str]] | None = None,
    now: Callable[[], datetime] | None = None,
) -> CaptureRecord:
    clock = now or (lambda: datetime.now(UTC))
    record = CaptureRecord(
        model=switch.model.key,
        host=switch.host,
        captured_at=clock().isoformat(),
        snapshot=fmt.jsonify(switch.snapshot()),
    )
    if snapshot_only:
        record.notes.append("snapshot-only: no raw protocol exchange recorded")
    elif raw_walk is None:
        record.notes.append(
            "no raw-capture backend available; recording a raw protocol exchange "
            "needs live-switch access (SNMP walk / NSDP / HTTP). Re-run on hardware."
        )
    else:
        base = switch.model.snmp_vendor_base or "1.3.6.1.2.1"
        request = f"walk {base}"
        try:
            lines = list(raw_walk(switch.host, base))
        except Exception as exc:
            # A raw walk can fail in many ways on real hardware (missing
            # snmpbulkwalk binary, nonzero exit, network timeout). The walk is
            # optional and best-effort: record the honest failure so the
            # capture record isn't silently missing data, but never let it
            # abort the rest of the capture.
            error = f"{type(exc).__name__}: {exc}"
            record.raw_exchanges.append(
                {"protocol": "snmp", "request": request, "error": error}
            )
            record.notes.append(f"raw protocol walk failed: {error}")
        else:
            record.raw_exchanges.append(
                {"protocol": "snmp", "request": request, "response": lines}
            )
    try:
        out_path.write_text(json.dumps(_as_dict(record), indent=2))
    except OSError as exc:
        raise ConfigError(f"cannot write capture output to {out_path}: {exc}") from exc
    return record


def _as_dict(record: CaptureRecord) -> dict[str, object]:
    return {
        "model": record.model,
        "host": record.host,
        "captured_at": record.captured_at,
        "snapshot": record.snapshot,
        "raw_exchanges": record.raw_exchanges,
        "notes": record.notes,
    }
