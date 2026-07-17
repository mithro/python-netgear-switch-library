"""Synchronous SNMP v2c client over the net-snmp CLI tools (subprocess).

No Python SNMP package is used. The net-snmp binaries (snmpget/snmpbulkwalk)
are a system requirement — install the OS `snmp` package
(`apt-get install -y snmp`). Args are passed as a list; shell is never used.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from typing import TYPE_CHECKING, Any, Protocol

from ...protocols.snmp.client import SnmpError, SnmpRow

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

# -On numeric OIDs, -Oe enums-as-numbers, -OU no units, -Ln no stderr logging.
_OUTPUT_FLAGS = ("-On", "-Oe", "-OU", "-Ln")

# Type tokens net-snmp prints for integer-family values.
_INT_TYPES = frozenset(
    {
        "INTEGER",
        "Integer32",
        "Gauge32",
        "Gauge",
        "Unsigned32",
        "Counter32",
        "Counter64",
        "Counter",
    }
)

_ABSENT_MARKERS = (
    "no such object",
    "no such instance",
    "no more variables",
)

_TIMETICKS_RE = re.compile(r"\((\d+)\)")


class _CompletedProcess(Protocol):
    returncode: int
    stdout: str
    stderr: str


def _which(binary: str) -> str:
    """Return the resolved path to a net-snmp binary or raise SnmpError."""
    path = shutil.which(binary)
    if path is None:
        raise SnmpError(
            f"net-snmp not installed: {binary!r} is not on PATH. "
            "Install the `snmp` package (e.g. `apt-get install -y snmp`)."
        )
    return path


def _normalize(snmp_type: str, value: str) -> int | str | bytes:
    """Normalize one net-snmp scalar value to a plain Python value.

    Mirrors the pysnmp client (Task 11) so SnmpRow values are transport-equal.
    """
    if snmp_type in _INT_TYPES:
        try:
            return int(value)
        except ValueError as exc:
            raise SnmpError(f"non-integer {snmp_type} value {value!r}") from exc
    if snmp_type == "Timeticks":
        m = _TIMETICKS_RE.search(value)
        if m is None:
            raise SnmpError(f"unparsable Timeticks value {value!r}")
        return int(m.group(1))
    if snmp_type == "STRING":
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            return value[1:-1]
        return value
    if snmp_type == "OID":
        return value.lstrip(".")
    # IpAddress and any other textual type: plain string.
    return value


def parse_netsnmp_lines(text: str) -> list[SnmpRow]:
    """Parse `snmpget`/`snmpbulkwalk` output (-On -Oe -OU -Ln) into SnmpRows.

    Raises SnmpError on a "No Such Object/Instance" line — an absent OID is
    surfaced early, never returned as an empty/None row. Multi-line Hex-STRING
    continuations are joined into one bytes value.
    """
    rows: list[SnmpRow] = []
    pending_oid: str | None = None
    pending_hex: list[str] = []

    def flush_hex() -> None:
        nonlocal pending_oid
        if pending_oid is not None:
            data = bytes(
                int(tok, 16) for chunk in pending_hex for tok in chunk.split()
            )
            rows.append(SnmpRow(pending_oid, data, "Hex-STRING"))
            pending_oid = None
            pending_hex.clear()

    for raw in text.splitlines():
        if not raw.strip():
            continue
        if " = " not in raw:
            if pending_oid is not None:  # Hex-STRING continuation line
                pending_hex.append(raw.strip())
            continue
        flush_hex()
        oid_part, rest = raw.split(" = ", 1)
        oid = oid_part.strip().lstrip(".")
        rest = rest.strip()
        if any(marker in rest.lower() for marker in _ABSENT_MARKERS):
            raise SnmpError(f"absent OID in net-snmp output: {oid} = {rest}")
        if rest in ('""', ""):
            rows.append(SnmpRow(oid, "", "STRING"))
            continue
        if ": " in rest:
            snmp_type, value = rest.split(": ", 1)
        elif rest.endswith(":"):
            snmp_type, value = rest[:-1], ""
        else:
            rows.append(SnmpRow(oid, rest, "STRING"))
            continue
        snmp_type = snmp_type.strip()
        value = value.strip()
        if snmp_type == "Hex-STRING":
            pending_oid = oid
            pending_hex = [value]
            continue
        rows.append(SnmpRow(oid, _normalize(snmp_type, value), snmp_type))
    flush_hex()
    return rows


class NetsnmpCliClient:
    """Read-only sync SNMP client shelling out to net-snmp CLI tools."""

    def __init__(
        self,
        host: str,
        community: str,
        *,
        timeout: int = 10,
        retries: int = 1,
        runner: Callable[..., _CompletedProcess] = subprocess.run,
    ) -> None:
        self.host = host
        self.community = community
        self.timeout = timeout
        self.retries = retries
        self._runner = runner

    def _base_args(self, binary: str) -> list[str]:
        return [
            _which(binary),
            "-v2c",
            "-c",
            self.community,
            *_OUTPUT_FLAGS,
            "-t",
            str(self.timeout),
            "-r",
            str(self.retries),
        ]

    def get(self, oids: list[str]) -> list[SnmpRow]:
        if not oids:
            return []
        argv = [*self._base_args("snmpget"), self.host, *oids]
        return self._invoke(argv)

    def walk(self, base_oid: str) -> list[SnmpRow]:
        argv = [*self._base_args("snmpbulkwalk"), self.host, base_oid]
        return self._invoke(argv)

    def _invoke(self, argv: Sequence[str]) -> list[SnmpRow]:
        kwargs: dict[str, Any] = {
            "capture_output": True,
            "text": True,
            "check": False,
        }
        try:
            proc = self._runner(list(argv), **kwargs)
        except OSError as exc:  # binary vanished between _which and run
            raise SnmpError(f"failed to run {argv[0]!r}: {exc}") from exc
        stderr = (proc.stderr or "").strip()
        if proc.returncode != 0 or stderr:
            raise SnmpError(
                f"{argv[0]} exited {proc.returncode} for {self.host}: "
                f"{stderr or 'unknown error'}"
            )
        return parse_netsnmp_lines(proc.stdout)
