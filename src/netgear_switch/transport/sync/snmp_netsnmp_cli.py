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

    from ...protocols.snmp.write import SetVarbind

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
)

# Benign terminator snmpbulkwalk appends once a walk reaches the end of the
# agent's MIB tree. Not an error: skip the line and return the rows already
# parsed so far.
_END_OF_MIB_MARKERS = (
    "no more variables left in this mib view",
    "past the end of the mib tree",
)

_TIMETICKS_RE = re.compile(r"\((\d+)\)")


def _format_set_value(vb: SetVarbind) -> str:
    """Render a SetVarbind value as the string snmpset expects for its type.

    ``x`` (hex/octets) is emitted as lowercase hex digits; every other type is
    stringified directly (net-snmp parses ``i``/``u``/``s``/``a`` from text).
    """
    if vb.type_letter == "x":
        data = (
            vb.value if isinstance(vb.value, bytes) else str(vb.value).encode("latin-1")
        )
        return data.hex()
    return str(vb.value)


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


def _split_typed(rest: str) -> tuple[str, str] | None:
    """If `rest` looks like `<TYPE>: <value>` (or `<TYPE>:` with no value),
    return `(snmp_type, value)`. Otherwise return None.

    This is checked *before* any marker text so a STRING value that merely
    contains marker words (e.g. `STRING: "no such object test"`) is always
    parsed as a normal typed value, never mistaken for a marker line.
    """
    if ": " in rest:
        snmp_type, value = rest.split(": ", 1)
        return snmp_type.strip(), value.strip()
    if rest.endswith(":"):
        return rest[:-1].strip(), ""
    return None


def parse_netsnmp_lines(text: str, *, empty_subtree_ok: bool = False) -> list[SnmpRow]:
    """Parse `snmpget`/`snmpbulkwalk` output (-On -Oe -OU -Ln) into SnmpRows.

    For a GET (``empty_subtree_ok=False``, the default) a "No Such
    Object/Instance" line raises SnmpError: the caller asked for a specific
    scalar and its absence must be surfaced, never fabricated as empty.

    For a WALK (``empty_subtree_ok=True``) a "No Such Object/Instance" line is
    the NORMAL response a real agent gives when the walked subtree has no
    entries at all (e.g. the RFC3621 PoE MIB on a non-PoE switch, an
    unimplemented sensor table, or an unpopulated ``ipAddrTable``). Verified
    against live hardware: ``snmpbulkwalk`` of an absent subtree emits exactly
    one ``<base> = No Such Object available on this agent at this OID`` line.
    In walk mode that line is treated like the benign end-of-MIB terminator —
    skipped, returning the rows collected so far (``[]`` for an empty subtree)
    instead of raising. This is what lets optional reads degrade to an empty
    result rather than crashing the whole call.

    The benign "No more variables left in this MIB View .../ past the end of
    the MIB tree" terminator that snmpbulkwalk appends at the end of a
    successful walk is always skipped. Multi-line Hex-STRING continuations are
    joined into one bytes value.
    """
    rows: list[SnmpRow] = []
    pending_oid: str | None = None
    pending_hex: list[str] = []

    def flush_hex() -> None:
        nonlocal pending_oid
        if pending_oid is not None:
            data = bytes(int(tok, 16) for chunk in pending_hex for tok in chunk.split())
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
        if rest in ('""', ""):
            rows.append(SnmpRow(oid, "", "STRING"))
            continue
        typed = _split_typed(rest)
        if typed is not None:
            snmp_type, value = typed
            if snmp_type == "Hex-STRING":
                pending_oid = oid
                pending_hex = [value]
                continue
            rows.append(SnmpRow(oid, _normalize(snmp_type, value), snmp_type))
            continue
        rest_lower = rest.lower()
        if any(marker in rest_lower for marker in _END_OF_MIB_MARKERS):
            continue
        if any(marker in rest_lower for marker in _ABSENT_MARKERS):
            if empty_subtree_ok:
                # Empty subtree: a walk of a base OID with no entries. Skip the
                # marker (like end-of-MIB) and return rows collected so far.
                continue
            raise SnmpError(f"absent OID in net-snmp output: {oid} = {rest}")
        raise SnmpError(f"unrecognized net-snmp output line: {oid} = {rest}")
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
        # A walk of an absent subtree is not an error: real agents answer with a
        # lone "No Such Object" line, which parse_netsnmp_lines treats as empty.
        return self._invoke(argv, empty_subtree_ok=True)

    def set(self, varbind: SetVarbind) -> None:
        self.set_many([varbind])

    def set_many(self, varbinds: list[SetVarbind]) -> None:
        if not varbinds:
            return
        triples: list[str] = []
        for vb in varbinds:
            triples += [vb.oid, vb.type_letter, _format_set_value(vb)]
        argv = [*self._base_args("snmpset"), self.host, *triples]
        # _invoke raises SnmpError on non-zero exit or any stderr (commitFailed,
        # noSuchName, wrong type). The echoed varbinds it parses are discarded.
        try:
            self._invoke(argv)
        except SnmpError as exc:
            # A timeout on a SET is ambiguous in a way that cost real debugging
            # time: an agent SILENTLY DROPS a request whose community lacks write
            # access (RFC-mandated -- no error is returned), so an unauthorized
            # write community is indistinguishable from an unreachable host. Say
            # so, since reads can be succeeding on the same host at the same time.
            # (Observed on an S3300-52X whose communities are "pib"/"public", both
            # Read/Write, while the fleet default write community is "private".)
            if "Timeout" in str(exc):
                raise SnmpError(
                    f"{exc} -- a SET that times out often means the write "
                    "community is not authorized for writes on this device "
                    "(agents drop unauthorized requests without replying); "
                    "check the device's community list and its access mode"
                ) from exc
            raise

    def _invoke(
        self, argv: Sequence[str], *, empty_subtree_ok: bool = False
    ) -> list[SnmpRow]:
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
        return parse_netsnmp_lines(proc.stdout, empty_subtree_ok=empty_subtree_ok)
