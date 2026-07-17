"""Asynchronous SNMP v2c client on pysnmp v7. pysnmp is imported lazily.

Value parity: each pysnmp SMI value is normalized to the SAME plain Python type
the net-snmp CLI client (Task 10) produces — int for integer-family, str for
text/OID/IP, bytes for non-printable octet strings (Hex-STRING). Task 16's
sync/async equivalence test compares these values, so they must match.

pysnmp ships with no type stubs and is untyped under mypy --strict. Rather than
a blanket `ignore_missing_imports` for the whole package, `_pysnmp_asyncio()`
is the single lazy-import seam. It resolves the module dynamically via
`importlib.import_module` (a plain `str -> ModuleType` call mypy can't follow
into pysnmp's untyped internals), so no `type: ignore` is needed at all;
everything downstream of this one seam is deliberately treated as `Any`, and
the rest of the module is fully typed.
"""
from __future__ import annotations

import importlib
from typing import Any

from ...protocols.snmp.client import ABSENT_TYPES, SnmpError, SnmpRow

Triple = tuple[str, int | str | bytes, str]


def _pysnmp_asyncio() -> Any:
    """Lazily import pysnmp's v3arch asyncio hlapi module."""
    return importlib.import_module("pysnmp.hlapi.v3arch.asyncio")

# pysnmp class name -> net-snmp-style type token (parity with the CLI client).
_TOKEN = {
    "Integer": "INTEGER",
    "Integer32": "INTEGER",
    "Gauge32": "Gauge32",
    "Unsigned32": "Gauge32",
    "Counter32": "Counter32",
    "Counter64": "Counter64",
    "TimeTicks": "Timeticks",
    "IpAddress": "IpAddress",
    "ObjectIdentifier": "OID",
    "ObjectIdentity": "OID",
}
_INT_CLASSES = frozenset(
    {"Integer", "Integer32", "Gauge32", "Unsigned32", "Counter32",
     "Counter64", "TimeTicks"}
)
_ABSENT_CLASSES = frozenset({"NoSuchObject", "NoSuchInstance", "EndOfMibView"})


def _octet_value(raw: bytes) -> tuple[str | bytes, str]:
    """Render an octet string as net-snmp does: printable -> STRING, else Hex."""
    if raw == b"" or all(0x20 <= b < 0x7F for b in raw):
        return raw.decode("ascii"), "STRING"
    return raw, "Hex-STRING"


def _normalize_varbind(name: Any, value: Any) -> Triple:
    """Convert a pysnmp (name, value) varbind into a normalized SnmpRow triple."""
    oid = str(name).lstrip(".")
    cls = value.__class__.__name__
    if cls in _ABSENT_CLASSES:
        return oid, "", cls.upper()  # e.g. "NOSUCHOBJECT" ∈ ABSENT_TYPES
    if cls in _INT_CLASSES:
        return oid, int(value), _TOKEN[cls]
    if cls == "OctetString":
        norm, token = _octet_value(bytes(value.asOctets()))
        return oid, norm, token
    if cls in ("ObjectIdentifier", "ObjectIdentity"):
        return oid, value.prettyPrint().lstrip("."), "OID"
    if cls == "IpAddress":
        return oid, value.prettyPrint(), "IpAddress"
    return oid, value.prettyPrint(), cls  # textual fallback


class PysnmpClient:
    """Read-only async SNMP client for a single switch."""

    def __init__(
        self,
        host: str,
        community: str,
        *,
        port: int = 161,
        timeout: float = 2.0,
        retries: int = 1,
    ) -> None:
        self.host = host
        self.community = community
        self.port = port
        self.timeout = timeout
        self.retries = retries

    async def _do_get(self, oids: list[str]) -> list[Triple]:
        hlapi = _pysnmp_asyncio()
        engine = hlapi.SnmpEngine()
        try:
            target = await hlapi.UdpTransportTarget.create(
                (self.host, self.port), timeout=self.timeout, retries=self.retries
            )
            err_ind, err_stat, _idx, binds = await hlapi.get_cmd(
                engine, hlapi.CommunityData(self.community), target,
                hlapi.ContextData(),
                *[hlapi.ObjectType(hlapi.ObjectIdentity(o)) for o in oids],
            )
            if err_ind or err_stat:
                raise SnmpError(f"GET {oids} on {self.host}: {err_ind or err_stat}")
            return [_normalize_varbind(vb[0], vb[1]) for vb in binds]
        finally:
            engine.close_dispatcher()

    async def _do_walk(self, base_oid: str) -> list[Triple]:
        hlapi = _pysnmp_asyncio()
        engine = hlapi.SnmpEngine()
        rows: list[Triple] = []
        try:
            target = await hlapi.UdpTransportTarget.create(
                (self.host, self.port), timeout=self.timeout, retries=self.retries
            )
            async for err_ind, err_stat, _idx, binds in hlapi.bulk_walk_cmd(
                engine, hlapi.CommunityData(self.community), target,
                hlapi.ContextData(), 0, 25,
                hlapi.ObjectType(hlapi.ObjectIdentity(base_oid)),
                lexicographicMode=False,
            ):
                if err_ind or err_stat:
                    raise SnmpError(
                        f"WALK {base_oid} on {self.host}: {err_ind or err_stat}"
                    )
                done = False
                for vb in binds:
                    oid, value, typ = _normalize_varbind(vb[0], vb[1])
                    if typ == "ENDOFMIBVIEW":
                        # Benign terminator (mirrors the sync client's
                        # _END_OF_MIB_MARKERS): stop, keep rows so far.
                        done = True
                        break
                    if typ.upper() in ABSENT_TYPES:
                        raise SnmpError(
                            f"absent OID in pysnmp WALK response: {oid}"
                        )
                    rows.append((oid, value, typ))
                if done:
                    break
            return rows
        finally:
            engine.close_dispatcher()

    async def get(self, oids: list[str]) -> list[SnmpRow]:
        if not oids:
            return []
        try:
            raw = await self._do_get(oids)
        except SnmpError:
            raise
        except Exception as exc:
            raise SnmpError(f"GET {oids} on {self.host} failed: {exc}") from exc
        rows: list[SnmpRow] = []
        for oid, value, typ in raw:
            if typ.upper() in ABSENT_TYPES:
                raise SnmpError(f"absent OID in pysnmp GET response: {oid}")
            rows.append(SnmpRow(oid, value, typ))
        return rows

    async def walk(self, base_oid: str) -> list[SnmpRow]:
        try:
            raw = await self._do_walk(base_oid)
        except SnmpError:
            raise
        except Exception as exc:
            raise SnmpError(f"WALK {base_oid} on {self.host} failed: {exc}") from exc
        return [
            SnmpRow(oid, value, typ)
            for oid, value, typ in raw
            if typ.upper() not in ABSENT_TYPES
        ]
