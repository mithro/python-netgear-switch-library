# src/netgear_switch/virtual/faces/snmp.py
"""A real pysnmp v2c command-responder agent serving a StateMibView.

This wires the pure ``StateMibView`` (Task 14) into an actual pysnmp v7 agent
bound to an ephemeral UDP port on 127.0.0.1, so both transport clients
(``NetsnmpCliClient`` and ``PysnmpClient``) can be exercised end-to-end
against a mock switch.

pysnmp is imported lazily (only when ``VirtualSnmpFace.start()`` runs, inside
the background thread), so this module — and the rest of the ``virtual``
package — stays importable without the ``[testing]``/``[async]`` extra
installed. pysnmp ships no type stubs; every reference is resolved through
``importlib.import_module`` (returning ``Any``), the same single-seam
pattern used by ``transport/aio/snmp_pysnmp.py``, so mypy --strict needs no
``ignore_missing_imports`` override for pysnmp at all.

**Adaptations from the Task 15 brief's sample code** (the brief explicitly
warned its snippets might be stale — they were):

* The brief's ``_StateInstrum`` sketch used ``read_vars``/``read_next_vars``.
  The *actual* installed pysnmp v7 MIB-instrumentation-controller callback
  names are ``read_variables``/``read_next_variables`` (confirmed by reading
  ``pysnmp.smi.instrum.AbstractMibInstrumController`` and how
  ``pysnmp.entity.rfc3413.cmdrsp.{Get,Next,Bulk}CommandResponder`` invoke
  them: ``self.snmpContext.get_mib_instrum(contextName).read_variables``.
  ``readVars``/``readNextVars`` exist only as *deprecated old-camelCase*
  aliases for those, never as ``read_vars``/``read_next_vars``).
* Rather than raising ``NoSuchInstanceError``/``EndOfMibViewError`` (which
  ``GetCommandResponder``/``NextCommandResponder`` would turn into a
  whole-PDU ``genErr`` — not spec-conformant SNMPv2c behaviour, and not what
  ``PysnmpClient``/net-snmp expect), this controller embeds the real
  ``pysnmp.proto.rfc1905`` exception *values* (``noSuchInstance`` /
  ``endOfMibView``) directly into the response var-bind, exactly as a real
  SNMPv2c agent does and exactly what both transport clients already treat
  as an absent-OID / walk-terminator marker.
* The custom controller is a plain class (no pysnmp base class to inherit
  from without a *static* pysnmp import, which would defeat the lazy-import
  seam) — it only needs to duck-type ``read_variables``/``read_next_variables``,
  which is all ``cmdrsp`` ever calls on it.
* The engine/transport/VACM setup follows ``pysnmp.entity.config``'s
  ``add_transport``/``add_v1_system``/``add_vacm_user`` (the real, current
  function names — no ``addTransport``/``addV1System`` camelCase, those are
  deprecated aliases too).
"""
from __future__ import annotations

import asyncio
import contextlib
import importlib
import socket
import threading
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .mibview import StateMibView

# SNMPv2c security model ID (pysnmp.proto.secmod.rfc2576.SnmpV2cSecurityModel
# .SECURITY_MODEL_ID); SNMPv1's is 1. Not exported anywhere more convenient.
_SNMP_V2C_SECURITY_MODEL = 2


def _pysnmp_engine() -> Any:
    return importlib.import_module("pysnmp.entity.engine")


def _pysnmp_config() -> Any:
    return importlib.import_module("pysnmp.entity.config")


def _pysnmp_cmdrsp() -> Any:
    return importlib.import_module("pysnmp.entity.rfc3413.cmdrsp")


def _pysnmp_context() -> Any:
    return importlib.import_module("pysnmp.entity.rfc3413.context")


def _pysnmp_udp() -> Any:
    return importlib.import_module("pysnmp.carrier.asyncio.dgram.udp")


def _pysnmp_rfc1902() -> Any:
    return importlib.import_module("pysnmp.proto.rfc1902")


def _pysnmp_rfc1905() -> Any:
    return importlib.import_module("pysnmp.proto.rfc1905")


def _to_smi_value(snmp_type: str, value: str) -> Any:
    """Convert one ``StateMibView`` ``(snmp_type, value)`` pair to the
    matching pysnmp SMI value object, so it goes on the wire with the right
    BER type.

    ``OCTETSTR`` values are always encoded latin-1 -> bytes: ``oid_map()``
    (Task 14) stores every octet-string value, printable or not (VLAN
    bitmaps, LLDP chassis IDs, port names, "Not Supported" sensor text), as a
    ``str`` produced via ``chr(byte)``/plain ASCII, so a latin-1 encode is
    the exact inverse in every case and round-trips the seeded bytes exactly.
    """
    rfc1902 = _pysnmp_rfc1902()
    if snmp_type == "INTEGER":
        return rfc1902.Integer32(int(value))
    if snmp_type == "Gauge32":
        return rfc1902.Gauge32(int(value))
    if snmp_type == "Counter32":
        return rfc1902.Counter32(int(value))
    if snmp_type == "Counter64":
        return rfc1902.Counter64(int(value))
    if snmp_type == "IPADDR":
        return rfc1902.IpAddress(value)
    if snmp_type == "OCTETSTR":
        return rfc1902.OctetString(value.encode("latin-1"))
    raise ValueError(f"unsupported snmp_type token: {snmp_type!r}")


class _StateInstrum:
    """Adapts ``StateMibView.get``/``get_next`` to pysnmp's MIB-instrumentation
    controller callbacks.

    Owns no ordering/lookup logic of its own (that all lives in
    ``StateMibView``) — it only translates var-bind OIDs to/from tuples and
    ``(snmp_type, value)`` pairs to pysnmp SMI values. Duck-typed rather than
    subclassing a pysnmp base class, since pysnmp is only ever imported
    lazily here.
    """

    def __init__(self, view: StateMibView) -> None:
        self._view = view
        rfc1905 = _pysnmp_rfc1905()
        self._no_such_instance = rfc1905.noSuchInstance
        self._end_of_mib_view = rfc1905.endOfMibView

    def read_variables(
        self, *var_binds: tuple[Any, Any], **_context: Any
    ) -> list[tuple[Any, Any]]:
        """Answer a GET: exact-match lookup per requested OID."""
        out: list[tuple[Any, Any]] = []
        for name, _val in var_binds:
            entry = self._view.get(tuple(name))
            if entry is None:
                out.append((name, self._no_such_instance))
            else:
                _oid, snmp_type, value = entry
                out.append((name, _to_smi_value(snmp_type, value)))
        return out

    def read_next_variables(
        self, *var_binds: tuple[Any, Any], **_context: Any
    ) -> list[tuple[Any, Any]]:
        """Answer one GETNEXT/GETBULK step: the next OID after each request."""
        out: list[tuple[Any, Any]] = []
        for name, _val in var_binds:
            entry = self._view.get_next(tuple(name))
            if entry is None:
                out.append((name, self._end_of_mib_view))
            else:
                next_oid, snmp_type, value = entry
                out.append((next_oid, _to_smi_value(snmp_type, value)))
        return out


class VirtualSnmpFace:
    """A pysnmp v2c command-responder agent serving a ``StateMibView``.

    Runs the pysnmp asyncio dispatcher on a dedicated background thread with
    its own event loop, bound to an ephemeral UDP port on ``host``.
    """

    def __init__(
        self, view: StateMibView, *, community: str = "public", host: str = "127.0.0.1"
    ) -> None:
        self._view = view
        self._community = community
        self._host = host
        self._port = 0
        self._engine: Any = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._start_error: Exception | None = None
        # The raw UDP socket the agent binds, captured here (not fished out of
        # pysnmp) since it is this exact object we hand to
        # ``UdpTransport.open_server_mode(sock=sock)`` in ``_run`` — asyncio's
        # ``create_datagram_endpoint(sock=...)`` path never dup()s a passed-in
        # socket, it wraps this literal object. See ``stop()`` for why closing
        # it ourselves, deterministically, is necessary.
        self._sock: socket.socket | None = None

    def start(self) -> int:
        """Bind the UDP socket, start the agent thread, and return the port."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self._host, 0))
        self._port = sock.getsockname()[1]
        self._sock = sock

        self._ready.clear()
        self._start_error = None
        self._thread = threading.Thread(
            target=self._run, args=(sock,), name="virtual-snmp-face", daemon=True
        )
        self._thread.start()
        self._ready.wait()
        if self._start_error is not None:
            raise self._start_error
        return self._port

    def stop(self) -> None:
        """Close the dispatcher, join the background thread, and close the
        agent's UDP socket deterministically.

        pysnmp's ``AsyncioDispatcher.close_dispatcher`` closes the asyncio
        transport by scheduling its real close (``loop.call_soon(...)``) for
        the *next* loop iteration, then immediately calls ``loop.stop()`` in
        that same callback — which breaks ``run_forever()`` before that next
        iteration ever runs. ``_run`` already compensates for this (it pumps
        the loop once more after ``run_forever()`` returns, so pysnmp's own
        deferred close normally does run before the loop is closed). Closing
        ``self._sock`` here too, after the thread has fully stopped, is a
        deliberate belt-and-braces backstop: it guarantees the fd is closed
        deterministically even if that compensation ever fails to run (e.g.
        a future pysnmp change altering the callback ordering), rather than
        depending on GC to eventually close it and emit a ResourceWarning.
        """
        if self._loop is not None and self._engine is not None:
            self._loop.call_soon_threadsafe(self._engine.close_dispatcher)
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._engine = None
        self._loop = None
        self._thread = None
        if self._sock is not None:
            # Already closed (e.g. by pysnmp's own deferred cleanup) is fine.
            with contextlib.suppress(OSError):
                self._sock.close()
            self._sock = None

    def _run(self, sock: socket.socket) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            engine_mod = _pysnmp_engine()
            config = _pysnmp_config()
            cmdrsp = _pysnmp_cmdrsp()
            context = _pysnmp_context()
            udp = _pysnmp_udp()

            engine = engine_mod.SnmpEngine()
            transport = udp.UdpTransport(loop=loop).open_server_mode(sock=sock)
            config.add_transport(engine, udp.DOMAIN_NAME, transport)

            config.add_v1_system(engine, "netgear-virtual", self._community)
            config.add_vacm_user(
                engine,
                _SNMP_V2C_SECURITY_MODEL,
                "netgear-virtual",
                "noAuthNoPriv",
                readSubTree=(1, 3, 6, 1),
            )

            snmp_context = context.SnmpContext(engine)
            snmp_context.context_names[b""] = _StateInstrum(self._view)

            cmdrsp.GetCommandResponder(engine, snmp_context)
            cmdrsp.NextCommandResponder(engine, snmp_context)
            cmdrsp.BulkCommandResponder(engine, snmp_context)
        except Exception as exc:  # surfaced to start() via _start_error, not swallowed
            self._start_error = exc
            self._ready.set()
            loop.close()
            return

        self._engine = engine
        self._loop = loop
        self._ready.set()
        try:
            engine.open_dispatcher()
        finally:
            # ``stop()`` schedules ``engine.close_dispatcher()`` then calls
            # ``loop.stop()`` in that very callback — before the asyncio
            # transport's own deferred close (itself scheduled via
            # ``loop.call_soon`` a moment earlier, by
            # ``close_dispatcher``'s ``transport.close_transport()``) gets a
            # turn to run. Left alone, that means the real UDP socket is
            # never closed by asyncio's own machinery, only by GC later —
            # a reproducible "unclosed transport"/"unclosed socket"
            # ResourceWarning on every stop. Running the loop for one more
            # complete iteration here (still on this same thread, before
            # ``loop.close()``) lets that already-queued deferred callback
            # execute, so the transport (and the raw socket it wraps —
            # ``self._sock`` in ``start()``) close deterministically instead.
            loop.run_until_complete(asyncio.sleep(0))
            loop.close()
