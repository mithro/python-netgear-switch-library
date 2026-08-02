How the fake is built
=====================

Read this if you are extending the mock, adding a model, or deciding whether to
trust a particular answer it gives.

One state, several faces
------------------------

.. code-block:: text

   tests/fixtures/captures/*.json     real device capture
              │
              ▼
   virtual/seed.py                    seed_<model>() hand-authors a state
              │
              ▼
   virtual/state.py                   VirtualSwitchState  ── the only truth
              │
     ┌────────┼────────┬─────────┐
     ▼        ▼        ▼         ▼
   faces/   faces/   faces/    faces/
   snmp.py  nsdp.py  http.py   cli.py

`netgear_switch.virtual.state.VirtualSwitchState` holds everything a switch
knows: ports (``PortSim``), VLANs (``VlanSim``), PVIDs, PoE (``PoeSim``),
sensors, the ENTITY-MIB inventory, the MAC table, bridge-port mappings, LLDP
neighbours, management configuration, identity strings, and the NSDP-specific
fields — authentication version, rotating salt, QoS engine, port mirroring, IGMP
snooping.

It also carries the **per-model protocol quirks** that make the mock faithful:
the measured VLAN ``PortList`` width, the switchport mode of each port, whether
a write should be rejected and with which error, and how many egress writes have
arrived in the current PDU.

Because there is exactly one state, a change written over one protocol is
visible over every other. That is not a convenience — it is what makes
cross-backend equivalence a meaningful test rather than a comparison of two
independent fictions.

The faces
---------

.. list-table::
   :header-rows: 1
   :widths: 20 20 60

   * - Face
     - Binds
     - Notes
   * - ``faces/snmp.py``
     - real UDP socket
     - A full agent: GET, GETNEXT, GETBULK and SET, including multi-varbind
       atomicity and rollback. Reads through ``faces/mibview.py``.
   * - ``faces/nsdp.py``
     - real UDP socket
     - Parses and emits real NSDP frames, models v1 and v2 authentication,
       rejects with the right error code and blames the right TLV tag.
   * - ``faces/http.py``
     - real TCP socket
     - Serves each model's real page set, rendered by the ``web_*.py`` modules
       from state. Validates the login POST and reproduces the M4300 ``Referer``
       CSRF check.
   * - ``faces/cli.py``
     - nothing
     - In-process: implements the ``CliSession`` protocol directly, so no SSH
       or telnet server is needed. Reached via :py:obj:`~netgear_switch.virtual.server.VirtualSwitch.cli_session`.

``faces/mibview.py`` deserves a note. It builds a **sorted** OID view from the
state so GETNEXT and GETBULK have real lexicographic-ordering semantics rather
than dictionary iteration order. A write mutates the state and rebuilds the view;
a multi-varbind SET defers the rebuild until every varbind has applied, so a
failure mid-PDU can roll the whole thing back — the atomicity a real agent has.

The per-model web renderers
---------------------------

The HTML dialects differ enough that each has its own renderer:
``web_fastpath_xui.py``, ``web_fastpath_vlan.py``, ``web_m4300.py``,
``web_gsm7252ps.py``, ``web_gsm7228ps.py``, ``web_gs110emx.py``,
``web_gs105pe.py`` and ``web_gs728tpp.py``, with shared pieces in ``web.py``.

``web_gs110emx_templates.py`` is pure data: single-line HTML strings copied
byte-for-byte from real captures. It is excluded from lint precisely because a
literal capture has no meaningful style to enforce, and reformatting it would
destroy its value as evidence.

From a real switch to a seed
----------------------------

.. code-block:: sh

   ngsw --switch core capture tmp/core.json

:doc:`ngsw capture <../cli>` records the switch's full state via
:py:obj:`~netgear_switch.sync_api.SyncSwitch.snapshot`, and — given live access and a raw-walk callable — the
reference ``snmpbulkwalk`` output alongside it. The result is a JSON file used
**for reference** when hand-authoring a seed; the mock deliberately never loads
it directly.

That last point is the important one. A seed is written by hand *from* a
capture, which forces a human to decide what each value means, and lets the
committed capture stay an independent artefact to check against. Four captures
are committed under ``tests/fixtures/captures/``, and the M4300 seeds are
transcribed directly from them.

Seeds also carry a documented distinction between what is *captured-real* and
what is *illustrative*. Each ``seed_*`` function's docstring says which is
which — so nobody later mistakes a plausible filler value for a measurement.

Rules for changing the mock
---------------------------

These are not stylistic preferences; each one exists because breaking it caused
a real defect to go unnoticed.

**When hardware and mock disagree, fix the mock.** Never adjust a test's
expectation to match a mock already known to be unfaithful, and never resolve a
divergence by making the real-hardware path more lenient.

**Never derive a value the code under test also derives.** Seed the measured
value instead. A mock that computes a bitmap width with the same formula as the
writer can only ever agree with that writer — which is exactly how the
``PortList``-width defect survived a green test suite while every real switch
disagreed with both.

**Model refusals as carefully as successes.** The right SMI error status, the
same preconditions, the same side effects, the same ordering sensitivity. A mock
that accepts everything tests only half your code, and it is the wrong half.

**Every hardware finding lands in the mock *and* a test, in the same change,**
with a comment naming the host and firmware version it was observed on. A
finding that lives only in a report gets regressed by the next change.

Independent cross-checks
------------------------

A mock validated only by the client that talks to it proves nothing, so the NSDP
face has been driven by third-party implementations that know nothing about this
library:

* **ProSafeLinux** decodes both mock switches completely, and every value it
  reports matches the seed.
* **ngadmin** (a C implementation) validated the packet header — and surfaced a
  real four-byte sequence-number bug in the process, which was fixed.

The harness is a veth pair into a network namespace, so NSDP's broadcast
behaviour is exercised rather than bypassed.

Adding a model
--------------

#. **Register it** in ``src/netgear_switch/registry.py``: key, display name,
   class, port and PoE counts, backends, vendor OID subtree. Set
   ``verified=False`` until a capture exists, and say in a comment exactly which
   fields are guesses.
#. **Add the protocol specs** it needs — ``HttpModelSpec`` in
   ``src/netgear_switch/protocols/http/endpoints.py`` with ``reads_verified=False``,
   and/or ``CliModelSpec`` in ``src/netgear_switch/protocols/cli/commands.py``.
#. **Capture a real device** with ``ngsw capture``, and commit the capture under
   ``tests/fixtures/captures/`` if it is to be evidence.
#. **Write a seed** in ``src/netgear_switch/virtual/seed.py``, transcribing from
   the capture, and register it in the ``_SEEDS`` map in
   ``src/netgear_switch/virtual/server.py``.
#. **Add tests** pinning what the capture showed, including whatever the device
   refuses.
#. **Flip the verification flags** only once the backend's output has been
   cross-verified against the live device — that flag is what lets the facade
   dispatch to it at all.

Every step is deliberately ordered so that a model can be usable before it is
verified, without ever being mistaken for verified.

Where things live
-----------------

.. list-table::
   :header-rows: 1
   :widths: 46 54

   * - Path
     - Contents
   * - ``src/netgear_switch/virtual/state.py``
     - The device state and its write semantics.
   * - ``src/netgear_switch/virtual/seed.py``
     - One seed builder per model.
   * - ``src/netgear_switch/virtual/server.py``
     - :py:class:`~netgear_switch.virtual.server.VirtualSwitch`, the seed map,
       and :py:func:`~netgear_switch.virtual.server.serve_forever`.
   * - ``src/netgear_switch/virtual/faces/``
     - The protocol faces.
   * - ``tests/fixtures/captures/``
     - Committed real-device captures.
   * - ``tests/virtual/``
     - Tests of the mock itself.
   * - ``tests/conftest.py``
     - The per-model :py:class:`~netgear_switch.virtual.server.VirtualSwitch`
       fixtures this project uses.
