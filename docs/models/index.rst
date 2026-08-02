Switch models
=============

Every model this library knows is a frozen :py:class:`~netgear_switch.registry.SwitchModel`
record in ``src/netgear_switch/registry.py``. The table below is generated from
that registry at documentation build time, so it cannot drift from the code.

.. ngsw-model-table::

Every model listed above is backed by a real device capture or a live run
against the hardware. :py:func:`~netgear_switch.registry.get_model` resolves a key — or
an alias, such as ``s3300`` — to the record; ``ngsw models`` prints the whole
registry, including the entries these tables leave out, named below.

.. ngsw-unverified-note::

Per-model pages
---------------

Each page carries the model's registry facts, its full operation-by-backend
support matrix, and the behaviour measured on it — including the quirks that
show up only on that firmware.

.. toctree::
   :maxdepth: 1

   m4300-24x
   m4300-16x
   gsm7252ps
   gsm7228ps
   gs728tpp
   gs110emx
   gs305ep
   gs105pe

Grouped by class
----------------

The class decides which protocols are available at all.

**Fully Managed** — full SNMP with the Netgear ``4526.10`` vendor subtree, a
FASTPATH CLI over SSH and telnet, and a web UI.

* :doc:`m4300-24x` — 10G aggregation, no PoE, FASTPATH 12.0.13.8.
* :doc:`m4300-16x` — 10G with PoE on every port, FASTPATH 12.0.19.15.
* :doc:`gsm7252ps` — 52 ports, 48 PoE; the widest verified coverage here.

**Smart Managed Pro** — SNMP and a web UI; one also has a CLI.

* :doc:`gsm7228ps` — the S3300-52X-PoE+, vendor subtree ``4526.11``, CLI over
  telnet on port 60000.
* :doc:`gs728tpp` — no vendor OIDs at all; standard MIBs and a GoAhead XML web
  API.

**Plus** — no SNMP agent whatsoever. Managed over :doc:`../protocols/nsdp` and
the web UI.

* :doc:`gs110emx` — 10 ports, multi-gigabit, NSDP v2 write authentication.
* :doc:`gs305ep` — 5 ports, 4 PoE; PoE only reachable over HTTP.
* :doc:`gs105pe` — 5 ports, no PSE, no MAC table on any interface.

Cross-model comparison
----------------------

:doc:`support` carries the full grids — which protocols each model exposes,
which operations each protocol serves, and every remaining backend-parity gap
with its reason.

Reading the support tables
--------------------------

A ``—`` cell is a genuine refusal with a stated reason, not an unimplemented
feature. A ``?`` cell means the operation is implemented but gated off because
that backend's output has not been cross-verified against live hardware; the
facade refuses to dispatch rather than hand back unchecked data. The same
verdicts are available in code from :py:func:`~netgear_switch.capabilities.support`.
