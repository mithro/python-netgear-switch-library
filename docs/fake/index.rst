The virtual switch
==================

The library ships **working mock switches** that speak SNMP, NSDP, HTTP and the
FASTPATH CLI on real sockets. Point anything at one: this library, your own
code, ``snmpwalk``, ``curl``, a monitoring agent, a configuration-management
tool.

.. code-block:: sh

   ngsw serve --model gsm7228ps

.. code-block:: text

   [gsm7228ps] host=127.0.0.1
       SNMP udp/36540
       HTTP tcp/42629
       community='public' http_password='password'
   serving 1 mock switch(es); press Ctrl-C to stop

Then, from any tool:

.. code-block:: sh

   snmpwalk -v2c -c public 127.0.0.1:36540 1.3.6.1.2.1.1

Why it is worth trusting
------------------------

A mock is only useful if it behaves like the thing it stands in for. This one is
built to a strict rule: **where the fake differs from real hardware, the fake is
what gets fixed.** Never the test's expectation, and never by making the
real-hardware path more forgiving.

Three consequences follow, and they are what distinguish this from a stub:

**It reproduces refusals, not just successes.** A write the real firmware
rejects is rejected here too — with the same SMI error status (``commitFailed``
versus ``notWritable`` versus ``wrongValue``), the same preconditions, the same
side effects and the same ordering sensitivity. The S3300 mock auto-untags a
port when its egress bit is set, and lets that side effect beat an untagged
varbind in the same PDU, because that is what the real switch does.

**Its values are measured, not computed.** The mock is seeded from real device
captures. Where a value could be derived, it is deliberately seeded instead —
because a mock that derives a value with the same formula as the code under test
can only ever agree with that code.

.. warning::

   That is not hypothetical. A VLAN ``PortList``-width defect went unnoticed for
   a long time because the mock emitted the bitmap using the *same wrong
   formula* as the buggy writer. Mock and library agreed with each other while
   both disagreed with every real switch — whose widths are 79, 131 and 45
   bytes, none derivable from the port count. The round trip was green and
   meaningless. The widths are now seeded from measurement.

**Every behaviour learned from hardware is encoded here and pinned by a test**,
with a comment naming the host and firmware version it was observed on. A
finding that lives only in a report gets regressed by the next change.

The mock has also been cross-checked by tools that know nothing about this
library: the third-party ProSafeLinux NSDP implementation decodes both mock
switches completely with every value matching the seed, and the C tool
``ngadmin`` validated the packet header — and surfaced a real four-byte
sequence-number bug in the process, which was fixed. A mock validated only by
the client that talks to it proves nothing.

What it is not
--------------

* **Not a simulator of forwarding behaviour.** It models the *management
  plane*: the data a switch reports and the configuration it accepts. Frames do
  not traverse it.
* **Not a complete firmware.** Pages, OIDs and tags that the library exercises
  are implemented; a model's full web UI is not reproduced.
* **Not a security boundary.** It accepts a configured community and password
  and models authentication faithfully enough to test against — including NSDP's
  v1 XOR and v2 salted-token schemes — but it is a test double, not a hardened
  service. Bind it to loopback unless you have a reason not to.

How it is put together
----------------------

.. code-block:: text

    seed.py  ── seeds ──▶  VirtualSwitchState  ◀── read/written by ── faces/
   (captured                (one in-memory                          snmp.py
    device                   device state)                          nsdp.py
    values)                                                         http.py
                                                                    cli.py

`netgear_switch.virtual.state.VirtualSwitchState` is the single authoritative
device state: ports, VLANs, PVIDs, PoE, sensors, MAC table, LLDP neighbours,
management configuration, firmware and serial, plus the NSDP-specific fields and
the per-model protocol quirks.

Each **face** serves that one state over a real protocol. Because there is one
state behind all of them, a change written over SNMP is visible over HTTP — the
same cross-protocol consistency a real switch has, and what makes cross-backend
equivalence testable at all.

`netgear_switch.virtual.server.VirtualSwitch` binds whichever faces the model's
registry entry declares, and hands out the ports it actually bound.

Which models are seeded
-----------------------

``gsm7252ps``, ``gsm7228ps``, ``gs110emx``, ``gs305ep``, ``gs105pe``,
``m4300-24x``, ``m4300-16x`` and ``gs728tpp`` all have hand-authored seeds built
from real captures. Any other registered model still constructs — every state
field has a default — but answers from a blank device rather than a realistic
one.

Next
----

* :doc:`serving` — run mocks as daemons and point external tools at them.
* :doc:`testing` — worked examples of testing your own code against the fake.
* :doc:`internals` — the state, the faces, and how a capture becomes a seed.
