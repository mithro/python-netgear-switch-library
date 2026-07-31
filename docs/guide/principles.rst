Design principles
=================

Five rules govern this library. Each exists because it was broken in practice,
and each is stated here with the concrete failure that produced it — an abstract
principle is easy to rationalise around, a remembered bug is not. The canonical
text lives in ``CLAUDE.md`` at the repository root.

They matter to *users* of the library because they explain what its behaviour
guarantees, and what a message from it actually means.

1. Fail fast and loud
---------------------

An operation that cannot be performed as asked **raises**, with the detail
needed to debug it: which backend, which OID, URL or command, and what the
device answered. Nothing is papered over.

In particular, **the protocol never changes mid-operation**. Ask for SNMP and
you get SNMP or an error.

*Why:* the facade used to loop over SNMP → NSDP → HTTP, silently returning the
next backend's answer when one raised. That concealed a real defect for months —
``HttpReader.get_vlans`` returned no untagged ports at all on the managed
switches, invisible because SNMP quietly answered in its place. It also made
every past "HTTP verified" claim untrustworthy, because the HTTP path may never
have run. On a write it is worse: an operator who deliberately restricts SNMP
write access could have their change pushed over another protocol without being
told.

Corollaries:

* Cross-backend comparison is only evidence if each backend answered on its own
  merits. Verification drives one backend directly.
* A degraded or partial result is a failure. No ``[]``, ``None`` or silently
  truncated value where the caller asked a question that could not be answered.
* Errors name the thing that failed — ``commitFailed`` on *which* OID, with
  *which* value, for *which* model.

2. Backends have parity
-----------------------

Every backend a model supports offers the **same** functionality. The point of
having several is that the *caller* chooses — when SNMP writes are locked down,
or when the web UI is the only thing reachable through a firewall. That choice
only exists if the backends are equivalent.

A backend missing an operation is a **missing implementation**, to be built. It
is not a device limitation until proven otherwise. Remaining gaps are listed in
:doc:`../models/support`, with the reason for each.

*Why:* every managed switch was once marked as having no HTTP VLAN-membership
path, so the web UI could neither report tagged/untagged membership nor write
it — while the same file already carried the working page for a sibling model.
There was also no CLI write backend at all, though the FASTPATH command
sequences were known to work.

3. Models have parity
---------------------

A feature is not done when it works on one switch. It is done when it works on
**every** registered model, verified against every reachable one. Firmware
differs between SKUs of the same family — never extrapolate.

*Why:* the M4300-16X was assigned its VLAN-write dialect purely by inference
from the M4300-24X ("same firmware family"). It runs different firmware
(12.0.19.15 versus 12.0.13.8) and *accepts* Q-BRIDGE writes the -24X refuses, so
the inference could not be trusted even though it happened to land on the right
answer.

Measuring it replaced both the inference and the counter-example with the actual
rule: ``dot1qVlanStaticEgressPorts`` is writable only while **no interface on
the switch** is in access mode — switch-wide, not per-VLAN, and the same on both
firmwares. An A/B/A on the -16X's port 1/0/1, issuing byte-identical writes
while flipping only that one port's mode, gave general → ``noError``, access →
``commitFailed``, general → ``noError``, trunk → ``noError``, access →
``commitFailed``, general → ``noError``. The -24X looks different only because
21 of its 24 ports are access-mode, so the column is never writable there.

4. A failure is a bug here first
--------------------------------

Not flaky hardware. Not "the switch is slow". Before blaming the device:

* **Have you actually debugged it,** or only observed it fail? What does the
  device say when asked directly — its CLI, its web UI, its own config dump?
* **Is another setting required first?** Some writes are gated by other state.
* **Are you sending the wrong details** — community, username, password, port,
  value type, encoding, field width, or **ordering** of operations?
* **Did you try every mechanism the device exposes,** or only the first one you
  thought of?

Only then, and only with captured device output as proof, may a limitation be
recorded — naming the firmware version it applies to.

*Why,* three times over in one session:

* "The S3300's SNMP agent is dead." It was not. The switch has no ``private``
  community; it publishes ``pib`` and ``public``, both read-write. An agent
  **silently drops** an unauthorised request, so a wrong write community looks
  exactly like an unreachable host. Reads had worked the whole time.
* "The M4300 refuses VLAN writes." It does not. One OID had been tried; the
  switch's own vendor switchport table accepts membership writes.
* "The S3300 forces untagged membership." It does not. Setting the egress bit
  auto-untags the port, and that side effect beats an untagged varbind in the
  **same** PDU. Two PDUs, egress first, work perfectly.

5. The fake must behave like the hardware
-----------------------------------------

The :doc:`virtual switch <../fake/index>` exists so this library can be tested
honestly without hardware. That only works if it is a **faithful** model of the
real devices — including their refusals, quirks and ordering requirements, not
just their happy paths.

* When live hardware differs from the mock, **the mock is wrong** and gets
  fixed. Never adjust a test's expectation to match a mock already known to be
  unfaithful, and never "fix" a divergence by making the real-hardware path
  lenient.
* The mock reproduces **rejections** as faithfully as successes: the right SMI
  error status (``commitFailed`` versus ``notWritable`` versus ``wrongValue``),
  the same preconditions, the same side effects, the same ordering sensitivity.
* The mock is an **independent** source of truth. A value it derives with the
  same formula as the code under test can only ever agree with that code, and
  proves nothing. Measured device values are seeded instead.
* Every behaviour learned from hardware is encoded in the mock **and** pinned by
  a test in the same change, with a comment naming the host and firmware it was
  observed on.

*Why:* a VLAN ``PortList``-width defect went unnoticed because the mock emitted
the bitmap using the same wrong formula as the buggy writer. Mock and code
agreed with each other while both disagreed with every real switch — whose
widths are 79, 131 and 45 bytes, none of them derivable from the port count. The
round trip was green and meaningless.

In practice
-----------

* **Ground everything in real devices.** Fixtures come from captured traffic and
  pages, never from imagination or from a MIB's ideal semantics.
* **Diff the device, don't guess the MIB.** To learn how something is
  configured: capture a full walk to a file, change the setting through the
  switch's own UI or CLI, walk again, diff. That is how the vendor switchport
  table was found with no MIB file available.
* **Never leave a device changed.** See :ref:`live-hardware-rules`.
* **Say what you actually verified.** "Live-verified on host X, firmware Y" is
  not the same claim as "assumed", and this library's registry, specs and
  documentation keep them apart.
