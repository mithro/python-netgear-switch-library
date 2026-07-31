Switch models
=============

Every model this library knows is a frozen record in
``src/netgear_switch/registry.py``. The table below is generated from that
registry at documentation build time, so it cannot drift from the code.

.. ngsw-model-table::

``ngsw models`` prints the same list. `get_model` resolves a key — or an alias,
such as ``s3300`` — to the `SwitchModel` record.

.. note::

   **Status** distinguishes measurement from assumption. *live-verified* means
   the model's fields are backed by a real device capture or a live run.
   **unverified** means the model was registered from a specification sheet
   with no capture behind it: standard-MIB reads should work, but the port
   counts, the vendor OID family and every vendor-specific read are a
   best-effort guess. Nothing in this project treats an unverified model as
   evidence of anything.

Fully Managed
-------------

M4300-24X (``m4300-24x``)
~~~~~~~~~~~~~~~~~~~~~~~~~

The XSM4324CS, running FASTPATH 12.0.13.8. SNMP, web UI (the Cheetah ``/v1``
interface) and the FASTPATH CLI over SSH or telnet.

It has **no PSE silicon**, so every PoE operation is refused on every backend —
not a gap in this library, and reported identically whichever protocol you ask.
Its registry ``port_count`` of 28 is a nominal upper bound used to size VLAN and
port bitmaps; the device reports 24 physical ports, and the CLI reader iterates
the switch's actual ports rather than trusting the count.

VLAN membership writes use the **vendor switchport table**, not Q-BRIDGE: the
standard static ``PortList`` columns here are read-only mirrors that
``commitFail`` even when written with byte-identical content.

.. ngsw-model-support:: m4300-24x

M4300-16X (``m4300-16x``)
~~~~~~~~~~~~~~~~~~~~~~~~~

The XSM4316, running FASTPATH 12.0.19.15 — a *different* firmware from the -24X,
which is why its behaviour was measured rather than inherited. All 16 ports are
PoE.

Its web UI is on **HTTPS port 49152**, not port 80, and the library's endpoint
spec carries that. See :doc:`../guide/principles` for the A/B/A measurement that
settled its VLAN-write dialect.

.. ngsw-model-support:: m4300-16x

GSM7252PS (``gsm7252ps``)
~~~~~~~~~~~~~~~~~~~~~~~~~

52 ports, 48 of them PoE. SNMP, the XE FASTPATH web UI, and the CLI over SSH or
telnet. Unlike the M4300s, its Q-BRIDGE static ``PortList`` columns really are
writable, so it uses the standard VLAN-write dialect — verified, not assumed: a
walk of the vendor switchport table returns zero rows on this switch.

This is the model with the widest verified backend coverage in the fleet, and
the one the cross-backend equivalence tests lean on hardest.

.. ngsw-model-support:: gsm7252ps

M7300-24XF (``m7300``) — unverified
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Registered from a product brief so a facade can be constructed for it. Which
exact SKU is in service is itself unconfirmed, and the ``4526.10`` vendor
subtree is a family guess. Standard-MIB reads should work; sensors and vendor
PoE power are unverified.

Smart Managed Pro
-----------------

S3300-52X-PoE+ (``gsm7228ps``, alias ``s3300``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

52 ports, 48 PoE — despite the ``GSM7228PS`` part-number family suggesting 28.
The registered key is ``gsm7228ps``; ``s3300`` resolves to the same record,
because the firmware's own ``sysDescr`` and the marketing name are "S3300-52X".

Identified by **sysObjectID**, not ``sysDescr``: its description text is
deliberately indistinguishable from the unregistered S3300-28X, so matching on
it would be a coin flip.

Two behaviours here are unusual and both are modelled:

* Its FASTPATH CLI is reachable over **telnet on port 60000**, not 23, and it
  runs no SSH listener on any port — so its CLI backend is telnet only.
* Setting a port's VLAN egress bit **auto-untags** that port, and the side
  effect beats an untagged varbind in the same PDU. Its membership writes are
  therefore split into two PDUs, egress first.

.. ngsw-model-support:: gsm7228ps

GS728TPP (``gs728tpp``)
~~~~~~~~~~~~~~~~~~~~~~~

28 ports, 24 PoE+. Its SNMP agent implements **zero Netgear vendor OIDs** — a
walk of ``1.3.6.1.4.1.4526`` answers ``noSuchObject`` — and serves everything
from standard MIBs instead: per-port PoE from RFC 3621, the management IP from
``ipAddrTable``, and the fan and PSU *inventory* from ENTITY-MIB. There is no
live sensor value anywhere in its SNMP.

Its web UI is a third distinct scheme, the GoAhead ``wcd`` XML API, whose login
is a ``GET`` with the credentials in the query string rather than a form POST.

Two honest per-backend differences remain, and they are differences rather than
bugs: SNMP has no per-port PoE milliwatt column, and SNMP sensors are inventory
only. Per-port statistics are SNMP-only on this UI.

.. ngsw-model-support:: gs728tpp

XS748T (``xs748t``) — unverified
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

48 × 10G copper, registered from the base specification. HTTP is deliberately
**omitted** rather than merely unverified: no login or read flow has been
captured, and listing it would imply a web-UI integration that does not exist
in this codebase.

Plus
----

Plus switches have no SNMP at all. They are managed over NSDP and their web UI.

GS110EMX (``gs110emx``)
~~~~~~~~~~~~~~~~~~~~~~~

10 ports, no PoE. NSDP and the Gambit web UI.

Neither interface exposes a MAC/FDB table, LLDP neighbours or environmental
sensors — established independently on both, by an exhaustive NSDP tag sweep of
a live unit and by the web UI's page set, rather than assumed from one and
extrapolated to the other.

.. ngsw-model-support:: gs110emx

GS305EP (``gs305ep``)
~~~~~~~~~~~~~~~~~~~~~

5 ports, 4 PoE. NSDP plus the ``MERGE_HASH_CGI`` web UI. PoE status and
configuration are available over the web UI — NSDP has no PoE tag at all — which
is a clean illustration of why naming a backend matters.

.. ngsw-model-support:: gs305ep

GS105PE (``gs105pe``)
~~~~~~~~~~~~~~~~~~~~~

5 ports, and **zero PoE ports** — confirmed, not assumed: the web UI's PoE
status page returns HTTP 404 on a real unit. The product's "PoE pass-through"
means it can *be powered* over PoE, which is not a claim to source power.

Like the GS110EMX it exposes no MAC/FDB table over any interface — a confirmed
firmware limitation rather than something merely unread.

.. ngsw-model-support:: gs105pe

Reading these tables
--------------------

A ``—`` cell is a genuine refusal with a stated reason, not an unimplemented
feature. A ``?`` cell means the operation is implemented but gated off because
that backend's output has not yet been cross-verified against live hardware; the
facade refuses to dispatch rather than hand back unchecked data.

The complete cross-model view, and the list of remaining backend-parity gaps, is
in :doc:`support`.
