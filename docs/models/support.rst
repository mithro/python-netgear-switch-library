Support matrix
==============

Which model can do what, over which protocol. Every table on this page is
generated at build time from ``src/netgear_switch/registry.py`` and
``src/netgear_switch/capabilities.py`` — the same data the library consults when
it dispatches an operation — so a table here cannot disagree with what the code
does.

The same answers are available at runtime:

.. code-block:: python

   from netgear_switch import Backend, support, matrix

   support("gs110emx", Backend.NSDP, "get_poe").supported   # False
   support("gs110emx", Backend.NSDP, "get_poe").reason
   # 'NSDP has no PoE status tag (measured by an exhaustive NSDP tag sweep ...)'

   for capability in matrix():
       ...

.. important::

   These tables describe :py:class:`~netgear_switch.sync_api.SyncSwitch`. The SNMP, NSDP
   and HTTP entries hold for :py:class:`~netgear_switch.aio_api.AsyncSwitch` too, but
   **the CLI columns do not**: all three CLI transports are blocking, so the
   async facade has no CLI backend and refuses SSH, telnet and console outright.
   See :doc:`../guide/concepts`.

Protocol support
----------------

Which backends each model exposes — the model's
:py:attr:`~netgear_switch.registry.SwitchModel.backends`, and exactly what
:py:obj:`~netgear_switch.sync_api.SyncSwitch.resolve_backend` accepts.

.. ngsw-protocol-table::

``SSH`` and ``TELNET`` are two transports for the same FASTPATH command surface.
A third, ``CONSOLE``, drives that same CLI over a serial line; being a transport
rather than a network backend, it is never registered on a model and never
selected automatically.

Read operations
---------------

Rows are operations, columns are models. Each cell names the backends that serve
that operation on that model:

**S** = SNMP · **N** = NSDP · **H** = HTTP web UI · **C** = FASTPATH CLI ·
**—** = not available on any backend.

.. ngsw-operation-table:: reads

Write operations
----------------

.. ngsw-operation-table:: writes

Backend parity gaps
-------------------

Every case where one backend of a model serves an operation and another does
not. This project treats a gap as a **missing implementation to build**, not a
device limitation, unless captured device output proves otherwise — so this
table is a work list as much as a reference.

Operations that are backend-fixed by nature are excluded: ``nsdp_device`` is
NSDP-only, and the two certificate-upload methods name their own transport.

.. ngsw-support-gaps::

How to read a refusal
---------------------

The reasons above are the *same strings* the library raises, because
``capabilities.py`` imports them from the readers and writers rather than
restating them. A refusal falls into one of three kinds:

**The protocol has no such notion.**
    NSDP has no PoE, MAC-table, LLDP or sensor tag. This was established by an
    exhaustive tag sweep of a live GS110EMX, not by reading a specification.

**The device has no such hardware.**
    The M4300-24X has no PSE silicon, so PoE is refused identically on SNMP,
    HTTP and the CLI — rather than SNMP returning an empty list from an empty
    ``pethPsePortTable`` while the other two raise.

**This model's web UI has no such page.**
    The web UI is a real, limited interface: if the firmware ships no page
    carrying the data, no amount of scraping produces it. These are the entries
    most likely to move, because a page that exists but has not been found yet
    looks exactly the same from here.

**The device's agent does not implement that operation.**
    The protocol defines it, the hardware has it, and the switch still refuses.
    The GS728TPP's SNMP agent will not create a VLAN: every documented RowStatus
    mechanism — ``createAndGo`` alone, ``createAndGo`` carrying
    ``dot1qVlanStaticName`` in one PDU, ``createAndWait`` → name → ``active``,
    setting the name column alone, and ``createAndGo`` with an egress PortList —
    is answered ``inconsistentValue``. That it is the agent and not the table is
    shown by what the same firmware *does* accept: an existing VLAN's membership
    columns, ``dot1qPvid``, and ``destroy(6)``, while its web UI creates a VLAN
    without complaint. So VLAN creation on that model is an HTTP operation, and
    the refusal names the backend that does work.

What is *not* on this list is "not implemented yet". A backend that could serve
an operation but does not is a bug in this library, and is fixed rather than
documented.

Verification status
-------------------

Two flags gate dispatch, and both appear in these tables as ``?``:

``HttpModelSpec.reads_verified``
    Set once that model's web-UI reads have been cross-verified against live
    hardware. While ``False``, the facade refuses HTTP for both reads and
    writes: unchecked output is worse than no output.

``CliModelSpec.reads_verified`` / ``writes_verified``
    The same for the FASTPATH CLI. ``writes_verified`` requires
    ``reads_verified``, and not incidentally — every CLI write confirms itself
    by reading back, so a model whose CLI reads are not trusted cannot honestly
    verify a CLI write either.

At the time this page was generated no registered model is gated off by either
flag; the mechanism is documented because it is what keeps an unverified backend
from quietly becoming a source of truth.
