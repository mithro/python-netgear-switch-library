Changing a switch
=================

Every write below is on :py:obj:`~netgear_switch.sync_api.SyncSwitch` and :py:obj:`~netgear_switch.aio_api.AsyncSwitch` alike. Each takes
``force=`` and ``backend=``, each runs over exactly one protocol, and each
reads back to confirm what it did.

The operations
--------------

.. list-table::
   :header-rows: 1
   :widths: 34 66

   * - Method
     - What it does
   * - :py:obj:`~netgear_switch.sync_api.SyncSwitch.set_port_enabled`
     - Administratively bring a port up or down.
   * - :py:obj:`~netgear_switch.sync_api.SyncSwitch.set_poe`
     - Enable or disable PoE on a port.
   * - :py:obj:`~netgear_switch.sync_api.SyncSwitch.cycle_poe`
     - Power-cycle a PoE port: off, wait for the port to stop delivering, on,
       wait for it to deliver again.
   * - :py:obj:`~netgear_switch.sync_api.SyncSwitch.clear_poe_fault`
     - Clear a latched PoE fault on a port.
   * - :py:obj:`~netgear_switch.sync_api.SyncSwitch.set_port_description`
     - Set or clear a port's label. Pass ``""`` to clear it.
   * - :py:obj:`~netgear_switch.sync_api.SyncSwitch.set_port_speed`
     - Force a port's speed and duplex, or restore auto-negotiation. See
       :ref:`speed-vs-negotiated` — the field this write verifies against is
       *not* ``PortStatus.speed_mbps``.
   * - :py:obj:`~netgear_switch.sync_api.SyncSwitch.set_pvid`
     - Set a port's PVID (native VLAN).
   * - :py:obj:`~netgear_switch.sync_api.SyncSwitch.set_vlan_membership`
     - Make a port ``UNTAGGED``, ``TAGGED`` or ``EXCLUDED`` on a VLAN.
   * - :py:obj:`~netgear_switch.sync_api.SyncSwitch.create_vlan`
     - Create a VLAN with a name.
   * - :py:obj:`~netgear_switch.sync_api.SyncSwitch.delete_vlan`
     - Delete a VLAN.
   * - :py:obj:`~netgear_switch.sync_api.SyncSwitch.set_mgmt_ip`
     - Set the management address, netmask and gateway.
   * - :py:obj:`~netgear_switch.sync_api.SyncSwitch.set_hostname`
     - Set the switch's host name.
   * - :py:obj:`~netgear_switch.sync_api.SyncSwitch.set_syslog_enabled`
     - Turn remote logging on or off. Does not change the collector list.
   * - :py:obj:`~netgear_switch.sync_api.SyncSwitch.upload_certificate` / :py:obj:`~netgear_switch.sync_api.SyncSwitch.upload_certificate_scp`
     - Install an HTTPS server certificate — over the web UI, or by FASTPATH
       ``copy scp://``.

Three safety rails
------------------

**1. ``force=True`` is required.** Every disruptive write refuses without it.
It is not a confirmation prompt in disguise but a keyword you have to type in
the calling code, so a write cannot happen by passing the wrong variable to a
read.

**2. Protected ports.** A port listed in the switch's ``protected_ports`` raises
:py:obj:`~netgear_switch.errors.ProtectedPortError` unless forced. ``delete_vlan`` extends this: before
deleting, the facade reads the VLAN's members **over the same backend** and
refuses if any is protected — because two of the three write backends do not
guard VLAN deletion themselves, so without the facade-level check the backends
would not be equally safe.

**3. Read-back verification.** After the write lands, the value is read back. A
mismatch raises :py:obj:`~netgear_switch.errors.WriteVerificationError`. A switch that accepts a SET and
silently discards it — which does happen, see below — is caught rather than
reported as success.

.. tab-set::

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

         from netgear_switch import VlanMode, WriteVerificationError

         try:
             switch.set_vlan_membership(
                 4001, port=7, mode=VlanMode.TAGGED, force=True
             )
         except WriteVerificationError as exc:
             print("the switch did not do what it said it did:", exc)

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

         from netgear_switch import VlanMode, WriteVerificationError

         try:
             await switch.set_vlan_membership(
                 4001, port=7, mode=VlanMode.TAGGED, force=True
             )
         except WriteVerificationError as exc:
             print("the switch did not do what it said it did:", exc)

Writes are model-specific in ways that matter
---------------------------------------------

One method call hides genuinely different mechanisms, chosen per model from
measurements, not from a MIB's ideal semantics.

**VLAN membership over SNMP has two dialects.** On most models it is a
read-modify-write of the standard Q-BRIDGE ``dot1qVlanStaticEgressPorts`` and
``dot1qVlanStaticUntaggedPorts`` bitmaps. On FASTPATH 12.x (both M4300 SKUs) it
is not: membership there is owned by the per-port *switchport mode*, and writes
go to Netgear's vendor switchport table. On that firmware
``dot1qVlanStaticEgressPorts`` is writable only while no interface on the switch
is in access mode — and since an untagged membership write is *expressed as*
access mode, the standard dialect would disable itself on first use. Worse,
``dot1qVlanStaticUntaggedPorts`` returns ``noError`` and then silently discards
the write. The model's ``snmp_vlan_write`` field selects the dialect; see
``src/netgear_switch/registry.py``.

**Some switches need two PDUs, not one.** On the S3300 (``gsm7228ps``), setting
a port's egress bit makes it an *untagged* member as a side effect, and that
side effect beats an untagged varbind travelling in the same PDU — so a
``TAGGED`` request silently lands as untagged. Splitting the write into two
PDUs, egress first, works. ``snmp_vlan_split_membership_writes`` turns this on
for that model only, because the GSM7252PS applies the combined PDU correctly
and its verified path is not worth disturbing.

You do not have to know any of this to call ``set_vlan_membership``. The detail
is here because it explains why the same call can behave differently across two
switches from the same family, and why this project refuses to extrapolate
between SKUs.

.. _speed-vs-negotiated:

Configured speed is not negotiated speed
----------------------------------------

``set_port_speed`` writes the port's *configuration*; :py:obj:`~netgear_switch.models.PortStatus`
reports both that and the result, in two separate fields:

* ``speed_config`` — a :py:obj:`~netgear_switch.models.PortSpeed`: what the port is **set** to
  (``show port``'s "Physical Mode" column). Answers even while the link is down.
* ``speed_mbps`` / ``full_duplex`` — what the link actually **negotiated**
  ("Physical Status"). ``None`` while the link is down, because a down port has
  negotiated nothing.

They are separate because they genuinely disagree, and disagree hardest exactly
where this library operates. A port forced to 100 Mbit/s with no cable in it
reports ``speed_config=PortSpeed.forced(100, full_duplex=True)`` and
``speed_mbps=None``. ``set_port_speed`` verifies itself against the first;
verifying against the second would mean a write to any link-down port could
never be confirmed.

.. code-block:: python

   from netgear_switch import PortSpeed

   switch.set_port_speed(8, PortSpeed.forced(100, full_duplex=True), force=True)
   switch.set_port_speed(8, PortSpeed.auto(), force=True)   # and back

**1000 Mbit/s cannot be forced.** 1000BASE-T requires auto-negotiation, and the
firmware encodes that by leaving 1000 out of its forced ``speed`` grammar
entirely while keeping it among the advertised rates. Asking for it raises
:py:obj:`~netgear_switch.errors.CliCommandError` before anything is sent, naming the reason —
rather than passing the request on for the switch to answer with a bare
``% Invalid input``.

Which *other* rates a port accepts follows its PHY, not its firmware: a 1G
copper port offered 10/100/10G while a 10GBASE-T port on another model offered
100/10G. The library therefore keeps no rate table and sends what you ask for;
a rate the port does not have comes back as ``CliCommandError`` carrying the
switch's own words.

Certificates
------------

Two mechanisms, and the right one depends on the model:

.. tab-set::

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

         # Web-UI multipart upload (S3300 / gsm7228ps, GS728TPP):
         switch.upload_certificate(cert_pem, key_pem, force=True)

         # FASTPATH copy scp:// (M4300, GSM7252PS):
         switch.upload_certificate_scp(
             scp_source="user@stage.example",
             scp_password="...",
             remote_dir="/srv/certs",
             chain=True,
         )

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

         # Web-UI multipart upload (S3300 / gsm7228ps, GS728TPP):
         await switch.upload_certificate(cert_pem, key_pem, force=True)

         # FASTPATH copy scp:// (M4300, GSM7252PS):
         await switch.upload_certificate_scp(
             scp_source="user@stage.example",
             scp_password="...",
             remote_dir="/srv/certs",
             chain=True,
         )

Calling ``upload_certificate`` on a model whose mechanism is SCP raises
`NotImplementedError` — deliberately, not :py:obj:`~netgear_switch.errors.UnsupportedCapabilityError` — naming
the mechanism and pointing at the other method. The hardware can do it; that
backend cannot.

The SCP flow is **not live-verified**: it is grounded in working prior art and
tested end-to-end against the mock, but a real run needs a staging SCP server
that CI does not have. It disables HTTPS, copies the server certificate (and
optionally the root chain), re-enables HTTPS to load it, and saves the
configuration. The switch is **not** rebooted. You must stage the PEM files on
the SCP source yourself: the switch pulls
``<host-with-dots-as-dashes>-server.pem`` from ``remote_dir``.

Management IP
-------------

:py:obj:`~netgear_switch.sync_api.SyncSwitch.set_mgmt_ip` is implemented and mock-verified on every backend that
has it. The address you are talking to changes mid-operation, so the connection
issuing the write is dropped by definition. This project has deliberately never
applied it to a live switch.

From the command line
---------------------

Every disruptive ``ngsw`` subcommand carries the same three gates:

.. code-block:: sh

   ngsw --switch core port 7 down --dry-run     # print, send nothing
   ngsw --switch core port 7 down               # prompt for confirmation
   ngsw --switch core port 7 down --yes         # skip the prompt
   ngsw --switch core vlan set 100 7 tagged --force

``--dry-run`` describes the operation at facade granularity — method, arguments
and host — rather than re-encoding the SNMP SET or the HTTP form, so what it
prints cannot drift from what would be sent.

.. _live-hardware-rules:

Testing writes against real hardware
------------------------------------

This project follows these rules for its own live verification. They are worth
adopting.

* **Record the exact prior state, restore it, and prove the restore by
  re-reading.** Not "I think it was enabled".
* **Use throwaway VLAN ids** — this project reserves 4001–4008 — never a
  production VLAN.
* **Touch only a port that is link-down and has no description.** Never a
  described production port.
* **Never save the configuration.** No ``write memory``: a mistake should not
  survive a reboot.
* **Never change a management IP on a switch you need to keep talking to.**

Why a write fails
-----------------

When a write is refused, the cause is almost never the hardware being flaky.
Check, in order:

#. **Credentials.** An SNMP agent silently *drops* an unauthorised request, so a
   wrong write community is indistinguishable from an unreachable host. One
   switch in this fleet has no ``private`` community at all — its read-write
   community is ``public``, and "the agent is dead" turned out to be a wrong
   credential.
#. **A prerequisite setting.** Some writes are gated by other state: on FASTPATH
   12.x, a port's switchport mode governs whether membership is writable at all.
#. **Ordering.** Two varbinds in one PDU are not the same as two PDUs, as the
   S3300 shows.
#. **The value's type, encoding or field width.** A ``PortList`` bitmap must be
   the width the *device* uses — 79, 131 and 45 bytes on three switches here,
   none of them derivable from the port count.

Only after all of that, with captured device output as proof, is a limitation
real — and it must name the firmware version it applies to. See
:doc:`principles`.
