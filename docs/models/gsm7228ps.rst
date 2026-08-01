S3300-52X-PoE+
==============

.. ngsw-model-photo:: gsm7228ps

A 52-port Smart Managed Pro switch with 48 PoE ports — despite the
``GSM7228PS`` part-number family suggesting 28. The registry key is
``gsm7228ps``; ``s3300`` is an alias resolving to the same record, because the
firmware's own ``sysDescr`` and the marketing name are both "S3300-52X".

At a glance
-----------

.. ngsw-model-facts:: gsm7228ps

Live-verified at 10.1.5.11. Capture:
``tests/fixtures/captures/gsm7228ps.json``; seed:
:py:func:`~netgear_switch.virtual.seed.seed_gsm7228ps`.

What works, over which protocol
-------------------------------

.. ngsw-model-support:: gsm7228ps

Measured behaviour
------------------

**Identified by sysObjectID, not sysDescr.** Its description text is
indistinguishable from the unregistered S3300-28X, so matching on it would be a
coin flip. :py:func:`~netgear_switch.detect_model` prefers the product OID
``4526.100.10.19`` — note that this is the product *identifier*, distinct from
the ``4526.11`` vendor **data** subtree its sensors and PoE live under.
Confusing the two is what made auto-detection fail on this switch.

**Its CLI is telnet on port 60000**, not 23, and it runs no SSH listener on any
port — its own ``tcpConnTable`` shows only 80, 443 and 60000. So the CLI backend
here is telnet only, and the transport dials the port from its spec.

**Egress writes auto-untag, and that beats the same PDU.** Setting a port's
egress bit makes it an untagged member as a side effect, and when both columns
travel in one PDU that side effect wins — so a ``TAGGED`` request silently lands
untagged:

.. code-block:: text

   one PDU  : egress=[1] untagged=[1]   ← untagged intent lost
   two PDUs : egress=[1] untagged=[]    ← correct, CLI confirms "Tagged"

:py:attr:`~netgear_switch.SwitchModel.snmp_vlan_split_membership_writes` turns
the two-PDU sequence on for this model alone.

**"The SNMP agent is dead" was a wrong credential.** This switch has no
``private`` community; it publishes ``pib`` and ``public``, both read-write. An
agent silently *drops* an unauthorised request, so a wrong write community looks
exactly like an unreachable host — reads had worked the whole time.

**Certificate upload is an HTTP multipart form** here, not SCP — the opposite of
its FASTPATH cousins. :py:meth:`~netgear_switch.SyncSwitch.upload_certificate`
is the right call for this model.

Protocols
---------

* :doc:`../protocols/snmp` — vendor subtree ``4526.11``.
* :doc:`../protocols/http` — ``CHEETAH_FORM`` login, ``S3300`` page dialect.
* :doc:`../protocols/cli` — telnet on port 60000 only.
