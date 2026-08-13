GS305EP
=======

.. ngsw-model-photo:: gs305ep

.. ngsw-model-diagram:: gs305ep

A 5-port Plus switch with PoE on 4 ports. No SNMP; managed over NSDP and the
web UI.

At a glance
-----------

.. ngsw-model-facts:: gs305ep

**Not captured from hardware.** This is the one model here with no device
capture and no live run: every unit in this fleet (10.1.5.28-.30) was powered
off when the attempt was made. What it *is* grounded in is two independent
implementations that drive these switches — ``py_netgear_plus`` for the
merge-hash login and the PoE/VLAN CGI paths, and ``netgear-smp-vlan`` for the
``8021qCf.cgi``/``8021qMembe.cgi``/``portPVID.cgi`` field shapes and the
1=untagged/2=tagged/3=excluded wire codes, observed on a GS105PE.

So the page shapes are grounded, but the *values* are not: the mock seed is
hand-invented (:py:func:`~netgear_switch.virtual.seed.seed_gs305ep` says so) and
the web-UI fixtures under ``tests/fixtures/http/gs305ep_*.html`` each carry an
``UNVERIFIED-pending-capture: synthetic`` marker. Treat behaviour recorded here
as the documented shape, not as observed values — and see
:doc:`gs105pe`, whose read paths turned out NOT to be shareable with this model
even though the two do share a login scheme.

Seed: :py:func:`~netgear_switch.virtual.seed.seed_gs305ep`.

What works, over which protocol
-------------------------------

.. ngsw-model-support:: gs305ep

Measured behaviour
------------------

**PoE is reachable over the web UI only.** The hardware is there, and both PoE
status and configuration are available — but NSDP has no PoE tag at all, which
makes this model the clearest argument for naming a backend:

.. tab-set::

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

         switch.get_poe()                      # UnsupportedCapabilityError
         switch.get_poe(backend=Backend.HTTP)  # works

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

         await switch.get_poe()                      # UnsupportedCapabilityError
         await switch.get_poe(backend=Backend.HTTP)  # works

The default backend for a Plus switch is NSDP, so the first call resolves there
and refuses rather than quietly answering over HTTP. The error names the
alternative — see :doc:`../guide/concepts`.

**Its web UI uses the ``MERGE_HASH_CGI`` scheme**, the same one as the GS105PE:
the login page carries a nonce, the password is hashed together with it, and the
result is posted to a ``.cgi`` endpoint.

**The management IP is readable over NSDP but not over its web UI**, which ships
no page carrying it — one of the backend-parity gaps listed in
:doc:`support`.

Protocols
---------

* :doc:`../protocols/nsdp` — the default backend.
* :doc:`../protocols/http` — the ``MERGE_HASH_CGI`` scheme; the only route to
  PoE on this model.
