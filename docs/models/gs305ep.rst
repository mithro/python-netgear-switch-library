GS305EP
=======

.. ngsw-model-photo:: gs305ep

.. ngsw-model-diagram:: gs305ep

A 5-port Plus switch with PoE on 4 ports. No SNMP; managed over NSDP and the
web UI.

At a glance
-----------

.. ngsw-model-facts:: gs305ep

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
