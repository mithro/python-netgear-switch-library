Concepts
========

Four ideas explain nearly all of this library's behaviour: the **model**, the
**backend**, **dispatch without fallback**, and **verification status**.

Models
------

A switch model is a frozen `netgear_switch.registry.SwitchModel` record: its
key, display name, class, port and PoE-port counts, the backends it exposes, its
SNMP vendor OID subtree, and a few per-model protocol dialect flags. The whole
registry lives in ``src/netgear_switch/registry.py``, and :py:obj:`~netgear_switch.registry.get_model` resolves a
key (or an alias, such as ``s3300`` for ``gsm7228ps``) to the record.

Models fall into three classes, and the class decides which protocols are
available:

Fully Managed (``FULLY_MANAGED``)
    M4300, GSM7252PS. Full SNMP with the Netgear ``4526.10`` vendor subtree, a
    FASTPATH CLI over SSH and telnet, and a web UI.

Smart Managed Pro (``SMART_MANAGED_PRO``)
    S3300/GSM7228PS, GS728TPP, XS748T. SNMP and a web UI; the S3300 also has a
    FASTPATH CLI, over telnet on the non-standard port 60000.

Plus (``PLUS``)
    GS110EMX, GS305EP, GS105PE. No SNMP at all. Managed by NSDP — Netgear's
    UDP discovery-and-config protocol — and by a web UI.

The registry is the single source of truth for these facts, and every table in
:doc:`../models/support` is generated from it.

Backends
--------

A backend is *the protocol an operation travels over*:

.. list-table::
   :header-rows: 1
   :widths: 12 88

   * - Backend
     - What it is
   * - ``SNMP``
     - Standard MIBs plus Netgear vendor subtrees. Synchronously via the
       net-snmp command-line tools; asynchronously via :pypi:`pysnmp`.
   * - ``NSDP``
     - The Netgear Switch Discovery Protocol, over UDP. The only management
       protocol besides the web UI on Plus switches.
   * - ``HTTP``
     - The switch's own web UI, scraped and driven as a browser would.
       |scheme-count| distinct login schemes and |dialect-count| page dialects
       across the fleet.
   * - ``SSH`` / ``TELNET`` / ``CONSOLE``
     - The FASTPATH command line. One command surface reached over three
       transports; ``CONSOLE`` is a serial line rather than a network backend,
       so it is never registered on a model.

The same |read-count| read operations and |write-count| write operations are implemented on every
backend a model has. That is deliberate: if SNMP writes are locked down on your
network, or the web UI is the only port through a firewall, you can pick a
different protocol and get the same answer. :doc:`../models/support` lists the
gaps that remain.

Dispatch: exactly one backend, every time
-----------------------------------------

.. tab-set::

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

         switch.get_vlans()                      # the model's default backend
         switch.get_vlans(backend=Backend.HTTP)  # exactly HTTP, or an error

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

         await switch.get_vlans()                      # the model's default backend
         await switch.get_vlans(backend=Backend.HTTP)  # exactly HTTP, or an error

When you **name** a backend, that backend runs. If the model does not have it,
you get :py:obj:`~netgear_switch.errors.UnsupportedCapabilityError` immediately. If it has it but cannot serve
that operation, you get :py:obj:`~netgear_switch.errors.UnsupportedCapabilityError` naming the backend you
asked for.

When you **do not** name one, :py:obj:`~netgear_switch.sync_api.SyncSwitch.resolve_backend` picks the first
backend the model declares, in the fixed order **SNMP → NSDP → HTTP → SSH →
TELNET → CONSOLE**. The choice depends only on the model, never on the
operation: the facade does not probe one backend, catch its refusal, and try
the next. If the default cannot serve the operation, the error says so and
names the other backends you could pass:

.. code-block:: text

   UnsupportedCapabilityError: model 'gs110emx': the default backend NSDP cannot
   serve this operation: NSDP has no PoE status tag (measured by an exhaustive
   NSDP tag sweep of a live GS110EMX); pass backend=Backend.<HTTP> to use
   another backend

.. warning::

   **The library will never answer over a protocol you did not get.** This was
   not always true, and the cost of the old behaviour is why the rule is
   absolute. :py:class:`~netgear_switch.sync_api.SyncSwitch` used to loop over
   SNMP → NSDP → HTTP, silently
   returning the next backend's answer when one raised. That hid a real defect
   for months — ``HttpReader.get_vlans`` returned no untagged ports at all on
   the managed switches, and nobody noticed because SNMP quietly answered
   instead. Worse, every past "verified over HTTP" claim became worthless,
   because the HTTP path may never have run. On a *write* it is worse still: an
   operator who deliberately restricted SNMP write access could have had their
   change pushed over another protocol without being told.

Choosing a default per facade
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Pass ``backend=`` to the constructor to change the default for every call:

.. tab-set::

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

         web_only = SyncSwitch(
             get_model("gsm7252ps"), host="10.1.5.22",
             http_password="...", backend=Backend.HTTP,
         )

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

         web_only = AsyncSwitch(
             get_model("gsm7252ps"), host="10.1.5.22",
             http_password="...", backend=Backend.HTTP,
         )

Per-call ``backend=`` still overrides it.

Verification status
-------------------

This project distinguishes what has been *measured* from what has been
*assumed*, and the distinction is visible in the API.

:py:attr:`~netgear_switch.registry.SwitchModel.verified`
    ``False`` marks a model registered from a specification sheet, with no
    device of that kind ever reachable from this project. Such a model is
    **excluded from every support table** — see :doc:`../models/index` —
    because putting it in a matrix would assert per-backend behaviour nobody has
    observed. It stays in the registry only so a caller can construct a facade
    for it, and nothing here treats it as evidence of anything.

``HttpModelSpec.reads_verified``, ``CliModelSpec.reads_verified`` / ``writes_verified``
    Per-model, per-backend flags recording whether that backend's output has
    been cross-verified against live hardware. While a flag is ``False`` the
    facade **refuses to dispatch** to that backend rather than return output
    nobody has checked. `netgear_switch.capabilities.Support.UNVERIFIED` is the
    corresponding verdict.

Errors
------

All errors derive from :py:obj:`~netgear_switch.errors.NetgearSwitchError`. The distinctions that matter:

.. list-table::
   :header-rows: 1
   :widths: 32 68

   * - Error
     - Means
   * - :py:obj:`~netgear_switch.errors.UnsupportedCapabilityError`
     - This backend genuinely cannot do this, for this model. Never "not
       implemented yet" — a missing implementation is a bug to fix, not a
       device limitation to document.
   * - :py:obj:`~netgear_switch.errors.CredentialError`
     - A credential is missing or wrong. An SNMP agent **silently drops** an
       unauthorised request, so a wrong write community looks exactly like an
       unreachable host.
   * - :py:obj:`~netgear_switch.errors.WriteVerificationError`
     - The write was sent and accepted, but reading back did not show the
       intended value.
   * - :py:obj:`~netgear_switch.errors.ProtectedPortError`
     - The port is in this switch's ``protected_ports`` set. Pass ``force=True``
       to override.
   * - :py:obj:`~netgear_switch.errors.HttpAuthError`, :py:obj:`~netgear_switch.errors.HttpUnexpectedPageError`
     - Web-UI login failed, or a page did not look like what the model's dialect
       expects (usually a session that expired).
   * - :py:obj:`~netgear_switch.errors.CliCommandError`
     - The switch's CLI rejected a command; the message carries what it said.

`NotImplementedError` appears in exactly one place — certificate upload on a
model whose real mechanism is known but not wired to that backend. It is
deliberately *not* :py:obj:`~netgear_switch.errors.UnsupportedCapabilityError`, because the hardware can do it;
see :doc:`../models/support`.

Synchronous and asynchronous
----------------------------

:py:class:`~netgear_switch.sync_api.SyncSwitch` and
:py:class:`~netgear_switch.aio_api.AsyncSwitch` expose the same operations with the same
arguments and the same semantics. They share the model registry, the parsers and
the backend-resolution seam in ``src/netgear_switch/_dispatch.py``; only the
transports differ. ``tests/test_facade_equivalence.py`` asserts they stay in
step.

.. important::

   **One backend is synchronous-only: the CLI.** All three CLI transports —
   SSH, telnet and the serial console — are blocking, and none has an async
   twin, so :py:class:`~netgear_switch.aio_api.AsyncSwitch` has no CLI backend at all.
   Asking for one raises rather than quietly blocking the event loop::

      UnsupportedCapabilityError: model 'gsm7252ps' CLI reads are not available
      via the async facade (CLI is synchronous ...)

   That also rules out
   :py:meth:`~netgear_switch.sync_api.SyncSwitch.upload_certificate_scp` on the async
   facade, since the operation is CLI-based by nature. Use
   :py:class:`~netgear_switch.sync_api.SyncSwitch` for those, or wrap the call in
   :py:func:`asyncio.to_thread`.

   **The support tables in** :doc:`../models/support` **describe the
   synchronous facade.** Every SNMP, NSDP and HTTP entry holds for both; the CLI
   columns apply to :py:class:`~netgear_switch.sync_api.SyncSwitch` only.
