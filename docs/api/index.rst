API reference
=============

Complete reference for every module in the ``netgear_switch`` package,
generated from the source.

Most callers need only :doc:`core` (the data model, the registry, the
capability oracle) and :doc:`facades` (`SyncSwitch` and `AsyncSwitch`).
The rest is there for anyone reading the source, extending a backend, or
building on the protocol layer directly.

.. toctree::
   :maxdepth: 2

   core
   facades
   operations
   protocols
   transport
   virtual
   cli
   mcp

Layering
--------

.. code-block:: text

   sync_api.py / aio_api.py        facades: pick ONE backend, no fallback
            │
            ├── _dispatch.py       backend resolution + lazy client builders
            │
   ┌────────┴───────────────────────────────┐
   snmp_read/write   nsdp_read/write         model-driven operations
   http_read/write   cli_read/write
            │
   protocols/…                               pure protocol knowledge, no I/O
            │
   transport/…                               sockets, subprocesses, sessions

``registry.py``, ``models.py``, ``errors.py``, ``capabilities.py`` and
``config.py`` sit beside all of it: every layer uses them, none of them import a
layer.

The package namespace
---------------------

.. automodule:: netgear_switch
   :no-members:

Everything in ``__all__`` is re-exported at the top level, so
``from netgear_switch import SyncSwitch, Backend, VlanMode`` is the intended
import style. The pages that follow document each name where it is defined.
