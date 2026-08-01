Facades
=======

:py:obj:`~netgear_switch.sync_api.SyncSwitch` and :py:obj:`~netgear_switch.aio_api.AsyncSwitch` are the public entry points. They expose the same
operations with the same arguments, and both resolve exactly one backend per
call — see :doc:`../guide/concepts`.

Synchronous
-----------

.. automodule:: netgear_switch.sync_api

Asynchronous
------------

.. automodule:: netgear_switch.aio_api

Backend resolution
------------------

The seam both facades share: which backend an operation runs on, and how each
backend's client is built. Internal, but documented because its behaviour is
the library's central guarantee.

.. automodule:: netgear_switch._dispatch
