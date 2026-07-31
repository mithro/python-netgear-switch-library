Development
===========

.. code-block:: sh

   git clone https://github.com/mithro/python-netgear-switch-library
   cd python-netgear-switch-library
   uv sync --all-extras

   uv run pytest
   uv run ruff check src/ tests/
   uv run mypy

``mypy`` runs in **strict** mode over the whole package, and ``ruff`` with a
broad rule set. Both must be clean.

Tests
-----

The suite runs entirely against the :doc:`virtual switch <fake/index>` — no
hardware, no network. Coverage is enforced at 90%.

.. list-table::
   :header-rows: 1
   :widths: 42 58

   * - Area
     - What it covers
   * - ``tests/virtual/``
     - The mock itself: state, faces, seeds, and the device quirks each one
       reproduces.
   * - ``tests/test_cross_backend_equivalence.py``
     - That every backend of a model reports the same thing — the parity
       guarantee, checked rather than asserted in prose.
   * - ``tests/test_facade_equivalence.py``
     - That `SyncSwitch` and `AsyncSwitch` stay in step.
   * - ``tests/test_capabilities.py``
     - That the support tables in these docs match what the code actually does,
       by driving every operation for real.
   * - ``tests/equivalence.py``, ``tests/capture_parity.py``
     - Shared harnesses: capture → replay → diff against committed captures.
   * - ``tests/fixtures/``
     - Real captured device output — SNMP walks, web pages, CLI transcripts.

.. note::

   On a memory-constrained machine, run one file at a time rather than the whole
   suite::

       PYTHONPATH=src .venv/bin/python -m pytest tests/test_snmp_read.py -q --no-cov

Documentation
-------------

.. code-block:: sh

   uv sync --extra docs
   make -C docs html          # warnings are errors, like Read the Docs
   make -C docs offline       # same, but skips the intersphinx fetch

Built with Sphinx from ``docs/``, published to Read the Docs per
``.readthedocs.yaml``. Two local extensions do the work that keeps these pages
honest:

``docs/_ext/support_tables.py``
    Generates every model and support table from
    ``src/netgear_switch/registry.py`` and
    ``src/netgear_switch/capabilities.py`` at build time. No support table in
    this documentation is hand-maintained, so none can drift from the code.

``docs/_ext/filelinks.py``
    Turns any inline literal naming a file in this repository into a link to
    that file — in prose *and* in docstrings pulled in by autodoc. A literal
    that looks like a repository path but does not exist is a warning, and
    warnings fail the build, so the documentation cannot keep pointing at a file
    that has been renamed or deleted.

Writing documentation, then, is mostly a matter of naming files in double
backticks and letting the extension do the rest::

    See ``src/netgear_switch/registry.py`` for the registry.

Use ``:repofile:`path``` where a reference must be guaranteed to resolve — that
role errors rather than warns.

Adding a switch model
---------------------

See :doc:`fake/internals`, which covers registration, protocol specs, capturing
a real device, writing a seed, and when a verification flag may be flipped.

The rules
---------

:doc:`guide/principles` is not optional reading for contributors. In particular:

* **Never declare something unsupported to finish a task.** If you cannot
  implement it, say so plainly — naming the model, backend and operation — and
  leave behind no `UnsupportedCapabilityError` that lacks captured device output
  as proof. An honest "not done, here's why" is wanted; a false "the hardware
  can't" is not.
* **Implement across all backends and all models,** or state precisely which
  combinations remain.
* **Verify by driving one backend directly**, never through a facade that might
  substitute another — otherwise a pass may be a different protocol answering.
* **Encode what you learn from hardware into the virtual switch, plus a test,**
  naming the host and firmware version in a comment.

Live hardware
-------------

If you have real switches, the rules in :ref:`live-hardware-rules` are
mandatory: record the prior state and prove the restore, use throwaway VLAN ids,
touch only link-down undescribed ports, and never save the configuration.

Releasing
---------

A rolling release: every merge to ``main`` publishes to PyPI and the apt
repository, with the version derived from git. There are no manual version
bumps. See ``RELEASING.md``.

Continuous integration
----------------------

``.github/workflows/ci.yml`` runs the test suite, lint, type-check and the
documentation build across supported Python versions;
``.github/workflows/publish-pypi.yml`` and ``.github/workflows/deb.yml`` handle
publication.
