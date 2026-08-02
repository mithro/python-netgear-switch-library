MERGE_HASH_CGI — the Plus web UI
================================

The login scheme of the Plus family. The login page carries a per-page nonce,
the password is hashed together with it, and the result is posted to a ``.cgi``
endpoint which answers with a session cookie.

Switches
--------

.. ngsw-http-scheme:: MERGE_HASH_CGI

How the login works
-------------------

The hash is ``md5(merge(password, rand))``, where ``rand`` is scraped from the
login page and ``merge`` interleaves the two strings one character at a time —
``merge("abc", "12")`` is ``"a1b2c"``. Both halves are pure functions with no
I/O, in ``src/netgear_switch/protocols/http/crypt.py``:
:py:func:`~netgear_switch.protocols.http.crypt.merge` and
:py:func:`~netgear_switch.protocols.http.crypt.merge_hash_md5`.

The nonce matters: it is per-page, so the hash cannot be precomputed and a
login must always begin by fetching the form.

Two switches, one scheme, two different page sets
-------------------------------------------------

``gs105pe`` and ``gs305ep`` share this login exactly, and share almost nothing
else. They are separate dialects — ``GS105PE`` and ``STANDARD`` — because their
read pages genuinely differ.

That distinction was learned the hard way. The GS105PE was first registered by
copying the GS305EP's read paths, on the reasonable-looking grounds that the
login was identical. Both ``dashboard.cgi`` and ``getPoePortStatus.cgi``
returned 404 on a real GS105PE. The paths in the spec now are the ones observed
on the device, grounded in six captures under ``tests/fixtures/http/``.

It is the same lesson the SNMP side learned from the M4300 pair: a shared
mechanism in one place is not evidence of a shared mechanism in another.

Pages each switch ships
-----------------------

A ``—`` is a real absence — that firmware serves no such page — not an
unimplemented reader. The reader raises rather than inventing a value.

.. ngsw-http-scheme-pages:: MERGE_HASH_CGI

Note the GS105PE's missing PoE status page. The product is marketed with "PoE
pass-through", which means it can *be powered* over PoE rather than source it;
``getPoePortStatus.cgi`` 404s on a real unit, and its ``poe_port_count`` is 0.

API
---

* ``netgear_switch.protocols.http.crypt`` — the login hash transforms.
* ``netgear_switch.protocols.http.endpoints`` — both specs, with the captures
  that ground them named in comments.
