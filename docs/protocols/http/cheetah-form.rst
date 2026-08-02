CHEETAH_FORM — the Cheetah login form
=====================================

The managed switches' web UI. A plain HTML form: username and password posted
in the clear to ``/base/cheetah_login.html``, answered with a session cookie.
No nonce, no hashing.

Switches
--------

.. ngsw-http-scheme:: CHEETAH_FORM

Two dialects on one login
-------------------------

``gsm7252ps`` and ``gsm7228ps`` log in identically and then serve the same
Cheetah XE page grid, so both reuse the ``parse_xe_*`` parsers for ports,
statistics, PVIDs, VLANs, PoE and LLDP.

They are separate dialects because two pages genuinely differ on the S3300: its
MAC table has shifted columns and escaped ``1/gN`` port names, and its sensor
page differs too. Everything else is shared.

The XUI shape worth knowing
---------------------------

These pages carry two ``<FORM>`` elements, and the interesting fields are not
always the visible ones. Two consequences:

**Errors arrive with HTTP 200.** A write that "succeeded" by status code may have
failed in the body, so the library reads the body's status fields rather than
trusting the response code.

**A write must replay the whole form**, including hidden and list-navigation
fields. This is where "the GSM7252PS refuses PoE writes over HTTP" came from —
it was not firmware. The form needs a list-unit field (``v_1_1_1``) that the
writer was not sending. With it, PoE writes apply cleanly.

That is worth stating plainly because it is the exact failure mode this project
treats as a bug in our code until proven otherwise: a missing field is rejected
by the firmware in a way that looks indistinguishable from a device limitation.

Pages
-----

.. ngsw-http-scheme-pages:: CHEETAH_FORM

Certificate upload
------------------

Both models accept an HTTPS certificate through this UI, and the S3300's flow is
grounded in a working prior implementation rather than inferred. See
:py:meth:`~netgear_switch.sync_api.SyncSwitch.upload_certificate`.

API
---

* ``netgear_switch.protocols.http.parse`` — the ``parse_xe_*`` parsers.
* ``netgear_switch.protocols.http.forms`` — form scraping and replay.
* ``netgear_switch.virtual.web_fastpath_xui`` — the mock's XUI renderer.
