CHEETAH_V1 — the M4300 ``/v1`` UI
=================================

The M4300's web interface. Login posts both a username and a password, and every
request afterwards is guarded by a ``Referer`` header rather than a CSRF token
field.

Switches
--------

.. ngsw-http-scheme:: CHEETAH_V1

How the login works
-------------------

**Both fields are required.** ``uname`` and ``pwd`` are posted together;
password-only login is rejected.

**The CSRF defence is the Referer header.** Requests without a plausible
``Referer`` are refused, which is why the spec carries ``needs_referer``. A
client written against any of the other four schemes fails here for reasons that
look like an authentication problem.

**The session id has a short life.** The RID the UI issues expires after about
60 seconds of inactivity, so a long-running read sequence must expect to
re-authenticate rather than assume one login covers the whole run.

The two SKUs are not reached the same way
-----------------------------------------

They share a dialect and a login, and differ in transport: the M4300-16X serves
its UI over **HTTPS on port 49152**, while the M4300-24X is plain HTTP on the
default port. The generated table above states each one's transport rather than
letting the shared dialect imply a shared endpoint.

That difference is measured, not assumed — the same pair of switches also runs
different firmware (12.0.19.15 vs 12.0.13.8) and behaves differently on SNMP
VLAN writes. Treating either as a proxy for the other has produced wrong answers
in this project before.

A dead end worth recording
--------------------------

Reading the M4300's HTML will not recover its read-page URLs: the server builds
its menu dynamically, so static analysis of the login page yields nothing. The
paths in the spec came from driving the live UI.

Pages
-----

.. ngsw-http-scheme-pages:: CHEETAH_V1

API
---

* ``netgear_switch.protocols.http.session`` — Referer handling and the RID.
* ``netgear_switch.virtual.web_m4300`` — the mock's renderer for these pages.
