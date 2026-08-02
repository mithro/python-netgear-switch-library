GAMBIT — merge-hash with a token
================================

The same password hash as :doc:`merge-hash-cgi`, and a different session
mechanism entirely: no cookie is ever issued. The switch answers a successful
login with a ``Gambit`` token that must be carried on every later request.

Switches
--------

.. ngsw-http-scheme:: GAMBIT

How the login works
-------------------

Three details, each of which breaks the login if guessed wrong:

**The nonce and the POST live on different pages.** ``rand`` is scraped from
``GET /``, and the credentials are posted to ``/redirect.html`` — which is why
the spec carries a separate ``login_post_path`` at all.

**The password hash is identical to the Plus scheme:**
``merge_hash_md5(password, rand)``, the very same function, posted here as
``LoginPassword``.

**The session is a token, not a cookie.** The response carries a ``Gambit``
value and no ``Set-Cookie`` header is ever sent. A client that only knows how to
persist cookies will authenticate successfully and then be logged out on its
next request.

Why this backend exists at all
------------------------------

The GS110EMX is an NSDP-first switch, so an HTTP backend for it looks redundant
until you ask what NSDP cannot answer. The web UI was built out to prove it
covers every NSDP read — and it does: port status, statistics, VLANs, PVIDs. The
two backends were then cross-verified against each other on the live switch,
which is the only reason either can be trusted.

Pages
-----

.. ngsw-http-scheme-pages:: GAMBIT

API
---

* ``netgear_switch.protocols.http.session`` — token session handling.
* ``netgear_switch.virtual.web_gs110emx`` — the mock's renderer for these pages.
