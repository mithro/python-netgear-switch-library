"""Pure Netgear web-UI login crypto (no I/O).

The Plus family authenticates with ``md5(merge(password, rand))`` where
``rand`` is a per-page nonce scraped from the login form and ``merge``
interleaves the two strings character by character. GROUNDED against
``rcfiles/bin/netgear-smp-vlan`` and ``py_netgear_plus/netgear_crypt.py``.
"""
from __future__ import annotations

import hashlib


def merge(str1: str, str2: str) -> str:
    """Interleave two strings character by character (Netgear login scheme)."""
    out: list[str] = []
    i = j = 0
    while i < len(str1) or j < len(str2):
        if i < len(str1):
            out.append(str1[i])
            i += 1
        if j < len(str2):
            out.append(str2[j])
            j += 1
    return "".join(out)


def merge_hash_md5(password: str, rand: str) -> str:
    """Return ``md5(merge(password, rand))`` as lowercase hex (Plus login hash)."""
    return hashlib.md5(merge(password, rand).encode()).hexdigest()
