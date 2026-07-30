"""NSDP authentication.

v1 auth (older Plus firmware, incl. the GS110EMX/GS305EP this slice targets)
sends the admin password in a ``PASSWORD`` (0x000A) TLV "encrypted" by a
repeating XOR against the 19-byte key ``NtgrSmartSwitchRock`` (the only detail
the source spec ``gdoc2netcfg/docs/nsdp-protocol.md`` gives — no worked example,
no padding rule). XOR is its own inverse, so ``encode_password_v1`` both encodes
outgoing and decodes an incoming PASSWORD TLV.

UNVERIFIED / NOT IMPLEMENTED: v2 salt+hash auth (tags AUTH_V2_SALT 0x0017 /
AUTH_V2_PASSWORD 0x001A, newer firmware). The source spec names ONLY the two tag
numbers and gives no algorithm (no hash function, no salt ordering), so there is
nothing to implement honestly without a hardware capture. A switch that rejects
v1 auth returns result 0x0700 (bad password); the transport surfaces that as an
NsdpError telling the caller v2 is required (see Task 4).
"""

from __future__ import annotations

V1_KEY = b"NtgrSmartSwitchRock"

AUTH_V2_UNSUPPORTED = (
    "NSDP v2 salt/hash auth (tags 0x0017/0x001A) is unverified and not "
    "implemented; this backend supports only v1 XOR auth"
)


def encode_password_v1(password: str) -> bytes:
    """Repeating-XOR the ASCII password with ``NtgrSmartSwitchRock`` (its own
    inverse). UNVERIFIED: no padding/truncation rule is documented; if a real
    switch rejects this, a hardware capture is needed to confirm the exact
    byte handling (see module docstring)."""
    pw = password.encode("ascii")
    return bytes(b ^ V1_KEY[i % len(V1_KEY)] for i, b in enumerate(pw))
