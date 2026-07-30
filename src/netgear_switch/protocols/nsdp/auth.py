"""NSDP write authentication (v1 XOR and v2 salted challenge-response).

Two schemes exist; a switch advertises which via the ``AUTH_V2_ENCPASS``
(0x0014) read: value 1 = v1, value 0x10 = v2.

**v1** (older Plus firmware): the admin password is sent in a ``PASSWORD``
(0x000A) TLV "encrypted" by a repeating XOR against the 19-byte key
``NtgrSmartSwitchRock``. XOR is its own inverse, so ``encode_password_v1`` both
encodes an outgoing and decodes an incoming PASSWORD TLV.

**v2** (newer firmware, incl. GS110EMX fw 1.0.2.8 -- LIVE-VERIFIED): a
challenge-response. The client reads a fresh 4-byte salt from ``AUTH_V2_SALT``
(0x0017, which rotates on every read), then writes an 8-byte token in
``AUTH_V2_PASSWORD`` (0x001A) alongside the config change. The token is NOT a
hash -- it is an 8-byte XOR fold of the 20-byte password, the 4-byte salt and
the switch's own 6-byte MAC (the MAC from the salt read's response header).
``auth_v2_password`` is transcribed from the reverse-engineered
``AuthV2Password`` in CursedHardware/go-nsdp (in turn from yaamai/go-nsdp); its
"each output byte XORs three password bytes" shape is exactly the weakness NCC
Group documented (CVE-2020-35221) for this scheme. Verified two ways: it
reproduces go-nsdp's own ``TestAuthV2Password`` vector byte-for-byte
(password="password", mac 12:34:56:78:9a:bc, salt 12:34:56:78 ->
c4:af:7c:00:a6:c4:1a:7d — see tests/protocols/nsdp/test_auth.py), and a real
GS110EMX accepts a WRITE carrying ``[config…, AUTH_V2_PASSWORD=fold]``.

Investigation evidence (GS110EMX @ 10.1.5.25/.26/.27, fw 1.0.2.8, 2026-07-29):

* The token is NOT any hash. Before finding go-nsdp, md5(merge(pw, salt)) and
  md5(pw+salt)/md5(salt+pw) were tried live, with the salt rendered as a decimal
  string (both endiannesses), a hex string, and raw bytes, and the payload sent
  as raw-16, 32-hex-ASCII, and each of those XOR'd with ``NtgrSmartSwitchRock``.
  EVERY one was rejected error 13. The switch's WEB UI *does* use
  ``md5(merge(password, rand))`` (rand = a decimal nonce; confirmed by a
  successful HTTP login), but NSDP's 0x001A token is the unrelated XOR fold here
  — the two auth paths do not share the transform.
* AUTH_V2_ENCPASS (0x0014) returns 0x00000010 on this SKU (v2); a v1 unit
  returns 1. AUTH_V2_SALT (0x0017) is a 4-byte value that rotates on EVERY read.
  AUTH_V2_PASSWORD (0x001A) is write-only (a READ of it returns error 3).
* Write structure matters: the 0x001A token must come FIRST, then the config
  TLVs (``[0x001A, config…]``) -- this is what authenticates (error 0). Sending
  it LAST is rejected error 13; a malformed/wrong-length token leading the
  packet was seen to return error 4. Broadcast vs switch-MAC targeting and a
  real vs dummy client MAC do NOT matter -- auth-first works with the library's
  broadcast/dummy framing.
* Lockout (belongs in the mock; see faces/nsdp.py): READS always work, even
  while writes are locked. Wrong-token writes return error 13 for the first few
  (4 consecutive seen at ~1.2 s spacing), then escalate to error 14, then the
  switch goes SILENT to writes (no reply) for a long cooldown (>10 min observed;
  each fresh failed attempt appears to restart the window). The exact failure
  count before 14 varied 2-5 across units, i.e. it is rate/time-based, not a
  clean counter.
"""

from __future__ import annotations

V1_KEY = b"NtgrSmartSwitchRock"

# AUTH_V2_ENCPASS (0x0014) values that select the write-auth scheme.
ENCPASS_V1 = 0x01
ENCPASS_V2 = 0x10


def encode_password_v1(password: str) -> bytes:
    """Repeating-XOR the ASCII password with ``NtgrSmartSwitchRock`` (its own
    inverse). No padding/truncation rule applies -- the ciphertext is the
    password's own length."""
    pw = password.encode("ascii")
    return bytes(b ^ V1_KEY[i % len(V1_KEY)] for i, b in enumerate(pw))


def auth_v2_password(password: str, switch_mac: bytes, salt: bytes) -> bytes:
    """Compute the 8-byte NSDP v2 auth token for a write.

    ``switch_mac`` is the device's own 6-byte MAC (the server MAC echoed in the
    ``AUTH_V2_SALT`` read response); ``salt`` is that read's fresh 4-byte value.
    The password is taken as a 20-byte key (ASCII, zero-padded / truncated to
    20 -- the web UI caps the field at 20 chars). Transcribed byte-for-byte from
    CursedHardware/go-nsdp ``AuthV2Password``.
    """
    if len(salt) != 4:
        raise ValueError(f"NSDP v2 salt must be 4 bytes, got {len(salt)}")
    if len(switch_mac) != 6:
        raise ValueError(f"NSDP v2 switch MAC must be 6 bytes, got {len(switch_mac)}")
    key = bytearray(20)
    pw = password.encode("ascii")[:20]
    key[: len(pw)] = pw
    s, m, k = salt, switch_mac, key
    return bytes(
        [
            s[3] ^ s[2] ^ m[1] ^ m[5] ^ k[0] ^ k[1] ^ k[2],
            s[3] ^ s[1] ^ m[4] ^ m[0] ^ k[3] ^ k[4] ^ k[5],
            s[0] ^ s[2] ^ m[3] ^ m[2] ^ k[6] ^ k[7] ^ k[8],
            s[0] ^ s[1] ^ m[4] ^ m[5] ^ k[9] ^ k[10] ^ k[11],
            s[3] ^ s[2] ^ m[1] ^ m[5] ^ k[12] ^ k[13] ^ k[14],
            s[3] ^ s[1] ^ m[4] ^ m[0] ^ k[15] ^ k[16] ^ k[17],
            s[0] ^ s[2] ^ m[3] ^ m[2] ^ k[18] ^ k[19] ^ k[0],
            s[0] ^ s[1] ^ m[4] ^ m[5] ^ k[1] ^ k[3] ^ k[5],
        ]
    )


def encpass_is_v2(value: bytes) -> bool:
    """Decide the write-auth scheme from an ``AUTH_V2_ENCPASS`` (0x0014) value.

    v2 iff the advertised value is 0x10 (observed 0x00000010 on a GS110EMX);
    any other value (notably 1) means legacy v1 XOR. An absent/empty value is
    treated as v1 -- the historical default.
    """
    if not value:
        return False
    return int.from_bytes(value, "big") == ENCPASS_V2
