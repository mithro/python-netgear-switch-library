from __future__ import annotations

import struct

from netgear_switch.protocols.nsdp.auth import (
    ENCPASS_V1,
    ENCPASS_V2,
    V1_KEY,
    auth_v2_password,
    encode_password_v1,
    encpass_is_v2,
)


def test_v1_key_is_the_documented_string():
    assert V1_KEY == b"NtgrSmartSwitchRock"
    assert len(V1_KEY) == 19


def test_v1_xor_is_its_own_inverse():
    pw = "s3cr3t-admin"
    enc = encode_password_v1(pw)
    assert enc != pw.encode("ascii")  # actually transformed
    # XOR with the same key again recovers the plaintext bytes.
    again = bytes(b ^ V1_KEY[i % len(V1_KEY)] for i, b in enumerate(enc))
    assert again == pw.encode("ascii")


def test_v1_known_vector_from_algorithm():
    # Derived from the algorithm itself (repeating XOR), NOT captured hardware.
    pw = "AAAA"
    enc = encode_password_v1(pw)
    assert enc == bytes(ord("A") ^ V1_KEY[i] for i in range(4))


def test_v2_matches_independent_go_nsdp_vector():
    # INDEPENDENT oracle: the exact vector asserted by CursedHardware/go-nsdp's
    # TestAuthV2Password (its reverse-engineered AuthV2Password). Not computed
    # by this library's own formula, so it genuinely pins the algorithm.
    token = auth_v2_password(
        "password",
        bytes([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]),  # switch MAC
        bytes([0x12, 0x34, 0x56, 0x78]),  # salt
    )
    assert token == bytes([0xC4, 0xAF, 0x7C, 0x00, 0xA6, 0xC4, 0x1A, 0x7D])


def test_v2_token_is_eight_bytes_and_salt_sensitive():
    a = auth_v2_password("password", b"\xbc\xa5\x11\xb8\xec\xf1", b"\x00\x01\x02\x03")
    b = auth_v2_password("password", b"\xbc\xa5\x11\xb8\xec\xf1", b"\x00\x01\x02\x04")
    assert len(a) == 8
    assert a != b  # a rotated salt yields a different token (challenge-response)


def test_v2_password_zero_padded_to_twenty():
    # Passwords are taken as a 20-byte key (zero-padded / truncated to 20); a
    # short password and its 20-char zero-extension must fold identically.
    mac, salt = b"\xbc\xa5\x11\xb8\xec\xf1", b"\x11\x22\x33\x44"
    short = auth_v2_password("pw", mac, salt)
    padded = auth_v2_password("pw" + "\x00" * 18, mac, salt)
    assert short == padded


def test_encpass_scheme_selection():
    assert encpass_is_v2(struct.pack(">I", ENCPASS_V2)) is True
    assert encpass_is_v2(struct.pack(">I", ENCPASS_V1)) is False
    assert encpass_is_v2(b"") is False  # absent -> legacy v1 default
