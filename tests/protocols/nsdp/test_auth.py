from __future__ import annotations

from netgear_switch.protocols.nsdp.auth import V1_KEY, encode_password_v1


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
