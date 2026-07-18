from __future__ import annotations

import hashlib

from netgear_switch.errors import (
    HttpAuthError,
    HttpError,
    HttpUnexpectedPageError,
    NetgearSwitchError,
)
from netgear_switch.protocols.http.crypt import merge, merge_hash_md5


def test_error_hierarchy() -> None:
    assert issubclass(HttpError, NetgearSwitchError)
    assert issubclass(HttpAuthError, HttpError)
    assert issubclass(HttpUnexpectedPageError, HttpError)


def test_merge_interleaves_characters() -> None:
    # GROUNDED: netgear-smp-vlan:merge / py_netgear_plus netgear_crypt.merge.
    assert merge("abc", "12") == "a1b2c"
    assert merge("ab", "1234") == "a1b234"
    assert merge("", "xy") == "xy"
    assert merge("xy", "") == "xy"


def test_merge_hash_md5_matches_reference() -> None:
    expected = hashlib.md5(merge("s3cr3t", "9917").encode()).hexdigest()
    assert merge_hash_md5("s3cr3t", "9917") == expected
    # 32-char lowercase hex.
    assert len(merge_hash_md5("p", "r")) == 32
