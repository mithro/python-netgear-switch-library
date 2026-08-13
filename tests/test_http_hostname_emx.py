# tests/test_http_hostname_emx.py
"""The GS110EMX host-name write, whose form also carries the management address.

Grounded in the live switch's OWN JavaScript, read from gs110emx3
(10.1.5.27, firmware 1.0.2.8) on 2026-08-05::

    function submitSwitchInfoForm() {
        ...
        if (!checkValidName(form1.elements.switch_name, 'Switch Information'))
            return false;
        ... IP/mask/gateway character validation ...
        form1.elements["ACTION"].value = "Apply";
        form1.submit();
    }

-- an ordinary whole-form POST with ``ACTION=Apply``. Which means the host name
travels in the SAME body as ``dhcp_mode``/``IP_ADDRESS``/``SUBNET_MASK``/
``GATEWAY_ADDRESS``, and a rename that gets those wrong does not merely fail to
rename: it moves the address the caller is talking to.

LIVE-VERIFIED on gs110emx3: renamed to a throwaway, confirmed the addressing was
byte-identical, restored, confirmed again.
"""

from __future__ import annotations

import pytest

from netgear_switch.errors import UnsupportedCapabilityError
from netgear_switch.protocols.http import forms


def test_the_form_is_the_whole_form() -> None:
    """Every field the page posts, with ACTION capitalised as its JS sets it.

    The port-admin page on the SAME switch sends lowercase "apply"; both
    spellings are in that function.js, per page. Pinning the capital one here
    is why a copy-paste from the other builder cannot pass unnoticed.
    """
    body = forms.gs110emx_switch_info_form(
        switch_name="sw-test",
        dhcp_mode=forms.EMX_DHCP_ON,
        ip_address="10.1.5.27",
        subnet_mask="255.255.255.0",
        gateway_address="10.1.5.1",
    )
    assert body == {
        "switch_name": "sw-test",
        "dhcp_mode": "1",
        "refresh": "0",
        "IP_ADDRESS": "10.1.5.27",
        "SUBNET_MASK": "255.255.255.0",
        "GATEWAY_ADDRESS": "10.1.5.1",
        "refreshFlag": "0",
        "errMsg": "",
        "ACTION": "Apply",
    }


def test_the_addressing_fields_have_no_defaults() -> None:
    """The builder cannot be called without them, by construction.

    A default would be a value invented for the field that decides whether the
    switch keeps its address -- so the signature is keyword-only and complete.
    """
    with pytest.raises(TypeError):
        forms.gs110emx_switch_info_form(switch_name="sw-test")  # type: ignore[call-arg]


def test_dhcp_codes_are_the_pages_own() -> None:
    """1 = Enable, 2 = Disable, read off the live <select name="dhcp_mode">.

    Backwards would silently convert a DHCP switch to static (or vice versa)
    while appearing to be "just a rename".
    """
    assert (forms.EMX_DHCP_ON, forms.EMX_DHCP_OFF) == ("1", "2")


def _writer(dialect_model: str = "gs110emx"):
    from netgear_switch.http_write import HttpWriter
    from netgear_switch.registry import get_model

    writer = HttpWriter.__new__(HttpWriter)
    writer.model = get_model(dialect_model)
    from netgear_switch.protocols.http.endpoints import http_spec

    writer._spec = http_spec(writer.model)
    return writer


@pytest.mark.parametrize(
    "name",
    [
        "",  # the page's box cannot be empty
        "x" * 21,  # maxlength="20"
        "sw—dash",  # em dash: checkValidName() walks printable ASCII only
        "sw\tname",
    ],
)
def test_a_name_the_page_would_reject_is_refused_here(name: str) -> None:
    """checkValidName() BLANKS the field and pops an alert rather than erroring,
    so a bad name would otherwise post an empty switch_name."""
    with pytest.raises(UnsupportedCapabilityError, match="printable ASCII"):
        _writer()._set_gs110emx_hostname(name)


def test_the_verification_puts_addressing_first() -> None:
    """A rename that moved the address must be reported even if the name took.

    Asserted on the source because the failure it guards cannot be produced
    against a fake without a mock that deliberately corrupts itself -- and the
    ORDER is the whole point: reporting "renamed OK" while the switch has
    silently moved is the outcome this write exists to prevent.
    """
    import inspect

    from netgear_switch.http_write import HttpWriter

    src = inspect.getsource(HttpWriter._set_gs110emx_hostname)
    moved = src.index("CHANGED this switch's management")
    named = src.index("did not read back as")
    assert moved < named, "the addressing check must run before the name check"


def test_other_dialects_still_refuse() -> None:
    """gs105pe has the same switch_name field but its own CSRF-hash envelope,
    which has not been driven -- so it is still refused by name."""
    with pytest.raises(UnsupportedCapabilityError, match="host-name write"):
        _writer("gs105pe").set_hostname("sw-test")
