"""Pure (I/O-free) builders for GoAhead ``wcd`` XML write bodies.

The GS728TPP web UI is not an HTML form UI: every page reads through
``GET wcd?{file=...}{Object}`` and writes through a single ``POST wcd`` whose
body is an XML document. Its site map has exactly one POST target -- ``wcd`` --
repeated for all 100-odd pages, so the object name and the action verb in the
body, not the URL, are what select the operation.

The wire shape is GROUNDED, not inferred. Each page's own JavaScript builds a
``post`` object and the framework serialises it; two of those builders were
captured verbatim from the live switch (10.2.5.10, firmware 6.0.1.30):

``Switching/VLAN/VlanMembership_jq.htm``::

    post.VLANMembershipList['set'] = [{VLAN: {VLANID: "5",
        MembershipList: [{VLANMember: {interfaceName: "g17",
            interfaceType: "1", membershipType: "2", taggingMode: "2"}}]}}]
    post.VLANMembershipList['delete'] = [{VLAN: {VLANID: "5",
        MembershipList: [{VLANMember: {interfaceName: "g17",
            interfaceType: "1"}}]}}]

``Switching/Ports/portConfiguration_master_jq.htm``::

    post.Standard802_3List = {set: [{Entry: {interfaceName: ..., ...}}]}

and the library's own ``_build_gs728tpp_cert_xml`` -- whose envelope came from
the certbot hook that works against real GS728TPPs -- serialises the same
structure as::

    <DeviceConfiguration><SSLCryptoCertificateImportList action="set">
      <Entry>...</Entry></SSLCryptoCertificateImportList></DeviceConfiguration>

So the rule is: the JS object key becomes the element name, the ``set``/
``delete`` key becomes the ``action`` attribute on the object element, and each
list entry is one repeated child element.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING
from xml.sax.saxutils import escape as _escape

if TYPE_CHECKING:
    from collections.abc import Sequence
    from typing import TypeAlias

    from ...models import PortSpeed, VlanMode

    #: One node of a wcd write body: text, a nested element, or repeated
    #: elements. Type-check-only, so the recursion needs no runtime resolution.
    Node: TypeAlias = "Mapping[str, str | Node | Sequence[Node]]"

# The framework escapes quotes as well as the three required characters. Kept
# identical to _build_gs728tpp_cert_xml so its proven output is unchanged.
_ESCAPES = {'"': "&quot;", "'": "&apos;"}

#: interfaceType in every VLAN/port object -- 1 = physical port, 2 = LAG.
#: (No ``:`` after the name, deliberately. Napoleon reads a ONE-LINE ``#:``
#: comment shaped ``x: y`` as "type x, described as y", which rendered a
#: nonsense "Type: interfaceType in every VLAN/port object" field on the page
#: and failed the nitpicky build. The two-line comment below is unaffected.)
INTERFACE_PHYSICAL = "1"
INTERFACE_LAG = "2"

#: taggingMode, from the membership page's own "Group Operation" select:
#: "2" Tag All, "1" Untag All, "0" Remove All.
TAGGING_TAGGED = "2"
TAGGING_UNTAGGED = "1"
TAGGING_REMOVED = "0"


def _render(node: Node) -> str:
    out: list[str] = []
    for name, value in node.items():
        if isinstance(value, str):
            out.append(f"<{name}>{_escape(value, _ESCAPES)}</{name}>")
        elif isinstance(value, Mapping):
            out.append(f"<{name}>{_render(value)}</{name}>")
        else:  # a sequence of single-key child elements
            inner = "".join(_render(item) for item in value)
            out.append(f"<{name}>{inner}</{name}>")
    return "".join(out)


def write_body(obj: str, action: str, children: Sequence[Node]) -> str:
    """Render one ``POST wcd`` body.

    ``obj`` is the page's object name (``VLANList``, ``PoEPSEInterfaceList``,
    ...), ``action`` the verb the page's JS used as the key (``set`` or
    ``delete``), and ``children`` the repeated child elements, each a
    single-key mapping whose key is the element name.
    """
    inner = "".join(_render(child) for child in children)
    return (
        "<?xml version='1.0' encoding='utf-8'?>"
        f'<DeviceConfiguration><{obj} action="{action}">'
        f"{inner}</{obj}></DeviceConfiguration>"
    )


def port_interface_name(port: int) -> str:
    """``17`` -> ``"g17"``, the ``interfaceName`` every wcd object keys on.

    The inverse of ``parse._goahead_port_num``, which is what the read side
    already relies on: the live switch names its 28 physical ports ``g1``..
    ``g28`` and its LAGs ``LAG1``.. -- so a name that does not match this shape
    is not a physical port at all. Kept beside the builders that use it, rather
    than formatted inline at each call site, so the convention has one
    definition on the write side too.
    """
    return f"g{port}"


def tagging_mode(mode: VlanMode) -> str:
    """The page's ``taggingMode`` code for a library ``VlanMode``."""
    from ...models import VlanMode as _VlanMode

    return {
        _VlanMode.TAGGED: TAGGING_TAGGED,
        _VlanMode.UNTAGGED: TAGGING_UNTAGGED,
        _VlanMode.EXCLUDED: TAGGING_REMOVED,
    }[mode]


def vlan_membership_body(vlan: int, port_name: str, mode: VlanMode) -> str:
    """One port's membership of ``vlan``.

    EXCLUDED is not a ``set`` with taggingMode 0 -- the page routes it to a
    separate ``delete`` action carrying only the interface identity, with no
    membershipType/taggingMode. That asymmetry is the page's, and reproducing
    it is the difference between removing a port and setting it to a mode the
    firmware does not have.
    """
    from ...models import VlanMode as _VlanMode

    member: dict[str, str] = {
        "interfaceName": port_name,
        "interfaceType": INTERFACE_PHYSICAL,
    }
    if mode is not _VlanMode.EXCLUDED:
        member["membershipType"] = "2"
        member["taggingMode"] = tagging_mode(mode)
    action = "delete" if mode is _VlanMode.EXCLUDED else "set"
    return write_body(
        "VLANMembershipList",
        action,
        [
            {
                "VLAN": {
                    "VLANID": str(vlan),
                    "MembershipList": [{"VLANMember": member}],
                }
            }
        ],
    )


def poe_admin_body(port_name: str, enabled: bool) -> str:
    """PoE admin state, via ``PoEPSEInterfaceList``.

    ``adminEnable`` 1 = enabled, 2 = disabled -- the same codes the READ side
    already decodes from this object.

    Note what is NOT here: this UI has no PoE reset/power-cycle control at all.
    ``Behaviour/UnitsPoe.js`` contains no reset, cycle or reboot action, and the
    page's only buttons are Refresh/Cancel/Apply. A power cycle over HTTP is
    therefore an admin off-then-on re-arm of this same field -- exactly what
    SnmpWriter does on models whose agent has no reset column either.
    """
    return write_body(
        "PoEPSEInterfaceList",
        "set",
        [
            {
                "Interface": {
                    "interfaceName": port_name,
                    "interfaceType": INTERFACE_PHYSICAL,
                    "adminEnable": "1" if enabled else "2",
                }
            }
        ],
    )


def vlan_create_body(vlan: int, name: str) -> str:
    """Create one VLAN, via ``VLANList``.

    There is no "add" verb on this UI: the framework (``js/home.js``) defines
    exactly ACTION_SET="set", ACTION_DELETE="delete" and ACTION_RESTORE=
    "restore", and ``createPostXml`` stamps a NEW row with ACTION_SET like any
    other edit. So creating and editing a VLAN are the same request shape.

    The switch's own page rejects ids outside 2-4093 (``VlanConfig
    .checkValidVLANId``), which is narrower than the 1-4094 the protocol allows
    -- VLAN 1 is the default VLAN and cannot be created.
    """
    return write_body(
        "VLANList",
        "set",
        [{"VLAN": {"VLANID": str(vlan), "VLANName": name}}],
    )


def vlan_delete_body(vlan: int) -> str:
    """Delete one VLAN, via ``VLANList``.

    The shape is taken verbatim from ``VlanConfig.Reset``, which posts a
    literal string rather than building it through the framework -- so it
    states the delete envelope exactly::

        <DeviceConfiguration><VLANInterfaceList action="restoreAll"/>
          <VLANList action="delete"><VLAN><VLANID>4-4093</VLANID></VLAN>
        </VLANList></DeviceConfiguration>

    (That page-level "restore everything" is deliberately NOT reproduced here:
    this deletes the one VLAN it was asked to, and nothing else.)
    """
    return write_body("VLANList", "delete", [{"VLAN": {"VLANID": str(vlan)}}])


def pvid_body(port_name: str, vlan: int) -> str:
    """One port's PVID, via ``VLANInterfaceList`` -- the object the read side
    already parses PVIDs and per-port membership out of.

    The page's own validation allows 1-4093 or 4095, and rejects 4094
    explicitly (``PortPVID.Apply``).
    """
    return write_body(
        "VLANInterfaceList",
        "set",
        [
            {
                "Interface": {
                    "interfaceName": port_name,
                    "interfaceType": INTERFACE_PHYSICAL,
                    "PVID": str(vlan),
                }
            }
        ],
    )


def port_config_body(
    port_name: str,
    port_id: int,
    *,
    admin_enabled: bool | None = None,
    description: str | None = None,
) -> str:
    """Port admin state and/or description, via ``Standard802_3List``.

    The page sends ``adminState`` 1 (up) / 2 (down) and omits every field the
    operator did not change -- its JS sets them to ``undefined``, which the
    serialiser drops -- so this builder emits only what it is asked to change.

    ``description`` is ``interfaceDescription``, the same element the read side
    already parses. An EMPTY string is a real value here (it clears the label),
    which is why the parameter defaults to None for "leave alone" rather than
    using "" as the sentinel.
    """
    entry: dict[str, str] = {
        "interfaceName": port_name,
        "interfaceType": INTERFACE_PHYSICAL,
        "interfaceID": str(port_id),
    }
    if admin_enabled is not None:
        entry["adminState"] = "1" if admin_enabled else "2"
    if description is not None:
        entry["interfaceDescription"] = description
    return write_body("Standard802_3List", "set", [{"Entry": entry}])


#: The speed/duplex choices this UI offers, READ OFF the page's own
#: ``slctPortSpeed`` ``<option>`` list (captured in
#: ``tests/fixtures/http/gs728tpp_ports.xml``)::
#:
#:     10H  10M Half Duplex      100H 100M Half Duplex     0 Auto
#:     10F  10M Full Duplex      100F 100M Full Duplex
#:                               1000F 1000M Full Duplex
#:
#: Two things fall out that a guess would have got wrong. This UI DOES offer a
#: forced 1000 -- unlike the FASTPATH CLI, whose grammar omits it -- which is
#: why the forced-1000 refusal lives in the CLI writer and not in ``PortSpeed``.
#: And there is no ``1000H``: gigabit half-duplex is not a thing the page will
#: let an operator ask for, so neither will this builder.
GOAHEAD_FORCED_SPEEDS: frozenset[tuple[int, bool]] = frozenset(
    {
        (10, False),
        (10, True),
        (100, False),
        (100, True),
        (1000, True),
    }
)

#: ``duplexAdminMode`` as the page's SUBMIT path writes it: 3 = full, 2 = half
#: (``duplexAdmin = (duplexCode == "H") ? "2" : "3"``). Deliberately NOT the
#: same enum as ``duplexOperMode`` on the read side, where 2 means full -- see
#: ``parse._GOAHEAD_DUPLEX_OPER``.
DUPLEX_ADMIN_FULL = "3"
DUPLEX_ADMIN_HALF = "2"
#: ``autoNegotiationAdminEnabled``: 1 = negotiating, 2 = forced.
AUTONEG_ON = "1"
AUTONEG_OFF = "2"


def port_speed_body(port_name: str, port_id: int, speed: PortSpeed) -> str:
    """Port speed/duplex via ``Standard802_3List``, exactly as the page sends it.

    Transcribed from the submit builder in the page's own JS, which turns one
    dropdown value into three elements::

        var autoNegAdmin = (speedAdmin == "0") ? "1" : "2";
        if (speedAdmin == "0") duplexAdmin = "3";
        else { duplexAdmin = (last char == "H") ? "2" : "3";
               speedAdmin = parseInt(speedAdmin, 10); }

    So AUTO sends ``autoNegotiationAdminEnabled=1, speedAdmin=0,
    duplexAdminMode=3`` -- note it sends a speed of 0 rather than omitting the
    field -- and a forced choice sends ``autoNegotiationAdminEnabled=2`` with
    the parsed rate and the duplex code.
    """
    if speed.autonegotiate:
        rate, autoneg, duplex = "0", AUTONEG_ON, DUPLEX_ADMIN_FULL
    else:
        assert speed.speed_mbps is not None  # PortSpeed.__post_init__ ensures it
        rate, autoneg = str(speed.speed_mbps), AUTONEG_OFF
        duplex = DUPLEX_ADMIN_FULL if speed.full_duplex else DUPLEX_ADMIN_HALF
    return write_body(
        "Standard802_3List",
        "set",
        [
            {
                "Entry": {
                    "interfaceName": port_name,
                    "interfaceType": INTERFACE_PHYSICAL,
                    "interfaceID": str(port_id),
                    "autoNegotiationAdminEnabled": autoneg,
                    "speedAdmin": rate,
                    "duplexAdminMode": duplex,
                }
            }
        ],
    )
