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

    from ...models import VlanMode

    #: One node of a wcd write body: text, a nested element, or repeated
    #: elements. Type-check-only, so the recursion needs no runtime resolution.
    Node: TypeAlias = "Mapping[str, str | Node | Sequence[Node]]"

# The framework escapes quotes as well as the three required characters. Kept
# identical to _build_gs728tpp_cert_xml so its proven output is unchanged.
_ESCAPES = {'"': "&quot;", "'": "&apos;"}

#: interfaceType in every VLAN/port object: 1 = physical port, 2 = LAG.
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


def port_config_body(
    port_name: str, port_id: int, *, admin_enabled: bool | None = None
) -> str:
    """Port admin state, via the ports page's ``Standard802_3List`` object.

    The page sends ``adminState`` 1 (up) / 2 (down) and omits every field the
    operator did not change -- its JS sets them to ``undefined``, which the
    serialiser drops -- so this builder emits only what it is asked to change.
    """
    entry: dict[str, str] = {
        "interfaceName": port_name,
        "interfaceType": INTERFACE_PHYSICAL,
        "interfaceID": str(port_id),
    }
    if admin_enabled is not None:
        entry["adminState"] = "1" if admin_enabled else "2"
    return write_body("Standard802_3List", "set", [{"Entry": entry}])
