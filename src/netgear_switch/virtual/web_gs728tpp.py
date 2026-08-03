# src/netgear_switch/virtual/web_gs728tpp.py
"""GS728TPP GoAhead ``wcd`` XML-API renderers for the virtual HTTP face.

Each function renders one wcd response from a ``VirtualSwitchState`` in the
SAME shape the real switch 10.2.5.10 returns (a trailing
``<DeviceConfiguration>`` data block of ``<Object type="section">`` elements),
so the SAME ``parse.parse_goahead_*`` parsers that read the real captures read
the mock back -- proving seed<->render<->parse round-trips with no hardware.

Only the data block matters to the parsers (they slice it out and ignore the
surrounding template), so this emits a minimal-but-faithful
``<ResponseData><DeviceConfiguration>..`` envelope.
"""

from __future__ import annotations

import xml.etree.ElementTree as ElementTree
from typing import TYPE_CHECKING
from xml.sax.saxutils import escape

from .state import VlanSim

if TYPE_CHECKING:
    from .state import VirtualSwitchState

# Wire codes (see protocols/http/parse.py's GOAHEAD docstring).
_ADMIN = {True: "1", False: "2"}
_LINK = {True: "1", False: "2"}


def _wcd(data_block: str) -> str:
    """Wrap a data block in the wcd ``<ResponseData>`` envelope the parsers
    expect (they read only the ``<DeviceConfiguration>`` slice)."""
    return (
        '<?xml version="1.0" encoding="UTF-8" ?>\n<ResponseData>\n'
        "<DeviceConfiguration>\n<version>1.0</version>\n"
        f"{data_block}\n</DeviceConfiguration>\n</ResponseData>\n"
    )


def _mac_text(mac_bytes: tuple[int, ...]) -> str:
    return ":".join(f"{b:02x}" for b in mac_bytes)


def _physical_ports(state: VirtualSwitchState) -> list[int]:
    """Just the PHYSICAL ports, in order.

    The seed carries ifIndex-keyed entries for the eight LAG pseudo-interfaces
    (``po 1``..``po 8`` at 1000-1007, ifType 161) because the switch's Q-BRIDGE
    bitmaps really do include them. The real wcd pages list ONLY physical ports:
    a live ``Standard802_3List`` fetch returns 28 ``<Entry>`` rows, and the
    per-port ``VLANInterfaceList`` likewise. Rendering the LAGs would make the
    HTTP reader report interfaces the web UI never shows -- and disagree with
    SNMP, which filters them by ifType."""
    from ..registry import get_model

    port_count = get_model(state.model_key).port_count
    return [p for p in sorted(state.ports) if p <= port_count]


def _port_entry(state: VirtualSwitchState, port: int) -> str:
    sim = state.ports[port]
    # duplexOperMode 2 while up / 4 while down, and flowControlOperType
    # 1 enabled / 2 disabled -- the codes the live switch returns, decoded
    # against SNMP (see parse._GOAHEAD_DUPLEX_OPER and _GOAHEAD_FLOW_CONTROL).
    return (
        f"<Entry><interfaceName>g{port}</interfaceName>"
        f"<interfaceType>1</interfaceType><interfaceID>{port}</interfaceID>"
        f"<interfaceDescription>{escape(sim.description or '')}"
        "</interfaceDescription>"
        f"<adminState>{_ADMIN[sim.admin]}</adminState>"
        f"<linkState>{_LINK[sim.link]}</linkState>"
        f"<speedOper>{sim.speed}</speedOper>"
        f"<duplexOperMode>{'2' if sim.link else '4'}</duplexOperMode>"
        f"<duplexAdminMode>3</duplexAdminMode>"
        f"<flowControlOperType>{'1' if sim.flow_control else '2'}</flowControlOperType>"
        f"<flowControlAdminType>{'1' if sim.flow_control else '2'}"
        "</flowControlAdminType></Entry>"
    )


def render_ports(state: VirtualSwitchState) -> str:
    rows = "".join(_port_entry(state, p) for p in _physical_ports(state))
    return _wcd(f'<Standard802_3List type="section">{rows}</Standard802_3List>')


def render_pvids_membership(state: VirtualSwitchState) -> str:
    rows = ""
    for p in _physical_ports(state):
        entries = "".join(
            f"<VLANEntry><VLANID>{vid}</VLANID>"
            f"<taggingMode>{'1' if p in vlan.untagged else '2'}</taggingMode>"
            "<customerMulticastTVVLANEnabled>2</customerMulticastTVVLANEnabled>"
            "</VLANEntry>"
            for vid, vlan in sorted(state.vlans.items())
            if p in vlan.member
        )
        rows += (
            f"<Interface><interfaceName>g{p}</interfaceName>"
            f"<interfaceType>1</interfaceType><interfaceID>{p}</interfaceID>"
            f"<PVID>{state.pvids.get(p, 1)}</PVID><frameType>1</frameType>"
            "<ingressFilteringEnabled>2</ingressFilteringEnabled>"
            f"<JoinVLANList>{entries}</JoinVLANList></Interface>"
        )
    return _wcd(f'<VLANInterfaceList type="section">{rows}</VLANInterfaceList>')


def render_vlans(state: VirtualSwitchState) -> str:
    rows = "".join(
        f"<VLAN><VLANID>{vid}</VLANID><VLANName>{escape(vlan.name)}</VLANName>"
        "<authorizationType>1</authorizationType>"
        f"<VLANType>{'1' if vid == 1 else '2'}</VLANType></VLAN>"
        for vid, vlan in sorted(state.vlans.items())
    )
    return _wcd(f'<VLANList type="section">{rows}</VLANList>')


def render_poe(state: VirtualSwitchState) -> str:
    rows = "".join(
        f"<Interface><interfaceName>g{p}</interfaceName>"
        f"<interfaceType>1</interfaceType><interfaceID>{p}</interfaceID>"
        f"<adminEnable>{_ADMIN[sim.admin]}</adminEnable>"
        f"<detectionStatus>{sim.detect}</detectionStatus>"
        "<poweredDevice></poweredDevice><powerPriority>3</powerPriority>"
        "<powerClassification>1</powerClassification>"
        f"<outputVoltage>0</outputVoltage><outputCurrent>0</outputCurrent>"
        f"<outputPower>{sim.power_mw}</outputPower>"
        "<powerLimit>30000</powerLimit></Interface>"
        for p, sim in sorted(state.poe.items())
    )
    return _wcd(f'<PoEPSEInterfaceList type="section">{rows}</PoEPSEInterfaceList>')


def render_macs(state: VirtualSwitchState) -> str:
    rows = "".join(
        "<Entry><VLANName>default</VLANName>"
        f"<VLANID>{m.vlan}</VLANID>"
        f"<MACAddress>{_mac_text(m.mac_bytes)}</MACAddress>"
        f"<interfaceType>1</interfaceType><interfaceName>g{m.bridge_port}"
        "</interfaceName><addressType>3</addressType></Entry>"
        for m in state.macs
    )
    return _wcd(f'<ForwardingTable type="section">{rows}</ForwardingTable>')


def _lldp_id_text(raw: str) -> str:
    """Render an LLDP chassis/port-id for the wcd page.

    A MAC-address subtype id is stored in the shared ``LldpSim`` field as the
    6 raw latin-1 bytes (so the SNMP face emits the proper binary
    lldpRemChassisId/lldpRemPortId that ``parse._format_chassis_id`` decodes) --
    the real GS728TPP web page renders that as LOWERCASE colon-hex (see the
    captured ``deviceID``/``advertisedPortID`` values), so decode it back to
    that exact text here. A non-MAC id (a plain interface-name string) is
    rendered unchanged."""
    if len(raw) == 6:
        return ":".join(f"{ord(c):02x}" for c in raw)
    return raw


def render_lldp(state: VirtualSwitchState) -> str:
    rows = "".join(
        f"<NeighborEntry><interfaceID>{n.local_port}</interfaceID>"
        f"<interfaceType>1</interfaceType><interfaceName>g{n.local_port}"
        "</interfaceName><deviceIDSubtype>4</deviceIDSubtype>"
        f"<deviceID>{escape(_lldp_id_text(n.chassis))}</deviceID>"
        "<advertisedPortIDSubtype>3</advertisedPortIDSubtype>"
        f"<advertisedPortID>{escape(_lldp_id_text(n.port_id))}</advertisedPortID>"
        f"<portDescription>{escape(n.port_desc)}</portDescription>"
        f"<systemName>{escape(n.sys_name)}</systemName></NeighborEntry>"
        for n in state.lldp
    )
    return _wcd(f'<LLDPMEDNeighborList type="section">{rows}</LLDPMEDNeighborList>')


def render_mgmt_ip(state: VirtualSwitchState) -> str:
    m = state.mgmt
    data = (
        '<IPv4InterfaceList type="section"><ifEntry>'
        "<interfaceName>VLAN5</interfaceName>"
        f"<IPAddr>{m.address}</IPAddr><subnetMask>{m.netmask}</subnetMask>"
        "<owner>2</owner></ifEntry></IPv4InterfaceList>"
        '<IPv4GatewayList type="section"><GWEntry>'
        f"<IPAddr>{m.gateway}</IPAddr><fwdStatus>1</fwdStatus>"
        "</GWEntry></IPv4GatewayList>"
    )
    return _wcd(data)


def render_device_info_and_sensors(state: VirtualSwitchState) -> str:
    """DeviceBasicInfo (cosmetic identity) + DiagnosticsUnitList (the sensors
    the library actually reads back via ``parse_goahead_sensors``).

    The DiagnosticsUnitList fields come from ``state.sysinfo_sensors`` (each
    ``SensorSim`` carries the XML tag in ``instance`` and the wire code in
    ``raw``), so the seed is the single source of truth for both faces."""
    diag = "".join(
        f"<{s.instance}>{s.raw}</{s.instance}>" for s in state.sysinfo_sensors
    )
    dev = (
        '<DeviceBasicInfo type="section">'
        f"<deviceName>{escape(state.hostname)}</deviceName>"
        "<model>164</model>"
        f"<firmwareVersion>{escape(state.firmware)}</firmwareVersion>"
        f"<MacAddre>{_mac_text(tuple(state.nsdp_mac))}</MacAddre>"
        f"<serialNumber>{escape(state.serial)}</serialNumber>"
        "<bootVersion>2.0.0.11</bootVersion>"
        "<systemUpTime>1366421600</systemUpTime></DeviceBasicInfo>"
    )
    diag_sec = (
        '<DiagnosticsUnitList type="section"><Entry><unitID>1</unitID>'
        f"{diag}<upTime>1366421600</upTime></Entry></DiagnosticsUnitList>"
    )
    return _wcd(dev + diag_sec)


# file= substring -> renderer. The wcd query names the source XML file; the
# real captures' exact filenames drive this routing.
_ROUTES = (
    ("SystemInfo_master", render_device_info_and_sensors),
    ("IPConf_master", render_mgmt_ip),
    ("portConfiguration_master", render_ports),
    ("PortPvidConf_master", render_pvids_membership),
    ("VlanConfBasic_master", render_vlans),
    ("DynamicAddresses_master", render_macs),
    ("PoeInterfaceConf_master", render_poe),
    ("NeighborsInformation_master", render_lldp),
)


def _status_response(code: int, message: str) -> str:
    """A minimal wcd ``<ResponseData>`` status envelope (the shape the real
    switch returns for a write): ``<statusCode>`` plus a ``<statusString>``."""
    return (
        '<?xml version="1.0" encoding="UTF-8" ?>'
        f"<ResponseData><statusCode>{code}</statusCode>"
        f"<statusString>{escape(message)}</statusString></ResponseData>"
    )


def apply_cert_import(state: VirtualSwitchState, xml_body: str) -> str:
    """Accept an ``SSLCryptoCertificateImportList`` XML upload, validate it, and
    record the received certificate on ``state.uploaded_cert``.

    Returns the wcd status response. Mirrors real firmware: a well-formed body
    carrying a non-empty ``<certificate>`` and ``<privateKey>`` yields
    ``<statusCode>0</statusCode>`` and records the cert; a malformed or empty
    upload yields a NON-zero statusCode (so a transport/writer regression that
    dropped the body would be caught here rather than passing silently). DTD/
    entity declarations are rejected outright (XXE hardening, matching
    ``parse._goahead_data_block``)."""
    if "<!DOCTYPE" in xml_body or "<!ENTITY" in xml_body:
        return _status_response(3, "DTD/entity declaration rejected")
    try:
        root = ElementTree.fromstring(xml_body)
    except ElementTree.ParseError as exc:
        return _status_response(1, f"malformed XML: {exc}")
    entry = root.find("./SSLCryptoCertificateImportList/Entry")
    if entry is None:
        return _status_response(2, "no SSLCryptoCertificateImportList/Entry")
    certificate = (entry.findtext("certificate") or "").strip()
    private_key = (entry.findtext("privateKey") or "").strip()
    if not certificate or not private_key:
        return _status_response(2, "missing certificate or privateKey")
    state.uploaded_cert = certificate
    return _status_response(0, "")


def unauthenticated_response() -> str:
    """What the switch answers a ``wcd`` request with no valid session.

    CAPTURED from the live GS728TPP (10.2.5.10, firmware 6.0.1.30) by issuing a
    request with a stale sessionID cookie. Note what it is NOT: not a 302, not
    a 401, and not an empty body -- it is **HTTP 200** carrying a normal
    ``<ResponseData>`` envelope whose ActionStatus says statusCode 4. That
    detail is the whole point of reproducing it: a mock that redirected instead
    would let the client's session-expiry handling look correct while missing
    the case real hardware actually produces.
    """
    return (
        "<?xml version='1.0' encoding='UTF-8'?>\n<ResponseData>\n<ActionStatus>\n"
        "<version>1.0</version>\n<requestURL>wcd</requestURL>\n"
        "<statusCode>4</statusCode>\n<deviceStatusCode>0</deviceStatusCode>\n"
        "<statusString>Request Is not authenticated</statusString>\n"
        "</ActionStatus>\n</ResponseData>\n"
    )


def _iface_port(entry: ElementTree.Element) -> int | None:
    """``<interfaceName>g17</interfaceName>`` -> 17; a LAG or junk -> None."""
    name = (entry.findtext("interfaceName") or "").strip()
    if not name.startswith("g") or not name[1:].isdigit():
        return None
    return int(name[1:])


def apply_write(state: VirtualSwitchState, xml_body: str) -> str:
    """Apply one ``POST wcd`` write body and return the wcd status response.

    The real UI writes EVERYTHING through this one endpoint, with the object
    name and the ``action`` attribute selecting the operation -- so the mock
    must dispatch the same way rather than recognising one special upload.
    Each branch mirrors what the switch was observed to do on 10.2.5.10
    (firmware 6.0.1.30) when the library drove that exact body.

    An unrecognised object is a NON-zero statusCode, never a silent success:
    a writer that posts a body this firmware has no handler for must fail
    loudly here too.
    """
    if "<!DOCTYPE" in xml_body or "<!ENTITY" in xml_body:
        return _status_response(3, "DTD/entity declaration rejected")
    try:
        root = ElementTree.fromstring(xml_body)
    except ElementTree.ParseError as exc:
        return _status_response(1, f"malformed XML: {exc}")

    if root.find("./SSLCryptoCertificateImportList/Entry") is not None:
        return apply_cert_import(state, xml_body)

    handled = False
    for section in root:
        action = section.get("action", "set")
        name = section.tag
        if name == "VLANList":
            for vlan_el in section.findall("VLAN"):
                vid_text = (vlan_el.findtext("VLANID") or "").strip()
                if not vid_text.isdigit():
                    return _status_response(2, f"bad VLANID {vid_text!r}")
                vid = int(vid_text)
                if action == "delete":
                    state.vlans.pop(vid, None)
                else:
                    vname = (vlan_el.findtext("VLANName") or "").strip()
                    if vid in state.vlans:
                        state.vlans[vid].name = vname
                    else:
                        state.vlans[vid] = VlanSim(name=vname)
            handled = True
        elif name == "VLANMembershipList":
            for vlan_el in section.findall("VLAN"):
                vid = int((vlan_el.findtext("VLANID") or "0").strip() or 0)
                vlan = state.vlans.get(vid)
                if vlan is None:
                    return _status_response(2, f"no such VLAN {vid}")
                for member in vlan_el.findall("./MembershipList/VLANMember"):
                    port = _iface_port(member)
                    if port is None:
                        continue
                    if action == "delete":
                        vlan.member.discard(port)
                        vlan.untagged.discard(port)
                    else:
                        vlan.member.add(port)
                        # taggingMode 1 = untagged, 2 = tagged.
                        if (member.findtext("taggingMode") or "").strip() == "1":
                            vlan.untagged.add(port)
                        else:
                            vlan.untagged.discard(port)
            handled = True
        elif name == "VLANInterfaceList":
            for iface in section.findall("Interface"):
                port = _iface_port(iface)
                pvid = (iface.findtext("PVID") or "").strip()
                if port is not None and pvid.isdigit():
                    state.pvids[port] = int(pvid)
            handled = True
        elif name == "PoEPSEInterfaceList":
            for iface in section.findall("Interface"):
                port = _iface_port(iface)
                admin = (iface.findtext("adminEnable") or "").strip()
                if port is None or port not in state.poe or admin not in ("1", "2"):
                    continue
                # Device coherence, as the real switch shows: admin off ->
                # detect disabled(1); admin on with nothing attached -> the
                # port resumes SEARCHING(2) rather than delivering.
                state.poe[port].admin = admin == "1"
                state.poe[port].detect = 2 if admin == "1" else 1
            handled = True
        elif name == "DeviceBasicInfo":
            # A SCALAR section: the fields sit directly under it, with no
            # repeated <Entry>. deviceName is the switch's host name -- measured
            # equal to SNMP sysName on the live switch.
            new_name = section.findtext("deviceName")
            if new_name is not None:
                state.hostname = new_name.strip()
            handled = True
        elif name == "Standard802_3List":
            for entry in section.findall("Entry"):
                port = _iface_port(entry)
                admin = (entry.findtext("adminState") or "").strip()
                if port is None or port not in state.ports:
                    continue
                if admin in ("1", "2"):
                    state.ports[port].admin = admin == "1"
                    if admin == "2":
                        state.ports[port].link = False
                desc = entry.findtext("interfaceDescription")
                if desc is not None:
                    state.ports[port].description = desc.strip() or None
            handled = True

    if not handled:
        return _status_response(2, f"no handler for {[s.tag for s in root]}")
    return _status_response(0, "")


def render_wcd(state: VirtualSwitchState, query: str) -> str | None:
    """Route a (percent-decoded) ``wcd?{file=..}{Object}..`` query to its
    renderer, or ``None`` if this face serves no such wcd query (the caller
    404s, never fabricating a page)."""
    for needle, renderer in _ROUTES:
        if needle in query:
            return renderer(state)
    return None
