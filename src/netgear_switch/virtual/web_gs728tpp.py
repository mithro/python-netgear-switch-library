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

from typing import TYPE_CHECKING
from xml.sax.saxutils import escape

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


def render_ports(state: VirtualSwitchState) -> str:
    rows = "".join(
        f"<Entry><interfaceName>g{p}</interfaceName>"
        f"<interfaceType>1</interfaceType><interfaceID>{p}</interfaceID>"
        f"<interfaceDescription>{escape(sim.description or '')}"
        "</interfaceDescription>"
        f"<adminState>{_ADMIN[sim.admin]}</adminState>"
        f"<linkState>{_LINK[sim.link]}</linkState>"
        f"<speedOper>{sim.speed}</speedOper></Entry>"
        for p, sim in sorted(state.ports.items())
    )
    return _wcd(f'<Standard802_3List type="section">{rows}</Standard802_3List>')


def render_pvids_membership(state: VirtualSwitchState) -> str:
    rows = ""
    for p, _sim in sorted(state.ports.items()):
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


def render_lldp(state: VirtualSwitchState) -> str:
    rows = "".join(
        f"<NeighborEntry><interfaceID>{n.local_port}</interfaceID>"
        f"<interfaceType>1</interfaceType><interfaceName>g{n.local_port}"
        "</interfaceName><deviceIDSubtype>4</deviceIDSubtype>"
        f"<deviceID>{escape(n.chassis)}</deviceID>"
        "<advertisedPortIDSubtype>3</advertisedPortIDSubtype>"
        f"<advertisedPortID>{escape(n.port_id)}</advertisedPortID>"
        f"<portDescription>{escape(n.port_desc)}</portDescription>"
        f"<systemName>{escape(n.sys_name)}</systemName></NeighborEntry>"
        for n in state.lldp
    )
    return _wcd(
        f'<LLDPMEDNeighborList type="section">{rows}</LLDPMEDNeighborList>'
    )


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
        f"<{s.instance}>{s.raw}</{s.instance}>"
        for s in state.sysinfo_sensors
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


def render_wcd(state: VirtualSwitchState, query: str) -> str | None:
    """Route a (percent-decoded) ``wcd?{file=..}{Object}..`` query to its
    renderer, or ``None`` if this face serves no such wcd query (the caller
    404s, never fabricating a page)."""
    for needle, renderer in _ROUTES:
        if needle in query:
            return renderer(state)
    return None
