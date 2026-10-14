"""Live check of HttpWriter.set_vlan_membership on a GS110EMX, HTTP backend only.

Touches only throwaway VLAN 4001 and one link-down, undescribed scratch port.
The caller records state before/after with emx_apply_experiment.py dump/diff.
Usage: emx_live_writer.py <inventory-name> <scratch-port>
"""

import sys

from netgear_switch.config import load_inventory
from netgear_switch.errors import HttpError
from netgear_switch.models import VlanMode
from netgear_switch.registry import Backend
from netgear_switch.sync_api import SyncSwitch

INVENTORY = "/home/tim/.config/ngsw/inventory.toml"
SCRATCH = 4001

name, port = sys.argv[1], int(sys.argv[2])
sw = SyncSwitch.from_config(load_inventory(INVENTORY)[name])


def show(label: str) -> None:
    (v,) = [v for v in sw.get_vlans(backend=Backend.HTTP) if v.vlan_id == SCRATCH]
    print(
        f"  {label:<34} VLAN {SCRATCH}: untagged={sorted(v.untagged_ports)} "
        f"tagged={sorted(v.tagged_ports)}",
        flush=True,
    )


ports = {p.port: p for p in sw.get_ports(backend=Backend.HTTP)}
assert not ports[port].link_up and not ports[port].name, ports[port]
print(f"{name}: scratch port {port} is link-down and undescribed", flush=True)

sw.create_vlan(SCRATCH, "scratch", backend=Backend.NSDP)
try:
    show("created (NSDP)")
    for mode in (VlanMode.TAGGED, VlanMode.UNTAGGED):
        sw.set_vlan_membership(SCRATCH, port, mode, backend=Backend.HTTP)
        show(f"HTTP set -> {mode.value}")
    sw.set_pvid(port, SCRATCH, backend=Backend.NSDP)
    print(f"  PVID of port {port} -> {SCRATCH} (NSDP)", flush=True)
    try:
        sw.set_vlan_membership(SCRATCH, port, VlanMode.EXCLUDED, backend=Backend.HTTP)
        print("  UNEXPECTED: exclude was accepted while the PVID names the VLAN")
    except HttpError as exc:
        print(f"  refusal raised: {type(exc).__name__}: {exc}", flush=True)
    show("after the refused exclude")
    try:
        sw.set_vlan_membership(4094, port, VlanMode.TAGGED, backend=Backend.HTTP)
        print("  UNEXPECTED: a VLAN the switch lacks was accepted")
    except HttpError as exc:
        print(f"  unknown VLAN raised: {type(exc).__name__}: {exc}", flush=True)
finally:
    sw.set_pvid(port, 1, backend=Backend.NSDP)
    print(f"  PVID of port {port} -> 1 (NSDP)", flush=True)
    sw.set_vlan_membership(SCRATCH, port, VlanMode.EXCLUDED, backend=Backend.HTTP)
    show("HTTP set -> excluded")
    sw.delete_vlan(SCRATCH, force=True, backend=Backend.NSDP)
    print(f"  deleted VLAN {SCRATCH} (NSDP)", flush=True)
