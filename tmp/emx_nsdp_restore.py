"""Restore a GS110EMX scratch port over NSDP only (no web login needed).

Puts <port>'s PVID back to <pvid> and deletes throwaway VLAN 4001, then prints
the VLAN table and PVIDs as NSDP reports them.
Usage: emx_nsdp_restore.py <inventory-name> <port> <pvid>
"""

import sys

from netgear_switch.config import load_inventory
from netgear_switch.registry import Backend
from netgear_switch.sync_api import SyncSwitch

INVENTORY = "/home/tim/.config/ngsw/inventory.toml"
SCRATCH = 4001

name, port, pvid = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
sw = SyncSwitch.from_config(load_inventory(INVENTORY)[name])
print(f"before: pvids {sw.get_pvids(backend=Backend.NSDP)}", flush=True)
if dict(sw.get_pvids(backend=Backend.NSDP))[port] != pvid:
    sw.set_pvid(port, pvid, backend=Backend.NSDP)
if any(v.vlan_id == SCRATCH for v in sw.get_vlans(backend=Backend.NSDP)):
    sw.delete_vlan(SCRATCH, force=True, backend=Backend.NSDP)
print(f"after:  pvids {sw.get_pvids(backend=Backend.NSDP)}", flush=True)
print(f"after:  vlans {[v.vlan_id for v in sw.get_vlans(backend=Backend.NSDP)]}")
