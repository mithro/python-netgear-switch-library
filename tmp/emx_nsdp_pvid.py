"""Set one scratch port's PVID over NSDP (for the apply experiment).

Usage: emx_nsdp_pvid.py <inventory-name> <port> <vlan>
"""

import sys

from netgear_switch.config import load_inventory
from netgear_switch.registry import Backend
from netgear_switch.sync_api import SyncSwitch

INVENTORY = "/home/tim/.config/ngsw/inventory.toml"

name, port, vlan = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
sw = SyncSwitch.from_config(load_inventory(INVENTORY)[name])
print(f"before: {sw.get_pvids(backend=Backend.NSDP)}")
sw.set_pvid(port, vlan, backend=Backend.NSDP)
print(f"after:  {sw.get_pvids(backend=Backend.NSDP)}")
