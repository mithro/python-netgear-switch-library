"""READ-ONLY live check: get_vlans over the HTTP backend only, per switch.

Usage: emx_live_get_vlans.py <inventory-name>...
"""

import sys

from netgear_switch.config import load_inventory
from netgear_switch.registry import Backend
from netgear_switch.sync_api import SyncSwitch

INVENTORY = "/home/tim/.config/ngsw/inventory.toml"

for name in sys.argv[1:]:
    sw = SyncSwitch.from_config(load_inventory(INVENTORY)[name])
    vlans = sw.get_vlans(backend=Backend.HTTP)
    print(f"{name}: {len(vlans)} VLANs over HTTP", flush=True)
    for v in vlans:
        print(
            f"  VLAN {v.vlan_id:>4}: untagged={sorted(v.untagged_ports)} "
            f"tagged={sorted(v.tagged_ports)}",
            flush=True,
        )
    sw.close()
