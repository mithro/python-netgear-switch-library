"""READ-ONLY live check: SyncSwitch.close() logs out of a GS110EMX's web UI.

Opens <count> library sessions one after another (HTTP backend only), each
closed when done, then confirms a login is still accepted afterwards.
Usage: emx_live_close.py <inventory-name> [count]
"""

import dataclasses
import socket
import sys
import warnings

from netgear_switch.config import load_inventory
from netgear_switch.registry import Backend
from netgear_switch.sync_api import SyncSwitch

warnings.simplefilter("error", RuntimeWarning)
INVENTORY = "/home/tim/.config/ngsw/inventory.toml"

name = sys.argv[1]
count = int(sys.argv[2]) if len(sys.argv) > 2 else 6
cfg = load_inventory(INVENTORY)[name]
cfg = dataclasses.replace(cfg, host=socket.gethostbyname(cfg.host))
for attempt in range(1, count + 1):
    with SyncSwitch.from_config(cfg) as sw:
        pvids = sw.get_pvids(backend=Backend.HTTP)
    print(f"session {attempt}: read {len(pvids)} PVIDs over HTTP, closed", flush=True)
print(f"{count} sessions in a row, none refused, no logout warning")
