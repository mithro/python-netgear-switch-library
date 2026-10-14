"""READ-ONLY: save GS110EMX pages to tmp/ with the Gambit token scrubbed.

Usage: emx_capture.py <inventory-name> <label> <path>...
A path of the form  vlan:<vid>  saves that VLAN's membership page.
"""

import re
import sys
from pathlib import Path

from netgear_switch.config import load_inventory
from netgear_switch.sync_api import SyncSwitch

INVENTORY = "/home/tim/.config/ngsw/inventory.toml"
MEMBER = "/iss/specific/vlanMembership.html"
OUT = Path(__file__).parent

name, label, *paths = sys.argv[1:]
sw = SyncSwitch.from_config(load_inventory(INVENTORY)[name])
sess = sw._http_session()
sess.login()
token = sess._token
try:
    for path in paths:
        if path.startswith("vlan:"):
            vid = path.split(":")[1]
            first = sess.get_page(MEMBER)
            shown = re.search(r'name="vlanIdSel" value="(\d+)"', first).group(1)
            text = (
                first
                if shown == vid
                else sess.post_form(MEMBER, {"VLAN_ID": vid, "vlanIdSel": shown})
            )
            stem = f"vlanmembership_vlan{vid}"
        else:
            text = sess.get_page(path)
            stem = Path(path).stem
        out = OUT / f"{name}_{label}_{stem}.html"
        out.write_text(text.replace(token, "GAMBITTOKEN"))
        print(f"{path}: {len(text)} bytes -> {out.name}")
finally:
    sess._client.get("/iss/specific/logout.html", params={"Gambit": token})
