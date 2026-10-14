"""GS110EMX vlan_pvidsetting.html apply experiment on a scratch port.

Posts exactly what the firmware's own submitPortPVID() posts.
Usage: emx_pvid_experiment.py <inventory-name> <port> <vlan> [port-no-format]
"""

import re
import sys

from netgear_switch.config import load_inventory
from netgear_switch.protocols.http import parse
from netgear_switch.sync_api import SyncSwitch

INVENTORY = "/home/tim/.config/ngsw/inventory.toml"
PAGE = "/iss/specific/vlan_pvidsetting.html"

name, port, vlan = sys.argv[1], sys.argv[2], sys.argv[3]
port_no = (sys.argv[4] if len(sys.argv) > 4 else "{};").format(port)
sw = SyncSwitch.from_config(load_inventory(INVENTORY)[name])
sess = sw._http_session()
sess.login()
client, token = sess._client, sess._token
try:
    print(f"  before {parse.parse_gs110emx_pvids(sess.get_page(PAGE))}")
    body = f"Gambit={token}&PORT_NO={port_no}&PORT_PVID={vlan}&ACTION=Apply"
    resp = client.post(
        PAGE,
        content=body.encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    err = re.search(r'name="errMsg"[^>]*value="([^"]*)"', resp.text)
    print(f"  POST {body.replace(token, '<tok>')}")
    print(
        f"    -> HTTP {resp.status_code} {len(resp.text)} bytes "
        f"errMsg={err.group(1) if err else None!r} head={resp.text[:60]!r}"
    )
    print(f"  after  {parse.parse_gs110emx_pvids(sess.get_page(PAGE))}")
finally:
    client.get("/iss/specific/logout.html", params={"Gambit": token})
