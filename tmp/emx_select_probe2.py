"""READ-ONLY probe 2: what exactly must vlanIdSel be, on each GS110EMX?

Never sends hiddenMem, so no request here can carry a membership to apply.
Usage: emx_select_probe2.py <inventory-name>...
"""

import re
import sys

from netgear_switch.config import load_inventory
from netgear_switch.protocols.http import parse
from netgear_switch.sync_api import SyncSwitch
from netgear_switch.registry import Backend

INVENTORY = "/home/tim/.config/ngsw/inventory.toml"
PAGE = "/iss/specific/vlanMembership.html"


def summary(text: str) -> str:
    mem = re.search(r'name="hiddenMem"[^>]*value="([^"]*)"', text)
    sel = re.search(r'name="vlanIdSel"[^>]*value="([^"]*)"', text)
    return (
        f"{len(text):>5} bytes vlanIdSel={sel.group(1) if sel else None!r} "
        f"hiddenMem={mem.group(1) if mem else None!r}"
    )


def probe(name: str) -> None:
    sw = SyncSwitch.from_config(load_inventory(INVENTORY)[name])
    sess = sw._http_session()
    sess.login()
    client, token = sess._client, sess._token
    try:
        dev = parse.parse_sysinfo(sess.get_page("/iss/specific/sysInfo.html"))
        print(f"== {name}: {dev}")
        vids = parse.parse_gs110emx_vlan_ids(sess.get_page("/iss/specific/Cf8021q.html"))
        print(f"  VLANs {vids}")
        first = sess.get_page(PAGE)
        print(f"  GET -> {summary(first)}")

        def post(vid: object, sel: object) -> None:
            resp = client.post(
                PAGE, data={"VLAN_ID": str(vid), "vlanIdSel": str(sel), "Gambit": token}
            )
            print(f"  POST VLAN_ID={vid!s:>5} vlanIdSel={sel!s:>5} -> {summary(resp.text)}")

        a, b = vids[1], vids[2]
        post(a, a)  # library shape
        post(a, vids[0])  # the VLAN a GET shows
        post(a, b)  # a third VLAN: neither shown nor requested
        post(a, 0)  # not a VLAN at all
        post(a, "")  # empty
        post(vids[0], vids[0])  # first VLAN, library shape
        post(vids[0], a)  # first VLAN, selected from another
        post(4094, vids[0])  # a VLAN that does not exist
        for vid in vids:
            post(vid, 0)
        print(f"  GET -> {summary(sess.get_page(PAGE))}")
        for p in sw.get_ports(backend=Backend.HTTP):
            print(f"  port {p}")
        print(f"  pvids {sw.get_pvids(backend=Backend.HTTP)}")
    finally:
        client.get("/iss/specific/logout.html", params={"Gambit": token})
        print("  logged out")


if __name__ == "__main__":
    for switch in sys.argv[1:]:
        probe(switch)
