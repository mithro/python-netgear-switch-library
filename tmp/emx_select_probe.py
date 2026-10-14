"""READ-ONLY probe: which VLAN-select POST shape does a real GS110EMX answer?

Never sends hiddenMem, so no request here can carry a membership to apply.
Usage: emx_select_probe.py <inventory-name> <target-vid>
"""

import re
import sys

from netgear_switch.config import load_inventory
from netgear_switch.sync_api import SyncSwitch

INVENTORY = "/home/tim/.config/ngsw/inventory.toml"
PAGE = "/iss/specific/vlanMembership.html"


def summary(text: str) -> str:
    mem = re.search(r'name="hiddenMem"[^>]*value="([^"]*)"', text)
    sel = re.search(r'name="vlanIdSel"[^>]*value="([^"]*)"', text)
    return (
        f"{len(text):>5} bytes vlanIdSel={sel.group(1) if sel else None!r} "
        f"hiddenMem={mem.group(1) if mem else None!r}"
    )


def main() -> None:
    name, target = sys.argv[1], sys.argv[2]
    sw = SyncSwitch.from_config(load_inventory(INVENTORY)[name])
    sess = sw._http_session()
    sess.login()
    client, token = sess._client, sess._token
    try:
        sys_html = sess.get_page("/iss/specific/sysInfo.html")
        fw = re.search(r"V\d+\.\d+\.\d+\.\d+", sys_html)
        print(f"{name}: firmware {fw.group(0) if fw else 'not found'}")

        def get() -> str:
            text = sess.get_page(PAGE)
            print(f"  GET                      -> {summary(text)}")
            sel = re.search(r'name="vlanIdSel"[^>]*value="([^"]*)"', text)
            return sel.group(1) if sel else ""

        def post(label: str, pairs: list[tuple[str, str]]) -> None:
            body = "&".join(f"{k}={v}" for k, v in pairs)
            resp = client.post(
                PAGE,
                content=body.encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            shown = body.replace(token, "<tok>")
            print(f"  POST {label}: {shown}")
            print(f"       -> HTTP {resp.status_code} {summary(resp.text)}")

        shown = get()
        g = ("Gambit", token)
        post("A library shape ", [("VLAN_ID", target), ("vlanIdSel", target), g])
        get()
        post("B sel=shown     ", [("VLAN_ID", target), ("vlanIdSel", shown), g])
        shown = get()
        post("C B+gambit first", [g, ("VLAN_ID", target), ("vlanIdSel", shown)])
        shown = get()
        post(
            "D C+ACTION empty",
            [g, ("VLAN_ID", target), ("vlanIdSel", shown), ("ACTION", "")],
        )
        get()
    finally:
        client.get("/iss/specific/logout.html", params={"Gambit": token})
        print("  logged out")


if __name__ == "__main__":
    main()
