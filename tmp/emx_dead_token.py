"""READ-ONLY, no login: what a GS110EMX answers a request with a dead token.

Usage: emx_dead_token.py <inventory-name>
"""

import pathlib
import socket
import sys

import httpx

from netgear_switch.config import load_inventory

INVENTORY = "/home/tim/.config/ngsw/inventory.toml"

cfg = load_inventory(INVENTORY)[sys.argv[1]]
addr = socket.gethostbyname(cfg.host)
out = pathlib.Path(__file__).parent
for label, path, params in (
    ("get_page", "/iss/specific/sysInfo.html", {"Gambit": "notarealtoken"}),
    ("logout", "/iss/specific/logout.html", {"Gambit": "notarealtoken"}),
):
    resp = httpx.get(f"http://{addr}{path}", params=params, timeout=15.0)
    print(f"{label}: HTTP {resp.status_code}, {len(resp.text)} bytes")
    (out / f"{sys.argv[1]}_dead_token_{label}.html").write_text(resp.text)
    print(resp.text)
resp = httpx.post(
    f"http://{addr}/iss/specific/vlan_pvidsetting.html",
    data={"Gambit": "notarealtoken"},
    timeout=15.0,
)
print(f"post: HTTP {resp.status_code}, {len(resp.text)} bytes")
print(resp.text[:400])
