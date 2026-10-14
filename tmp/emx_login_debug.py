"""ONE web-UI login attempt on a GS110EMX, printing what the switch answers.

Never prints the password or a session token. Logs out again if it got in.
Usage: emx_login_debug.py <inventory-name>
"""

import os
import pathlib
import re
import socket
import sys

import httpx

from netgear_switch.config import load_inventory
from netgear_switch.protocols.http.endpoints import http_spec
from netgear_switch.transport.http.client import _login_body, _referer_headers

INVENTORY = "/home/tim/.config/ngsw/inventory.toml"

cfg = load_inventory(INVENTORY)[sys.argv[1]]
spec = http_spec(cfg.model)
addr = socket.gethostbyname(cfg.host)
client = httpx.Client(
    base_url=f"http://{addr}",
    timeout=15.0,
    headers=_referer_headers(spec, addr, secure=False),
)
page = client.get(spec.login_path)
print(f"GET {spec.login_path} -> HTTP {page.status_code}, {len(page.text)} bytes")
resp = client.post(
    spec.login_post_path, data=_login_body(spec, cfg.http_password(env=dict(os.environ)), page.text)
)
token = re.search(r'name="Gambit"[^>]*value="([^"]*)"', resp.text)
got = bool(token and token.group(1))
print(f"POST {spec.login_post_path} -> HTTP {resp.status_code}, {len(resp.text)} bytes")
print(f"token returned: {got}")
shown = resp.text.replace(token.group(1), "<tok>") if got else resp.text
pathlib.Path(__file__).with_name(f"{sys.argv[1]}_login_reply.html").write_text(shown)
for line in shown.splitlines():
    if re.search(r"err|Err|maxim|session|attempt|locked|wait|rand", line):
        print("   |", line.strip()[:200])
if got:
    out = client.get("/iss/specific/logout.html", params={"Gambit": token.group(1)})
    print(f"logout -> HTTP {out.status_code}")
