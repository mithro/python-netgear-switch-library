"""Poll a GS110EMX once a minute until its web UI lets a session in again.

Measures how long a full session table takes to drain. Each attempt is one
login; a successful one is logged out again at once. Prints no secret.
Usage: emx_session_wait.py <inventory-name> [max-minutes]
"""

import os
import re
import socket
import sys
import time

import httpx

from netgear_switch.config import load_inventory
from netgear_switch.protocols.http.endpoints import http_spec
from netgear_switch.transport.http.client import _login_body, _referer_headers

INVENTORY = "/home/tim/.config/ngsw/inventory.toml"

cfg = load_inventory(INVENTORY)[sys.argv[1]]
limit = int(sys.argv[2]) if len(sys.argv) > 2 else 40
spec = http_spec(cfg.model)
addr = socket.gethostbyname(cfg.host)
password = cfg.http_password(env=dict(os.environ))
for minute in range(limit):
    with httpx.Client(
        base_url=f"http://{addr}",
        timeout=15.0,
        headers=_referer_headers(spec, addr, secure=False),
    ) as client:
        page = client.get(spec.login_path)
        resp = client.post(
            spec.login_post_path, data=_login_body(spec, password, page.text)
        )
        token = re.search(r'name="Gambit"[^>]*value="([^"]*)"', resp.text)
        said = re.search(r'id="login_err_msg"[^>]*>([^<]*)<', resp.text)
        stamp = time.strftime("%H:%M:%S")
        if token and token.group(1):
            client.get("/iss/specific/logout.html", params={"Gambit": token.group(1)})
            print(f"{stamp} login OK (logged out again)", flush=True)
            break
        print(f"{stamp} refused: {said.group(1) if said else '?'}", flush=True)
    time.sleep(60)
