"""Live check of logout-on-close on the cookie-session Plus switches (GS105PE).

READ-ONLY: per switch, log in, read the PVID page, close (which requests
/logout.cgi), then ask for the same page with the old cookie and report whether
the switch still honours it. Skips a switch that does not answer at all.
Usage: plus_logout_check.py <inventory-name>...
"""

import dataclasses
import os
import socket
import sys
import warnings

import httpx

from netgear_switch.config import load_inventory
from netgear_switch.protocols.http.endpoints import http_spec
from netgear_switch.transport.http.client import HttpClient

warnings.simplefilter("error", RuntimeWarning)
INVENTORY = "/home/tim/.config/ngsw/inventory.toml"

for name in sys.argv[1:]:
    cfg = load_inventory(INVENTORY)[name]
    spec = http_spec(cfg.model)
    try:
        addr = socket.gethostbyname(cfg.host)
        httpx.get(f"http://{addr}{spec.login_path}", timeout=5.0)
    except (OSError, httpx.HTTPError) as exc:
        print(f"{name}: not reachable ({type(exc).__name__}) -- skipped", flush=True)
        continue
    cfg = dataclasses.replace(cfg, host=addr)
    client = HttpClient(addr, cfg.http_password(env=dict(os.environ)) or "", spec)
    client.login()
    page = client.get_page(spec.pvid_path)
    cookies = dict(client._client.cookies)
    print(f"{name} ({cfg.model.key}): logged in, PVID page {len(page)} bytes")
    client.close()
    after = httpx.get(
        f"http://{addr}{spec.pvid_path}", cookies=cookies, timeout=10.0
    )
    print(
        f"  after close(): old cookie -> HTTP {after.status_code}, "
        f"{len(after.text)} bytes, same page: {after.text == page}; "
        f"head {after.text[:70]!r}",
        flush=True,
    )
