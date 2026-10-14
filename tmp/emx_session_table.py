"""Measure a GS110EMX's web session table, then leave it EMPTY again.

Logs in repeatedly, keeping every token, until the switch refuses; shows that
logging ONE session out frees a slot; then logs out every session it opened.
No configuration is read or changed. Prints no secret.
Usage: emx_session_table.py <inventory-name>
"""

import os
import re
import socket
import sys

import httpx

from netgear_switch.config import load_inventory
from netgear_switch.protocols.http.endpoints import http_spec
from netgear_switch.transport.http.client import _login_body, _referer_headers

INVENTORY = "/home/tim/.config/ngsw/inventory.toml"
LOGOUT = "/iss/specific/logout.html"
PROBE = "/iss/specific/sysInfo.html"

cfg = load_inventory(INVENTORY)[sys.argv[1]]
spec = http_spec(cfg.model)
addr = socket.gethostbyname(cfg.host)
password = cfg.http_password(env=dict(os.environ))
client = httpx.Client(
    base_url=f"http://{addr}",
    timeout=15.0,
    headers=_referer_headers(spec, addr, secure=False),
)


def login() -> tuple[str | None, str]:
    page = client.get(spec.login_path)
    resp = client.post(spec.login_post_path, data=_login_body(spec, password, page.text))
    token = re.search(r'name="Gambit"[^>]*value="([^"]*)"', resp.text)
    said = re.search(r'id="login_err_msg"[^>]*>([^<]*)<', resp.text)
    return (token.group(1) if token and token.group(1) else None), (
        said.group(1) if said else ""
    )


def alive(token: str) -> str:
    page = client.get(PROBE, params={"Gambit": token})
    return f"{len(page.text)} bytes, sysInfo={'Product Name' in page.text}"


tokens: list[str] = []
try:
    for attempt in range(1, 13):
        token, said = login()
        if token is None:
            print(f"login {attempt}: REFUSED -- {said!r}")
            break
        tokens.append(token)
        print(f"login {attempt}: ok ({len(set(tokens))} distinct tokens held)")
    print(f"sessions the table held: {len(tokens)}")
    print(f"oldest session still answers: {alive(tokens[0])}")
    gone = tokens.pop(0)
    out = client.get(LOGOUT, params={"Gambit": gone})
    print(f"logged ONE out -> HTTP {out.status_code}, {len(out.text)} bytes")
    print(f"that token afterwards: {alive(gone)}")
    token, said = login()
    print(f"login after one logout: {'ok' if token else 'REFUSED -- ' + repr(said)}")
    if token:
        tokens.append(token)
finally:
    for token in tokens:
        client.get(LOGOUT, params={"Gambit": token})
    print(f"logged out all {len(tokens)} sessions this run still held")
    token, said = login()
    print(f"table usable afterwards: {'yes' if token else 'NO -- ' + repr(said)}")
    if token:
        client.get(LOGOUT, params={"Gambit": token})
    client.close()
