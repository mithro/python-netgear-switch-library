"""GS110EMX vlan_pvidsetting.html: measure, then verify HttpWriter.set_pvid.

Touches only throwaway VLAN 4001 and link-down, undescribed scratch ports.
Talks to the switch by IPv4 address (its IPv6 address answers HTTP only
intermittently, and each miss costs a 15 s connect timeout).

Usage: emx_pvid_live.py <inventory-name> <stage> <port> [other-port]
  bare     what a PORT_NO without the trailing ';' does (raw POST)
  verify   set_pvid through the HTTP backend only, plus its refusals
"""

import dataclasses
import re
import socket
import sys

from netgear_switch.config import load_inventory
from netgear_switch.errors import HttpError
from netgear_switch.models import VlanMode
from netgear_switch.registry import Backend
from netgear_switch.sync_api import SyncSwitch

INVENTORY = "/home/tim/.config/ngsw/inventory.toml"
PAGE = "/iss/specific/vlan_pvidsetting.html"
SCRATCH = 4001

name, stage, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
cfg = load_inventory(INVENTORY)[name]
sw = SyncSwitch.from_config(
    dataclasses.replace(cfg, host=socket.gethostbyname(cfg.host))
)


def pvids() -> dict[int, int]:
    return dict(sw.get_pvids(backend=Backend.HTTP))


def raw_pvid_post(port_no: str, vlan: int) -> None:
    sess = sw._http_session()
    if not sess._logged_in:
        sess.login()
    body = f"Gambit={sess._token}&PORT_NO={port_no}&PORT_PVID={vlan}&ACTION=Apply"
    resp = sess._client.post(
        PAGE,
        content=body.encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    err = re.search(r'name="errMsg"[^>]*value="([^"]*)"', resp.text)
    print(f"  POST {body.replace(sess._token, '<tok>')}")
    print(
        f"    -> HTTP {resp.status_code} {len(resp.text)} bytes "
        f"errMsg={err.group(1) if err else None!r}",
        flush=True,
    )


ports = {p.port: p for p in sw.get_ports(backend=Backend.HTTP)}
assert not ports[port].link_up and not ports[port].name, ports[port]
start = pvids()
print(f"{name}: scratch port {port} link-down, undescribed; PVIDs {start}", flush=True)

sw.create_vlan(SCRATCH, "scratch", backend=Backend.NSDP)
try:
    sw.set_vlan_membership(SCRATCH, port, VlanMode.UNTAGGED, backend=Backend.HTTP)
    print(f"  VLAN {SCRATCH} created (NSDP), port {port} untagged in it (HTTP)")
    if stage == "bare":
        raw_pvid_post(str(port), SCRATCH)
        print(f"  PVIDs after bare PORT_NO: {pvids()}", flush=True)
        raw_pvid_post(f"{port};", 4094)
        print(f"  PVIDs after PVID -> missing VLAN 4094: {pvids()}", flush=True)
    else:
        other = int(sys.argv[4])
        assert not ports[other].link_up and not ports[other].name, ports[other]
        sw.set_pvid(port, SCRATCH, backend=Backend.HTTP)
        print(f"  HTTP set_pvid({port}, {SCRATCH}) -> PVIDs {pvids()}", flush=True)
        for bad_port, bad_vlan, why in (
            (other, SCRATCH, "a VLAN the port is not in"),
            (port, 4094, "a VLAN the switch lacks"),
        ):
            try:
                sw.set_pvid(bad_port, bad_vlan, backend=Backend.HTTP)
                print(f"  UNEXPECTED: PVID -> {why} was accepted")
            except HttpError as exc:
                print(f"  {why}: {type(exc).__name__}: {exc}", flush=True)
        print(f"  PVIDs after the refusals: {pvids()}", flush=True)
finally:
    if pvids() != start:
        if stage == "bare":
            raw_pvid_post(f"{port};", start[port])
        else:
            sw.set_pvid(port, start[port], backend=Backend.HTTP)
    print(f"  PVIDs restored: {pvids() == start} {pvids()}", flush=True)
    sw.set_vlan_membership(SCRATCH, port, VlanMode.EXCLUDED, backend=Backend.HTTP)
    sw.delete_vlan(SCRATCH, force=True, backend=Backend.NSDP)
    print(f"  port {port} excluded (HTTP), VLAN {SCRATCH} deleted (NSDP)", flush=True)
    # This branch predates logout-on-close: end the web session by hand so the
    # switch's (five-slot) session table is left as it was found.
    web = sw._http_session()
    web._client.get("/iss/specific/logout.html", params={"Gambit": web._token})
    print("  web session logged out", flush=True)
