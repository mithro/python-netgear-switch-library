"""Staged GS110EMX vlanMembership.html apply experiment on a THROWAWAY VLAN.

Only ever targets VLAN 4001 and one link-down, undescribed scratch port.
Usage: emx_apply_experiment.py <inventory-name> <stage> [args]

Stages:
  dump <label>          record VLAN list, every VLAN's hiddenMem and the PVIDs
  create                create VLAN 4001 over NSDP
  select                the browser's dropdown POST (carries hiddenMem) -> 4001
  apply <port> <code>   set <port>'s code (1/2/3) in VLAN 4001, browser Apply shape
  delete                delete VLAN 4001 over NSDP
  diff <a> <b>          compare two recorded dumps
"""

import json
import re
import sys
from pathlib import Path

from netgear_switch.config import load_inventory
from netgear_switch.protocols.http import parse
from netgear_switch.registry import Backend
from netgear_switch.sync_api import SyncSwitch

INVENTORY = "/home/tim/.config/ngsw/inventory.toml"
PAGE = "/iss/specific/vlanMembership.html"
SCRATCH = 4001
OUT = Path(__file__).parent


def field(text: str, name: str) -> str | None:
    m = re.search(rf'name="{name}"[^>]*value="([^"]*)"', text)
    return m.group(1) if m else None


def summary(text: str) -> str:
    return (
        f"{len(text):>5} bytes vlanIdSel={field(text, 'vlanIdSel')!r} "
        f"hiddenMem={field(text, 'hiddenMem')!r} errMsg={field(text, 'errMsg')!r}"
    )


class Web:
    def __init__(self, sw: SyncSwitch) -> None:
        self.sess = sw._http_session()
        self.sess.login()
        self.client, self.token = self.sess._client, self.sess._token

    def close(self) -> None:
        self.client.get("/iss/specific/logout.html", params={"Gambit": self.token})

    def post(self, pairs: list[tuple[str, str]]) -> str:
        body = "&".join(f"{k}={v}" for k, v in [("Gambit", self.token), *pairs])
        resp = self.client.post(
            PAGE,
            content=body.encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        print(f"  POST {body.replace(self.token, '<tok>')}")
        print(f"    -> HTTP {resp.status_code} {summary(resp.text)}")
        return resp.text

    def membership(self, vid: int, shown: str) -> str:
        if str(vid) == shown:
            return self.sess.get_page(PAGE)
        return self.sess.post_form(PAGE, {"VLAN_ID": str(vid), "vlanIdSel": shown})

    def dump(self) -> dict[str, object]:
        vids = parse.parse_gs110emx_vlan_ids(
            self.sess.get_page("/iss/specific/Cf8021q.html")
        )
        first = self.sess.get_page(PAGE)
        shown = field(first, "vlanIdSel") or ""
        mem = {}
        for vid in vids:
            page = self.membership(vid, shown)
            assert field(page, "vlanIdSel") == str(vid), summary(page)
            mem[str(vid)] = field(page, "hiddenMem")
        pvids = parse.parse_gs110emx_pvids(
            self.sess.get_page("/iss/specific/vlan_pvidsetting.html")
        )
        return {"vlans": vids, "hiddenMem": mem, "pvids": [list(p) for p in pvids]}


def main() -> None:
    name, stage, *args = sys.argv[1:]
    if stage == "diff":
        a = json.loads((OUT / f"{name}_{args[0]}.json").read_text())
        b = json.loads((OUT / f"{name}_{args[1]}.json").read_text())
        print(f"{args[0]} == {args[1]}: {a == b}")
        for key in a:
            if a[key] != b[key]:
                print(f"  {key}:\n    {a[key]}\n    {b[key]}")
        return
    sw = SyncSwitch.from_config(load_inventory(INVENTORY)[name])
    if stage == "create":
        sw.create_vlan(SCRATCH, "scratch", backend=Backend.NSDP)
        print(f"created VLAN {SCRATCH} over NSDP")
        return
    if stage == "delete":
        sw.delete_vlan(SCRATCH, force=True, backend=Backend.NSDP)
        print(f"deleted VLAN {SCRATCH} over NSDP")
        return
    web = Web(sw)
    try:
        if stage == "dump":
            state = web.dump()
            (OUT / f"{name}_{args[0]}.json").write_text(json.dumps(state, indent=1))
            print(json.dumps(state))
        elif stage == "select":
            first = web.sess.get_page(PAGE)
            print(f"  GET -> {summary(first)}")
            web.post(
                [
                    ("VLAN_ID", str(SCRATCH)),
                    ("vlanIdSel", field(first, "vlanIdSel") or ""),
                    ("hiddenMem", field(first, "hiddenMem") or ""),
                    ("ACTION", ""),
                ]
            )
        elif stage == "apply":
            port, code = int(args[0]), args[1]
            first = web.sess.get_page(PAGE)
            shown = field(first, "vlanIdSel") or ""
            page = web.membership(SCRATCH, shown)
            print(f"  before -> {summary(page)}")
            mem = list(field(page, "hiddenMem") or "")
            mem[port - 1] = code
            web.post(
                [
                    ("VLAN_ID", str(SCRATCH)),
                    ("vlanIdSel", str(SCRATCH)),
                    ("hiddenMem", "".join(mem)),
                    ("ACTION", ""),
                ]
            )
            print(f"  after  -> {summary(web.membership(SCRATCH, shown))}")
    finally:
        web.close()


if __name__ == "__main__":
    main()
