"""``ngsw`` entry point: argparse wiring, dispatch, and error handling."""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from typing import TYPE_CHECKING, TypedDict

from netgear_switch.errors import NetgearSwitchError
from netgear_switch.models import VlanMode
from netgear_switch.registry import MODELS

from . import format as fmt
from . import safety
from .context import EXIT_OK, EXIT_USAGE, CliContext, exit_code_for

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import TextIO

    from netgear_switch.sync_api import SyncSwitch


def _global_parser(*, suppress_defaults: bool = False) -> argparse.ArgumentParser:
    """Options shared by the top-level parser and every subparser.

    ``argparse`` subparsers parse into a *fresh* namespace and then copy
    every attribute (including unset defaults) back onto the parent
    namespace, so a global flag given before the subcommand (e.g.
    ``ngsw --json models``) would otherwise be clobbered back to its
    default by the subparser's own copy of the same option. When this
    parser is used as a parent for a *subparser* (``suppress_defaults``),
    each option's default becomes ``argparse.SUPPRESS`` so an option left
    unset at the subcommand level doesn't overwrite a value already set
    at the top level, while explicitly repeating the flag after the
    subcommand still takes effect normally.
    """
    default = argparse.SUPPRESS if suppress_defaults else None
    gp = argparse.ArgumentParser(add_help=False)
    gp.add_argument(
        "--config",
        metavar="INVENTORY.toml",
        help="TOML inventory file",
        default=default,
    )
    gp.add_argument(
        "--switch",
        metavar="NAME",
        help="switch name from the inventory",
        default=default,
    )
    gp.add_argument(
        "--host", metavar="HOST", help="switch host (with --model)", default=default
    )
    gp.add_argument(
        "--model", metavar="KEY", help="model key (with --host)", default=default
    )
    gp.add_argument(
        "--community",
        metavar="STR",
        help="SNMP read community override",
        default=default,
    )
    gp.add_argument(
        "--write-community",
        metavar="STR",
        help="SNMP write community override",
        default=default,
    )
    gp.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON output",
        default=argparse.SUPPRESS if suppress_defaults else False,
    )
    gp.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="print tracebacks on error",
        default=argparse.SUPPRESS if suppress_defaults else False,
    )
    return gp


_ModelRow = TypedDict(
    "_ModelRow",
    {
        "key": str,
        "display_name": str,
        "class": str,
        "ports": int,
        "backends": list[str],
    },
)


def _cmd_models(
    args: argparse.Namespace,
    ctx: CliContext,
    get_switch: Callable[[], SyncSwitch],
) -> int:
    del args, get_switch  # unused: this handler needs neither
    rows: list[_ModelRow] = [
        {
            "key": m.key,
            "display_name": m.display_name,
            "class": m.switch_class.value,
            "ports": m.port_count,
            "backends": sorted(b.value for b in m.backends),
        }
        for m in MODELS.values()
    ]
    if ctx.as_json:
        print(json.dumps(rows, indent=2), file=ctx.out)
    else:
        for row in rows:
            print(
                f"{row['key']:<12} {row['display_name']:<24} "
                f"{'+'.join(row['backends'])}",
                file=ctx.out,
            )
    return EXIT_OK


def _cmd_ports(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    fmt.emit(ctx, get_switch().get_ports(), fmt.ports_table)
    return EXIT_OK


def _cmd_vlans(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    fmt.emit(ctx, get_switch().get_vlans(), fmt.vlans_table)
    return EXIT_OK


def _cmd_pvids(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    fmt.emit(ctx, get_switch().get_pvids(), fmt.pvids_table)
    return EXIT_OK


def _cmd_lldp(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    fmt.emit(ctx, get_switch().get_lldp(), fmt.lldp_table)
    return EXIT_OK


def _cmd_macs(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    fmt.emit(ctx, get_switch().get_macs(), fmt.macs_table)
    return EXIT_OK


def _cmd_sensors(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    fmt.emit(ctx, get_switch().get_sensors(), fmt.sensors_table)
    return EXIT_OK


def _cmd_show(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    fmt.emit(ctx, get_switch().snapshot(), fmt.snapshot_text)
    return EXIT_OK


def _cmd_poe(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    switch = get_switch()
    if args.port is None:
        fmt.emit(ctx, switch.get_poe(), fmt.poe_table)
        return EXIT_OK
    if args.action is None:
        print(
            "error: an action (on|off|cycle|clear-fault) is required with a port",
            file=ctx.err,
        )
        return EXIT_USAGE
    actions: dict[str, Callable[[], None]] = {
        "on": lambda: switch.set_poe(args.port, True, force=args.force),
        "off": lambda: switch.set_poe(args.port, False, force=args.force),
        "cycle": lambda: switch.cycle_poe(args.port, force=args.force),
        "clear-fault": lambda: switch.clear_poe_fault(args.port, force=args.force),
    }
    return safety.do_write(
        ctx,
        dry_run=args.dry_run,
        assume_yes=args.yes,
        host=switch.host,
        description=f"set PoE port {args.port} -> {args.action}",
        action=actions[args.action],
    )


def _cmd_port(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    switch = get_switch()
    enabled = args.state == "up"
    return safety.do_write(
        ctx,
        dry_run=args.dry_run,
        assume_yes=args.yes,
        host=switch.host,
        description=f"set port {args.port} {'up' if enabled else 'down'}",
        action=lambda: switch.set_port_enabled(args.port, enabled, force=args.force),
    )


def _cmd_pvid(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    switch = get_switch()
    return safety.do_write(
        ctx,
        dry_run=args.dry_run,
        assume_yes=args.yes,
        host=switch.host,
        description=f"set PVID port {args.port} -> VLAN {args.vlan}",
        action=lambda: switch.set_pvid(args.port, args.vlan, force=args.force),
    )


def _cmd_vlan_set(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    switch = get_switch()
    mode = VlanMode(args.mode)
    return safety.do_write(
        ctx,
        dry_run=args.dry_run,
        assume_yes=args.yes,
        host=switch.host,
        description=f"set VLAN {args.vlan} port {args.port} -> {args.mode}",
        action=lambda: switch.set_vlan_membership(
            args.vlan, args.port, mode, force=args.force
        ),
    )


def _cmd_vlan_create(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    switch = get_switch()
    return safety.do_write(
        ctx,
        dry_run=args.dry_run,
        assume_yes=args.yes,
        host=switch.host,
        description=f"create VLAN {args.vlan} named {args.name!r}",
        action=lambda: switch.create_vlan(args.vlan, args.name, force=args.force),
    )


def _cmd_vlan_delete(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    switch = get_switch()
    return safety.do_write(
        ctx,
        dry_run=args.dry_run,
        assume_yes=args.yes,
        host=switch.host,
        description=f"delete VLAN {args.vlan}",
        action=lambda: switch.delete_vlan(args.vlan, force=args.force),
    )


def _cmd_ip(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    del args
    fmt.emit(ctx, get_switch().get_mgmt_ip(), fmt.mgmt_ip_text)
    return EXIT_OK


def _cmd_ip_set(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    switch = get_switch()
    return safety.do_write(
        ctx,
        dry_run=args.dry_run,
        assume_yes=args.yes,
        host=switch.host,
        description=(
            f"set mgmt IP {args.address} netmask {args.netmask} gw {args.gateway}"
        ),
        action=lambda: switch.set_mgmt_ip(
            args.address, args.netmask, args.gateway, force=args.force
        ),
        warning="WARNING: a wrong management-IP change can strand the switch.",
    )


def build_parser() -> argparse.ArgumentParser:
    gp = _global_parser()
    parser = argparse.ArgumentParser(
        prog="ngsw",
        parents=[gp],
        description="Query and control Netgear switches over the SyncSwitch facade.",
    )
    parser.set_defaults(func=None)
    sub = parser.add_subparsers(dest="command")
    child_gp = _global_parser(suppress_defaults=True)
    models = sub.add_parser(
        "models", parents=[child_gp], help="list the known switch models"
    )
    models.set_defaults(func=_cmd_models)

    def read_cmd(name: str, handler: object, help_text: str) -> None:
        parser_ = sub.add_parser(name, parents=[child_gp], help=help_text)
        parser_.set_defaults(func=handler)

    read_cmd("ports", _cmd_ports, "show port status")
    read_cmd("vlans", _cmd_vlans, "show VLANs")
    read_cmd("pvids", _cmd_pvids, "show per-port PVIDs")
    read_cmd("lldp", _cmd_lldp, "show LLDP neighbours")
    read_cmd("macs", _cmd_macs, "show the MAC/FDB table")
    read_cmd("sensors", _cmd_sensors, "show sensors")
    read_cmd("show", _cmd_show, "show a full switch snapshot")

    poe = sub.add_parser(
        "poe", parents=[child_gp], help="show PoE status, or control a port's PoE"
    )
    poe.add_argument("port", type=int, nargs="?", help="port number to control")
    poe.add_argument(
        "action",
        nargs="?",
        choices=("on", "off", "cycle", "clear-fault"),
        help="PoE action for the given port",
    )
    safety.add_write_args(poe)
    poe.set_defaults(func=_cmd_poe)

    port = sub.add_parser("port", parents=[child_gp], help="bring a port up or down")
    port.add_argument("port", type=int, help="port number")
    port.add_argument("state", choices=("up", "down"), help="admin state")
    safety.add_write_args(port)
    port.set_defaults(func=_cmd_port)

    pvid = sub.add_parser("pvid", parents=[child_gp], help="set a port's PVID")
    pvid.add_argument("port", type=int, help="port number")
    pvid.add_argument("vlan", type=int, help="VLAN id")
    safety.add_write_args(pvid)
    pvid.set_defaults(func=_cmd_pvid)

    vlan = sub.add_parser(
        "vlan", parents=[child_gp], help="create/delete VLANs or set membership"
    )
    vlan_sub = vlan.add_subparsers(dest="vlan_cmd", required=True)

    vlan_set = vlan_sub.add_parser(
        "set", parents=[child_gp], help="set port VLAN membership"
    )
    vlan_set.add_argument("vlan", type=int)
    vlan_set.add_argument("port", type=int)
    vlan_set.add_argument("mode", choices=("untagged", "tagged", "excluded"))
    safety.add_write_args(vlan_set)
    vlan_set.set_defaults(func=_cmd_vlan_set)

    vlan_create = vlan_sub.add_parser(
        "create", parents=[child_gp], help="create a VLAN"
    )
    vlan_create.add_argument("vlan", type=int)
    vlan_create.add_argument("name")
    safety.add_write_args(vlan_create)
    vlan_create.set_defaults(func=_cmd_vlan_create)

    vlan_delete = vlan_sub.add_parser(
        "delete", parents=[child_gp], help="delete a VLAN"
    )
    vlan_delete.add_argument("vlan", type=int)
    safety.add_write_args(vlan_delete)
    vlan_delete.set_defaults(func=_cmd_vlan_delete)

    ip = sub.add_parser("ip", parents=[child_gp], help="show or set the management IP")
    ip.set_defaults(func=_cmd_ip)
    ip_sub = ip.add_subparsers(dest="ip_cmd")
    ip_set = ip_sub.add_parser(
        "set", parents=[child_gp], help="set the management IP"
    )
    ip_set.add_argument("address")
    ip_set.add_argument("netmask")
    ip_set.add_argument("gateway")
    safety.add_write_args(ip_set)
    ip_set.set_defaults(func=_cmd_ip_set)

    return parser


def main(
    argv: list[str] | None = None,
    *,
    switch_factory: Callable[[argparse.Namespace, CliContext], SyncSwitch]
    | None = None,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    out = sys.stdout if stdout is None else stdout
    err = sys.stderr if stderr is None else stderr
    inp = sys.stdin if stdin is None else stdin
    ctx = CliContext(out=out, err=err, inp=inp, as_json=args.json, verbose=args.verbose)
    if args.func is None:
        parser.print_help(err)
        return EXIT_USAGE

    def get_switch() -> SyncSwitch:
        if switch_factory is not None:
            return switch_factory(args, ctx)
        from .resolve import resolve_switch

        return resolve_switch(args)

    try:
        result: int = args.func(args, ctx, get_switch)
        return result
    except NetgearSwitchError as exc:
        if ctx.verbose:
            traceback.print_exc(file=err)
        print(f"error: {exc}", file=err)
        return exit_code_for(exc)
