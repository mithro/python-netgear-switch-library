"""``ngsw`` entry point: argparse wiring, dispatch, and error handling."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
import traceback
from typing import TYPE_CHECKING, TypedDict

from netgear_switch.errors import NetgearSwitchError
from netgear_switch.models import VlanMode
from netgear_switch.registry import MODELS, Backend

from . import capture, safety
from . import format as fmt
from .context import EXIT_ERROR, EXIT_OK, EXIT_USAGE, CliContext, exit_code_for

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
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
        "--nsdp-interface",
        metavar="IFACE",
        help="network interface for NSDP (Plus switch) queries, e.g. eth0; "
        "overrides the inventory's nsdp.interface when both are set",
        default=default,
    )
    gp.add_argument(
        "--http-password",
        metavar="STR",
        help="web-UI/NSDP admin password for a Plus switch (HTTP + NSDP v1 "
        "auth share this one secret); overrides the inventory's http.password "
        "when both are set",
        default=default,
    )
    gp.add_argument(
        "--backend",
        metavar="NAME",
        choices=[b.name.lower() for b in Backend],
        help="run the operation over EXACTLY this backend (snmp/nsdp/http/ssh/"
        "telnet/console) instead of the model's default; the operation fails if "
        "that backend cannot serve it -- it is never re-routed to another "
        "protocol",
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
        "verified": bool,
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
            "verified": m.verified,
        }
        for m in MODELS.values()
    ]
    if ctx.as_json:
        print(json.dumps(rows, indent=2), file=ctx.out)
    else:
        for row in rows:
            # UNVERIFIED-pending-capture models (registry.py's `verified`
            # flag) are marked so `ngsw models` never implies these are
            # capture-confirmed like the rest of the registry.
            suffix = "" if row["verified"] else "  [UNVERIFIED]"
            print(
                f"{row['key']:<12} {row['display_name']:<24} "
                f"{'+'.join(row['backends'])}{suffix}",
                file=ctx.out,
            )
    return EXIT_OK


def _cmd_ports(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    fmt.emit(ctx, get_switch().get_ports(), fmt.ports_table)
    return EXIT_OK


def _cmd_stats(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    fmt.emit(ctx, get_switch().get_stats(), fmt.stats_table)
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


def _cmd_port_describe(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    switch = get_switch()
    text = args.description
    return safety.do_write(
        ctx,
        dry_run=args.dry_run,
        assume_yes=args.yes,
        host=switch.host,
        description=(
            f"clear the description on port {args.port}"
            if text == ""
            else f"describe port {args.port} as {text!r}"
        ),
        action=lambda: switch.set_port_description(
            args.port, text, force=args.force
        ),
    )


def _cmd_users(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    del args
    fmt.emit(ctx, get_switch().get_users(), fmt.users_table)
    return EXIT_OK


def _cmd_services(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    del args
    fmt.emit(ctx, get_switch().get_services(), fmt.services_table)
    return EXIT_OK


def _cmd_syslog(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    del args
    fmt.emit(ctx, get_switch().get_syslog(), fmt.syslog_text)
    return EXIT_OK


def _cmd_syslog_set(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    switch = get_switch()
    enabled = args.state == "on"
    return safety.do_write(
        ctx,
        dry_run=args.dry_run,
        assume_yes=args.yes,
        host=switch.host,
        description=f"turn remote logging {args.state}",
        action=lambda: switch.set_syslog_enabled(enabled, force=args.force),
    )


def _cmd_hostname(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    del args
    fmt.emit(ctx, get_switch().get_hostname(), fmt.hostname_text)
    return EXIT_OK


def _cmd_hostname_set(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    switch = get_switch()
    return safety.do_write(
        ctx,
        dry_run=args.dry_run,
        assume_yes=args.yes,
        host=switch.host,
        description=f"set hostname to {args.name!r}",
        action=lambda: switch.set_hostname(args.name, force=args.force),
    )


def _cmd_show(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    fmt.emit(ctx, get_switch().snapshot(), fmt.snapshot_text)
    return EXIT_OK


def _cmd_identify(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    del args
    fmt.emit(ctx, get_switch().identify(), fmt.detected_model_text)
    return EXIT_OK


def _cmd_nsdp_device(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    del args
    fmt.emit(ctx, get_switch().nsdp_device(), fmt.nsdp_device_text)
    return EXIT_OK


def _cmd_cycle_poe(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    switch = get_switch()
    return safety.do_write(
        ctx,
        dry_run=args.dry_run,
        assume_yes=args.yes,
        host=switch.host,
        description=f"power-cycle PoE port {args.port}",
        action=lambda: switch.cycle_poe(args.port, force=args.force),
    )


def _cmd_clear_poe_fault(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    switch = get_switch()
    return safety.do_write(
        ctx,
        dry_run=args.dry_run,
        assume_yes=args.yes,
        host=switch.host,
        description=f"clear PoE fault on port {args.port}",
        action=lambda: switch.clear_poe_fault(args.port, force=args.force),
    )


def _cmd_upload_certificate(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    from pathlib import Path

    switch = get_switch()
    try:
        cert_pem = Path(args.cert).read_text()
        key_pem = Path(args.key).read_text()
    except OSError as exc:
        print(f"error: {exc}", file=ctx.err)
        return EXIT_ERROR
    return safety.do_write(
        ctx,
        dry_run=args.dry_run,
        assume_yes=args.yes,
        host=switch.host,
        description=f"upload SSL certificate ({args.cert}) + key ({args.key})",
        action=lambda: switch.upload_certificate(cert_pem, key_pem, force=args.force),
        warning=(
            "WARNING: uploading a certificate replaces the switch's running "
            "certificate and restarts its web server."
        ),
    )


def _cmd_upload_certificate_scp(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    from pathlib import Path

    switch = get_switch()
    try:
        scp_password = Path(args.scp_password_file).read_text().strip()
    except OSError as exc:
        print(f"error: {exc}", file=ctx.err)
        return EXIT_ERROR
    if not scp_password:
        print("error: --scp-password-file is empty", file=ctx.err)
        return EXIT_ERROR
    # NOTE: the CALLER must stage the PEM(s) on the SCP source first; this only
    # SENDS the copy-scp commands to the switch (FASTPATH M4300/GSM7252PS).
    return safety.do_write(
        ctx,
        dry_run=args.dry_run,
        assume_yes=args.yes,
        host=switch.host,
        description=(
            f"deploy SSL certificate over SCP from {args.scp_source}{args.remote_dir}"
        ),
        action=lambda: switch.upload_certificate_scp(
            scp_source=args.scp_source,
            scp_password=scp_password,
            remote_dir=args.remote_dir,
            chain=args.chain,
        ),
        warning=(
            "WARNING: this replaces the switch's running HTTPS certificate "
            "(disables + re-enables the secure web server); stage the PEM on the "
            "SCP source first."
        ),
    )


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


def _cmd_capture(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    from pathlib import Path

    switch = get_switch()
    record = capture.run_capture(
        switch,
        Path(args.output),
        snapshot_only=args.snapshot_only,
        raw_walk=None if args.snapshot_only else capture.default_raw_walk,
    )
    print(f"wrote capture for {record.model} to {args.output}", file=ctx.out)
    for note in record.notes:
        print(f"note: {note}", file=ctx.err)
    return EXIT_OK


def _cmd_serve(
    args: argparse.Namespace, ctx: CliContext, get_switch: Callable[[], SyncSwitch]
) -> int:
    """Run one or more in-repo mock switches as a blocking, standalone daemon.

    Builds a ``VirtualSwitch`` per requested model, wires SIGINT/SIGTERM to a
    clean shutdown, then hands off to ``virtual.server.serve_forever`` which
    prints where each switch is reachable and blocks until interrupted.
    """
    import signal
    import threading

    from netgear_switch.errors import UnknownModelError
    from netgear_switch.virtual.server import VirtualSwitch, serve_forever

    del get_switch  # a mock daemon builds VirtualSwitches, not a client SyncSwitch

    model_keys = list(MODELS) if args.all else list(args.models or [])
    if not model_keys:
        print("error: give one or more --model KEY, or --all", file=ctx.err)
        return EXIT_USAGE
    if (args.port or args.http_port) and len(model_keys) > 1:
        print(
            "error: --port/--http-port pin a single listener; they cannot be "
            "shared across multiple served models",
            file=ctx.err,
        )
        return EXIT_USAGE

    switches: list[VirtualSwitch] = []
    for key in model_keys:
        try:
            switches.append(
                VirtualSwitch(
                    key,
                    community=args.serve_community,
                    http_password=args.http_password,
                    host=args.serve_host,
                    port=args.port,
                    http_port=args.http_port,
                )
            )
        except UnknownModelError as exc:
            print(f"error: {exc}", file=ctx.err)
            return EXIT_USAGE

    stop = threading.Event()

    def _request_stop(_signum: int, _frame: object) -> None:
        stop.set()

    old_handlers = {
        signal.SIGINT: signal.signal(signal.SIGINT, _request_stop),
        signal.SIGTERM: signal.signal(signal.SIGTERM, _request_stop),
    }
    try:
        served = serve_forever(switches, out=ctx.out, stop=stop)
    finally:
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)
    return EXIT_OK if served else EXIT_ERROR


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
    read_cmd("stats", _cmd_stats, "show port RX/TX counters")
    read_cmd("vlans", _cmd_vlans, "show VLANs")
    read_cmd("pvids", _cmd_pvids, "show per-port PVIDs")
    read_cmd("lldp", _cmd_lldp, "show LLDP neighbours")
    read_cmd("macs", _cmd_macs, "show the MAC/FDB table")
    read_cmd("sensors", _cmd_sensors, "show sensors")
    read_cmd("users", _cmd_users, "show local login accounts")
    read_cmd("services", _cmd_services, "show which management services are enabled")
    read_cmd("show", _cmd_show, "show a full switch snapshot")
    read_cmd("identify", _cmd_identify, "detect the switch's real model over SNMP")
    read_cmd(
        "nsdp-device",
        _cmd_nsdp_device,
        "show the raw NSDP device record (NSDP-capable models only)",
    )

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

    describe = sub.add_parser(
        "describe",
        parents=[child_gp],
        help="set or clear a port's description (pass '' to clear)",
    )
    describe.add_argument("port", type=int, help="port number")
    describe.add_argument("description", help="the label; '' clears it")
    safety.add_write_args(describe)
    describe.set_defaults(func=_cmd_port_describe)

    cycle_poe = sub.add_parser(
        "cycle-poe", parents=[child_gp], help="power-cycle a port's PoE"
    )
    cycle_poe.add_argument("port", type=int, help="port number")
    safety.add_write_args(cycle_poe)
    cycle_poe.set_defaults(func=_cmd_cycle_poe)

    clear_poe_fault = sub.add_parser(
        "clear-poe-fault", parents=[child_gp], help="clear a port's PoE fault state"
    )
    clear_poe_fault.add_argument("port", type=int, help="port number")
    safety.add_write_args(clear_poe_fault)
    clear_poe_fault.set_defaults(func=_cmd_clear_poe_fault)

    upload_cert = sub.add_parser(
        "upload-certificate",
        parents=[child_gp],
        help="upload an HTTPS SSL certificate + private key",
    )
    upload_cert.add_argument(
        "--cert", required=True, metavar="FILE", help="PEM certificate file"
    )
    upload_cert.add_argument(
        "--key", required=True, metavar="FILE", help="PEM private-key file"
    )
    safety.add_write_args(upload_cert)
    upload_cert.set_defaults(func=_cmd_upload_certificate)

    upload_cert_scp = sub.add_parser(
        "upload-certificate-scp",
        parents=[child_gp],
        help="deploy an HTTPS SSL certificate over SCP (FASTPATH M4300/GSM7252PS)",
    )
    upload_cert_scp.add_argument(
        "--scp-source",
        required=True,
        metavar="USER@HOST[:PORT]",
        help="SCP source the switch pulls the staged PEM from",
    )
    upload_cert_scp.add_argument(
        "--scp-password-file",
        required=True,
        metavar="FILE",
        help="file holding the SCP source password",
    )
    upload_cert_scp.add_argument(
        "--remote-dir",
        default="/var/lib/switchcert/staging",
        metavar="DIR",
        help="directory on the SCP source holding the staged PEM(s)",
    )
    upload_cert_scp.add_argument(
        "--chain",
        action="store_true",
        help="also copy the CA-chain PEM to nvram:sslpem-root",
    )
    safety.add_write_args(upload_cert_scp)
    upload_cert_scp.set_defaults(func=_cmd_upload_certificate_scp)

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
    ip_set = ip_sub.add_parser("set", parents=[child_gp], help="set the management IP")
    ip_set.add_argument("address")
    ip_set.add_argument("netmask")
    ip_set.add_argument("gateway")
    safety.add_write_args(ip_set)
    ip_set.set_defaults(func=_cmd_ip_set)

    # hostname / syslog follow the `ip` shape: bare command reads, `set` writes.
    hostname = sub.add_parser(
        "hostname", parents=[child_gp], help="show or set the switch's host name"
    )
    hostname.set_defaults(func=_cmd_hostname)
    hostname_sub = hostname.add_subparsers(dest="hostname_cmd")
    hostname_set = hostname_sub.add_parser(
        "set", parents=[child_gp], help="set the switch's host name"
    )
    hostname_set.add_argument("name")
    safety.add_write_args(hostname_set)
    hostname_set.set_defaults(func=_cmd_hostname_set)

    syslog = sub.add_parser(
        "syslog",
        parents=[child_gp],
        help="show remote-logging config, or turn it on/off",
    )
    syslog.set_defaults(func=_cmd_syslog)
    syslog_sub = syslog.add_subparsers(dest="syslog_cmd")
    syslog_set = syslog_sub.add_parser(
        "set", parents=[child_gp], help="turn remote logging on or off"
    )
    syslog_set.add_argument("state", choices=("on", "off"))
    safety.add_write_args(syslog_set)
    syslog_set.set_defaults(func=_cmd_syslog_set)

    cap = sub.add_parser(
        "capture",
        parents=[child_gp],
        help="record a real switch's state + protocol exchanges (opt-in, live)",
    )
    cap.add_argument("output", help="output JSON file path")
    cap.add_argument(
        "--snapshot-only",
        action="store_true",
        help="record only the state snapshot (skip the live raw protocol walk)",
    )
    cap.set_defaults(func=_cmd_capture)

    # `serve` runs the in-repo mock switches as standalone daemons. It does NOT
    # inherit `child_gp`: it needs its own repeatable `--model` (append) and its
    # own `--host`/`--community`, which would collide with the shared single-
    # value global flags of the same name. `--json`/`--verbose` still work when
    # given before the subcommand (they live on the top-level parser).
    serve = sub.add_parser(
        "serve",
        help="run the in-repo mock/virtual switches as standalone daemons",
        description=(
            "Serve one or more in-repo mock switches on real sockets so an "
            "external tool can point at them when hardware is unavailable. "
            "Prints each switch's bound port(s), SNMP community and HTTP "
            "password, then blocks until interrupted (SIGINT/SIGTERM)."
        ),
    )
    serve.add_argument(
        "--model",
        dest="models",
        metavar="KEY",
        action="append",
        help="model key to serve (repeatable); e.g. --model gsm7228ps",
    )
    serve.add_argument(
        "--all", action="store_true", help="serve every registered model"
    )
    serve.add_argument(
        "--host",
        dest="serve_host",
        metavar="IP",
        default="127.0.0.1",
        help="bind address (default 127.0.0.1; use 0.0.0.0 to expose off-host)",
    )
    serve.add_argument(
        "--community",
        dest="serve_community",
        metavar="STR",
        default="public",
        help="SNMP community the mock accepts (default: public)",
    )
    serve.add_argument(
        "--http-password",
        metavar="STR",
        default="password",
        help="HTTP admin password the mock accepts (default: password)",
    )
    serve.add_argument(
        "--port",
        type=int,
        default=0,
        metavar="N",
        help="pin the SNMP/NSDP UDP port (default 0 = ephemeral; single model only)",
    )
    serve.add_argument(
        "--http-port",
        type=int,
        default=0,
        metavar="N",
        help="pin the HTTP TCP port (default 0 = ephemeral; single model only)",
    )
    serve.set_defaults(func=_cmd_serve)

    return parser


def main(
    argv: list[str] | None = None,
    *,
    switch_factory: Callable[[argparse.Namespace, CliContext], SyncSwitch]
    | None = None,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    env: Mapping[str, str] | None = None,
    prompt: Callable[[str], str] = getpass.getpass,
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

        return resolve_switch(args, env=env, prompt=prompt)

    try:
        result: int = args.func(args, ctx, get_switch)
        return result
    except NetgearSwitchError as exc:
        if ctx.verbose:
            traceback.print_exc(file=err)
        print(f"error: {exc}", file=err)
        return exit_code_for(exc)
    except NotImplementedError as exc:
        # A model whose real mechanism is known but not yet implemented (e.g.
        # upload_certificate on m4300/gs728tpp) raises NotImplementedError,
        # which is NOT a NetgearSwitchError. Surface it as a clean CLI error
        # rather than an uncaught stack trace.
        if ctx.verbose:
            traceback.print_exc(file=err)
        print(f"error: {exc}", file=err)
        return EXIT_ERROR
