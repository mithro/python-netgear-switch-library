"""``ngsw`` entry point: argparse wiring, dispatch, and error handling."""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from typing import TYPE_CHECKING, TypedDict

from netgear_switch.errors import NetgearSwitchError
from netgear_switch.registry import MODELS

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
