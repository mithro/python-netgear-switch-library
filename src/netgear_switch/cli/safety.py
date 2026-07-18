"""Write-safety gates for disruptive ngsw commands (design spec §6)."""
from __future__ import annotations

from typing import TYPE_CHECKING

from .context import EXIT_ERROR, EXIT_OK

if TYPE_CHECKING:
    import argparse
    from collections.abc import Callable

    from .context import CliContext


def add_write_args(parser: argparse.ArgumentParser) -> None:
    """Attach the shared --dry-run / --yes / --force gates to a subparser."""
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the operation that would be sent, then send nothing",
    )
    parser.add_argument(
        "-y", "--yes", action="store_true", help="skip the confirmation prompt"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="override protected_ports and other force-gates",
    )


def confirm(prompt: str, *, assume_yes: bool, ctx: CliContext) -> bool:
    """Ask for confirmation on stderr; read one line from ctx.inp."""
    if assume_yes:
        return True
    print(f"{prompt} [y/N]: ", end="", file=ctx.err)
    ctx.err.flush()
    reply = ctx.inp.readline().strip().lower()
    return reply in {"y", "yes"}


def do_write(
    ctx: CliContext,
    *,
    dry_run: bool,
    assume_yes: bool,
    host: str,
    description: str,
    action: Callable[[], None],
    warning: str | None = None,
) -> int:
    """The single disruptive-write gate: dry-run -> confirm -> execute -> report.

    ``action`` is the verify-after-write facade call; any NetgearSwitchError it
    raises propagates to main() for clean reporting. The CLI describes the
    operation at facade granularity (method + args + host) rather than
    re-encoding the SNMP SET / NSDP packet / HTTP form, so no library logic is
    duplicated here.
    """
    if dry_run:
        print(f"DRY-RUN: would {description} on {host} (nothing sent)", file=ctx.out)
        return EXIT_OK
    prompt = f"About to {description} on {host}."
    if warning:
        prompt = f"{warning}\n{prompt}"
    if not confirm(prompt, assume_yes=assume_yes, ctx=ctx):
        print("aborted: no changes made", file=ctx.err)
        return EXIT_ERROR
    action()
    print(f"ok: {description}", file=ctx.out)
    return EXIT_OK
