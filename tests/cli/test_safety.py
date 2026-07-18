from __future__ import annotations

import argparse
import io

from netgear_switch.cli import context
from netgear_switch.cli.safety import add_write_args, confirm, do_write


def make_ctx(stdin_text: str = "") -> context.CliContext:
    return context.CliContext(
        out=io.StringIO(),
        err=io.StringIO(),
        inp=io.StringIO(stdin_text),
        as_json=False,
        verbose=False,
    )


def test_add_write_args_defines_the_three_gates() -> None:
    parser = argparse.ArgumentParser()
    add_write_args(parser)
    args = parser.parse_args(["--dry-run", "--yes", "--force"])
    assert args.dry_run
    assert args.yes
    assert args.force


def test_dry_run_prints_and_does_not_call_action() -> None:
    ctx = make_ctx()
    called = []
    code = do_write(
        ctx,
        dry_run=True,
        assume_yes=False,
        host="10.0.0.1",
        description="set PoE port 3 -> off",
        action=lambda: called.append("x"),
    )
    assert code == context.EXIT_OK
    assert called == []
    assert "DRY-RUN" in ctx.out.getvalue()
    assert "nothing sent" in ctx.out.getvalue()


def test_confirm_declined_aborts_without_running_action() -> None:
    ctx = make_ctx("n\n")
    called = []
    code = do_write(
        ctx,
        dry_run=False,
        assume_yes=False,
        host="h",
        description="set port 1 down",
        action=lambda: called.append("x"),
    )
    assert code == context.EXIT_ERROR
    assert called == []
    assert "aborted" in ctx.err.getvalue()


def test_yes_response_runs_action() -> None:
    ctx = make_ctx("y\n")
    called = []
    code = do_write(
        ctx,
        dry_run=False,
        assume_yes=False,
        host="h",
        description="set port 1 down",
        action=lambda: called.append("x"),
    )
    assert code == context.EXIT_OK
    assert called == ["x"]
    assert "ok: set port 1 down" in ctx.out.getvalue()


def test_assume_yes_skips_prompt() -> None:
    ctx = make_ctx()  # empty stdin: if it tried to read, confirm would decline
    called = []
    do_write(
        ctx,
        dry_run=False,
        assume_yes=True,
        host="h",
        description="op",
        action=lambda: called.append("x"),
    )
    assert called == ["x"]


def test_warning_is_shown_in_prompt() -> None:
    ctx = make_ctx("n\n")
    do_write(
        ctx,
        dry_run=False,
        assume_yes=False,
        host="h",
        description="set mgmt IP",
        action=lambda: None,
        warning="WARNING: can strand the switch.",
    )
    assert "strand" in ctx.err.getvalue()


def test_confirm_helper_reads_stdin() -> None:
    assert confirm("go?", assume_yes=False, ctx=make_ctx("yes\n")) is True
    assert confirm("go?", assume_yes=False, ctx=make_ctx("\n")) is False
    assert confirm("go?", assume_yes=True, ctx=make_ctx("")) is True
