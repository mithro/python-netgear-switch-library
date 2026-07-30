# tests/cli/test_serve.py
"""``ngsw serve`` argument wiring and usage-error handling.

The happy-path serving loop (bind, print, SNMP-read, clean stop) is covered by
``tests/virtual/test_serve_daemon.py`` against ``serve_forever`` directly --
the same primitive ``_cmd_serve`` hands off to. ``_cmd_serve`` itself installs
SIGINT/SIGTERM handlers (only legal from the main thread), so its blocking path
can't run under a background test thread; here we pin down the parser and the
validation branches that return *before* any signal handler or socket bind.
"""
from __future__ import annotations

import io

from netgear_switch.cli.context import EXIT_USAGE
from netgear_switch.cli.main import build_parser, main


def _run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def test_serve_requires_a_model() -> None:
    code, _out, err = _run(["serve"])
    assert code == EXIT_USAGE
    assert "one or more --model" in err


def test_serve_rejects_port_pin_with_multiple_models() -> None:
    code, _out, err = _run(
        ["serve", "--model", "gsm7252ps", "--model", "gsm7228ps", "--port", "16161"]
    )
    assert code == EXIT_USAGE
    assert "cannot be shared across multiple served models" in err


def test_serve_rejects_unknown_model() -> None:
    code, _out, err = _run(["serve", "--model", "no-such-switch"])
    assert code == EXIT_USAGE
    assert "no-such-switch" in err


def test_serve_parser_collects_repeated_models_and_all() -> None:
    parser = build_parser()
    args = parser.parse_args(
        ["serve", "--model", "gsm7252ps", "--model", "gs305ep", "--all"]
    )
    assert args.models == ["gsm7252ps", "gs305ep"]
    assert args.all is True
    assert args.serve_host == "127.0.0.1"
    assert args.serve_community == "public"
    assert args.http_password == "password"
    assert args.port == 0
    assert args.http_port == 0
    assert args.func.__name__ == "_cmd_serve"
