from __future__ import annotations

import io

import pytest

from netgear_switch.cli import context
from netgear_switch.cli.main import main
from netgear_switch.errors import (
    NetgearSwitchError,
    ProtectedPortError,
    WriteVerificationError,
)


def run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def test_exit_code_for_maps_error_types() -> None:
    assert context.exit_code_for(WriteVerificationError("x", before=1, after=2)) == 3
    assert context.exit_code_for(ProtectedPortError("x")) == 4
    assert context.exit_code_for(NetgearSwitchError("x")) == 1


def test_no_subcommand_prints_help_and_returns_usage_code() -> None:
    code, _out, err = run([])
    assert code == context.EXIT_USAGE
    assert "usage" in err.lower()


def test_models_subcommand_lists_known_models() -> None:
    code, out, _err = run(["models"])
    assert code == context.EXIT_OK
    assert "gsm7252ps" in out
    assert "m4300-24x" in out


def test_models_json_is_machine_readable() -> None:
    import json

    code, out, _err = run(["--json", "models"])
    assert code == context.EXIT_OK
    data = json.loads(out)
    keys = {m["key"] for m in data}
    assert "gsm7252ps" in keys


def test_bad_subcommand_exits_usage() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["not-a-command"], stdout=io.StringIO(), stderr=io.StringIO())
    assert exc.value.code == 2
