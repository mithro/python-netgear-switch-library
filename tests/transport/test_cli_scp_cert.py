# tests/transport/test_cli_scp_cert.py
"""Byte-level integration test for the FASTPATH copy-scp cert-deploy path.

Mirrors ``test_cli_telnet.py``: drives the REAL shared ``ShellDriver`` (its plain
``run`` plus the new interactive ``run_scp_copy`` / ``run_write_memory``) end to
end against a local fake FASTPATH shell that REACTS to the driver's writes --
revealing each ``copy scp://`` prompt (host-key TOFU -> ``yes``, remote
``Password:`` -> password, ``(y/n)`` overwrite -> bare ``y``) only after the
expected reply arrives. This proves the deploy driver drives the handshake in the
right order, not just that it tolerates a fixed script.

HONESTY: the real transport cannot be live-tested from CI (a real run is a
production write needing a staging SCP server); this is the strongest
verification of the deploy byte-path achievable here -- see
``cli_write.deploy_certificate_scp`` and ``transport/cli/session.ShellDriver``.
"""
from __future__ import annotations

import pytest

from netgear_switch.cli_write import deploy_certificate_scp
from netgear_switch.transport.cli.session import CliTransportError, ShellDriver

_PROMPT = "\r\n(M4300-24X) #"


class _FakeDeployShell:
    """A reactive byte-level FASTPATH shell for the cert-deploy sequence.

    Exposes ``send``/``recv`` byte callables (what ``ShellDriver`` is built on)
    and records the deploy so a test can assert it. It normalises CR/CRLF to LF
    for its line states; the two single-keystroke confirms (``y`` with no newline)
    are matched by scanning for the ``y`` byte, exactly like the real prompts.
    """

    def __init__(self, *, fail_copy: bool = False) -> None:
        self._inbuf = ""
        self._out = bytearray()
        self._state = "cmd"
        self.fail_copy = fail_copy
        # records for assertions
        self.commands: list[str] = []
        self.copies: list[tuple[str, str]] = []
        self.https_disabled = False
        self.https_enabled = False
        self.saved = False

    # --- byte callables the ShellDriver drives ---------------------------
    def send(self, data: bytes) -> None:
        self._inbuf += data.decode("latin-1").replace("\r\n", "\n").replace("\r", "\n")
        while self._step():
            pass

    def recv(self, _n: int) -> bytes:
        chunk = bytes(self._out)
        self._out.clear()
        return chunk

    # --- reactive state machine ------------------------------------------
    def _emit(self, text: str) -> None:
        self._out += text.encode("latin-1")

    def _take_line(self) -> str | None:
        if "\n" not in self._inbuf:
            return None
        line, _, self._inbuf = self._inbuf.partition("\n")
        return line

    def _step(self) -> bool:
        if self._state in ("copy_confirm", "wmem_confirm"):
            idx = self._inbuf.find("y")
            if idx == -1:
                return False
            self._inbuf = self._inbuf[idx + 1 :]
            if self._state == "copy_confirm":
                if self.fail_copy:
                    self._emit("\r\nTransfer failed!" + _PROMPT)
                else:
                    self._emit(
                        "\r\nData transfer complete. 1976 bytes transferred." + _PROMPT
                    )
            else:
                self.saved = True
                self._emit(_PROMPT)
            self._state = "cmd"
            return True

        line = self._take_line()
        if line is None:
            return False
        line = line.strip()
        if not line:
            return True
        if self._state == "copy_tofu":
            self._emit("\r\nswitchcert@10.1.5.1's password: ")
            self._state = "copy_pw"
            return True
        if self._state == "copy_pw":
            self._emit("\r\nWarning: file exists. Overwrite (y/n)? ")
            self._state = "copy_confirm"
            return True
        # default "cmd" state
        if line == "no ip http secure-server":
            self.https_disabled = True
            self.commands.append(line)
            self._emit(line + _PROMPT)
        elif line == "ip http secure-server":
            self.https_enabled = True
            self.commands.append(line)
            self._emit(line + _PROMPT)
        elif line == "write memory":
            self.commands.append(line)
            self._emit(
                "\r\nThis operation may take a few minutes.\r\n"
                "Are you sure you want to save? (y/n) "
            )
            self._state = "wmem_confirm"
        elif line.startswith("copy "):
            _, src, dest = line.split()
            self.copies.append((src, dest))
            self.commands.append(line)
            self._emit(
                "\r\nThe authenticity of host '10.1.5.1' can't be established.\r\n"
                "Are you sure you want to continue connecting (yes/no)? "
            )
            self._state = "copy_tofu"
        else:
            self._emit(line + _PROMPT)
        return True


class _DriverSession:
    """Adapt a ShellDriver to the ``CliSession`` methods the deploy driver calls."""

    def __init__(self, driver: ShellDriver) -> None:
        self._driver = driver

    def run(self, command: str) -> str:
        return self._driver.run(command)

    def run_scp_copy(self, command: str, scp_password: str) -> str:
        return self._driver.run_scp_copy(command, scp_password)

    def run_write_memory(
        self, command: str = "write memory", *, prestuff: bool
    ) -> str:
        return self._driver.run_write_memory(command, prestuff=prestuff)

    def close(self) -> None:
        pass


def _run_deploy(shell: _FakeDeployShell, *, chain: bool, writemem_stuff: bool) -> None:
    driver = ShellDriver(shell.send, shell.recv)
    deploy_certificate_scp(
        _DriverSession(driver),
        scp_source="switchcert@10.1.5.1",
        scp_password="s3cr3t",
        remote_dir="/var/lib/switchcert/staging",
        base="10-1-5-13",
        chain=chain,
        writemem_stuff=writemem_stuff,
    )


def test_deploy_drives_full_sequence_m4300() -> None:
    shell = _FakeDeployShell()
    _run_deploy(shell, chain=False, writemem_stuff=False)

    # HTTPS toggled off then back on around the copy; config saved.
    assert shell.https_disabled
    assert shell.https_enabled
    assert shell.saved
    # Exactly one server-cert copy to the right nvram: destination.
    assert shell.copies == [
        (
            "scp://switchcert@10.1.5.1/var/lib/switchcert/staging/10-1-5-13-server.pem",
            "nvram:sslpem-server",
        )
    ]
    # Command ORDER: disable -> copy -> enable -> write memory.
    assert shell.commands == [
        "no ip http secure-server",
        "copy scp://switchcert@10.1.5.1/var/lib/switchcert/staging/"
        "10-1-5-13-server.pem nvram:sslpem-server",
        "ip http secure-server",
        "write memory",
    ]


def test_deploy_with_chain_copies_root() -> None:
    shell = _FakeDeployShell()
    _run_deploy(shell, chain=True, writemem_stuff=False)
    assert [dest for _src, dest in shell.copies] == [
        "nvram:sslpem-server",
        "nvram:sslpem-root",
    ]
    assert shell.copies[1][0].endswith("10-1-5-13-root.pem")


def test_deploy_gsm_prestuffs_write_memory() -> None:
    # The GSM7252PS confirm timeout is tiny: run_write_memory pre-stuffs the `y`
    # in the same write. The fake still records the save, proving the prestuff
    # write reaches the shell and completes.
    shell = _FakeDeployShell()
    _run_deploy(shell, chain=False, writemem_stuff=True)
    assert shell.saved
    assert shell.commands[-1] == "write memory"


def test_copy_failure_raises() -> None:
    shell = _FakeDeployShell(fail_copy=True)
    with pytest.raises(CliTransportError):
        _run_deploy(shell, chain=False, writemem_stuff=False)
    # The failure happened on the server copy, before HTTPS was re-enabled.
    assert shell.https_disabled
    assert not shell.https_enabled


def test_run_scp_copy_handshake_order() -> None:
    # Directly exercise ShellDriver.run_scp_copy: it must answer TOFU -> yes,
    # Password -> password, (y/n) -> y, then return on the success prompt.
    shell = _FakeDeployShell()
    driver = ShellDriver(shell.send, shell.recv)
    out = driver.run_scp_copy(
        "copy scp://switchcert@10.1.5.1/staging/x-server.pem nvram:sslpem-server",
        "s3cr3t",
    )
    assert "bytes transferred" in out
    assert shell.copies == [
        (
            "scp://switchcert@10.1.5.1/staging/x-server.pem",
            "nvram:sslpem-server",
        )
    ]
