"""Transport-agnostic CLI session seam + a shared interactive-shell driver.

``CliSession`` is the single seam ``cli_read.CliReader`` depends on -- the CLI
analogue of ``protocols.http.session.HttpSession``. The real SSH/telnet/console
transports implement it, and so does the in-process mock face
(``virtual.faces.cli.VirtualCliFace``), so ONE reader codebase runs against both
real hardware and the virtual switch.

``ShellDriver`` holds the byte-level interactive-shell logic (send a command,
read back until the FASTPATH prompt reappears, strip the command echo and the
trailing prompt) so all three real transports share it -- they differ only in
how a channel's ``send``/``recv`` bytes are wired. The parsers
(``protocols.cli.parse``) are shared too: the transports carry bytes, the driver
frames them into per-command text, and the parsers turn that text into models.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Callable

# FASTPATH prompts look like "(GSM7252PS) #" (privileged) or "(GSM7252PS) >"
# (unprivileged); some pages also show "(GSM7252PS) (Config)#". Match a ")"
# followed by an optional word and a #/> at end of the buffered output.
_PROMPT_RE = re.compile(r"\)\s*(?:\([^)]*\)\s*)?[#>]\s*$")
_PASSWORD_RE = re.compile(r"[Pp]assword:\s*$")
# A hard cap so a transport that never sees a prompt (wrong device, hung link)
# fails instead of looping forever.
_MAX_READS = 10_000


class CliSession(Protocol):
    """A ready-to-use authenticated CLI session for one switch.

    ``run`` issues one command and returns its output text with the echoed
    command line and the trailing prompt removed. Setup (enable + disable
    paging) is the transport's responsibility, done before the first ``run``.
    """

    def run(self, command: str) -> str: ...

    def close(self) -> None: ...


class CliTransportError(Exception):
    """A CLI transport failed to connect, authenticate, or read a prompt."""


class ShellDriver:
    """Frames an interactive shell (send/recv bytes) into per-command text.

    ``send`` writes bytes to the channel; ``recv`` returns up to ``n`` bytes
    (blocking, may return a partial chunk). This is deliberately transport-free
    so SSH, telnet and console reuse it unchanged. It cannot be exercised against
    real hardware from CI (no network), so it is transport-only and covered by a
    fake-channel unit test rather than a live session.
    """

    def __init__(
        self,
        send: Callable[[bytes], None],
        recv: Callable[[int], bytes],
        *,
        enable_cmd: str = "enable",
        paging_off_cmd: str = "terminal length 0",
        enable_password: str | None = None,
        newline: str = "\r\n",
    ) -> None:
        self._send = send
        self._recv = recv
        self._enable_cmd = enable_cmd
        self._paging_off_cmd = paging_off_cmd
        self._enable_password = enable_password
        self._newline = newline

    def _read_until(self, *, allow_password: bool) -> str:
        buf = ""
        for _ in range(_MAX_READS):
            chunk = self._recv(4096)
            if chunk:
                buf += chunk.decode("latin-1", errors="replace")
            if _PROMPT_RE.search(buf):
                return buf
            if allow_password and _PASSWORD_RE.search(buf):
                return buf
            if not chunk:
                # Channel closed with no prompt seen.
                break
        raise CliTransportError("no CLI prompt seen before end of stream")

    def _write_line(self, text: str) -> None:
        self._send((text + self._newline).encode("latin-1"))

    def setup(self) -> None:
        """Consume the initial banner/prompt, ``enable``, then disable paging."""
        self._read_until(allow_password=False)  # initial prompt
        self._write_line(self._enable_cmd)
        out = self._read_until(allow_password=True)
        if _PASSWORD_RE.search(out):
            # enable asked for a password; reuse the login password by default.
            self._write_line(self._enable_password or "")
            self._read_until(allow_password=False)
        self._write_line(self._paging_off_cmd)
        self._read_until(allow_password=False)

    def run(self, command: str) -> str:
        self._write_line(command)
        raw = self._read_until(allow_password=False)
        return self._clean(raw, command)

    @staticmethod
    def _clean(raw: str, command: str) -> str:
        """Drop the echoed command line and the trailing prompt line."""
        lines = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        # Remove the first line if it echoes the command we sent.
        if lines and command.strip() and command.strip() in lines[0]:
            lines = lines[1:]
        # Remove the trailing prompt line(s).
        while lines and _PROMPT_RE.search(lines[-1]):
            lines = lines[:-1]
        return "\n".join(lines).strip("\n")
