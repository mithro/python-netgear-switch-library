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

# Prompts the interactive ``copy scp://...`` command emits mid-flight, and the
# success/failure markers that close it. GROUNDED in the working certbot-hook
# ``FastpathScpUpdater._send_copy`` regexes -- see that prior art. Not anchored to
# end-of-buffer (unlike ``_PROMPT_RE``): these appear inline as the switch's SCP
# client runs, so they are matched anywhere in the accumulated read buffer.
_SCP_TOFU_RE = re.compile(r"host key|continue connecting|\(yes\s*/\s*no", re.IGNORECASE)
_SCP_PASSWORD_RE = re.compile(r"[Pp]assword:")
_SCP_CONFIRM_RE = re.compile(r"\(y\s*/\s*n\)")
_SCP_SUCCESS_RE = re.compile(
    r"bytes transferred|completed successfully|operation completed", re.IGNORECASE
)
_SCP_FAILURE_RE = re.compile(
    r"transfer failed|failed!|%\s*error|error during", re.IGNORECASE
)


class CliSession(Protocol):
    """A ready-to-use authenticated CLI session for one switch.

    ``run`` issues one command and returns its output text with the echoed
    command line and the trailing prompt removed. Setup (enable + disable
    paging) is the transport's responsibility, done before the first ``run``.
    """

    def run(self, command: str) -> str: ...

    def run_scp_copy(self, command: str, scp_password: str) -> str:
        """Issue an interactive ``copy scp://...`` and drive its mid-command
        prompts (host-key TOFU, remote password, ``(y/n)`` overwrite), returning
        the transcript on success and raising ``CliTransportError`` on failure.
        Only the FASTPATH cert-deploy path (``cli_write``) uses this; a session
        used purely for reads never calls it."""
        ...

    def run_write_memory(self, command: str = "write memory", *, prestuff: bool) -> str:
        """Issue ``write memory`` and answer its ``(y/n)`` save-config confirm."""
        ...

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

    def run_scp_copy(self, command: str, scp_password: str) -> str:
        """Drive a ``copy scp://<src> <dest>`` transfer to completion.

        The genuinely-new interactive transport bit: unlike a plain EXEC command
        (``run``), ``copy scp://`` prompts the operator mid-flight. This sends the
        command then loops over ``_recv`` chunks, answering each prompt with the
        same ``_send``/``_write_line`` primitives ``run`` uses -- no new transport,
        no ``pexpect``:

        * host-key TOFU (``... continue connecting (yes/no)?``) -> ``yes``
        * remote ``Password:`` -> ``scp_password``
        * ``(y/n)`` overwrite confirm -> a bare ``y`` (no newline, matching the
          real FASTPATH prompt)

        It returns when the shell prompt reappears after the switch reports the
        transfer, and raises ``CliTransportError`` if the switch reports a failed
        transfer or the stream ends without a prompt. GROUNDED in the working
        certbot-hook ``FastpathScpUpdater._send_copy``; MOCK-TESTED, not
        live-verified (a real SCP upload is a production write needing a staging
        SCP server), so it cannot be exercised from CI -- covered by a byte-level
        fake-shell test, like the rest of ShellDriver.
        """
        self._write_line(command)
        transcript = ""
        buf = ""
        succeeded = False
        for _ in range(_MAX_READS):
            chunk = self._recv(4096)
            if chunk:
                text = chunk.decode("latin-1", errors="replace")
                transcript += text
                buf += text
            if _SCP_FAILURE_RE.search(buf):
                raise CliTransportError(
                    f"SCP copy reported a failed transfer: {command!r}"
                )
            if _SCP_TOFU_RE.search(buf):
                self._write_line("yes")
                buf = ""
                continue
            if _SCP_PASSWORD_RE.search(buf):
                self._write_line(scp_password)
                buf = ""
                continue
            if _SCP_CONFIRM_RE.search(buf):
                # FASTPATH's (y/n) overwrite confirm takes a single keystroke.
                self._send(b"y")
                buf = ""
                continue
            if _SCP_SUCCESS_RE.search(buf):
                succeeded = True
            if _PROMPT_RE.search(buf):
                return transcript
            if not chunk:
                break
        if succeeded:
            return transcript
        raise CliTransportError(f"SCP copy did not complete: {command!r}")

    def run_write_memory(self, command: str = "write memory", *, prestuff: bool) -> str:
        """Persist the running config, answering the ``(y/n)`` save confirm.

        ``prestuff=True`` (GSM7252PS) pre-stuffs the ``y`` in the SAME write as the
        command, because that image's confirm has a tiny timeout that a
        read-then-answer round trip races -- exactly the certbot-hook
        ``writemem_stuff`` behaviour. ``prestuff=False`` (M4300) waits for the
        ``(y/n)`` prompt then answers ``y``. GROUNDED in prior art, mock-tested.
        """
        if prestuff:
            self._send((command + "\ry\r").encode("latin-1"))
        else:
            self._write_line(command)
        transcript = ""
        buf = ""
        for _ in range(_MAX_READS):
            chunk = self._recv(4096)
            if chunk:
                text = chunk.decode("latin-1", errors="replace")
                transcript += text
                buf += text
            if not prestuff and _SCP_CONFIRM_RE.search(buf):
                self._send(b"y")
                buf = ""
                continue
            if _PROMPT_RE.search(buf):
                return transcript
            if not chunk:
                break
        raise CliTransportError("write memory did not complete")

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
