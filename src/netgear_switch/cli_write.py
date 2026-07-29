"""FASTPATH SSL-certificate deploy over the CLI ``copy scp://`` command.

The CLI write analogue of ``http_write``'s cert upload, for the Fully Managed
FASTPATH line (M4300 / GSM7252PS) whose firmware takes an HTTPS server
certificate over SCP -- ``copy scp://<src> nvram:sslpem-server`` -- rather than
an HTTP form. It REUSES the library's existing CLI transport: plain EXEC steps go
through ``CliSession.run``; the interactive ``copy`` and ``write memory`` steps
go through ``CliSession.run_scp_copy`` / ``run_write_memory`` (the byte-level
interactive driving lives on the shared ``ShellDriver`` -- no new transport).

HONESTY: GROUNDED in the working certbot-hook ``FastpathScpUpdater`` (see
``tmp/certbot_hook_prior_art.py``) and MOCK-TESTED end-to-end, but NOT
live-verified -- a real run is a production write that needs a staging SCP server
to pull the PEM from, which CI has neither the hardware nor the network for. The
library only SENDS the copy commands; the CALLER stages the PEM on the SCP source
first (per the user's decision), exactly as the certbot hook's ``main`` does.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .transport.cli.session import CliSession

# nvram: destinations FASTPATH loads the HTTPS material from (grounded prior art).
_SERVER_DEST = "nvram:sslpem-server"
_ROOT_DEST = "nvram:sslpem-root"
_SERVER_SUFFIX = "-server.pem"
_ROOT_SUFFIX = "-root.pem"
_WRITE_MEMORY = "write memory"
# FASTPATH refuses the sslpem upload while the HTTP secure-server is enabled
# ("HTTP Secure-server must be disabled prior to upgrade"), so disable -> copy ->
# re-enable. Re-enabling loads the new cert in place; NO reboot (backbone-safe).
_HTTPS_OFF = "no ip http secure-server"
_HTTPS_ON = "ip http secure-server"


def scp_source_url(scp_source: str, remote_dir: str, filename: str) -> str:
    """Build the ``scp://`` source URL for one staged PEM.

    Mirrors ``FastpathScpUpdater._source_url``: an ABSOLUTE staging path so
    FASTPATH's scp client requests the exact path the SCP source's ForceCommand
    wrapper authorises (no home-relative ambiguity). ``scp_source`` is the
    ``user@host[:port]`` the caller's staging server answers on.
    """
    return f"scp://{scp_source}{remote_dir}/{filename}"


def _copy_cmd(scp_source: str, remote_dir: str, filename: str, dest: str) -> str:
    return f"copy {scp_source_url(scp_source, remote_dir, filename)} {dest}"


def deploy_certificate_scp(
    session: CliSession,
    *,
    scp_source: str,
    scp_password: str,
    remote_dir: str,
    base: str,
    chain: bool,
    writemem_stuff: bool,
) -> None:
    """Run the 5-step FASTPATH cert-deploy EXEC sequence over ``session``.

    ``session`` must already be set up (enable + paging off -- the transport does
    this on connect). The staged PEMs are named ``<base>-server.pem`` (and, when
    ``chain`` is set, ``<base>-root.pem``) under ``remote_dir`` on the SCP source.

    Steps (grounded in ``FastpathScpUpdater.upload_certificate``):

    1. ``no ip http secure-server`` -- HTTPS must be off to accept the sslpem.
    2. ``copy scp://<src>/<base>-server.pem nvram:sslpem-server`` (interactive).
    3. optional ``copy scp://<src>/<base>-root.pem nvram:sslpem-root`` (CA chain).
    4. ``ip http secure-server`` -- re-enable; loads the new cert, no reboot.
    5. ``write memory`` -- persist, with the per-model confirm (``writemem_stuff``).
    """
    session.run(_HTTPS_OFF)
    session.run_scp_copy(
        _copy_cmd(scp_source, remote_dir, f"{base}{_SERVER_SUFFIX}", _SERVER_DEST),
        scp_password,
    )
    if chain:
        session.run_scp_copy(
            _copy_cmd(scp_source, remote_dir, f"{base}{_ROOT_SUFFIX}", _ROOT_DEST),
            scp_password,
        )
    session.run(_HTTPS_ON)
    session.run_write_memory(_WRITE_MEMORY, prestuff=writemem_stuff)
