"""MCP server exposing the switch library's read/write ops as MCP tools.

Optional: requires the ``[mcp]`` extra (the ``mcp`` SDK). ``server.build_server``
constructs a ``FastMCP`` instance wired to the same inventory/credential
resolution the ``ngsw`` CLI uses; ``server.main`` runs it over stdio (the
``ngsw-mcp`` entry point). Writes are OFF unless ``NGSW_MCP_ALLOW_WRITES`` is
set, so an MCP client cannot reconfigure a switch by default.
"""
from __future__ import annotations

from .server import build_server, main

__all__ = ["build_server", "main"]
