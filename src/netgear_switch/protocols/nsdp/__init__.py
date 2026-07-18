"""Pure, zero-dependency NSDP wire protocol package.

Lifted from the standalone ``gdoc2netcfg/src/nsdp`` package (protocol/types/
parsers) and extended with a write path. No network here: sockets live in
``transport/{sync,aio}/nsdp_udp.py``. NSDP needs no third-party dependency.
"""
from __future__ import annotations
