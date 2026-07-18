"""Transport-agnostic web-UI session seam (Protocols only, no I/O).

Both the sync (``httpx.Client``) and async (``httpx.AsyncClient``) transports
implement these. Readers/writers depend only on these three methods, so the
pure protocol layer is the single shared codebase across sync and async.
"""
from __future__ import annotations

from typing import Protocol


class HttpSession(Protocol):
    """Synchronous authenticated web-UI session for one switch."""

    def login(self) -> None: ...

    def get_page(self, path: str) -> str: ...

    def post_form(self, path: str, data: dict[str, str]) -> str: ...


class AsyncHttpSession(Protocol):
    """Asynchronous authenticated web-UI session for one switch."""

    async def login(self) -> None: ...

    async def get_page(self, path: str) -> str: ...

    async def post_form(self, path: str, data: dict[str, str]) -> str: ...
