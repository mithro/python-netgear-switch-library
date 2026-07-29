"""Transport-agnostic web-UI session seam (Protocols only, no I/O).

Both the sync (``httpx.Client``) and async (``httpx.AsyncClient``) transports
implement these. Readers/writers depend only on these three methods, so the
pure protocol layer is the single shared codebase across sync and async.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class MultipartFile:
    """One file part of a ``multipart/form-data`` POST (see ``post_multipart``).

    Used by the SSL-certificate upload flow: ``field`` is the form field name
    the switch expects the file under (e.g. gsm7228ps's ``.v_1_3_1_handle``),
    ``content`` is the raw file bytes served as ``filename`` with MIME
    ``content_type`` (e.g. ``application/octet-stream``).
    """

    field: str
    filename: str
    content: bytes
    content_type: str


class HttpSession(Protocol):
    """Synchronous authenticated web-UI session for one switch."""

    def login(self) -> None: ...

    def get_page(self, path: str) -> str: ...

    def post_form(self, path: str, data: dict[str, str]) -> str: ...

    def post_multipart(
        self, path: str, data: dict[str, str], file: MultipartFile
    ) -> str: ...

    def post_xml(self, path: str, body: str) -> str: ...


class AsyncHttpSession(Protocol):
    """Asynchronous authenticated web-UI session for one switch."""

    async def login(self) -> None: ...

    async def get_page(self, path: str) -> str: ...

    async def post_form(self, path: str, data: dict[str, str]) -> str: ...

    async def post_multipart(
        self, path: str, data: dict[str, str], file: MultipartFile
    ) -> str: ...

    async def post_xml(self, path: str, body: str) -> str: ...
