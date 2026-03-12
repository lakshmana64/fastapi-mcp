"""
Executes MCP tool calls by proxying them to the underlying FastAPI endpoints.

Routing rules
─────────────
• Path parameters  →  substituted directly into the URL template
• GET / DELETE     →  remaining args become query-string parameters
• POST / PUT/PATCH →  remaining args sent as a JSON body

The executor owns a single shared ``httpx.AsyncClient`` (connection pooling +
keep-alive) for the lifetime of the server process.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from .schemas import Tool


class ToolExecutor:
    """Async HTTP client that proxies tool calls to a FastAPI application."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 15.0,
        headers: dict[str, str] | None = None,
    ) -> None:
        """
        Parameters
        ----------
        base_url:
            Root URL of the upstream FastAPI app, e.g. ``http://localhost:8000``.
        timeout:
            Seconds before abandoning an upstream call.
        headers:
            Extra HTTP headers forwarded on every request (e.g. an auth token).
        """
        self._base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            timeout         = httpx.Timeout(timeout),
            follow_redirects= True,
            headers         = headers or {},
        )

    # ── Public ─────────────────────────────────────────────────────────────

    async def execute(self, tool: Tool, arguments: dict[str, Any]) -> tuple[Any, int]:
        """
        Call the upstream endpoint and return ``(parsed_response, status_code)``.

        Raises
        ------
        httpx.HTTPStatusError
            When the upstream returns 4xx / 5xx.
        httpx.RequestError
            On network / timeout failures.
        """
        path_params = _extract_path_params(tool.path)
        url         = _build_url(self._base_url, tool.path, arguments, path_params)
        remaining   = {k: v for k, v in arguments.items() if k not in path_params}

        if tool.method in {"POST", "PUT", "PATCH"}:
            response = await self._client.request(
                tool.method, url, json=remaining or None
            )
        else:
            response = await self._client.request(
                tool.method, url, params=remaining or None
            )

        response.raise_for_status()
        return _parse_response(response), response.status_code

    async def aclose(self) -> None:
        """Release the underlying connection pool. Call on app shutdown."""
        await self._client.aclose()

    @property
    def base_url(self) -> str:
        return self._base_url

    @property
    def base_host(self) -> str | None:
        return httpx.URL(self._base_url).host


# ── Helpers ────────────────────────────────────────────────────────────────────

def _extract_path_params(path: str) -> set[str]:
    """Return the set of variable names in a path template."""
    return set(re.findall(r"\{(\w+)\}", path))


def _build_url(
    base: str,
    path: str,
    arguments: dict[str, Any],
    path_params: set[str],
) -> str:
    resolved = path
    for name in path_params:
        if name in arguments:
            resolved = resolved.replace(f"{{{name}}}", str(arguments[name]))
    return f"{base}{resolved}"


def _parse_response(response: httpx.Response) -> Any:
    """Return JSON if the content-type says so, otherwise plain text."""
    ct = response.headers.get("content-type", "")
    if "application/json" in ct:
        return response.json()
    return response.text
