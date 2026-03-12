"""
MCPRouter — the public-facing class users add to their FastAPI app.

Usage (one-liner)
─────────────────
    from fastapi import FastAPI
    from fastapi_mcp import MCPRouter

    app = FastAPI()

    # … your routes …

    mcp = MCPRouter(app)        # discovers all routes automatically
    app.include_router(mcp)     # mounts /mcp/tools and /mcp/call

Usage (with OWASP security)
────────────────────────────
    from fastapi_mcp import MCPRouter
    from fastapi_mcp.security import SecurityConfig, apply_security

    app = FastAPI()
    # … your routes …

    mcp = MCPRouter(app)
    security = SecurityConfig(api_keys={"sk-secret"}, rate_limit_calls_per_minute=30)
    bundle = apply_security(app, mcp, security)
    app.include_router(mcp)
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx
from fastapi import APIRouter, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse

from .executor import ToolExecutor
from .parser import parse_openapi
from .registry import ToolRegistry
from .schemas import Tool, ToolCallRequest, ToolCallResponse

logger = logging.getLogger(__name__)


class MCPRouter(APIRouter):
    """
    A FastAPI APIRouter that automatically exposes every endpoint of a
    FastAPI application as an MCP tool.

    Parameters
    ----------
    app:
        The FastAPI instance whose routes become tools.
    base_url:
        Where app is actually running. Used by the executor to proxy calls.
        Defaults to http://localhost:8000.
    prefix:
        URL prefix for the MCP endpoints. Defaults to /mcp.
    include_tags:
        Whitelist of OpenAPI tags. Only endpoints with at least one matching
        tag are exposed. None (default) exposes every endpoint.
    exclude_tags:
        Blacklist of OpenAPI tags. Endpoints with a matching tag are hidden.
    exclude_paths:
        Path prefixes to exclude completely, e.g. ["/health", "/metrics"].
        The MCP prefix itself is always excluded automatically.
    timeout:
        HTTP timeout (seconds) for upstream calls. Defaults to 15 s.
    extra_headers:
        Headers forwarded on every upstream request (e.g. Authorization).
    """

    def __init__(
        self,
        app: FastAPI,
        *,
        base_url: str = "http://localhost:8000",
        prefix: str = "/mcp",
        include_tags: list[str] | None = None,
        exclude_tags: list[str] | None = None,
        exclude_paths: list[str] | None = None,
        timeout: float = 15.0,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(prefix=prefix, tags=["MCP"])

        # Optional security bundle — attached by apply_security() after init
        self._security: Any = None

        self._registry = ToolRegistry()
        self._executor = ToolExecutor(
            base_url=base_url, timeout=timeout, headers=extra_headers
        )

        # Always hide the MCP endpoints themselves from the tool list
        _exclude = list(exclude_paths or []) + [prefix]

        schema     = app.openapi()
        tool_count = parse_openapi(
            schema,
            self._registry,
            include_tags  = include_tags,
            exclude_tags  = exclude_tags,
            exclude_paths = _exclude,
        )
        logger.info("fastapi-mcp: registered %d tools", tool_count)

        app.add_event_handler("shutdown", self._on_shutdown)
        self._register_routes()

    # ── Routes ─────────────────────────────────────────────────────────────

    def _register_routes(self) -> None:
        registry = self._registry
        executor = self._executor

        def build_error_response(
            *,
            tool: str,
            message: str,
            code: str,
            status_code: int,
            retryable: bool,
            headers: dict[str, str] | None = None,
        ) -> JSONResponse:
            body = ToolCallResponse(
                tool=tool,
                result=None,
                error=message,
                error_code=code,
                retryable=retryable,
                status_code=status_code,
            )
            return JSONResponse(
                status_code=status_code,
                content=body.model_dump(),
                headers=headers or {},
            )

        @self.get(
            "/tools",
            response_model=list[Tool],
            summary="List all MCP tools",
            description=(
                "Returns every FastAPI endpoint that has been converted into an "
                "MCP tool. AI agents use this to discover what they can call."
            ),
        )
        async def list_tools(
            request: Request,
            http_response: Response,
            tag: str | None = Query(None, description="Filter by OpenAPI tag"),
        ) -> list[Tool]:
            sec = self._security
            if sec:
                start = time.perf_counter()
                sec.authenticator.authenticate(request)
                client_ip = sec.identity_resolver.client_ip(request)
                sec.list_limiter.check(client_ip)
                http_response.headers["X-MCP-API-Version"] = sec.version_policy.api_version
                http_response.headers["X-MCP-Compatibility"] = "n/a"
                sec.observability.record(
                    "list_tools",
                    ip=client_ip,
                    tag=tag,
                    latency_ms=round((time.perf_counter() - start) * 1000, 2),
                )
                if sec.config.log_tool_calls:
                    logger.info("MCP-LIST ip=%s", client_ip)
            return registry.list_tools(tag=tag)

        @self.post(
            "/call",
            response_model=ToolCallResponse,
            summary="Call an MCP tool",
            description=(
                "Invoke a tool by name. The server looks up the corresponding "
                "FastAPI endpoint and proxies the call, returning the JSON result."
            ),
        )
        async def call_tool(
            request: Request,
            http_response: Response,
            payload: ToolCallRequest,
        ) -> ToolCallResponse | Response:
            sec = self._security
            client_ip = request.client.host if request.client else "unknown"
            start = time.perf_counter()
            compatibility = "n/a"
            caller_identity = f"ip:{client_ip}"

            try:
                # ── OWASP controls (if security bundle is attached) ────────────
                roles: list[str] = []
                if sec:
                    # API2 — Authentication
                    roles = sec.authenticator.authenticate(request)
                    client_ip = sec.identity_resolver.client_ip(request)
                    caller_identity = sec.identity_resolver.caller_identity(request, client_ip)
                    compatibility = sec.version_policy.assess(payload.client_version)
                    http_response.headers["X-MCP-API-Version"] = sec.version_policy.api_version
                    http_response.headers["X-MCP-Compatibility"] = compatibility

                    # API4 — Rate limiting
                    sec.rate_limiter.check(client_ip)
                    if sec.per_identity_limiter:
                        sec.per_identity_limiter.check(caller_identity)

                    # API7 — SSRF: path traversal in arguments
                    sec.ssrf_guard.validate_path_arguments(payload.arguments)
                    if executor.base_host:
                        sec.ssrf_guard.validate_resolved_host(executor.base_host)

                tool = registry.get(payload.tool)
                if tool is None:
                    return build_error_response(
                        tool=payload.tool,
                        message=(
                            f"Tool '{payload.tool}' not found. "
                            "Call GET /mcp/tools to see available tools."
                        ),
                        code="TOOL_NOT_FOUND",
                        status_code=404,
                        retryable=False,
                    )

                if sec:
                    # API1/5 — Authorization
                    sec.authenticator.authorize_tool(payload.tool, roles)
                    tool_limiter = sec.per_tool_limiters.get(payload.tool)
                    if tool_limiter:
                        tool_limiter.check(caller_identity)

                    # API3 — Strip unknown/oversized arguments
                    allowed = {p.name for p in tool.parameters}
                    arguments = sec.arg_validator.validate(payload.arguments, allowed)

                    # API9 — Audit log + deprecation header
                    sec.inventory.record_call(payload.tool, client_ip)
                    dep_header = sec.inventory.deprecation_header(payload.tool)
                else:
                    arguments = payload.arguments
                    dep_header = None
            except HTTPException as exc:
                code = "MCP_HTTP_ERROR"
                if exc.status_code == 400:
                    code = "INVALID_REQUEST"
                elif exc.status_code == 401:
                    code = "AUTH_REQUIRED"
                elif exc.status_code == 403:
                    code = "ACCESS_DENIED"
                elif exc.status_code == 409:
                    code = "CLIENT_VERSION_INCOMPATIBLE"
                elif exc.status_code == 429:
                    code = "RATE_LIMITED"
                error_headers = dict(exc.headers) if exc.headers else None
                return build_error_response(
                    tool=payload.tool,
                    message=str(exc.detail),
                    code=code,
                    status_code=exc.status_code,
                    retryable=exc.status_code in {409, 429},
                    headers=error_headers,
                )

            try:
                result, status = await executor.execute(tool, arguments)

                # API10 — Validate upstream response size
                if sec:
                    import json as _json
                    raw = _json.dumps(result).encode()
                    sec.response_checker.validate_size(raw, payload.tool)

                tool_response = ToolCallResponse(
                    tool        = payload.tool,
                    result      = result,
                    error       = None,
                    error_code  = None,
                    retryable   = False,
                    status_code = status,
                )

                if dep_header:
                    # Attach RFC-8594 Deprecation header via JSONResponse
                    headers = {
                        "Deprecation": dep_header,
                        "X-MCP-API-Version": sec.version_policy.api_version,
                        "X-MCP-Compatibility": compatibility,
                    }
                    return JSONResponse(
                        content    = tool_response.model_dump(),
                        headers    = headers,
                        status_code= 200,
                    )

                if sec:
                    sec.observability.record(
                        "tool_call_success",
                        tool=payload.tool,
                        ip=client_ip,
                        identity=caller_identity,
                        status_code=status,
                        compatibility=compatibility,
                        latency_ms=round((time.perf_counter() - start) * 1000, 2),
                    )
                return tool_response

            except httpx.HTTPStatusError as exc:
                if sec:
                    sec.observability.record(
                        "tool_call_http_error",
                        tool=payload.tool,
                        ip=client_ip,
                        identity=caller_identity,
                        status_code=exc.response.status_code,
                        compatibility=compatibility,
                        latency_ms=round((time.perf_counter() - start) * 1000, 2),
                    )
                return build_error_response(
                    tool=payload.tool,
                    message=f"Upstream error from {tool.method} {tool.path}: {exc.response.text}",
                    code="UPSTREAM_HTTP_ERROR",
                    status_code=exc.response.status_code,
                    retryable=500 <= exc.response.status_code < 600,
                )
            except httpx.TimeoutException as exc:
                if sec:
                    sec.observability.record(
                        "tool_call_timeout",
                        tool=payload.tool,
                        ip=client_ip,
                        identity=caller_identity,
                        compatibility=compatibility,
                        latency_ms=round((time.perf_counter() - start) * 1000, 2),
                    )
                return build_error_response(
                    tool=payload.tool,
                    message=f"Upstream call timed out: {exc}",
                    code="UPSTREAM_TIMEOUT",
                    status_code=504,
                    retryable=True,
                )
            except httpx.RequestError as exc:
                if sec:
                    sec.observability.record(
                        "tool_call_request_error",
                        tool=payload.tool,
                        ip=client_ip,
                        identity=caller_identity,
                        compatibility=compatibility,
                        latency_ms=round((time.perf_counter() - start) * 1000, 2),
                    )
                return build_error_response(
                    tool=payload.tool,
                    message=f"Could not reach upstream service: {exc}",
                    code="UPSTREAM_UNREACHABLE",
                    status_code=503,
                    retryable=True,
                )

    # ── Lifecycle ──────────────────────────────────────────────────────────

    async def _on_shutdown(self) -> None:
        await self._executor.aclose()

    # ── Convenience properties ─────────────────────────────────────────────

    @property
    def registry(self) -> ToolRegistry:
        return self._registry

    @property
    def tool_count(self) -> int:
        return len(self._registry)
