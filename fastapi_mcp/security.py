"""
fastapi_mcp/security.py
═══════════════════════════════════════════════════════════════════════════════
OWASP API Security Top 10 (2023) — full defence layer for fastapi-mcp.

Each protection is labelled with the OWASP risk it mitigates so you can
trace every line back to a threat category.

OWASP API Security Top 10 (2023) mapping
─────────────────────────────────────────
  API1  Broken Object Level Authorization  →  MCPAuthenticator (tool-level ACL)
  API2  Broken Authentication              →  MCPAuthenticator (API key / Bearer)
  API3  Broken Object Property Level Auth  →  ArgumentValidator (allowlist params)
  API4  Unrestricted Resource Consumption  →  RateLimiter (sliding-window counter)
  API5  Broken Function Level Authorization→  MCPAuthenticator (role-based tools)
  API6  Unrestricted Access to Business Flows → RateLimiter + RoleGuard
  API7  Server-Side Request Forgery (SSRF) →  SSRFGuard (URL/IP validation)
  API8  Security Misconfiguration          →  SecurityHeadersMiddleware
  API9  Improper Inventory Management      →  ToolInventory (version/deprecation)
  API10 Unsafe Consumption of APIs         →  ResponseSanitizer (size + type check)

Usage — minimal secure setup
─────────────────────────────
    from fastapi_mcp import MCPRouter
    from fastapi_mcp.security import SecurityConfig, apply_security

    app = FastAPI()
    # … your routes …

    security = SecurityConfig(
        api_keys={"sk-my-secret-key"},
        rate_limit_calls_per_minute=30,
        allowed_base_urls={"http://localhost:8000"},
    )
    mcp = MCPRouter(app)
    apply_security(app, mcp, security)
    app.include_router(mcp)

Usage — role-based access
──────────────────────────
    security = SecurityConfig(
        api_keys={"sk-admin": ["admin"], "sk-readonly": ["viewer"]},
        tool_roles={"delete_user": ["admin"], "create_user": ["admin"]},
    )
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import re
import socket
import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, Literal
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)


class RateLimitStore:
    """Backend contract for rate-limiter state (in-memory, Redis, etc.)."""

    def hit_and_count(self, bucket: str, subject: str, now: float, window_seconds: int) -> int:
        raise NotImplementedError

    def count(self, bucket: str, subject: str, now: float, window_seconds: int) -> int:
        raise NotImplementedError


class InMemoryRateLimitStore(RateLimitStore):
    """Process-local sliding-window store."""

    def __init__(self) -> None:
        self._windows: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def hit_and_count(self, bucket: str, subject: str, now: float, window_seconds: int) -> int:
        key = f"{bucket}:{subject}"
        with self._lock:
            window = self._windows[key]
            while window and window[0] < now - window_seconds:
                window.popleft()
            window.append(now)
            return len(window)

    def count(self, bucket: str, subject: str, now: float, window_seconds: int) -> int:
        key = f"{bucket}:{subject}"
        with self._lock:
            window = self._windows[key]
            while window and window[0] < now - window_seconds:
                window.popleft()
            return len(window)


class RedisRateLimitStore(RateLimitStore):
    """
    Redis-backed sliding-window store for multi-instance deployments.

    Requires `redis` package to be installed by the application using this class.
    """

    def __init__(self, redis_url: str, *, key_prefix: str = "fastapi_mcp:ratelimit") -> None:
        try:
            import redis
        except ImportError as exc:  # pragma: no cover - env-dependent
            raise RuntimeError(
                "RedisRateLimitStore requires the 'redis' package. "
                "Install it in your application environment."
            ) from exc
        self._client = redis.Redis.from_url(redis_url, decode_responses=True)
        self._prefix = key_prefix

    def _key(self, bucket: str, subject: str) -> str:
        return f"{self._prefix}:{bucket}:{subject}"

    def hit_and_count(self, bucket: str, subject: str, now: float, window_seconds: int) -> int:
        key = self._key(bucket, subject)
        member = f"{now}:{time.time_ns()}"
        pipe = self._client.pipeline()
        pipe.zremrangebyscore(key, "-inf", now - window_seconds)
        pipe.zadd(key, {member: now})
        pipe.zcard(key)
        pipe.expire(key, window_seconds * 2)
        _removed, _added, count, _expire = pipe.execute()
        return int(count)

    def count(self, bucket: str, subject: str, now: float, window_seconds: int) -> int:
        key = self._key(bucket, subject)
        pipe = self._client.pipeline()
        pipe.zremrangebyscore(key, "-inf", now - window_seconds)
        pipe.zcard(key)
        _removed, count = pipe.execute()
        return int(count)


class ObservabilityRecorder:
    """Captures counters and emits structured events for external telemetry."""

    def __init__(self, sink: Callable[[dict[str, Any]], None] | None = None) -> None:
        self._sink = sink
        self._event_counts: dict[str, int] = defaultdict(int)

    def record(self, event: str, **fields: Any) -> None:
        self._event_counts[event] += 1
        payload = {
            "event": event,
            "ts": time.time(),
            **fields,
        }
        if self._sink:
            self._sink(payload)
        logger.info("MCP-OBS %s", payload)

    @property
    def stats(self) -> dict[str, Any]:
        return {"event_counts": dict(self._event_counts)}


class VersionPolicy:
    """Compatibility checks between MCP client version and server API version."""

    def __init__(
        self,
        api_version: str,
        *,
        min_supported_client_version: str = "1.0",
        enforce_client_version: bool = False,
    ) -> None:
        self.api_version = api_version
        self.min_supported_client_version = min_supported_client_version
        self.enforce_client_version = enforce_client_version

    @staticmethod
    def _major(version: str) -> int:
        try:
            return int(version.split(".")[0])
        except (ValueError, IndexError):
            return -1

    def assess(self, client_version: str | None) -> str:
        if not client_version:
            if self.enforce_client_version:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Client version required by server policy. "
                        "Send 'client_version' in POST /mcp/call."
                    ),
                )
            return "unknown"

        server_major = self._major(self.api_version)
        client_major = self._major(client_version)
        min_major = self._major(self.min_supported_client_version)
        compatible = (
            server_major >= 0
            and client_major >= 0
            and client_major == server_major
            and client_major >= min_major
        )
        if compatible:
            return "compatible"

        if self.enforce_client_version:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Incompatible client version '{client_version}'. "
                    f"Server expects major version {server_major}.x."
                ),
            )
        return "incompatible"


# ══════════════════════════════════════════════════════════════════════════════
# Configuration dataclass
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SecurityConfig:
    """
    Central configuration object for all security controls.

    Parameters
    ----------
    api_keys : set[str] | dict[str, list[str]]
        Accepted API keys.  Supply a plain set for keyless roles, or a
        {key: [role1, role2]} dict to map keys to roles.
        If empty / None, authentication is DISABLED (dev-only).
    bearer_tokens : set[str]
        Alternative: accepted Authorization: Bearer <token> tokens.
    rate_limit_calls_per_minute : int
        Maximum POST /mcp/call requests per IP per minute (API4).
        Set to 0 to disable.
    rate_limit_list_per_minute : int
        Maximum GET /mcp/tools requests per IP per minute (API4).
        Set to 0 to disable.
    rate_limit_store : RateLimitStore | None
        Shared backend for rate-limit counters. Defaults to in-memory.
        Use RedisRateLimitStore for multi-instance deployments.
    rate_limit_store_failure_mode : Literal["fail_open", "fail_closed"]
        Behavior when rate-limit backend is unavailable. fail_closed returns 503,
        fail_open allows the request while emitting a warning.
    per_identity_calls_per_minute : int
        Optional quota per authenticated identity (or client IP when unauthenticated).
        Set to 0 to disable.
    per_tool_calls_per_minute : dict[str, int]
        Optional per-tool quotas. Example: {"delete_user": 10}.
    trusted_proxy_cidrs : set[str]
        Proxy CIDRs trusted to supply X-Forwarded-For client IPs.
    use_x_forwarded_for : bool
        If true, use X-Forwarded-For when request comes from a trusted proxy.
    allowed_base_urls : set[str]
        Explicit allowlist of base_url values the executor may call.
        Blocks SSRF against unexpected hosts (API7).
    block_private_ips : bool
        When True (default) the executor refuses to proxy calls to
        RFC-1918 / loopback addresses, preventing SSRF (API7).
    ssrf_revalidate_interval_seconds : int
        Runtime revalidation interval for upstream DNS resolution to reduce
        DNS rebinding/drift risk. Set to 0 to validate every request.
    tool_roles : dict[str, list[str]]
        {tool_name: [required_role, ...]} — callers must hold at least
        one matching role (API1 / API5).
    max_argument_length : int
        Maximum character length of any single string argument value (API3).
    max_body_size_bytes : int
        Maximum Content-Length accepted on POST /mcp/call (API4).
    allowed_content_types : set[str]
        Accepted Content-Type values (API8).
    add_security_headers : bool
        Inject OWASP-recommended HTTP response headers (API8).
    log_tool_calls : bool
        Emit structured log entries for every tool call (API9 audit trail).
    max_response_bytes : int
        Upstream responses larger than this are truncated / rejected (API10).
    deprecated_tools : set[str]
        Tools that still work but emit a Deprecation response header (API9).
    observability_sink : Callable[[dict[str, Any]], None] | None
        Optional callback invoked with structured events for each MCP action.
    api_version : str
        Server API compatibility version exposed via response headers.
    min_supported_client_version : str
        Minimum client version expected by compatibility policy.
    enforce_client_version : bool
        If true, reject missing/incompatible client versions.
    strict_production_mode : bool
        If true, security setup rejects configurations that disable authentication.
    """

    # API2 — Authentication
    api_keys: set[str] | dict[str, list[str]] | None = None
    bearer_tokens: set[str] = field(default_factory=set)

    # API4 — Rate limiting
    rate_limit_calls_per_minute: int = 60
    rate_limit_list_per_minute: int = 120
    rate_limit_store: RateLimitStore | None = None
    rate_limit_store_failure_mode: Literal["fail_open", "fail_closed"] = "fail_closed"
    per_identity_calls_per_minute: int = 0
    per_tool_calls_per_minute: dict[str, int] = field(default_factory=dict)
    trusted_proxy_cidrs: set[str] = field(default_factory=set)
    use_x_forwarded_for: bool = True

    # API7 — SSRF
    allowed_base_urls: set[str] = field(default_factory=set)
    block_private_ips: bool = True
    ssrf_revalidate_interval_seconds: int = 300

    # API1/5 — Authorization / RBAC
    tool_roles: dict[str, list[str]] = field(default_factory=dict)

    # API3 — Property-level authorization / input limits
    max_argument_length: int = 4096
    max_argument_nesting: int = 5

    # API4/8 — Resource limits & misconfiguration
    max_body_size_bytes: int = 65536  # 64 KiB
    allowed_content_types: set[str] = field(default_factory=lambda: {"application/json"})
    add_security_headers: bool = True

    # API9 — Inventory / audit
    log_tool_calls: bool = True
    deprecated_tools: set[str] = field(default_factory=set)
    observability_sink: Callable[[dict[str, Any]], None] | None = None

    # Compatibility policy
    api_version: str = "1.0"
    min_supported_client_version: str = "1.0"
    enforce_client_version: bool = False
    strict_production_mode: bool = False

    # API10 — Upstream response validation
    max_response_bytes: int = 10 * 1024 * 1024  # 10 MiB


# ══════════════════════════════════════════════════════════════════════════════
# API2 + API1/5 — Authentication & Authorization
# ══════════════════════════════════════════════════════════════════════════════

class MCPAuthenticator:
    """
    Validates API keys / Bearer tokens and enforces tool-level RBAC.

    OWASP coverage
    API2 Broken Authentication:  rejects requests with missing/invalid creds
    API1 BOLA:                   users can only call tools their role permits
    API5 BFLA:                   role list prevents calling privileged tools
    """

    def __init__(self, config: SecurityConfig) -> None:
        self._cfg = config

        # Normalise api_keys to dict[key → roles]
        if config.api_keys is None:
            self._key_roles: dict[str, list[str]] = {}
            self._auth_required = False
        elif isinstance(config.api_keys, set):
            self._key_roles = {k: [] for k in config.api_keys}
            self._auth_required = True
        else:
            self._key_roles = dict(config.api_keys)
            self._auth_required = True

        self._bearer_set = set(config.bearer_tokens)
        if self._bearer_set:
            self._auth_required = True

    def authenticate(self, request: Request) -> list[str]:
        """Extract credentials and return caller roles. Raises 401 if invalid."""
        if not self._auth_required:
            return []

        api_key = request.headers.get("X-API-Key")
        if api_key:
            return self._validate_api_key(api_key)

        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            return self._validate_bearer(token)

        raise HTTPException(
            status_code=401,
            detail="Authentication required. Provide X-API-Key or Authorization: Bearer <token>.",
            headers={"WWW-Authenticate": 'Bearer realm="fastapi-mcp"'},
        )

    def authorize_tool(self, tool_name: str, roles: list[str]) -> None:
        """Raise 403 if roles do not permit calling tool_name (API1/API5)."""
        required = self._cfg.tool_roles.get(tool_name)
        if not required:
            return

        if not any(r in required for r in roles):
            logger.warning(
                "OWASP-API5: unauthorized tool call denied tool=%s caller_roles=%s required=%s",
                tool_name, roles, required,
            )
            raise HTTPException(
                status_code=403,
                detail=f"You do not have permission to call tool '{tool_name}'.",
            )

    def _validate_api_key(self, key: str) -> list[str]:
        # Constant-time comparison prevents timing attacks (API2)
        for stored_key, roles in self._key_roles.items():
            if hmac.compare_digest(
                hashlib.sha256(key.encode()).digest(),
                hashlib.sha256(stored_key.encode()).digest(),
            ):
                return roles
        logger.warning("OWASP-API2: invalid API key attempt (last 4: ...%s)", key[-4:])
        raise HTTPException(status_code=401, detail="Invalid API key.")

    def _validate_bearer(self, token: str) -> list[str]:
        for stored in self._bearer_set:
            if hmac.compare_digest(
                hashlib.sha256(token.encode()).digest(),
                hashlib.sha256(stored.encode()).digest(),
            ):
                return []
        logger.warning("OWASP-API2: invalid Bearer token")
        raise HTTPException(status_code=401, detail="Invalid Bearer token.")


# ══════════════════════════════════════════════════════════════════════════════
# API4 — Rate Limiter (sliding-window, in-process)
# ══════════════════════════════════════════════════════════════════════════════

class RateLimiter:
    """
    Per-IP sliding-window rate limiter.

    OWASP coverage
    API4 Unrestricted Resource Consumption — caps calls/min per IP
    API6 Unrestricted Business Flows       — slows bot-style automation

    Note: can use in-memory or a shared backend (e.g. RedisRateLimitStore).
    """

    def __init__(
        self,
        max_per_minute: int,
        *,
        store: RateLimitStore | None = None,
        bucket: str = "call",
        on_store_error: Literal["fail_open", "fail_closed"] = "fail_closed",
    ) -> None:
        self._limit = max_per_minute
        self._store = store or InMemoryRateLimitStore()
        self._bucket = bucket
        self._on_store_error = on_store_error

    def _handle_store_error(self, exc: Exception) -> None:
        logger.error(
            "OWASP-API4: rate-limit backend error bucket=%s mode=%s err=%s",
            self._bucket,
            self._on_store_error,
            exc,
        )
        if self._on_store_error == "fail_open":
            return
        raise HTTPException(
            status_code=503,
            detail="Rate limiter backend unavailable.",
        ) from exc

    def check(self, subject: str) -> None:
        """Raise 429 when subject exceeds the limit."""
        if self._limit <= 0:
            return

        now = time.monotonic()
        try:
            count = self._store.hit_and_count(self._bucket, subject, now, window_seconds=60)
        except Exception as exc:  # noqa: BLE001 - backend failure policy decides behavior
            self._handle_store_error(exc)
            return
        if count > self._limit:
            logger.warning("OWASP-API4: rate limit exceeded subject=%s", subject)
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded. Max {self._limit} requests per minute.",
                headers={"Retry-After": "60"},
            )

    def remaining(self, subject: str) -> int:
        """Calls remaining in the current window for this subject."""
        now = time.monotonic()
        try:
            active = self._store.count(self._bucket, subject, now, window_seconds=60)
        except Exception as exc:  # noqa: BLE001 - backend failure policy decides behavior
            self._handle_store_error(exc)
            return self._limit
        return max(0, self._limit - active)


# ══════════════════════════════════════════════════════════════════════════════
# API7 — SSRF Guard
# ══════════════════════════════════════════════════════════════════════════════

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

_PATH_TRAVERSAL_RE = re.compile(r"\.\./|%2e%2e|%252e", re.IGNORECASE)


class SSRFGuard:
    """
    Prevents Server-Side Request Forgery attacks.

    OWASP coverage
    API7 SSRF — blocks calls to private IPs, path traversal, unexpected hosts

    Checks:
    1. base_url must be in allowed_base_urls (if set is non-empty)
    2. Resolved IP of target host must not be in a private range
    3. Path arguments must not contain ../ or URL-encoded variants
    """

    def __init__(self, config: SecurityConfig) -> None:
        self._allowed = config.allowed_base_urls
        self._block_private = config.block_private_ips
        self._revalidate_interval = max(0, config.ssrf_revalidate_interval_seconds)
        self._allowed_hosts = {
            host
            for url in self._allowed
            if (host := urlparse(url).hostname)
        }
        self._last_validated: dict[str, float] = {}

    def validate_base_url(self, base_url: str) -> None:
        """Called once at MCPRouter init time."""
        if not self._allowed:
            return
        normalised = base_url.rstrip("/")
        if normalised not in {u.rstrip("/") for u in self._allowed}:
            raise ValueError(
                f"OWASP-API7 (SSRF): base_url '{base_url}' is not in "
                "allowed_base_urls. Add it to SecurityConfig.allowed_base_urls."
            )

    def validate_path_arguments(self, arguments: dict[str, Any]) -> None:
        """Reject path-traversal strings hidden in argument values."""
        for key, value in arguments.items():
            if isinstance(value, str) and _PATH_TRAVERSAL_RE.search(value):
                logger.warning(
                    "OWASP-API7: path traversal attempt blocked key=%s value=%.80r",
                    key, value,
                )
                raise HTTPException(
                    status_code=400,
                    detail=f"Argument '{key}' contains a forbidden path-traversal sequence.",
                )

    def validate_resolved_host(self, host: str, *, force: bool = False) -> None:
        """Resolve host and block if the IP is private (SSRF)."""
        if not self._block_private:
            return
        if host in self._allowed_hosts:
            return
        now = time.monotonic()
        last = self._last_validated.get(host)
        if (
            not force
            and last is not None
            and self._revalidate_interval > 0
            and now - last < self._revalidate_interval
        ):
            return
        try:
            info = socket.getaddrinfo(host, None)
        except socket.gaierror:
            return

        for _family, _type, _proto, _canonname, sockaddr in info:
            raw_ip = sockaddr[0]
            try:
                addr = ipaddress.ip_address(raw_ip)
            except ValueError:
                continue
            for net in _PRIVATE_NETWORKS:
                if addr in net:
                    logger.warning(
                        "OWASP-API7: SSRF blocked host=%s ip=%s", host, raw_ip
                    )
                    raise HTTPException(
                        status_code=403,
                        detail=(
                            f"SSRF protection: host '{host}' resolves to a "
                            "private/reserved address and cannot be called."
                        ),
                    )
        self._last_validated[host] = now


class ClientIdentityResolver:
    """Extracts trusted client IP and stable caller identity keys."""

    def __init__(self, config: SecurityConfig) -> None:
        self._use_xff = config.use_x_forwarded_for
        self._trusted_proxies = [
            ipaddress.ip_network(cidr)
            for cidr in config.trusted_proxy_cidrs
        ]

    def _is_trusted_proxy(self, remote_ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(remote_ip)
        except ValueError:
            return False
        return any(addr in net for net in self._trusted_proxies)

    def client_ip(self, request: Request) -> str:
        remote_ip = request.client.host if request.client else "unknown"
        if not self._use_xff or not self._trusted_proxies:
            return remote_ip
        if not self._is_trusted_proxy(remote_ip):
            return remote_ip

        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            candidate = xff.split(",")[0].strip()
            try:
                ipaddress.ip_address(candidate)
                return candidate
            except ValueError:
                return remote_ip
        return remote_ip

    def caller_identity(self, request: Request, client_ip: str) -> str:
        api_key = request.headers.get("X-API-Key")
        if api_key:
            digest = hashlib.sha256(api_key.encode()).hexdigest()[:16]
            return f"api_key:{digest}"

        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            digest = hashlib.sha256(token.encode()).hexdigest()[:16]
            return f"bearer:{digest}"

        return f"ip:{client_ip}"


# ══════════════════════════════════════════════════════════════════════════════
# API3 — Argument Validator
# ══════════════════════════════════════════════════════════════════════════════

class ArgumentValidator:
    """
    Enforces argument constraints on every tool call.

    OWASP coverage
    API3 Broken Object Property Level Auth — strips unknown/oversized fields
    API4 Resource Consumption              — caps total argument payload size
    """

    def __init__(self, config: SecurityConfig) -> None:
        self._max_len     = config.max_argument_length
        self._max_nesting = config.max_argument_nesting

    def validate(self, arguments: dict[str, Any], allowed_params: set[str]) -> dict[str, Any]:
        """
        Strip undeclared parameters (mass-assignment protection) and enforce
        size limits. Returns a cleaned copy of arguments.
        """
        unknown = set(arguments) - allowed_params
        if unknown:
            logger.info("OWASP-API3: stripping undeclared arguments %s", unknown)
        clean = {k: v for k, v in arguments.items() if k in allowed_params}
        self._check_value(clean, depth=0)
        return clean

    def _check_value(self, value: Any, depth: int) -> None:
        if depth > self._max_nesting:
            raise HTTPException(
                status_code=400,
                detail=f"Argument nesting exceeds maximum depth of {self._max_nesting}.",
            )
        if isinstance(value, str) and len(value) > self._max_len:
            raise HTTPException(
                status_code=400,
                detail=f"Argument value too long. Maximum {self._max_len} characters.",
            )
        if isinstance(value, dict):
            for v in value.values():
                self._check_value(v, depth + 1)
        elif isinstance(value, list):
            for item in value:
                self._check_value(item, depth + 1)


# ══════════════════════════════════════════════════════════════════════════════
# API8 — Security Headers Middleware
# ══════════════════════════════════════════════════════════════════════════════

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Injects OWASP-recommended HTTP security response headers.

    OWASP coverage
    API8 Security Misconfiguration — adds defensive headers browsers enforce.

    Headers added:
      X-Content-Type-Options: nosniff       — stops MIME-type sniffing
      X-Frame-Options: DENY                 — blocks clickjacking
      Content-Security-Policy: default-src 'none'  — no scripts needed
      Referrer-Policy: no-referrer          — no URL leakage
      Cache-Control: no-store               — never cache sensitive responses
      Permissions-Policy                    — disable unused browser APIs
      Strict-Transport-Security (optional)  — force HTTPS (TLS deployments)
    Headers removed:
      X-Powered-By, Server                  — hides framework fingerprint
    """

    _HEADERS = {
        "X-Content-Type-Options":  "nosniff",
        "X-Frame-Options":         "DENY",
        "Referrer-Policy":         "no-referrer",
        "Cache-Control":           "no-store, no-cache, must-revalidate, private",
        "Content-Security-Policy": "default-src 'none'",
        "Permissions-Policy":      "geolocation=(), microphone=(), camera=()",
    }

    def __init__(self, app: ASGIApp, *, enable_hsts: bool = False) -> None:
        super().__init__(app)
        self._enable_hsts = enable_hsts

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        response = await call_next(request)
        for header, value in self._HEADERS.items():
            response.headers[header] = value
        if self._enable_hsts:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )
        if "X-Powered-By" in response.headers:
            del response.headers["X-Powered-By"]
        if "Server" in response.headers:
            del response.headers["Server"]
        return response


# ══════════════════════════════════════════════════════════════════════════════
# API4/8 — Request Size Guard Middleware
# ══════════════════════════════════════════════════════════════════════════════

class RequestSizeMiddleware(BaseHTTPMiddleware):
    """
    Rejects oversized requests and enforces Content-Type policy.

    OWASP coverage
    API4 Unrestricted Resource Consumption — prevents DoS via huge bodies
    API8 Security Misconfiguration         — enforces content-type discipline
    """

    def __init__(
        self,
        app: ASGIApp,
        max_bytes: int,
        allowed_content_types: set[str],
        mcp_prefix: str = "/mcp",
    ) -> None:
        super().__init__(app)
        self._max     = max_bytes
        self._allowed = allowed_content_types
        self._prefix  = mcp_prefix

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        if not request.url.path.startswith(self._prefix):
            return await call_next(request)

        if request.method in {"POST", "PUT", "PATCH"}:
            ct = request.headers.get("content-type", "").split(";")[0].strip()
            if ct and ct not in self._allowed:
                return Response(content=f"Unsupported Content-Type '{ct}'.", status_code=415)

        cl_header = request.headers.get("content-length")
        if cl_header:
            try:
                if int(cl_header) > self._max:
                    return Response(
                        content=f"Request body too large. Max {self._max // 1024} KiB allowed.",
                        status_code=413,
                    )
            except ValueError:
                pass

        return await call_next(request)


# ══════════════════════════════════════════════════════════════════════════════
# API9 — Tool Inventory & Audit Logger
# ══════════════════════════════════════════════════════════════════════════════

class ToolInventory:
    """
    Tracks tool usage and marks deprecated tools.

    OWASP coverage
    API9 Improper Inventory Management — logs every call so zombie/shadow
         tools can be identified and decommissioned before they become liabilities.
    """

    def __init__(self, deprecated: set[str]) -> None:
        self._deprecated  = deprecated
        self._call_counts: dict[str, int] = defaultdict(int)
        self._last_called: dict[str, float] = {}

    def record_call(self, tool_name: str, caller_ip: str) -> None:
        self._call_counts[tool_name] += 1
        self._last_called[tool_name] = time.time()
        logger.info(
            "MCP-AUDIT tool=%s ip=%s total_calls=%d",
            tool_name, caller_ip, self._call_counts[tool_name],
        )

    def deprecation_header(self, tool_name: str) -> str | None:
        """Return RFC 8594 Deprecation header value if this tool is deprecated."""
        if tool_name in self._deprecated:
            logger.warning("OWASP-API9: deprecated tool called tool=%s", tool_name)
            return "true"
        return None

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "call_counts": dict(self._call_counts),
            "last_called": dict(self._last_called),
        }


# ══════════════════════════════════════════════════════════════════════════════
# API10 — Response Sanitizer
# ══════════════════════════════════════════════════════════════════════════════

class ResponseSanitizer:
    """
    Validates upstream responses before forwarding to the caller.

    OWASP coverage
    API10 Unsafe Consumption of APIs — treats upstream like untrusted input:
          caps payload size, strips dangerous response headers that leak
          internal implementation details.
    """

    _DANGEROUS_HEADERS = frozenset({
        "set-cookie", "x-powered-by", "server",
        "x-aspnet-version", "x-aspnetmvc-version",
    })

    def __init__(self, max_bytes: int) -> None:
        self._max = max_bytes

    def validate_size(self, content: bytes | str, tool_name: str) -> None:
        size = len(content) if isinstance(content, bytes) else len(content.encode())
        if size > self._max:
            logger.warning(
                "OWASP-API10: upstream response too large tool=%s size=%d max=%d",
                tool_name, size, self._max,
            )
            raise HTTPException(
                status_code=502,
                detail=(
                    f"Upstream response for '{tool_name}' exceeds the "
                    f"{self._max // (1024 * 1024)} MiB safety limit."
                ),
            )

    def strip_dangerous_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Remove headers that leak internal implementation details."""
        return {k: v for k, v in headers.items() if k.lower() not in self._DANGEROUS_HEADERS}


# ══════════════════════════════════════════════════════════════════════════════
# Convenience: apply_security()
# ══════════════════════════════════════════════════════════════════════════════

def apply_security(
    app: FastAPI,
    mcp_router: Any,
    config: SecurityConfig,
    *,
    enable_hsts: bool = False,
) -> SecurityBundle:
    """
    Wire all OWASP security controls onto *app* and *mcp_router* in one call.

    Returns a SecurityBundle you can store for testing or monitoring.

    Example::

        bundle = apply_security(app, mcp, SecurityConfig(api_keys={"sk-secret"}))
        bundle.inventory.stats     # call statistics (API9)
        bundle.rate_limiter        # inspect remaining quota (API4)
    """
    if config.strict_production_mode:
        has_api_keys = bool(config.api_keys)
        has_bearer = bool(config.bearer_tokens)
        if not has_api_keys and not has_bearer:
            raise ValueError(
                "strict_production_mode requires authentication. "
                "Set api_keys or bearer_tokens in SecurityConfig."
            )

    bundle = SecurityBundle(config)
    executor = getattr(mcp_router, "_executor", None)
    if executor is not None:
        base_url = getattr(executor, "base_url", None)
        base_host = getattr(executor, "base_host", None)
        if isinstance(base_url, str):
            bundle.ssrf_guard.validate_base_url(base_url)
        if isinstance(base_host, str) and base_host:
            bundle.ssrf_guard.validate_resolved_host(base_host, force=True)

    if config.add_security_headers:
        app.add_middleware(SecurityHeadersMiddleware, enable_hsts=enable_hsts)

    app.add_middleware(
        RequestSizeMiddleware,
        max_bytes             = config.max_body_size_bytes,
        allowed_content_types = config.allowed_content_types,
        mcp_prefix            = getattr(mcp_router, "prefix", "/mcp"),
    )

    mcp_router._security = bundle

    logger.info(
        "fastapi-mcp security: auth=%s rate_limit=%d/min ssrf_guard=%s headers=%s",
        bundle.authenticator._auth_required,
        config.rate_limit_calls_per_minute,
        config.block_private_ips,
        config.add_security_headers,
    )

    return bundle


@dataclass
class SecurityBundle:
    """All live security components in one place (useful for testing)."""

    config:           SecurityConfig
    authenticator:    MCPAuthenticator  = field(init=False)
    rate_limiter:     RateLimiter       = field(init=False)
    list_limiter:     RateLimiter       = field(init=False)
    per_identity_limiter: RateLimiter | None = field(init=False)
    per_tool_limiters: dict[str, RateLimiter] = field(init=False)
    ssrf_guard:       SSRFGuard         = field(init=False)
    identity_resolver: ClientIdentityResolver = field(init=False)
    arg_validator:    ArgumentValidator = field(init=False)
    inventory:        ToolInventory     = field(init=False)
    response_checker: ResponseSanitizer = field(init=False)
    observability:    ObservabilityRecorder = field(init=False)
    version_policy:   VersionPolicy = field(init=False)

    def __post_init__(self) -> None:
        c = self.config
        shared_store = c.rate_limit_store or InMemoryRateLimitStore()
        self.authenticator    = MCPAuthenticator(c)
        self.rate_limiter     = RateLimiter(
            c.rate_limit_calls_per_minute,
            store=shared_store,
            bucket="call",
            on_store_error=c.rate_limit_store_failure_mode,
        )
        self.list_limiter     = RateLimiter(
            c.rate_limit_list_per_minute,
            store=shared_store,
            bucket="list",
            on_store_error=c.rate_limit_store_failure_mode,
        )
        self.per_identity_limiter = (
            RateLimiter(
                c.per_identity_calls_per_minute,
                store=shared_store,
                bucket="identity",
                on_store_error=c.rate_limit_store_failure_mode,
            )
            if c.per_identity_calls_per_minute > 0
            else None
        )
        self.per_tool_limiters = {
            tool_name: RateLimiter(
                limit,
                store=shared_store,
                bucket=f"tool:{tool_name}",
                on_store_error=c.rate_limit_store_failure_mode,
            )
            for tool_name, limit in c.per_tool_calls_per_minute.items()
            if limit > 0
        }
        self.ssrf_guard       = SSRFGuard(c)
        self.identity_resolver = ClientIdentityResolver(c)
        self.arg_validator    = ArgumentValidator(c)
        self.inventory        = ToolInventory(c.deprecated_tools)
        self.response_checker = ResponseSanitizer(c.max_response_bytes)
        self.observability    = ObservabilityRecorder(c.observability_sink)
        self.version_policy   = VersionPolicy(
            c.api_version,
            min_supported_client_version=c.min_supported_client_version,
            enforce_client_version=c.enforce_client_version,
        )
