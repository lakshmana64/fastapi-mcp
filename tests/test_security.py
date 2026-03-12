"""
tests/test_security.py
Tests for every OWASP API Security Top 10 (2023) control in security.py.
Each test class is labelled with the OWASP risk it targets.
"""
from __future__ import annotations

import time
from unittest.mock import patch

import pytest
from fastapi import FastAPI, HTTPException, Request

from fastapi_mcp import MCPRouter
from fastapi_mcp.security import (
    ArgumentValidator,
    ClientIdentityResolver,
    InMemoryRateLimitStore,
    MCPAuthenticator,
    RateLimiter,
    RateLimitStore,
    ResponseSanitizer,
    SecurityBundle,
    SecurityConfig,
    SSRFGuard,
    ToolInventory,
    VersionPolicy,
    apply_security,
)


def make_request(headers: dict[str, str]) -> Request:
    scope = {
        "type": "http", "method": "POST", "path": "/mcp/call",
        "query_string": b"",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
    }
    return Request(scope)


# ── API2 — Broken Authentication ──────────────────────────────────────────────
class TestMCPAuthenticator:
    def test_auth_disabled_when_no_keys(self):
        auth = MCPAuthenticator(SecurityConfig(api_keys=None))
        assert auth.authenticate(make_request({})) == []

    def test_valid_api_key_accepted(self):
        auth = MCPAuthenticator(SecurityConfig(api_keys={"sk-secret"}))
        assert auth.authenticate(make_request({"X-API-Key": "sk-secret"})) == []

    def test_invalid_api_key_raises_401(self):
        auth = MCPAuthenticator(SecurityConfig(api_keys={"sk-secret"}))
        with pytest.raises(HTTPException) as exc:
            auth.authenticate(make_request({"X-API-Key": "sk-wrong"}))
        assert exc.value.status_code == 401

    def test_no_credentials_raises_401(self):
        auth = MCPAuthenticator(SecurityConfig(api_keys={"sk-secret"}))
        with pytest.raises(HTTPException) as exc:
            auth.authenticate(make_request({}))
        assert exc.value.status_code == 401

    def test_bearer_token_accepted(self):
        auth = MCPAuthenticator(SecurityConfig(bearer_tokens={"tok-abc"}))
        assert auth.authenticate(make_request({"Authorization": "Bearer tok-abc"})) == []

    def test_invalid_bearer_raises_401(self):
        auth = MCPAuthenticator(SecurityConfig(bearer_tokens={"tok-abc"}))
        with pytest.raises(HTTPException) as exc:
            auth.authenticate(make_request({"Authorization": "Bearer tok-bad"}))
        assert exc.value.status_code == 401

    def test_api_key_with_roles_returned(self):
        auth = MCPAuthenticator(SecurityConfig(api_keys={"sk-admin": ["admin", "editor"]}))
        roles = auth.authenticate(make_request({"X-API-Key": "sk-admin"}))
        assert "admin" in roles and "editor" in roles


# ── API1/5 — Authorization ─────────────────────────────────────────────────────
class TestToolAuthorization:
    def test_unrestricted_tool_allowed(self):
        auth = MCPAuthenticator(SecurityConfig(tool_roles={}))
        auth.authorize_tool("get_weather", ["viewer"])  # no raise

    def test_restricted_tool_allowed_with_role(self):
        auth = MCPAuthenticator(SecurityConfig(tool_roles={"delete_user": ["admin"]}))
        auth.authorize_tool("delete_user", ["admin"])  # no raise

    def test_restricted_tool_denied_wrong_role(self):
        auth = MCPAuthenticator(SecurityConfig(tool_roles={"delete_user": ["admin"]}))
        with pytest.raises(HTTPException) as exc:
            auth.authorize_tool("delete_user", ["viewer"])
        assert exc.value.status_code == 403

    def test_empty_roles_denied(self):
        auth = MCPAuthenticator(SecurityConfig(tool_roles={"admin_panel": ["admin"]}))
        with pytest.raises(HTTPException) as exc:
            auth.authorize_tool("admin_panel", [])
        assert exc.value.status_code == 403

    def test_multiple_accepted_roles(self):
        auth = MCPAuthenticator(SecurityConfig(tool_roles={"manage": ["admin", "manager"]}))
        auth.authorize_tool("manage", ["manager"])  # no raise


# ── API4 — Rate Limiting ───────────────────────────────────────────────────────
class TestRateLimiter:
    class _BrokenStore(RateLimitStore):
        def hit_and_count(self, bucket: str, subject: str, now: float, window_seconds: int) -> int:
            raise RuntimeError("store unavailable")

        def count(self, bucket: str, subject: str, now: float, window_seconds: int) -> int:
            raise RuntimeError("store unavailable")

    def test_under_limit_passes(self):
        rl = RateLimiter(5)
        for _ in range(5):
            rl.check("1.2.3.4")

    def test_exceeding_limit_raises_429(self):
        rl = RateLimiter(3)
        for _ in range(3):
            rl.check("1.2.3.4")
        with pytest.raises(HTTPException) as exc:
            rl.check("1.2.3.4")
        assert exc.value.status_code == 429

    def test_different_ips_independent(self):
        rl = RateLimiter(2)
        rl.check("1.1.1.1")
        rl.check("1.1.1.1")
        rl.check("2.2.2.2")  # different IP — no raise

    def test_disabled_never_raises(self):
        rl = RateLimiter(0)
        for _ in range(1000):
            rl.check("9.9.9.9")

    def test_remaining_decrements(self):
        rl = RateLimiter(10)
        rl.check("3.3.3.3")
        rl.check("3.3.3.3")
        assert rl.remaining("3.3.3.3") == 8

    def test_retry_after_header_present(self):
        rl = RateLimiter(1)
        rl.check("5.5.5.5")
        with pytest.raises(HTTPException) as exc:
            rl.check("5.5.5.5")
        assert "Retry-After" in exc.value.headers

    def test_shared_store_works_across_limiter_instances(self):
        store = InMemoryRateLimitStore()
        rl_one = RateLimiter(2, store=store, bucket="call")
        rl_two = RateLimiter(2, store=store, bucket="call")
        rl_one.check("7.7.7.7")
        rl_two.check("7.7.7.7")
        with pytest.raises(HTTPException) as exc:
            rl_one.check("7.7.7.7")
        assert exc.value.status_code == 429

    def test_store_failure_fail_closed_raises_503(self):
        rl = RateLimiter(
            10,
            store=self._BrokenStore(),
            on_store_error="fail_closed",
        )
        with pytest.raises(HTTPException) as exc:
            rl.check("8.8.8.8")
        assert exc.value.status_code == 503

    def test_store_failure_fail_open_allows_request(self):
        rl = RateLimiter(
            10,
            store=self._BrokenStore(),
            on_store_error="fail_open",
        )
        rl.check("8.8.4.4")


# ── API7 — SSRF ────────────────────────────────────────────────────────────────
class TestSSRFGuard:
    def test_base_url_in_allowlist_passes(self):
        guard = SSRFGuard(SecurityConfig(allowed_base_urls={"http://localhost:8000"}))
        guard.validate_base_url("http://localhost:8000")

    def test_base_url_not_in_allowlist_raises(self):
        guard = SSRFGuard(SecurityConfig(allowed_base_urls={"http://localhost:8000"}))
        with pytest.raises(ValueError, match="SSRF"):
            guard.validate_base_url("http://evil.com")

    def test_empty_allowlist_skips_check(self):
        guard = SSRFGuard(SecurityConfig(allowed_base_urls=set()))
        guard.validate_base_url("http://anything.com")

    def test_path_traversal_blocked(self):
        guard = SSRFGuard(SecurityConfig())
        with pytest.raises(HTTPException) as exc:
            guard.validate_path_arguments({"id": "../../etc/passwd"})
        assert exc.value.status_code == 400

    def test_url_encoded_traversal_blocked(self):
        guard = SSRFGuard(SecurityConfig())
        with pytest.raises(HTTPException):
            guard.validate_path_arguments({"path": "%2e%2e%2fetc"})

    def test_clean_arguments_pass(self):
        guard = SSRFGuard(SecurityConfig())
        guard.validate_path_arguments({"city": "Bangalore", "limit": "10"})

    def test_private_ip_blocked(self):
        guard = SSRFGuard(SecurityConfig(block_private_ips=True))
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [(2, 1, 6, "", ("192.168.1.1", 0))]
            with pytest.raises(HTTPException) as exc:
                guard.validate_resolved_host("internal.corp")
            assert exc.value.status_code == 403

    def test_loopback_blocked(self):
        guard = SSRFGuard(SecurityConfig(block_private_ips=True))
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [(2, 1, 6, "", ("127.0.0.1", 0))]
            with pytest.raises(HTTPException) as exc:
                guard.validate_resolved_host("localhost")
            assert exc.value.status_code == 403

    def test_public_ip_allowed(self):
        guard = SSRFGuard(SecurityConfig(block_private_ips=True))
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [(2, 1, 6, "", ("8.8.8.8", 0))]
            guard.validate_resolved_host("dns.google")  # no raise

    def test_ssrf_disabled_skips_check(self):
        guard = SSRFGuard(SecurityConfig(block_private_ips=False))
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [(2, 1, 6, "", ("10.0.0.1", 0))]
            guard.validate_resolved_host("internal.corp")  # no raise

    def test_runtime_revalidation_is_cached_until_interval(self):
        guard = SSRFGuard(SecurityConfig(block_private_ips=True, ssrf_revalidate_interval_seconds=600))
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [(2, 1, 6, "", ("8.8.8.8", 0))]
            guard.validate_resolved_host("dns.google")
            guard.validate_resolved_host("dns.google")
            assert mock_dns.call_count == 1

    def test_runtime_revalidation_zero_rechecks_every_request(self):
        guard = SSRFGuard(SecurityConfig(block_private_ips=True, ssrf_revalidate_interval_seconds=0))
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [(2, 1, 6, "", ("8.8.8.8", 0))]
            guard.validate_resolved_host("dns.google")
            guard.validate_resolved_host("dns.google")
            assert mock_dns.call_count == 2


class TestClientIdentityResolver:
    def test_xff_trusted_proxy_used(self):
        resolver = ClientIdentityResolver(
            SecurityConfig(
                trusted_proxy_cidrs={"10.0.0.0/8"},
                use_x_forwarded_for=True,
            )
        )
        request = make_request({"X-Forwarded-For": "203.0.113.10"})
        request.scope["client"] = ("10.1.2.3", 12345)
        assert resolver.client_ip(request) == "203.0.113.10"

    def test_xff_untrusted_proxy_ignored(self):
        resolver = ClientIdentityResolver(
            SecurityConfig(
                trusted_proxy_cidrs={"10.0.0.0/8"},
                use_x_forwarded_for=True,
            )
        )
        request = make_request({"X-Forwarded-For": "203.0.113.10"})
        request.scope["client"] = ("198.51.100.5", 12345)
        assert resolver.client_ip(request) == "198.51.100.5"


# ── API3 — Argument Validator ─────────────────────────────────────────────────
class TestArgumentValidator:
    def test_unknown_params_stripped(self):
        av = ArgumentValidator(SecurityConfig())
        result = av.validate({"city": "Bangalore", "admin_override": "true"}, {"city"})
        assert "admin_override" not in result
        assert result["city"] == "Bangalore"

    def test_known_params_pass(self):
        av = ArgumentValidator(SecurityConfig())
        result = av.validate({"name": "Alice", "email": "a@b.com"}, {"name", "email"})
        assert result == {"name": "Alice", "email": "a@b.com"}

    def test_oversized_string_rejected(self):
        av = ArgumentValidator(SecurityConfig(max_argument_length=10))
        with pytest.raises(HTTPException) as exc:
            av.validate({"q": "x" * 11}, {"q"})
        assert exc.value.status_code == 400

    def test_excessive_nesting_rejected(self):
        av = ArgumentValidator(SecurityConfig(max_argument_nesting=2))
        deep = {"a": {"b": {"c": {"d": "too deep"}}}}
        with pytest.raises(HTTPException) as exc:
            av.validate(deep, {"a"})
        assert exc.value.status_code == 400

    def test_nested_within_limit_passes(self):
        av = ArgumentValidator(SecurityConfig(max_argument_nesting=3))
        payload = {"a": {"b": {"c": "ok"}}}
        assert av.validate(payload, {"a"}) == payload

    def test_list_values_size_checked(self):
        av = ArgumentValidator(SecurityConfig(max_argument_length=5))
        with pytest.raises(HTTPException):
            av.validate({"ids": ["1", "2", "toolong"]}, {"ids"})


# ── API9 — Inventory Management ───────────────────────────────────────────────
class TestToolInventory:
    def test_call_recorded(self):
        inv = ToolInventory(deprecated=set())
        inv.record_call("get_weather", "1.2.3.4")
        assert inv.stats["call_counts"]["get_weather"] == 1

    def test_multiple_calls_counted(self):
        inv = ToolInventory(deprecated=set())
        for _ in range(5):
            inv.record_call("list_users", "1.2.3.4")
        assert inv.stats["call_counts"]["list_users"] == 5

    def test_deprecated_tool_returns_header(self):
        inv = ToolInventory(deprecated={"old_endpoint"})
        assert inv.deprecation_header("old_endpoint") == "true"

    def test_non_deprecated_returns_none(self):
        inv = ToolInventory(deprecated={"old_endpoint"})
        assert inv.deprecation_header("get_weather") is None

    def test_last_called_timestamp(self):
        inv = ToolInventory(deprecated=set())
        before = time.time()
        inv.record_call("ping", "9.9.9.9")
        after = time.time()
        ts = inv.stats["last_called"]["ping"]
        assert before <= ts <= after


# ── API10 — Response Sanitizer ────────────────────────────────────────────────
class TestResponseSanitizer:
    def test_small_response_passes(self):
        rs = ResponseSanitizer(max_bytes=1024)
        rs.validate_size(b"hello", "get_weather")

    def test_oversized_response_raises_502(self):
        rs = ResponseSanitizer(max_bytes=10)
        with pytest.raises(HTTPException) as exc:
            rs.validate_size(b"x" * 11, "big_tool")
        assert exc.value.status_code == 502

    def test_string_content_size_checked(self):
        rs = ResponseSanitizer(max_bytes=5)
        with pytest.raises(HTTPException):
            rs.validate_size("hello world", "tool")

    def test_dangerous_headers_stripped(self):
        rs = ResponseSanitizer(max_bytes=1024)
        headers = {
            "content-type": "application/json",
            "x-powered-by": "Express",
            "server":        "nginx/1.18",
            "set-cookie":    "session=abc",
            "x-custom":      "keep-me",
        }
        clean = rs.strip_dangerous_headers(headers)
        assert "x-powered-by" not in clean
        assert "server"        not in clean
        assert "set-cookie"    not in clean
        assert "content-type"  in clean
        assert "x-custom"      in clean


# ── Full bundle integration ────────────────────────────────────────────────────
class TestSecurityBundle:
    def test_bundle_creates_all_components(self):
        bundle = SecurityBundle(SecurityConfig(api_keys={"sk-test"}))
        assert all([
            bundle.authenticator, bundle.rate_limiter, bundle.list_limiter,
            bundle.ssrf_guard, bundle.arg_validator, bundle.inventory,
            bundle.response_checker,
        ])

    def test_full_secure_call_flow(self):
        config = SecurityConfig(api_keys={"sk-test": ["user"]}, tool_roles={})
        bundle = SecurityBundle(config)
        roles = bundle.authenticator.authenticate(make_request({"X-API-Key": "sk-test"}))
        assert roles == ["user"]
        bundle.rate_limiter.check("1.1.1.1")
        clean = bundle.arg_validator.validate(
            {"city": "Bangalore", "injected": "x"}, {"city"}
        )
        assert "injected" not in clean
        bundle.inventory.record_call("get_weather", "1.1.1.1")
        assert bundle.inventory.stats["call_counts"]["get_weather"] == 1
        bundle.response_checker.validate_size(b'{"city":"Bangalore"}', "get_weather")


class TestVersionPolicy:
    def test_compatible_major_version(self):
        policy = VersionPolicy("1.2", min_supported_client_version="1.0")
        assert policy.assess("1.0") == "compatible"

    def test_incompatible_major_without_enforcement(self):
        policy = VersionPolicy("2.0", enforce_client_version=False)
        assert policy.assess("1.4") == "incompatible"

    def test_incompatible_major_with_enforcement_raises(self):
        policy = VersionPolicy("2.0", enforce_client_version=True)
        with pytest.raises(HTTPException) as exc:
            policy.assess("1.4")
        assert exc.value.status_code == 409


def test_apply_security_enforces_base_url_allowlist():
    app = FastAPI()

    @app.get("/ping")
    async def ping() -> dict[str, str]:
        return {"ok": "true"}

    mcp = MCPRouter(app, base_url="http://evil.example")
    with pytest.raises(ValueError, match="allowed_base_urls"):
        apply_security(
            app,
            mcp,
            SecurityConfig(
                api_keys=None,
                allowed_base_urls={"http://testserver"},
                block_private_ips=False,
            ),
        )


def test_apply_security_strict_production_requires_auth():
    app = FastAPI()

    @app.get("/ping")
    async def ping() -> dict[str, str]:
        return {"ok": "true"}

    mcp = MCPRouter(app, base_url="http://testserver")
    with pytest.raises(ValueError, match="strict_production_mode requires authentication"):
        apply_security(
            app,
            mcp,
            SecurityConfig(
                api_keys=None,
                bearer_tokens=set(),
                strict_production_mode=True,
                allowed_base_urls={"http://testserver"},
                block_private_ips=False,
            ),
        )
