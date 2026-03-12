# Changelog

All notable changes to **fastapi-mcp** are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added
- Optional distributed rate-limit backend contract (`RateLimitStore`)
- `InMemoryRateLimitStore` and `RedisRateLimitStore` implementations
- Compatibility policy with `api_version`, `min_supported_client_version`, and enforcement option
- `client_version` field in tool call request schema
- Structured observability sink hook (`observability_sink`) for telemetry integration
- Structured error fields in tool responses (`error_code`, `retryable`)
- Risk metadata per tool (`risk_level`) for agent-side safety planning
- Scenario-driven AI eval scaffold tests (`tests/test_agent_eval.py`)
- Optional dependency group for Redis integrations (`uv add "fastapi-mcp[redis]"`)
- Backward compatibility policy document (`docs/backward-compatibility.md`)
- CI workflow with a separate `agent-evals` quality gate
- Response headers for compatibility metadata:
  - `X-MCP-API-Version`
  - `X-MCP-Compatibility`
- Rate-limit backend failure strategy configuration (`fail_open` / `fail_closed`)
- Strict production mode guard (`strict_production_mode`) to require authentication config
- Community health files: `CODE_OF_CONDUCT.md`, `SECURITY.md`, `SUPPORT.md`
- GitHub issue templates and pull request template
- Public roadmap document (`docs/roadmap.md`)
- Production-oriented example app (`example/secure_main.py`)

### Changed
- Rate limiting now supports shared backend stores for multi-instance deployments
- Added optional per-identity and per-tool quotas for finer-grained flow protection
- Added trusted proxy CIDR handling for safer client IP extraction behind load balancers
- `/mcp/call` and `/mcp/tools` now emit observability events when security is enabled
- Request-body parser now resolves component `$ref` schemas for FastAPI/Pydantic models
- Security middleware header handling fixed for Starlette `MutableHeaders`
- Security setup now validates base URL allowlists and resolved hosts during initialization
- Runtime SSRF host revalidation added to reduce DNS rebinding/drift risk
- Runtime SSRF revalidation interval now explicitly test-covered (`0` revalidates every request)

### Fixed
- Crash in `SecurityHeadersMiddleware` caused by `MutableHeaders.pop(...)`
- Missing body-parameter extraction for `$ref` request schemas

## [0.1.0] — 2025-01-01

### Added
- `MCPRouter` class — one-liner to expose all FastAPI routes as MCP tools
- `GET /mcp/tools` — lists discovered tools with full parameter schemas
- `POST /mcp/call` — proxies tool calls to the underlying FastAPI endpoints
- Tag-based `include_tags` / `exclude_tags` filtering
- Path prefix exclusion via `exclude_paths`
- Async HTTP executor with connection pooling (`httpx.AsyncClient`)
- Proper path-parameter substitution in URL templates
- Request body flattening for POST / PUT / PATCH endpoints
- Clean tool-name derivation from FastAPI auto-generated operationIds
- Graceful shutdown — HTTP client is closed on app lifespan end
- Full unit + integration test suite (`pytest` + `respx`)
