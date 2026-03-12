# fastapi-mcp

> **One import. One line. Every FastAPI endpoint becomes an MCP tool.**

`fastapi-mcp` automatically reads your FastAPI app's OpenAPI schema and exposes every endpoint as a [Model Context Protocol (MCP)](https://modelcontextprotocol.io) tool, so AI agents — Claude, Cursor, ChatGPT — can discover and call your API without any manual wiring.

```bash
uv add fastapi-mcp
```

---

## The problem it solves

You have a FastAPI app. You want AI agents to use it. Without fastapi-mcp you need to:

- Manually write tool definitions for every endpoint
- Keep them in sync as your API evolves
- Handle parameter routing (path vs query vs body) yourself
- Write boilerplate proxy logic for every AI platform

With fastapi-mcp you do **none of that**. Add two lines and you're done.

---

## What this tool does (in plain English)

`fastapi-mcp` turns your FastAPI endpoints into MCP tools that AI agents can discover and call over HTTP.

- `GET /mcp/tools` gives agents a machine-readable tool catalog
- `POST /mcp/call` lets agents call a tool by name with arguments
- It maps arguments correctly to path params, query params, or JSON body
- It returns the upstream endpoint result in a consistent response envelope
- Optional security controls add authentication, authorization, rate limits, and SSRF protections

If your FastAPI app already has OpenAPI docs, this package reuses that metadata so you do not maintain a separate tool schema manually.

---

## Quick start

```python
from fastapi import FastAPI
from fastapi_mcp import MCPRouter

app = FastAPI()

@app.get("/weather")
async def get_weather(city: str) -> dict:
    return {"city": city, "temp_c": 22, "condition": "Sunny"}

# ↓ This is the only new code you need
mcp = MCPRouter(app)
app.include_router(mcp)
```

```bash
uvicorn main:app --reload
```

```bash
# See all tools
curl http://localhost:8000/mcp/tools

# Call a tool
curl -X POST http://localhost:8000/mcp/call \
     -H "Content-Type: application/json" \
     -d '{"tool": "get_weather", "arguments": {"city": "Bangalore"}}'
```

```json
{
  "tool": "get_weather",
  "result": {"city": "Bangalore", "temp_c": 22, "condition": "Sunny"},
  "error": null,
  "status_code": 200
}
```

---

## How it works

```
Your FastAPI app               fastapi-mcp                   AI agent
──────────────────             ───────────────               ──────────────
GET  /weather          ──►     parse app.openapi()
POST /users            ──►     register as Tools      ──►   GET /mcp/tools
GET  /users/{id}       ──►                            ◄──   [{name, params, …}]

                               POST /mcp/call          ◄──  {tool, arguments}
                               proxy via httpx
GET  /weather?city=X   ◄──                             ──►  {result}
      ↑ real endpoint
```

1. `MCPRouter(app)` calls `app.openapi()` once at startup and walks every path
2. Each endpoint becomes a `Tool` with a clean name, description, and parameter schema
3. `GET /mcp/tools` returns the full catalogue — agents use this to introspect
4. `POST /mcp/call` looks up the tool, builds the right HTTP request (path params,
   query params, or JSON body), proxies it via **httpx**, and returns the result

---

## Architecture

Core runtime components:

| Component | File | Responsibility |
|-----------|------|----------------|
| `MCPRouter` | `fastapi_mcp/router.py` | Exposes `/mcp/tools` and `/mcp/call`, orchestrates registry + executor |
| `OpenAPI parser` | `fastapi_mcp/parser.py` | Converts `app.openapi()` into MCP `Tool` models |
| `ToolRegistry` | `fastapi_mcp/registry.py` | In-memory index of discovered tools |
| `ToolExecutor` | `fastapi_mcp/executor.py` | Proxies tool calls to real FastAPI endpoints via `httpx` |
| `Schemas` | `fastapi_mcp/schemas.py` | Shared request/response/domain models |
| `Security layer` (optional) | `fastapi_mcp/security.py` | Auth, RBAC, distributed rate limits, request checks, SSRF controls, observability, compatibility policy |

Request flow (`POST /mcp/call`):

1. Agent sends `{tool, arguments}` to MCP endpoint.
2. Router resolves tool metadata from `ToolRegistry`.
3. Optional security pipeline validates auth/authorization and input limits.
4. Executor maps arguments to path/query/body and calls upstream endpoint.
5. Upstream response is normalized into `ToolCallResponse`.

Security placement:

- **Before execution**: authentication, role checks, rate limits, argument checks.
- **During setup**: base URL allowlist and host-level SSRF validation.
- **After execution**: response size checks and response security headers.

---

## API reference

### `GET /mcp/tools`

Returns all registered MCP tools.

| Query param | Type   | Description                        |
|-------------|--------|------------------------------------|
| `tag`       | string | Filter by OpenAPI tag (optional)   |

**Response**

```json
[
  {
    "name": "get_weather",
    "description": "Return current weather conditions for the requested city.",
    "method": "GET",
    "path": "/weather",
    "risk_level": "read",
    "parameters": [
      {
        "name": "city",
        "type": "string",
        "description": "city",
        "required": true,
        "location": "query"
      }
    ],
    "tags": ["weather"]
  }
]
```

---

### `POST /mcp/call`

Invoke a tool by name.

**Request**

```json
{
  "tool": "get_weather",
  "arguments": { "city": "Tokyo" },
  "client_version": "1.2"
}
```

**Response**

```json
{
  "tool": "get_weather",
  "result": { "city": "Tokyo", "temp_c": 18, "condition": "Rainy" },
  "error": null,
  "status_code": 200
}
```

**Structured error response**

```json
{
  "tool": "missing_tool",
  "result": null,
  "error": "Tool 'missing_tool' not found. Call GET /mcp/tools to see available tools.",
  "error_code": "TOOL_NOT_FOUND",
  "retryable": false,
  "status_code": 404
}
```

When security is enabled, responses also include:

- `X-MCP-API-Version`: server compatibility version (for example `1.2`)
- `X-MCP-Compatibility`: `compatible`, `incompatible`, `unknown`, or `n/a`

Common `error_code` values for agents:

- `TOOL_NOT_FOUND`
- `INVALID_REQUEST`
- `AUTH_REQUIRED`
- `ACCESS_DENIED`
- `RATE_LIMITED`
- `UPSTREAM_TIMEOUT`
- `UPSTREAM_UNREACHABLE`
- `UPSTREAM_HTTP_ERROR`
- `CLIENT_VERSION_INCOMPATIBLE`

---

## Configuration

`MCPRouter` accepts several options:

```python
mcp = MCPRouter(
    app,

    # Where your FastAPI app is running (used to proxy calls)
    base_url="http://localhost:8000",

    # URL prefix for MCP endpoints
    prefix="/mcp",

    # Only expose endpoints with these OpenAPI tags
    include_tags=["public", "v2"],

    # Hide endpoints with these tags
    exclude_tags=["internal", "admin"],

    # Hide entire path prefixes
    exclude_paths=["/health", "/metrics", "/internal"],

    # Upstream call timeout in seconds
    timeout=15.0,

    # Headers forwarded on every upstream request (e.g. auth)
    extra_headers={"X-Internal-Token": "secret"},
)
app.include_router(mcp)
```

### Security setup (recommended for production)

For real deployments, attach the security layer:

```python
from fastapi_mcp import MCPRouter
from fastapi_mcp.security import RedisRateLimitStore, SecurityConfig, apply_security

mcp = MCPRouter(app, base_url="https://api.example.com")
apply_security(
    app,
    mcp,
    SecurityConfig(
        # API auth (set or key->roles dict)
        api_keys={"sk-live-123": ["admin"]},

        # Per-IP limits
        rate_limit_calls_per_minute=60,
        rate_limit_list_per_minute=120,
        rate_limit_store=RedisRateLimitStore("redis://localhost:6379/0"),
        per_identity_calls_per_minute=300,
        per_tool_calls_per_minute={"delete_user": 20},
        trusted_proxy_cidrs={"10.0.0.0/8"},
        use_x_forwarded_for=True,
        rate_limit_store_failure_mode="fail_closed",

        # SSRF allowlist for upstream base_url values
        allowed_base_urls={"https://api.example.com"},
        ssrf_revalidate_interval_seconds=300,

        # Compatibility policy
        api_version="1.2",
        min_supported_client_version="1.0",
        enforce_client_version=False,
        strict_production_mode=True,
    ),
)
app.include_router(mcp)
```

Notes:
- `RedisRateLimitStore` requires the Redis extra (`uv add "fastapi-mcp[redis]"`).
- If `allowed_base_urls` is set, `base_url` must be in that set.
- Set `trusted_proxy_cidrs` before trusting `X-Forwarded-For` headers.
- Keep `base_url` explicit and predictable in production.
- For multi-instance rate limiting, use a shared store (`RedisRateLimitStore`).
- Set `rate_limit_store_failure_mode` explicitly (`fail_closed` recommended for production).
- Use `per_identity_calls_per_minute` and `per_tool_calls_per_minute` for high-risk operations.
- Use `ssrf_revalidate_interval_seconds` to re-check DNS at runtime.
- Set `strict_production_mode=True` to reject auth-disabled security configs.
- `POST /mcp/call` can include `client_version` for compatibility checks.

### Observability hook

You can stream structured MCP events to your telemetry pipeline:

```python
def emit_event(event: dict) -> None:
    # forward to Datadog / OpenTelemetry / custom logger
    print(event)

apply_security(
    app,
    mcp,
    SecurityConfig(
        api_keys={"sk-live"},
        observability_sink=emit_event,
    ),
)
```

---

## Compatibility Policy

Backward-compatibility guarantees and deprecation windows are documented in
[`docs/backward-compatibility.md`](docs/backward-compatibility.md).

---

## Example app

A full working example lives in [`example/main.py`](example/main.py).
A production-oriented secure example lives in [`example/secure_main.py`](example/secure_main.py).

```bash
# From the repo root
uv sync --extra server
uvicorn example.main:app --reload
```

Endpoints exposed as tools:

| Endpoint                  | Tool name     | Parameters              |
|---------------------------|---------------|-------------------------|
| `GET /users`              | `list_users`  | —                       |
| `GET /users/{user_id}`    | `get_user`    | `user_id` (int, path)   |
| `POST /users`             | `create_user` | `name`, `email`, `role` |
| `GET /weather`            | `get_weather` | `city` (string)         |
| `GET /products`           | `list_products` | `category` (optional) |

---

## Tool calls — more examples

```bash
# List all users
curl -X POST http://localhost:8000/mcp/call \
  -H "Content-Type: application/json" \
  -d '{"tool": "list_users", "arguments": {}}'

# Get user by ID
curl -X POST http://localhost:8000/mcp/call \
  -H "Content-Type: application/json" \
  -d '{"tool": "get_user", "arguments": {"user_id": 2}}'

# Create a user
curl -X POST http://localhost:8000/mcp/call \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "create_user",
    "arguments": {"name": "Dana", "email": "dana@example.com"}
  }'

# Filter products
curl -X POST http://localhost:8000/mcp/call \
  -H "Content-Type: application/json" \
  -d '{"tool": "list_products", "arguments": {"category": "electronics"}}'
```

---

## Project layout

```
fastapi-mcp/
├── fastapi_mcp/
│   ├── __init__.py      Public API surface
│   ├── router.py        MCPRouter — the main class users import
│   ├── parser.py        OpenAPI schema → Tool objects
│   ├── executor.py      Async HTTP proxy via httpx
│   ├── registry.py      In-memory tool store
│   ├── schemas.py       Pydantic models (Tool, ToolCallRequest, …)
│   └── security.py      Optional OWASP security + observability controls
├── example/
│   ├── main.py          Working demo app
│   └── secure_main.py   Production-oriented secure example
├── tests/
│   ├── test_parser.py   Unit tests for name sanitisation + parsing
│   ├── test_router.py   Integration tests (TestClient + respx mocks)
│   ├── test_security.py Unit tests for security controls
│   └── test_agent_eval.py  Agent behavior eval scaffold tests
├── docs/
│   ├── backward-compatibility.md  Version policy and deprecation windows
│   └── roadmap.md  Public roadmap and priorities
├── .github/
│   ├── workflows/ci.yml  Lint/type/tests + dedicated agent eval gate
│   ├── ISSUE_TEMPLATE/  Bug and feature templates
│   └── pull_request_template.md
├── pyproject.toml
├── CHANGELOG.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── SECURITY.md
├── SUPPORT.md
└── LICENSE
```

---

## Connecting AI agents

### Claude (MCP HTTP transport)

Point the MCP client at `http://localhost:8000/mcp`.

### Cursor

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "my-api": {
      "url": "http://localhost:8000/mcp/call",
      "tools": "http://localhost:8000/mcp/tools"
    }
  }
}
```

### Any LLM / custom agent

```python
import httpx

# 1. Discover tools
tools = httpx.get("http://localhost:8000/mcp/tools").json()

# 2. Call a tool
result = httpx.post(
    "http://localhost:8000/mcp/call",
    json={
        "tool": "get_weather",
        "arguments": {"city": "London"},
        "client_version": "1.2",
    },
).json()
```

---

## Development

```bash
git clone https://github.com/YOUR_USERNAME/fastapi-mcp
cd fastapi-mcp
uv sync --extra dev

uv run pytest          # run tests
uv run ruff check .    # lint
uv run ruff format .   # format
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines.

## Community and Trust

- Code of conduct: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)
- Security policy: [`SECURITY.md`](SECURITY.md)
- Support guide: [`SUPPORT.md`](SUPPORT.md)
- Public roadmap: [`docs/roadmap.md`](docs/roadmap.md)
- Compatibility policy: [`docs/backward-compatibility.md`](docs/backward-compatibility.md)

---

## License

[MIT](LICENSE)
