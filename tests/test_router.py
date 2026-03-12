"""
Integration tests for GET /mcp/tools and POST /mcp/call.

Uses FastAPI's built-in TestClient (runs synchronously on top of ASGI)
so no real server process is needed.
"""

from __future__ import annotations

import httpx
import pytest
import respx
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel

from fastapi_mcp import MCPRouter
from fastapi_mcp.security import SecurityConfig, apply_security

# ── Fixture: tiny FastAPI app ──────────────────────────────────────────────────


class CreateUserBody(BaseModel):
    name: str
    email: str


def build_app() -> FastAPI:
    app = FastAPI()

    @app.get("/greet", tags=["demo"])
    async def greet(name: str = "world") -> dict:
        return {"message": f"Hello, {name}!"}

    @app.get("/items/{item_id}", tags=["demo"])
    async def get_item(item_id: int) -> dict:
        return {"id": item_id, "name": "Widget"}

    mcp = MCPRouter(app, base_url="http://testserver")
    app.include_router(mcp)
    return app


def build_secure_app() -> FastAPI:
    app = FastAPI()

    @app.post("/users", tags=["demo"])
    async def create_user(body: CreateUserBody) -> dict:
        return body.model_dump()

    mcp = MCPRouter(app, base_url="http://testserver")
    apply_security(
        app,
        mcp,
        SecurityConfig(
            api_keys=None,
            add_security_headers=True,
            allowed_base_urls={"http://testserver"},
            api_version="1.2",
        ),
    )
    app.include_router(mcp)
    return app


def build_enforced_version_app() -> FastAPI:
    app = FastAPI()

    @app.get("/ping", tags=["demo"])
    async def ping() -> dict[str, str]:
        return {"ok": "true"}

    mcp = MCPRouter(app, base_url="http://testserver")
    apply_security(
        app,
        mcp,
        SecurityConfig(
            api_keys=None,
            add_security_headers=False,
            allowed_base_urls={"http://testserver"},
            enforce_client_version=True,
            api_version="2.0",
        ),
    )
    app.include_router(mcp)
    return app


def build_identity_quota_app() -> FastAPI:
    app = FastAPI()

    @app.get("/ping", tags=["demo"])
    async def ping() -> dict[str, str]:
        return {"ok": "ping"}

    @app.get("/pong", tags=["demo"])
    async def pong() -> dict[str, str]:
        return {"ok": "pong"}

    mcp = MCPRouter(app, base_url="http://testserver")
    apply_security(
        app,
        mcp,
        SecurityConfig(
            api_keys=None,
            add_security_headers=False,
            allowed_base_urls={"http://testserver"},
            block_private_ips=False,
            per_identity_calls_per_minute=1,
        ),
    )
    app.include_router(mcp)
    return app


def build_tool_quota_app() -> FastAPI:
    app = FastAPI()

    @app.get("/ping", tags=["demo"])
    async def ping() -> dict[str, str]:
        return {"ok": "ping"}

    @app.get("/pong", tags=["demo"])
    async def pong() -> dict[str, str]:
        return {"ok": "pong"}

    mcp = MCPRouter(app, base_url="http://testserver")
    apply_security(
        app,
        mcp,
        SecurityConfig(
            api_keys=None,
            add_security_headers=False,
            allowed_base_urls={"http://testserver"},
            block_private_ips=False,
            per_tool_calls_per_minute={"ping": 1},
        ),
    )
    app.include_router(mcp)
    return app


@pytest.fixture(scope="module")
def client():
    app = build_app()
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def secure_client():
    app = build_secure_app()
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def enforced_version_client():
    app = build_enforced_version_app()
    with TestClient(app) as c:
        yield c


@pytest.fixture
def identity_quota_client():
    app = build_identity_quota_app()
    with TestClient(app) as c:
        yield c


@pytest.fixture
def tool_quota_client():
    app = build_tool_quota_app()
    with TestClient(app) as c:
        yield c


# ── GET /mcp/tools ─────────────────────────────────────────────────────────────

def test_list_tools_returns_200(client):
    r = client.get("/mcp/tools")
    assert r.status_code == 200


def test_list_tools_contains_greet(client):
    tools = {t["name"]: t for t in client.get("/mcp/tools").json()}
    assert "greet" in tools


def test_list_tools_contains_get_item(client):
    tools = {t["name"]: t for t in client.get("/mcp/tools").json()}
    assert "get_item" in tools


def test_list_tools_does_not_expose_mcp_itself(client):
    names = [t["name"] for t in client.get("/mcp/tools").json()]
    assert not any("mcp" in n for n in names)


def test_list_tools_tag_filter(client):
    r = client.get("/mcp/tools?tag=demo")
    assert r.status_code == 200
    names = [t["name"] for t in r.json()]
    assert "greet" in names


def test_tool_schema_has_parameters(client):
    tools = {t["name"]: t for t in client.get("/mcp/tools").json()}
    greet = tools["greet"]
    assert len(greet["parameters"]) == 1
    p = greet["parameters"][0]
    assert p["name"] == "name"
    assert p["type"] == "string"
    assert greet["risk_level"] == "read"


def test_ref_body_schema_parameters_exposed(secure_client):
    tools = {t["name"]: t for t in secure_client.get("/mcp/tools").json()}
    create_user = tools["create_user"]
    names = {p["name"] for p in create_user["parameters"]}
    assert names == {"name", "email"}
    assert secure_client.get("/mcp/tools").headers["X-MCP-API-Version"] == "1.2"


# ── POST /mcp/call ─────────────────────────────────────────────────────────────

def test_call_unknown_tool_returns_404(client):
    r = client.post("/mcp/call", json={"tool": "does_not_exist", "arguments": {}})
    assert r.status_code == 404
    body = r.json()
    assert body["error_code"] == "TOOL_NOT_FOUND"
    assert body["retryable"] is False


@respx.mock
def test_call_greet_proxies_correctly(client):
    """
    Mock the upstream HTTP call and verify the executor builds the right request.
    """
    respx.get("http://testserver/greet").mock(
        return_value=httpx.Response(200, json={"message": "Hello, Alice!"})
    )
    r = client.post(
        "/mcp/call",
        json={"tool": "greet", "arguments": {"name": "Alice"}},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["tool"]   == "greet"
    assert body["error"]  is None
    assert body["result"] == {"message": "Hello, Alice!"}


@respx.mock
def test_call_path_param_substituted(client):
    respx.get("http://testserver/items/42").mock(
        return_value=httpx.Response(200, json={"id": 42, "name": "Widget"})
    )
    r = client.post(
        "/mcp/call",
        json={"tool": "get_item", "arguments": {"item_id": 42}},
    )
    assert r.status_code == 200
    assert r.json()["result"]["id"] == 42


@respx.mock
def test_call_upstream_404_surfaces_correctly(client):
    respx.get("http://testserver/greet").mock(
        return_value=httpx.Response(404, json={"detail": "not found"})
    )
    r = client.post(
        "/mcp/call",
        json={"tool": "greet", "arguments": {}},
    )
    assert r.status_code == 404


@respx.mock
def test_secure_call_does_not_crash_headers_middleware(secure_client):
    respx.post("http://testserver/users").mock(
        return_value=httpx.Response(200, json={"name": "Alice", "email": "a@example.com"})
    )
    r = secure_client.post(
        "/mcp/call",
        json={"tool": "create_user", "arguments": {"name": "Alice", "email": "a@example.com"}},
    )
    assert r.status_code == 200
    assert r.json()["result"]["name"] == "Alice"
    assert r.headers["X-MCP-API-Version"] == "1.2"
    assert r.headers["X-MCP-Compatibility"] == "unknown"


def test_call_rejects_missing_client_version_when_enforced(enforced_version_client):
    r = enforced_version_client.post(
        "/mcp/call",
        json={"tool": "ping", "arguments": {}},
    )
    assert r.status_code == 400
    assert r.json()["error_code"] == "INVALID_REQUEST"


@respx.mock
def test_per_identity_quota_enforced(identity_quota_client):
    respx.get("http://testserver/ping").mock(return_value=httpx.Response(200, json={"ok": "ping"}))
    respx.get("http://testserver/pong").mock(return_value=httpx.Response(200, json={"ok": "pong"}))
    first = identity_quota_client.post("/mcp/call", json={"tool": "ping", "arguments": {}})
    assert first.status_code == 200
    second = identity_quota_client.post("/mcp/call", json={"tool": "pong", "arguments": {}})
    assert second.status_code == 429
    assert second.json()["error_code"] == "RATE_LIMITED"


@respx.mock
def test_per_tool_quota_enforced(tool_quota_client):
    respx.get("http://testserver/ping").mock(return_value=httpx.Response(200, json={"ok": "ping"}))
    respx.get("http://testserver/pong").mock(return_value=httpx.Response(200, json={"ok": "pong"}))
    first = tool_quota_client.post("/mcp/call", json={"tool": "ping", "arguments": {}})
    assert first.status_code == 200
    second = tool_quota_client.post("/mcp/call", json={"tool": "ping", "arguments": {}})
    assert second.status_code == 429
    assert second.json()["error_code"] == "RATE_LIMITED"
    third = tool_quota_client.post("/mcp/call", json={"tool": "pong", "arguments": {}})
    assert third.status_code == 200
