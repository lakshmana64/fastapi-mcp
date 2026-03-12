"""
Production-oriented example for fastapi-mcp.

Run:
    uv sync --extra server --extra redis
    uvicorn example.secure_main:app --reload
"""

from __future__ import annotations

from fastapi import FastAPI

from fastapi_mcp import MCPRouter
from fastapi_mcp.security import RedisRateLimitStore, SecurityConfig, apply_security

app = FastAPI(title="fastapi-mcp secure example")


@app.get("/healthz", tags=["ops"])
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/weather", tags=["public"])
async def weather(city: str) -> dict[str, str | int]:
    return {"city": city, "temp_c": 24}


mcp = MCPRouter(
    app,
    base_url="http://localhost:8000",
    include_tags=["public"],
    exclude_paths=["/healthz"],
)

apply_security(
    app,
    mcp,
    SecurityConfig(
        api_keys={"sk-example-admin": ["admin"]},
        strict_production_mode=True,
        rate_limit_store=RedisRateLimitStore("redis://localhost:6379/0"),
        rate_limit_store_failure_mode="fail_closed",
        rate_limit_calls_per_minute=60,
        per_identity_calls_per_minute=300,
        per_tool_calls_per_minute={"weather": 120},
        trusted_proxy_cidrs={"10.0.0.0/8"},
        use_x_forwarded_for=True,
        allowed_base_urls={"http://localhost:8000"},
        ssrf_revalidate_interval_seconds=300,
        api_version="1.2",
    ),
)

app.include_router(mcp)
