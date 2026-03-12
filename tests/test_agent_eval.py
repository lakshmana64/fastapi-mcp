"""
Scaffolded AI-agent behavior evals.

These tests are intentionally scenario-driven so maintainers can extend
coverage for tool selection, argument construction, and error recovery.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx
import pytest
import respx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_mcp import MCPRouter


@dataclass
class AgentEvalCase:
    name: str
    payload: dict
    expected_status: int
    expected_error_code: str | None


def build_eval_client() -> TestClient:
    app = FastAPI()

    @app.get("/weather", tags=["demo"])
    async def get_weather(city: str) -> dict:
        return {"city": city, "temp_c": 22}

    mcp = MCPRouter(app, base_url="http://testserver")
    app.include_router(mcp)
    return TestClient(app)


@respx.mock
@pytest.mark.parametrize(
    "case",
    [
        AgentEvalCase(
            name="successful_tool_call",
            payload={"tool": "get_weather", "arguments": {"city": "Bangalore"}},
            expected_status=200,
            expected_error_code=None,
        ),
        AgentEvalCase(
            name="unknown_tool_fails_with_structured_code",
            payload={"tool": "missing_tool", "arguments": {}},
            expected_status=404,
            expected_error_code="TOOL_NOT_FOUND",
        ),
    ],
)
def test_agent_eval_cases(case: AgentEvalCase) -> None:
    """
    Baseline eval matrix for AI-call behavior.

    Add new cases here for:
    - retry logic (`UPSTREAM_TIMEOUT`, `UPSTREAM_UNREACHABLE`)
    - permission failures (`ACCESS_DENIED`)
    - malformed payload handling (`INVALID_REQUEST`)
    """
    respx.get("http://testserver/weather").mock(
        return_value=httpx.Response(200, json={"city": "Bangalore", "temp_c": 22})
    )
    with build_eval_client() as client:
        response = client.post("/mcp/call", json=case.payload)
    assert response.status_code == case.expected_status
    body = response.json()
    assert body["error_code"] == case.expected_error_code

