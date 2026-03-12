"""
Data models shared across the fastapi-mcp package.

These are the canonical types that flow between the parser,
registry, executor, and HTTP layer.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class ToolParameter(BaseModel):
    """One parameter accepted by an MCP tool."""

    name: str = Field(..., description="Parameter name as it appears in the API")
    type: str = Field(..., description="JSON Schema primitive type")
    description: str = Field("", description="Human-readable hint for the AI agent")
    required: bool = Field(False, description="Whether the caller must supply this value")
    location: str = Field("query", description="'path', 'query', 'header', or 'body'")


class Tool(BaseModel):
    """One MCP tool derived from a single FastAPI endpoint."""

    name: str = Field(..., description="Stable, snake_case identifier used by agents")
    description: str = Field(..., description="What this tool does")
    method: str = Field(..., description="HTTP verb: GET, POST, PUT, PATCH, DELETE")
    path: str = Field(..., description="URL path template, e.g. /users/{user_id}")
    parameters: list[ToolParameter] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list, description="OpenAPI tags for grouping")
    risk_level: Literal["read", "write", "destructive"] = Field(
        "read",
        description="Execution risk classification for AI planning/safety checks.",
    )


class ToolCallRequest(BaseModel):
    """Payload an AI agent sends to invoke a tool."""

    tool: str = Field(..., description="Tool name from GET /mcp/tools")
    arguments: dict[str, Any] = Field(default_factory=dict, description="Tool arguments")
    client_version: str | None = Field(
        None,
        description="Optional MCP client version for compatibility checks.",
    )


class ToolCallResponse(BaseModel):
    """Response envelope returned after a tool call."""

    tool: str
    result: Any = None
    error: str | None = None
    error_code: str | None = Field(
        None,
        description="Stable machine-readable error code for agent logic.",
    )
    retryable: bool = Field(
        False,
        description="Whether an automated retry may succeed.",
    )
    status_code: int = Field(200, description="HTTP status from the upstream endpoint")
