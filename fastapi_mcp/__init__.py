"""
fastapi-mcp
===========
Automatically expose every FastAPI endpoint as an MCP tool.
Includes OWASP Top 10 security controls out of the box.
"""

from .parser import parse_openapi
from .registry import ToolRegistry
from .router import MCPRouter
from .schemas import Tool, ToolCallRequest, ToolCallResponse, ToolParameter
from .security import (
    InMemoryRateLimitStore,
    RedisRateLimitStore,
    SecurityBundle,
    SecurityConfig,
    apply_security,
)

__all__ = [
    "MCPRouter",
    "SecurityConfig",
    "SecurityBundle",
    "InMemoryRateLimitStore",
    "RedisRateLimitStore",
    "apply_security",
    "Tool",
    "ToolCallRequest",
    "ToolCallResponse",
    "ToolParameter",
    "ToolRegistry",
    "parse_openapi",
]

__version__ = "0.1.0"
__author__  = "fastapi-mcp contributors"
__license__ = "MIT"
