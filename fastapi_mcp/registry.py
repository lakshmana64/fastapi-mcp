"""
In-memory registry that holds all MCP tools discovered from a FastAPI app.

Intentionally simple — a thin dict wrapper — so it is easy to swap out
for a persistent store (Redis, SQL, …) in production if needed.
"""

from __future__ import annotations

from .schemas import Tool


class ToolRegistry:
    """Thread-safe (GIL-protected) in-memory store for Tool objects."""

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    # ── Write ──────────────────────────────────────────────────────────────

    def register(self, tool: Tool) -> None:
        """Add or overwrite a tool. Later registrations win on name collision."""
        self._tools[tool.name] = tool

    def clear(self) -> None:
        """Remove all registered tools (useful for testing)."""
        self._tools.clear()

    # ── Read ───────────────────────────────────────────────────────────────

    def get(self, name: str) -> Tool | None:
        """Return a tool by name, or ``None`` if not found."""
        return self._tools.get(name)

    def list_tools(self, tag: str | None = None) -> list[Tool]:
        """
        Return all tools, optionally filtered by OpenAPI tag.
        Results are sorted by name for stable output.
        """
        tools = self._tools.values()
        if tag:
            tools = (t for t in tools if tag in t.tags)  # type: ignore[assignment]
        return sorted(tools, key=lambda t: t.name)

    def __len__(self) -> int:
        return len(self._tools)

    def __contains__(self, name: str) -> bool:
        return name in self._tools
