"""
Converts a FastAPI OpenAPI schema into MCP Tool objects.

FastAPI auto-generates operationIds like:
    get_weather_weather_get       (fn=get_weather, path=/weather,          method=GET)
    get_user_users__user_id__get  (fn=get_user,    path=/users/{user_id},  method=GET)

We strip the path slug and method suffix to recover the original function name,
which becomes the stable, human-readable tool name agents see.
"""

from __future__ import annotations

import re
from typing import Any, Literal, cast

from .registry import ToolRegistry
from .schemas import Tool, ToolParameter

# ── Type helpers ───────────────────────────────────────────────────────────────

_OPENAPI_TO_JSON: dict[str, str] = {
    "string":  "string",
    "integer": "integer",
    "number":  "number",
    "boolean": "boolean",
    "array":   "array",
    "object":  "object",
}

_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
_DESTRUCTIVE_HINTS = (
    "delete",
    "destroy",
    "remove",
    "purge",
    "reset",
    "truncate",
    "drop",
)


def _json_type(schema: dict[str, Any]) -> str:
    return _OPENAPI_TO_JSON.get(schema.get("type", "string"), "string")


def _risk_level(
    method: str,
    path: str,
    operation_id: str,
    spec: dict[str, Any],
) -> Literal["read", "write", "destructive"]:
    explicit = spec.get("x-mcp-risk-level")
    if isinstance(explicit, str) and explicit in {"read", "write", "destructive"}:
        return cast(Literal["read", "write", "destructive"], explicit)

    upper = method.upper()
    joined = f"{path} {operation_id}".lower()
    if upper == "DELETE" or any(hint in joined for hint in _DESTRUCTIVE_HINTS):
        return "destructive"
    if upper in {"POST", "PUT", "PATCH"}:
        return "write"
    return "read"


def _resolve_schema_ref(
    schema: dict[str, Any],
    openapi_schema: dict[str, Any],
) -> dict[str, Any]:
    """Resolve local OpenAPI component refs like '#/components/schemas/Foo'."""
    ref = schema.get("$ref")
    if not isinstance(ref, str):
        return schema

    prefix = "#/components/schemas/"
    if not ref.startswith(prefix):
        return {}

    schema_name = ref[len(prefix):]
    resolved = (
        openapi_schema
        .get("components", {})
        .get("schemas", {})
        .get(schema_name, {})
    )
    if isinstance(resolved, dict):
        return resolved
    return {}


# ── Name sanitisation ──────────────────────────────────────────────────────────

def _tool_name(operation_id: str, path: str) -> str:
    """
    Recover the Python function name from a FastAPI-generated operationId.

    FastAPI builds:  {fn_name}_{path_slug}_{http_method}

    Path slug rules (FastAPI source):
      • leading  /  →  dropped
      • inner    /  →  _
      • { and }      →  _  each (so {user_id} becomes _user_id_)

    Example:
        operation_id = "get_user_users__user_id__get"
        path         = "/users/{user_id}"
        path_slug    = "users__user_id_"   ← note trailing _ from closing }
        strip method → "get_user_users__user_id_"
        strip slug   → "get_user"
    """
    # Step 1 – remove trailing _<method>
    name = re.sub(
        r"_(get|post|put|patch|delete|head|options)$",
        "",
        operation_id,
        flags=re.IGNORECASE,
    )

    # Step 2 – reproduce the path slug FastAPI appends
    #   /users/{user_id}  →  users__user_id_
    raw_slug = path.lstrip("/")                    # drop leading slash
    path_slug = re.sub(r"[/{}\-]", "_", raw_slug)  # special chars → _

    # Step 3 – strip the slug suffix (and its leading separator _)
    suffix = f"_{path_slug}"
    if name.endswith(suffix):
        name = name[: -len(suffix)]

    return name or operation_id  # guard: never return an empty string


# ── Parameter builders ─────────────────────────────────────────────────────────

def _query_path_params(spec: dict[str, Any]) -> list[ToolParameter]:
    """Parse 'parameters' array (query, path, header)."""
    params: list[ToolParameter] = []
    for p in spec.get("parameters", []):
        s = p.get("schema", {})
        params.append(ToolParameter(
            name        = p["name"],
            type        = _json_type(s),
            description = p.get("description", "") or p["name"],
            required    = p.get("required", False),
            location    = p.get("in", "query"),
        ))
    return params


def _body_params(
    spec: dict[str, Any],
    openapi_schema: dict[str, Any],
) -> list[ToolParameter]:
    """Flatten a JSON request body into individual ToolParameters."""
    body = spec.get("requestBody")
    if not body:
        return []

    json_schema = (
        body
        .get("content", {})
        .get("application/json", {})
        .get("schema", {})
    )

    if "$ref" in json_schema:
        json_schema = _resolve_schema_ref(json_schema, openapi_schema)
        if not json_schema:
            return []

    required_fields = set(json_schema.get("required", []))
    params: list[ToolParameter] = []

    for field, field_schema in json_schema.get("properties", {}).items():
        if not isinstance(field_schema, dict):
            field_schema = {}
        params.append(ToolParameter(
            name        = field,
            type        = _json_type(field_schema),
            description = field_schema.get("description", "") or field,
            required    = field in required_fields,
            location    = "body",
        ))

    return params


# ── Public API ─────────────────────────────────────────────────────────────────

def parse_openapi(
    openapi_schema: dict[str, Any],
    registry: ToolRegistry,
    *,
    include_tags: list[str] | None = None,
    exclude_tags: list[str] | None = None,
    exclude_paths: list[str] | None = None,
) -> int:
    """
    Walk every path/method in *openapi_schema* and register each one
    as a :class:`Tool` in *registry*.

    Parameters
    ----------
    openapi_schema:
        The dict returned by ``app.openapi()``.
    registry:
        Destination :class:`ToolRegistry`.
    include_tags:
        If set, only endpoints whose OpenAPI tags overlap with this list
        are registered.  ``None`` means *include everything*.
    exclude_tags:
        Endpoints whose tags overlap with this list are **skipped**.
        Applied after *include_tags*.
    exclude_paths:
        Path prefixes to skip entirely, e.g. ``["/health", "/metrics"]``.

    Returns
    -------
    int
        Number of tools successfully registered.
    """
    exclude_paths = exclude_paths or []
    count = 0

    for path, path_item in openapi_schema.get("paths", {}).items():
        # Skip excluded path prefixes
        if any(path.startswith(prefix) for prefix in exclude_paths):
            continue

        for method, spec in path_item.items():
            if method.upper() not in _HTTP_METHODS:
                continue  # skip OpenAPI path-level keys like "parameters"

            operation_id: str | None = spec.get("operationId")
            if not operation_id:
                continue  # can't produce a stable name without an operationId

            tags: list[str] = spec.get("tags", [])

            # Tag filtering
            if include_tags and not any(t in include_tags for t in tags):
                continue
            if exclude_tags and any(t in exclude_tags for t in tags):
                continue

            # Combine description sources: docstring > summary > name
            summary     = spec.get("summary", "")
            description = spec.get("description", summary).strip() or operation_id

            parameters = _query_path_params(spec) + _body_params(spec, openapi_schema)

            registry.register(Tool(
                name        = _tool_name(operation_id, path),
                description = description,
                method      = method.upper(),
                path        = path,
                parameters  = parameters,
                tags        = tags,
                risk_level  = _risk_level(method, path, operation_id, spec),
            ))
            count += 1

    return count
