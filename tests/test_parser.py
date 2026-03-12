"""
Unit tests for fastapi_mcp.parser
"""

import pytest

from fastapi_mcp.parser import _tool_name, parse_openapi
from fastapi_mcp.registry import ToolRegistry

# ── _tool_name ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("operation_id,path,expected", [
    ("get_weather_weather_get",             "/weather",           "get_weather"),
    ("list_users_users_get",                "/users",             "list_users"),
    ("get_user_users__user_id__get",        "/users/{user_id}",   "get_user"),
    ("create_user_users_post",              "/users",             "create_user"),
    ("list_products_products_get",          "/products",          "list_products"),
    ("delete_item_items__item_id__delete",  "/items/{item_id}",   "delete_item"),
])
def test_tool_name(operation_id, path, expected):
    assert _tool_name(operation_id, path) == expected


# ── parse_openapi ──────────────────────────────────────────────────────────────

_MINIMAL_SCHEMA = {
    "openapi": "3.1.0",
    "info": {"title": "Test", "version": "0.1.0"},
    "paths": {
        "/weather": {
            "get": {
                "operationId": "get_weather_weather_get",
                "summary": "Get weather",
                "tags": ["weather"],
                "parameters": [
                    {
                        "name": "city",
                        "in": "query",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
            }
        },
        "/users": {
            "get": {
                "operationId": "list_users_users_get",
                "summary": "List users",
                "tags": ["users"],
                "parameters": [],
            },
            "post": {
                "operationId": "create_user_users_post",
                "summary": "Create user",
                "tags": ["users"],
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["name"],
                                "properties": {
                                    "name":  {"type": "string"},
                                    "email": {"type": "string"},
                                },
                            }
                        }
                    }
                },
            },
        },
        "/health": {
            "get": {
                "operationId": "health_health_get",
                "summary": "Health check",
                "tags": ["ops"],
                "parameters": [],
            }
        },
    },
}

_REF_SCHEMA = {
    "openapi": "3.1.0",
    "info": {"title": "Ref Test", "version": "0.1.0"},
    "paths": {
        "/users": {
            "post": {
                "operationId": "create_user_users_post",
                "summary": "Create user",
                "tags": ["users"],
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/CreateUserBody"}
                        }
                    }
                },
            }
        }
    },
    "components": {
        "schemas": {
            "CreateUserBody": {
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": {"type": "string"},
                    "email": {"type": "string"},
                },
            }
        }
    },
}


def make_registry() -> ToolRegistry:
    r = ToolRegistry()
    return r


def test_parse_registers_all_endpoints():
    r = make_registry()
    count = parse_openapi(_MINIMAL_SCHEMA, r)
    assert count == 4
    assert len(r) == 4


def test_tool_names_are_clean():
    r = make_registry()
    parse_openapi(_MINIMAL_SCHEMA, r)
    assert "get_weather"  in r
    assert "list_users"   in r
    assert "create_user"  in r


def test_parameters_parsed():
    r = make_registry()
    parse_openapi(_MINIMAL_SCHEMA, r)
    weather_tool = r.get("get_weather")
    assert weather_tool is not None
    assert len(weather_tool.parameters) == 1
    p = weather_tool.parameters[0]
    assert p.name     == "city"
    assert p.type     == "string"
    assert p.required is True
    assert p.location == "query"


def test_body_params_parsed():
    r = make_registry()
    parse_openapi(_MINIMAL_SCHEMA, r)
    tool = r.get("create_user")
    assert tool is not None
    names = {p.name for p in tool.parameters}
    assert names == {"name", "email"}
    required = {p.name for p in tool.parameters if p.required}
    assert required == {"name"}


def test_body_params_parsed_from_component_ref():
    r = make_registry()
    parse_openapi(_REF_SCHEMA, r)
    tool = r.get("create_user")
    assert tool is not None
    names = {p.name for p in tool.parameters}
    assert names == {"name", "email"}
    required = {p.name for p in tool.parameters if p.required}
    assert required == {"name"}


def test_include_tags_filter():
    r = make_registry()
    count = parse_openapi(_MINIMAL_SCHEMA, r, include_tags=["weather"])
    assert count == 1
    assert "get_weather" in r
    assert "list_users" not in r


def test_exclude_tags_filter():
    r = make_registry()
    parse_openapi(_MINIMAL_SCHEMA, r, exclude_tags=["ops"])
    assert "health" not in r


def test_exclude_paths_filter():
    r = make_registry()
    parse_openapi(_MINIMAL_SCHEMA, r, exclude_paths=["/health"])
    assert "health_health" not in r
    assert len(r) == 3


def test_list_tools_sorted():
    r = make_registry()
    parse_openapi(_MINIMAL_SCHEMA, r)
    names = [t.name for t in r.list_tools()]
    assert names == sorted(names)


def test_list_tools_by_tag():
    r = make_registry()
    parse_openapi(_MINIMAL_SCHEMA, r)
    user_tools = r.list_tools(tag="users")
    assert {t.name for t in user_tools} == {"list_users", "create_user"}


def test_risk_level_inference_and_override():
    schema = {
        "openapi": "3.1.0",
        "info": {"title": "Risk Test", "version": "0.1.0"},
        "paths": {
            "/reports": {
                "get": {
                    "operationId": "list_reports_reports_get",
                    "summary": "List reports",
                    "tags": ["reports"],
                },
                "post": {
                    "operationId": "create_report_reports_post",
                    "summary": "Create report",
                    "tags": ["reports"],
                },
            },
            "/users/{user_id}": {
                "delete": {
                    "operationId": "delete_user_users__user_id__delete",
                    "summary": "Delete user",
                    "tags": ["users"],
                }
            },
            "/maintenance/reindex": {
                "post": {
                    "operationId": "reindex_maintenance_reindex_post",
                    "summary": "Reindex all records",
                    "x-mcp-risk-level": "destructive",
                    "tags": ["ops"],
                }
            },
        },
    }
    r = make_registry()
    parse_openapi(schema, r)
    assert r.get("list_reports").risk_level == "read"
    assert r.get("create_report").risk_level == "write"
    assert r.get("delete_user").risk_level == "destructive"
    assert r.get("reindex").risk_level == "destructive"
