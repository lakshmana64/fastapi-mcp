# Backward Compatibility Policy

This document defines compatibility guarantees for `fastapi-mcp` server and MCP clients.

## Scope

The policy covers:

- HTTP MCP endpoints: `GET /mcp/tools`, `POST /mcp/call`
- request/response schemas (`Tool`, `ToolCallRequest`, `ToolCallResponse`)
- compatibility headers:
  - `X-MCP-API-Version`
  - `X-MCP-Compatibility`
- structured `error_code` values

It does not guarantee compatibility for internal Python module internals not documented as public API.

## Versioning Model

`api_version` follows `MAJOR.MINOR` semantics:

- **MAJOR**: breaking protocol/schema changes
- **MINOR**: additive, backward-compatible changes

Client compatibility is checked against **major version**.

## Compatibility Matrix

| Server `api_version` | Client `client_version` | Result |
|----------------------|-------------------------|--------|
| `1.x` | `1.x` | compatible |
| `1.x` | missing | unknown (or rejected if enforcement is enabled) |
| `1.x` | `2.x` | incompatible |
| `2.x` | `1.x` | incompatible |

When `enforce_client_version=True`, missing/incompatible versions are rejected.

## Deprecation Window

Deprecations use this timeline:

1. **Announce** in `CHANGELOG.md` and docs in a minor release.
2. **Warn** for at least **2 minor releases** (or **90 days**, whichever is longer).
3. **Remove** in the next major release.

For tool-level deprecations, use `deprecated_tools` and `Deprecation` response header during the warning phase.

## Error Code Stability

Structured `error_code` values are treated as contract keys for agent automation.
Existing codes are maintained through a major line; new codes are additive.
Code removals/renames happen only in major releases with deprecation notice.

## Operational Guidance

- Pin `api_version` explicitly in production.
- Send `client_version` from agents on every `POST /mcp/call`.
- Enable `enforce_client_version=True` after all active clients are upgraded.
- Track compatibility status via `X-MCP-Compatibility` and observability events.
