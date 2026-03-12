"""
example/main.py
───────────────
Minimal demo that shows fastapi-mcp in action.

Run:
    uv add fastapi-mcp uvicorn
    uvicorn example.main:app --reload
    # or from this directory:
    uvicorn main:app --reload

Then try:
    curl http://localhost:8000/mcp/tools
    curl -X POST http://localhost:8000/mcp/call \
         -H "Content-Type: application/json" \
         -d '{"tool": "get_weather", "arguments": {"city": "Bangalore"}}'
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# ── App ────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title       = "fastapi-mcp demo",
    description = "Example app — every endpoint below becomes an MCP tool.",
    version     = "1.0.0",
)

# ── Tiny in-memory "database" ──────────────────────────────────────────────────

_USERS: dict[int, dict] = {
    1: {"id": 1, "name": "Alice",   "email": "alice@example.com",   "role": "admin"},
    2: {"id": 2, "name": "Bob",     "email": "bob@example.com",     "role": "user"},
    3: {"id": 3, "name": "Charlie", "email": "charlie@example.com", "role": "user"},
}

_WEATHER: dict[str, dict] = {
    "bangalore": {"city": "Bangalore", "temp_c": 30, "condition": "Sunny",  "humidity": 55},
    "london":    {"city": "London",    "temp_c": 12, "condition": "Cloudy", "humidity": 80},
    "new york":  {"city": "New York",  "temp_c": 22, "condition": "Clear",  "humidity": 60},
    "tokyo":     {"city": "Tokyo",     "temp_c": 18, "condition": "Rainy",  "humidity": 75},
}

_PRODUCTS = [
    {"id": 1, "name": "Laptop",     "price": 999.99, "category": "electronics"},
    {"id": 2, "name": "Headphones", "price":  49.99, "category": "electronics"},
    {"id": 3, "name": "Notebook",   "price":   4.99, "category": "stationery"},
]

# ── Request bodies ─────────────────────────────────────────────────────────────

class CreateUserBody(BaseModel):
    name:  str
    email: str
    role:  str = "user"

# ── Endpoints  (these become MCP tools automatically) ─────────────────────────

@app.get("/users", summary="List all users", tags=["users"])
async def list_users() -> list[dict]:
    """Return every user in the system."""
    return list(_USERS.values())


@app.get("/users/{user_id}", summary="Get a user by ID", tags=["users"])
async def get_user(user_id: int) -> dict:
    """Fetch a single user by their numeric ID."""
    user = _USERS.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail=f"User {user_id} not found")
    return user


@app.post("/users", summary="Create a new user", tags=["users"], status_code=201)
async def create_user(body: CreateUserBody) -> dict:
    """Add a new user and return the created record."""
    new_id          = max(_USERS) + 1
    _USERS[new_id]  = {"id": new_id, **body.model_dump()}
    return _USERS[new_id]


@app.get("/weather", summary="Get weather for a city", tags=["weather"])
async def get_weather(city: str) -> dict:
    """
    Return current weather conditions for the requested city.
    Supported: Bangalore, London, New York, Tokyo.
    """
    data = _WEATHER.get(city.lower())
    if not data:
        raise HTTPException(
            status_code=404,
            detail=f"No data for '{city}'. Try: {', '.join(k.title() for k in _WEATHER)}",
        )
    return data


@app.get("/products", summary="List products", tags=["products"])
async def list_products(category: str | None = None) -> list[dict]:
    """Return all products, optionally filtered by category."""
    if category:
        return [p for p in _PRODUCTS if p["category"] == category.lower()]
    return _PRODUCTS


# ── Attach the MCP router ──────────────────────────────────────────────────────
# Import AFTER the routes are defined so that app.openapi() includes them all.

from fastapi_mcp import MCPRouter  # noqa: E402

mcp = MCPRouter(app, base_url="http://localhost:8000")
app.include_router(mcp)
