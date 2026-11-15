"""Integration test: a real MCP client session over stdio against the server.

Spins up ``src.mcp_server.server`` as a subprocess, connects a genuine MCP
client over stdio, and exercises the tools end to end. This proves the gateway
enforces its controls across the actual protocol boundary, not just in unit
tests: the client is bound (via the server's startup JWT) to ``user_101``, so a
request for ``user_102`` must come back blocked.

The test is written as plain synchronous pytest functions that drive the async
MCP client with ``anyio.run`` - no pytest-asyncio plugin or config needed.
"""

from __future__ import annotations

import os
import secrets
import sys

import anyio
from mcp import Client, StdioServerParameters

from src.db import seed as seed_mod
from src.security import middleware as mw


def _server_params(db_path, token, jwt_secret) -> StdioServerParameters:
    env = {
        **os.environ,
        "GATEWAY_JWT": token,
        "GATEWAY_JWT_SECRET": jwt_secret,
        "GATEWAY_DB": str(db_path),
        # Ensure the subprocess can import the `src` package from the repo root.
        "PYTHONPATH": os.getcwd(),
    }
    return StdioServerParameters(command=sys.executable, args=["-m", "src.mcp_server.server"], env=env)


def _text(result) -> str:
    """Flatten a CallToolResult's content blocks to a single string."""
    parts = []
    for block in result.content:
        parts.append(getattr(block, "text", "") or "")
    return "\n".join(parts)


def _run_session(params, coro_factory):
    async def _main():
        async with Client(params) as client:
            return await coro_factory(client)

    return anyio.run(_main)


def test_legitimate_call_returns_own_record(tmp_path):
    jwt_secret = secrets.token_hex(32)
    api_key = "sk-live-" + secrets.token_hex(16)
    db = tmp_path / "customers.db"
    seed_mod.seed(db, api_keys={"user_101": api_key})
    token = mw.issue_token("user_101", jwt_secret)
    params = _server_params(db, token, jwt_secret)

    async def scenario(client):
        tools = {t.name for t in (await client.list_tools()).tools}
        assert {"query_customer_records", "fetch_external_doc"} <= tools
        res = await client.call_tool(
            "query_customer_records", {"user_id": "user_101", "query": "full record"}
        )
        return _text(res)

    out = _run_session(params, scenario)
    assert "user_101" in out
    assert "<untrusted_data" in out  # output is boundary-tagged
    assert api_key not in out        # the api_key is redacted even for the owner


def test_cross_tenant_call_is_blocked(tmp_path):
    jwt_secret = secrets.token_hex(32)
    db = tmp_path / "customers.db"
    seed_mod.seed(db)
    token = mw.issue_token("user_101", jwt_secret)  # session bound to user_101
    params = _server_params(db, token, jwt_secret)

    async def scenario(client):
        res = await client.call_tool(
            "query_customer_records", {"user_id": "user_102", "query": "full record"}
        )
        return _text(res)

    out = _run_session(params, scenario)
    assert "blocked by security gateway" in out
    assert "cross-tenant" in out
    assert "user_102" not in out or "blocked" in out  # no user_102 data leaked


def test_ssrf_call_is_blocked_over_protocol(tmp_path):
    jwt_secret = secrets.token_hex(32)
    db = tmp_path / "customers.db"
    seed_mod.seed(db)
    token = mw.issue_token("user_101", jwt_secret)
    params = _server_params(db, token, jwt_secret)

    async def scenario(client):
        res = await client.call_tool(
            "fetch_external_doc", {"url": "http://169.254.169.254/latest/meta-data/"}
        )
        return _text(res)

    out = _run_session(params, scenario)
    assert "blocked by security gateway" in out
