"""MCP stdio server that exposes the two tools *behind* the guardrail gateway.

This is the production shape of the project: an MCP client (an LLM host such as
Claude Desktop, or the integration test) connects over stdio and calls
`query_customer_records` / `fetch_external_doc`. Every call is routed through
``SecureGateway`` with ``secure_mode=True``, so the four deterministic controls
run no matter what the connected model was persuaded to request.

The server is bound to a single authenticated identity at startup, supplied out
of band via environment variables (never over the MCP channel, which the model
can influence):

* ``GATEWAY_JWT``        - a ``Bearer``-less HS256 token; its ``sub`` is the
                           session identity that all tool calls are bound to.
* ``GATEWAY_JWT_SECRET`` - the HS256 signing secret.
* ``GATEWAY_DB``         - optional path to the SQLite store.

Run:  ``GATEWAY_JWT=... GATEWAY_JWT_SECRET=... python -m src.mcp_server.server``
"""

from __future__ import annotations

import functools
import os

from mcp.server.mcpserver import MCPServer

from src.gateway.secure_gateway import SecureGateway, ToolCall
from src.security import middleware as mw
from src.tools import customer_tools

# mcp SDK 2.x renamed FastMCP -> MCPServer; the .tool() decorator and .run()
# surface are unchanged.
mcp = MCPServer("mcp-guardrail-gateway")


def build_gateway() -> SecureGateway:
    """Construct the secure gateway from environment configuration."""
    token = os.environ.get("GATEWAY_JWT")
    secret = os.environ.get("GATEWAY_JWT_SECRET")
    if not token or not secret:
        raise RuntimeError("GATEWAY_JWT and GATEWAY_JWT_SECRET must be set")
    auth = mw.authenticate(f"Bearer {token}", secret)

    db_path = os.environ.get("GATEWAY_DB")
    overrides = {}
    if db_path:
        overrides["query_customer_records"] = functools.partial(
            customer_tools.query_customer_records, db_path=db_path
        )
    return SecureGateway(auth=auth, secure_mode=True, tool_overrides=overrides)


# Built once at process start; the identity is fixed for the session's lifetime.
_gateway: SecureGateway | None = None


def _gw() -> SecureGateway:
    global _gateway
    if _gateway is None:
        _gateway = build_gateway()
    return _gateway


def _format(result) -> str:
    if result.blocked:
        return f"[blocked by security gateway: {result.reason}]"
    return result.for_model if result.for_model is not None else str(result.output)


@mcp.tool()
def query_customer_records(user_id: str, query: str) -> str:
    """Look up a customer record.

    The ``user_id`` argument is advisory: the gateway binds every lookup to the
    server's authenticated session identity and refuses cross-tenant access.
    """
    return _format(_gw().call(ToolCall("query_customer_records", {"user_id": user_id, "query": query})))


@mcp.tool()
def fetch_external_doc(url: str) -> str:
    """Fetch an external document, subject to SSRF and domain-allowlist checks."""
    return _format(_gw().call(ToolCall("fetch_external_doc", {"url": url})))


if __name__ == "__main__":
    mcp.run()
