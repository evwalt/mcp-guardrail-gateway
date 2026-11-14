"""The guardrail gateway: a single choke point for tool execution.

Every tool call the agent makes passes through :meth:`SecureGateway.call`. When
``secure_mode`` is True the four middleware controls run around the tool; when
it is False the tool runs raw, which is how the red-team suite demonstrates
that the vulnerability is real before showing the control closes it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from src.security import middleware as mw
from src.tools import customer_tools


@dataclass
class ToolCall:
    name: str
    arguments: dict[str, Any]


@dataclass
class ToolResult:
    name: str
    output: Any
    blocked: bool = False
    reason: str | None = None
    # ``for_model`` is the string that re-enters the LLM context (boundary-
    # tagged + redacted in secure mode). ``output`` is the structured payload.
    for_model: str | None = None
    events: list[str] = field(default_factory=list)


class SecureGateway:
    def __init__(
        self,
        *,
        auth: mw.AuthContext | None = None,
        secure_mode: bool = True,
        url_resolver: Callable = mw._resolve,
        tool_overrides: dict[str, Callable] | None = None,
    ) -> None:
        self.auth = auth
        self.secure_mode = secure_mode
        self.url_resolver = url_resolver
        overrides = tool_overrides or {}
        self._tools: dict[str, Callable] = {
            "query_customer_records": overrides.get(
                "query_customer_records", customer_tools.query_customer_records
            ),
            "fetch_external_doc": overrides.get(
                "fetch_external_doc", customer_tools.fetch_external_doc
            ),
        }

    def call(self, tool_call: ToolCall) -> ToolResult:
        fn = self._tools.get(tool_call.name)
        if fn is None:
            return ToolResult(tool_call.name, None, blocked=True, reason="unknown tool")
        args = dict(tool_call.arguments)
        events: list[str] = []

        if tool_call.name == "query_customer_records":
            return self._call_query(fn, args, events)
        if tool_call.name == "fetch_external_doc":
            return self._call_fetch(fn, args, events)
        return ToolResult(tool_call.name, None, blocked=True, reason="unhandled tool")

    # -- query_customer_records -------------------------------------------- #
    def _call_query(self, fn, args, events) -> ToolResult:
        if self.secure_mode:
            if self.auth is None:
                return ToolResult(
                    "query_customer_records", None, blocked=True,
                    reason="no authenticated session", events=events,
                )
            try:
                bound = mw.enforce_user_id(self.auth, args.get("user_id"))
            except mw.SecurityError as exc:
                events.append(f"session-binding: {exc}")
                return ToolResult(
                    "query_customer_records", None, blocked=True,
                    reason=str(exc), events=events,
                )
            if args.get("user_id") != bound:
                events.append(f"session-binding: user_id forced to '{bound}'")
            args["user_id"] = bound

        output = fn(**args)

        if self.secure_mode:
            safe_output = mw.redact(output)
            if safe_output != output:
                events.append("redaction: secrets removed from output")
            notes = ""
            if safe_output.get("found"):
                notes = str(safe_output.get("record", {}).get("notes", ""))
            for_model = mw.wrap_untrusted(_render(safe_output), source="customer_db")
            return ToolResult(
                "query_customer_records", safe_output, for_model=for_model, events=events,
            )
        return ToolResult(
            "query_customer_records", output, for_model=_render(output), events=events,
        )

    # -- fetch_external_doc ------------------------------------------------- #
    def _call_fetch(self, fn, args, events) -> ToolResult:
        url = args.get("url", "")
        if self.secure_mode:
            try:
                mw.validate_url(url, resolver=self.url_resolver)
            except mw.SecurityError as exc:
                events.append(f"ssrf: {exc}")
                return ToolResult(
                    "fetch_external_doc", None, blocked=True, reason=str(exc), events=events,
                )

        output = fn(**args)

        if self.secure_mode:
            safe_output = mw.redact(output)
            if safe_output != output:
                events.append("redaction: secrets removed from output")
            for_model = mw.wrap_untrusted(
                str(safe_output.get("content", "")), source="external_web"
            )
            return ToolResult(
                "fetch_external_doc", safe_output, for_model=for_model, events=events,
            )
        return ToolResult(
            "fetch_external_doc", output,
            for_model=str(output.get("content", "")), events=events,
        )


def _render(output: dict[str, Any]) -> str:
    if not output.get("found"):
        return f"No record found for user_id={output.get('user_id')!r}."
    rec = output.get("record", {})
    lines = [f"{k}: {v}" for k, v in rec.items()]
    return "\n".join(lines)
