"""Tools exposed to the LLM agent.

These functions are deliberately *naive*: they do exactly what their arguments
say. Authorization, egress policy, and output sanitization are not their job;
they live in ``src.security.middleware`` so that one deterministic layer
enforces policy for every tool, regardless of what the model asked for.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

import httpx

from src.db.seed import DEFAULT_DB_PATH

COLUMNS = ("user_id", "name", "email", "billing_tier", "api_key", "notes")
MAX_RESPONSE_BYTES = 1_000_000
FETCH_TIMEOUT_SECONDS = 5.0


def query_customer_records(
    user_id: str, query: str, *, db_path: Path | str | None = None
) -> dict[str, Any]:
    """Return the customer record for ``user_id``.

    ``query`` is the model's free-text description of what it wants. If it
    names specific columns (e.g. "billing tier"), only those are returned;
    otherwise the full record is.
    """
    path = Path(db_path or DEFAULT_DB_PATH)
    if not path.exists():
        raise FileNotFoundError(f"{path} not found; run `python -m src.db.seed` first")

    wanted = [c for c in COLUMNS if c.replace("_", " ") in query.lower() or c in query.lower()]
    with closing(sqlite3.connect(path)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT user_id, name, email, billing_tier, api_key, notes "
            "FROM customers WHERE user_id = ?",
            (user_id,),
        ).fetchone()

    if row is None:
        return {"found": False, "user_id": user_id}
    record = dict(row)
    if wanted:
        record = {"user_id": record["user_id"], **{c: record[c] for c in wanted}}
    return {"found": True, "record": record}


def fetch_external_doc(
    url: str,
    *,
    client: httpx.Client | None = None,
    max_bytes: int = MAX_RESPONSE_BYTES,
) -> dict[str, Any]:
    """GET ``url`` and return its (size-capped) text body.

    Redirects are never followed: a redirect is an attacker-controlled second
    URL that would bypass any check made on the first one.
    """
    owns_client = client is None
    http = client or httpx.Client(timeout=FETCH_TIMEOUT_SECONDS, follow_redirects=False)
    try:
        with http.stream("GET", url, follow_redirects=False) as resp:
            chunks: list[bytes] = []
            total = 0
            truncated = False
            for chunk in resp.iter_bytes():
                total += len(chunk)
                if total > max_bytes:
                    chunks.append(chunk[: max_bytes - (total - len(chunk))])
                    truncated = True
                    break
                chunks.append(chunk)
            body = b"".join(chunks).decode(resp.encoding or "utf-8", errors="replace")
            result: dict[str, Any] = {
                "url": url,
                "status_code": resp.status_code,
                "content": body,
                "truncated": truncated,
            }
            if resp.is_redirect:
                result["redirect_not_followed"] = resp.headers.get("location", "")
            return result
    finally:
        if owns_client:
            http.close()
