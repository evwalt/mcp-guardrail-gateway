"""Measure the gateway's own per-call overhead (secure_mode on vs. off).

Tools are real (SQLite query) or stubbed (fetch), and DNS is stubbed, so this
isolates the cost of the security controls, not network latency.

    python bench/overhead.py
"""

from __future__ import annotations

import pathlib
import secrets
import statistics
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from src.db import seed as seed_mod  # noqa: E402
from src.gateway.secure_gateway import SecureGateway, ToolCall  # noqa: E402
from src.security import middleware as mw  # noqa: E402
from tests.red_team.test_exploits import _fake_resolver, make_gateway  # noqa: E402

N = 5000


def measure(fn) -> tuple[float, float]:
    """Return (p50, p95) in microseconds."""
    for _ in range(200):
        fn()
    xs = []
    for _ in range(N):
        t = time.perf_counter_ns()
        fn()
        xs.append(time.perf_counter_ns() - t)
    xs.sort()
    return statistics.median(xs) / 1000, xs[int(N * 0.95)] / 1000


def stub_fetch(url, **kw):
    return {"url": url, "status_code": 200, "content": "public doc", "truncated": False}


def main() -> None:
    secret = secrets.token_hex(32)
    token = mw.issue_token("user_101", secret)
    db = pathlib.Path(tempfile.mkdtemp()) / "customers.db"
    ids = ("user_101", "user_102", "admin_001")
    seed_mod.seed(db, api_keys={u: "sk-live-" + secrets.token_hex(16) for u in ids})
    auth = mw.authenticate(f"Bearer {token}", secret)

    query = ToolCall("query_customer_records", {"user_id": "user_101", "query": "full record"})
    fetch = ToolCall("fetch_external_doc", {"url": "https://docs.example.com/guide"})

    rows = {}
    for secure in (False, True):
        gq = make_gateway(auth, secure_mode=secure, db_path=db)
        gf = SecureGateway(auth=auth, secure_mode=secure, url_resolver=_fake_resolver,
                           tool_overrides={"fetch_external_doc": stub_fetch})
        rows[secure] = (measure(lambda: gq.call(query)), measure(lambda: gf.call(fetch)))

    print(f"{'call':<28}{'off p50/p95 (us)':>20}{'on p50/p95 (us)':>20}{'overhead p50':>16}")
    for i, name in enumerate(("query own record (SQLite)", "fetch allowlisted URL")):
        off, on = rows[False][i], rows[True][i]
        print(f"{name:<28}{off[0]:>10.1f}/{off[1]:<9.1f}{on[0]:>10.1f}/{on[1]:<9.1f}{on[0] - off[0]:>12.1f} us")
    print(f"JWT verify, once per session: p50 {measure(lambda: mw.authenticate(f'Bearer {token}', secret))[0]:.1f} us")


if __name__ == "__main__":
    main()
