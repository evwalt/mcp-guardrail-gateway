# MCP Guardrail Gateway

A deterministic security layer that wraps an LLM agent's tool calls. It
demonstrates, with runnable exploit-vs-blocked tests, why prompt-only
guardrails fail and what to enforce in code instead.

The agent has two tools — `query_customer_records` and `fetch_external_doc` —
over a SQLite customer store. Four OWASP-LLM attack vectors are shown succeeding
against the unguarded agent and then deterministically blocked by the gateway.

## The problem

An instruction like *"only access the current user's data"* or *"never reveal
secrets"* placed in the system prompt is a **request to a probabilistic model**,
not a guarantee. Indirect prompt injection — malicious text planted in data the
agent reads (a support note, a fetched web page) — can talk the model out of it.
Once the model is steered, any defense that lives only in the prompt is gone.

This project puts the defenses in ordinary Python at two choke points — before a
tool runs (authorization, egress policy) and after it runs (output
sanitization) — so they hold no matter what the model was convinced to attempt.

## Four controls (`src/security/middleware.py`)

1. **JWT auth & session binding** — verifies an HS256 `Bearer` token, extracts
   `sub`, and *overrides* any `user_id` the model supplied. Blocks BOLA/IDOR.
2. **SSRF & domain allowlist** — `urllib.parse` + `ipaddress` resolution rejects
   loopback, RFC1918, link-local (incl. `169.254.169.254`), and any
   non-allowlisted domain. Redirects are never followed.
3. **Outbound secret & PII redaction** — scrubs API keys (`sk-…`, `ghp_…`,
   AWS), JWTs, and SSNs from tool output before it re-enters the context or
   reaches the user.
4. **Prompt-injection boundary tagging** — wraps untrusted tool output in
   `<untrusted_data>` with explicit instruction-hierarchy framing.

`src/gateway/secure_gateway.py` is the single choke point: every tool call goes
through `SecureGateway.call`, which runs the controls when `secure_mode=True`.

### Hardening detail

The controls defend against the realistic bypasses, not just the obvious inputs:

- **SSRF:** blocks IPv4-mapped IPv6 (`[::ffff:169.254.169.254]`),
  integer-encoded IPs (decimal `2852039166`, hex `0xA9FEA9FE`), userinfo tricks
  (`http://example.com@169.254.169.254/`), and never follows redirects. Hosts
  are resolved and checked against private/loopback/link-local ranges, not
  string-matched.
- **JWT:** pins `algorithms=["HS256"]` (rejecting `alg:none` and RS/HS confusion)
  and requires verified `exp` and `sub` claims.

## MCP server

`src/mcp_server/server.py` exposes both tools over the Model Context Protocol
(stdio) using the `mcp` SDK, with every call routed through `SecureGateway`
(`secure_mode=True`). The server binds to one authenticated identity at startup
via environment variables, so an MCP client cannot spoof another tenant:

```bash
GATEWAY_JWT=<hs256-token> GATEWAY_JWT_SECRET=<secret> \
  python -m src.mcp_server.server          # speaks MCP over stdio
```

`tests/test_mcp_protocol.py` spins up this server as a subprocess and drives it
with a real MCP client over stdio, asserting a legitimate `user_101` call
succeeds (boundary-tagged, secret redacted) while a `user_102` call from the
same session is blocked by session binding.

## Run the red-team comparison in 30 seconds

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m src.db.seed          # creates data/customers.db
pytest -v                      # 56 tests: exploit-succeeds + blocked, per vector
```

Every vector is proven **twice**: once with `secure_mode=False` asserting the
exploit succeeds, once with `secure_mode=True` asserting the control blocks it —
so a green suite means the attack was real *and* the fix works.
`tests/red_team/test_exploits.py` covers:

| Vector | Insecure | Secure |
|--------|----------|--------|
| BOLA / IDOR cross-tenant read | `user_101` reads `admin_001` | session binding forces `user_101` |
| Indirect prompt injection | poisoned `user_102.notes` triggers admin read + metadata fetch | both follow-on actions blocked; note fenced as data |
| SSRF → cloud metadata | `169.254.169.254` / `127.0.0.1` fetched | blocked before the tool runs |
| Secret exfiltration | `sk-live-…` reaches the user | redacted to `[REDACTED]` |

The tests run **fully offline** with no API key: a deterministic `MockLLM`
(`src/agent/agent_runner.py`) plays the model, including playing a *compromised*
model that obeys the injection — which is exactly what lets us prove the gateway
stops the action anyway. A live Anthropic backend (`AnthropicLLM`) is available
when `ANTHROPIC_API_KEY` is set, but is never needed for the suite.

No secret-shaped literals are committed: the seeded API keys and JWT secrets are
generated at runtime (`secrets.token_hex`) in the seeder and pytest fixtures, so
Gitleaks stays clean.

## CI (`.github/workflows/security-ci.yml`)

On every push and PR: `pytest` (red-team suite as a mandatory merge gate),
**Semgrep** (`p/python`, `p/owasp-top-ten`, `p/secrets`), **Gitleaks**, and
**pip-audit**.

## Performance

`python bench/overhead.py` measures the gateway's own cost per tool call, with
`secure_mode` off vs. on (real SQLite query, stubbed fetch and DNS, 5,000 runs).
On a 2017 dual-core Intel i5 laptop the controls add about 30-40 us (p50) per call,
under 0.1 ms at p95; JWT verification (about 80 us) runs once per session. Real
DNS resolution for the SSRF check adds network time, which the fetch itself
would pay anyway.

## Architectural findings

**Prompt-level guardrails and action-level guardrails are not substitutes.** The
clearest result from building this is that boundary tagging (control 4) and the
deterministic action controls (1–3) defend different things. Tagging reduces the
*probability* the model obeys an injection; it cannot reduce it to zero, because
the model still ultimately decides. The authorization and egress checks don't
care what the model decided — when the injected instruction in `user_102`'s
notes tells the agent to read `admin_001` and curl the metadata endpoint, the
`MockLLM` in the secure test *does obey*, emitting exactly those calls, and both
are still refused at the gateway. That asymmetry is the whole argument for
pushing security below the model.

**Session binding beats input validation for BOLA.** The naive fix for
cross-tenant access is to validate the `user_id` argument. But the id is
model-supplied and therefore attacker-influenced; validating it only checks that
the attacker's chosen id is well-formed. Binding the effective id to the
authenticated `sub` and discarding the argument removes the parameter from the
attack surface entirely. The gateway treats a mismatched id as a blockable event
rather than silently overriding, so the attempt is auditable — a deliberate
choice, since a silent override hides reconnaissance.

**SSRF defense must resolve, not pattern-match.** Blocking the literal string
`169.254.169.254` is trivially bypassed (decimal IPs, DNS names that resolve
internally, allowlist-suffix tricks like `evil.example.com.attacker.test`). The
control resolves the host through `getaddrinfo` and rejects any address in a
private/loopback/link-local range, and rejects IP literals outright since they
can't be on a domain allowlist. The residual TOCTOU gap between resolution and
the tool's own connection is documented in the threat model as the next
hardening step (pin the resolved IP for the request).

**Redaction is defense-in-depth, not a primary control.** Pattern-based scrubbing
catches known secret shapes but will miss novel formats. It earns its place as a
backstop for the cases the earlier controls don't cover — e.g. a secret that was
legitimately stored in a field the authorized user *is* allowed to read, but
which should never be echoed verbatim into a model's context or a chat reply.

**Determinism is what makes the controls testable.** Because every control is
plain synchronous Python with injectable dependencies (the DNS resolver, the
tool functions, the model), each attack has a fast, offline, repeatable test.
The red-team suite is a merge gate precisely because it never flakes on a model
sampling differently — the security property is decoupled from model behavior.

See `docs/THREAT_MODEL.md` for the STRIDE analysis and data-flow diagram.
