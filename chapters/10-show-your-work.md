# Chapter 10 — Show Your Work

**Audit Logging, Observability, and Incident Response for AI Agents**

## The Scenario

Three months after launch, your security team receives a report: a customer's data was exfiltrated over a two-week period. The agent had been making small, regular calls to an external API that nobody had flagged — each call looked like a legitimate web search.

You open your logs to reconstruct what happened.

The logs show:

```
INFO  2024-10-14 09:12:03  agent started
INFO  2024-10-14 09:12:47  agent completed
INFO  2024-10-14 09:13:01  agent started
INFO  2024-10-14 09:13:44  agent completed
```

That is everything. No tool call details. No user ID. No request content. No external URLs contacted. No token counts. The agent ran hundreds of times and left nothing useful behind.

You cannot reconstruct what happened. You cannot determine the scope of the breach. You cannot tell a regulator what data was accessed. You cannot even confirm whether the incident is still ongoing.

This is not a logging gap. It is a **design gap** — the system was built without the assumption that something would go wrong and someone would need to understand what the agent did, step by step.

---

## What Agents Must Log

An AI agent that acts in the world — reading data, calling tools, sending messages, modifying records — has a real effect on real systems. Every one of those effects must be traceable. The minimum audit record for any agent run is:

| Field | Why it matters |
|-------|---------------|
| `request_id` | Correlates every step of one run across all services |
| `user_id` | Who triggered this run (from auth token — Chapter 03) |
| `user_role` | What permissions applied |
| `tool_name` | What tool was called |
| `tool_args` | What arguments were passed (redacted for sensitive values) |
| `tool_result_summary` | What came back (length/shape, not full content) |
| `external_urls` | Any outbound URL contacted |
| `tokens_used` | Cost traceability |
| `step_number` | Position in the run |
| `timestamp` | When each step happened |
| `status` | completed / incomplete / error |
| `error_type` | If an exception was raised, what kind |

---

## Vulnerable Pattern 1 — No Structured Logging

```python
# ❌ VULNERABLE: print statements and unstructured log lines
def run_agent_no_logs(user_request: str) -> str:
    print("Agent starting...")
    messages = [{"role": "user", "content": user_request}]

    while True:
        response = llm.chat(messages=messages)

        if response.tool_calls:
            for call in response.tool_calls:
                print(f"Calling tool: {call.name}")     # unstructured
                result = execute_tool(call.name, call.args)
                messages.append({"role": "tool", "content": result})
        else:
            print("Agent done.")
            return response.content
    # In production:
    # - No user_id → cannot determine who triggered this
    # - No request_id → cannot correlate steps across services
    # - No tool args → cannot reconstruct what data was accessed
    # - No timestamps per step → cannot build a timeline
    # - No error details → cannot diagnose failures
```

**What breaks:** When something goes wrong, you have no basis for investigation. You know the agent ran and completed. You don't know what it did, to what data, on whose behalf, in what order.

**Hardened implementation — structured JSON log per step with correlation ID:**

```python
import logging
import json
import time
import uuid
from dataclasses import dataclass, asdict
from typing import Any, Optional

# Use a structured logger — outputs JSON lines in production
logger = logging.getLogger("agent.audit")

@dataclass
class AgentStepLog:
    request_id: str
    user_id: str
    user_role: str
    step_number: int
    tool_name: str
    tool_args_redacted: dict        # sensitive values replaced with [REDACTED]
    tool_result_summary: str        # shape/length, not full content
    external_urls: list[str]
    tokens_used: int
    duration_ms: float
    timestamp: str
    status: str                     # "ok" | "error" | "rate_limited" | "blocked"
    error_type: Optional[str] = None

def redact_args(args: dict) -> dict:
    """Replace sensitive argument values with [REDACTED] before logging."""
    SENSITIVE_KEYS = {"password", "token", "key", "secret", "credential", "ssn", "dob"}
    return {
        k: "[REDACTED]" if any(s in k.lower() for s in SENSITIVE_KEYS) else v
        for k, v in args.items()
    }

def run_agent_structured(user_id: str, user_role: str, user_request: str) -> dict:
    """
    Agent loop with structured per-step audit logging.

    Every tool call produces a structured log record with:
    - request_id for full-run correlation
    - user_id and role from the auth layer
    - redacted tool args
    - result summary (not full content)
    - external URLs contacted
    """
    request_id = str(uuid.uuid4())
    messages   = [{"role": "user", "content": user_request}]
    step       = 0
    total_tokens = 0

    # Log run start
    logger.info(json.dumps({
        "event": "agent_run_start",
        "request_id": request_id,
        "user_id": user_id,
        "user_role": user_role,
        "request_length": len(user_request),
    }))

    while step < MAX_STEPS:
        step += 1
        t0 = time.monotonic()

        response = llm.chat(messages=messages)
        total_tokens += response.usage.total_tokens

        if not response.tool_calls:
            logger.info(json.dumps({
                "event": "agent_run_complete",
                "request_id": request_id,
                "user_id": user_id,
                "steps": step,
                "total_tokens": total_tokens,
                "status": "completed",
            }))
            return {"status": "completed", "steps": step, "result": response.content}

        for call in response.tool_calls:
            t_call = time.monotonic()
            try:
                result = execute_tool(call.name, call.args)
                log = AgentStepLog(
                    request_id=request_id,
                    user_id=user_id,
                    user_role=user_role,
                    step_number=step,
                    tool_name=call.name,
                    tool_args_redacted=redact_args(call.args),
                    tool_result_summary=f"len={len(str(result))} chars",
                    external_urls=_extract_urls(call.args),
                    tokens_used=response.usage.total_tokens,
                    duration_ms=round((time.monotonic() - t_call) * 1000, 1),
                    timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    status="ok",
                )
                logger.info(json.dumps(asdict(log)))
                messages.append({"role": "tool", "content": result})

            except Exception as exc:
                logger.error(json.dumps({
                    "event": "tool_error",
                    "request_id": request_id,
                    "user_id": user_id,
                    "step": step,
                    "tool_name": call.name,
                    "error_type": type(exc).__name__,
                    "error_msg": str(exc)[:200],
                }))
                raise

    logger.warning(json.dumps({
        "event": "agent_step_limit_reached",
        "request_id": request_id,
        "user_id": user_id,
        "steps": step,
        "total_tokens": total_tokens,
    }))
    return {"status": "incomplete", "steps": step}

def _extract_urls(args: dict) -> list[str]:
    """Extract any URL-shaped values from tool args for the egress log."""
    import re
    urls = []
    for v in args.values():
        if isinstance(v, str) and re.match(r"https?://", v):
            urls.append(v)
    return urls
```

**What changed:** Every tool call produces a structured JSON log record with a `request_id` that ties the full run together, `user_id` and `user_role` from the auth layer, redacted args (so sensitive values never appear in logs), a result summary, and any external URLs contacted. Run start and completion are also logged. This is the minimum record needed to reconstruct any agent run after the fact.

---

## Vulnerable Pattern 2 — No Anomaly Detection

```python
# ❌ VULNERABLE: agent runs with no alerting on unusual behaviour
def run_agent_no_monitoring(user_id: str, user_request: str) -> str:
    result = run_agent(user_request)
    # No check: is this user making an unusual number of requests?
    # No check: is this run using 10x the normal tokens?
    # No check: is the agent contacting an unusual external domain?
    # No check: are there repeated tool errors?
    return result
```

**What breaks:** Slow exfiltration, account compromise, and runaway agents all look like normal traffic until they are compared to a baseline. Without anomaly detection, a compromised account making 500 agent calls per hour looks identical to a legitimate user making 5.

**Hardened implementation — threshold checks on key signals:**

```python
from collections import defaultdict
from datetime import datetime, timezone

# In-memory counters (use Redis or time-series DB in production)
_run_counts: dict[str, list[float]] = defaultdict(list)
_token_totals: dict[str, list[int]] = defaultdict(list)
_error_counts: dict[str, int]       = defaultdict(int)

# Anomaly thresholds (tune per agent type and user tier)
THRESHOLDS = {
    "runs_per_hour":       50,     # more than 50 runs/hour from one user = alert
    "tokens_per_run":      100_000, # single run using >100k tokens = alert
    "errors_per_hour":     10,     # >10 tool errors/hour = alert
    "new_external_domain": True,   # any URL to a domain not in the known list = alert
}

KNOWN_EXTERNAL_DOMAINS = {
    "api.openai.com",
    "api.anthropic.com",
    "brave-search.api.search.brave.com",
    "api.github.com",
}

def check_anomalies(user_id: str, tokens_used: int,
                    external_urls: list[str], had_error: bool) -> list[str]:
    """
    Check agent run metrics against anomaly thresholds.
    Returns list of triggered alerts (empty = normal).
    """
    alerts = []
    now = time.monotonic()
    hour_ago = now - 3600

    # Runs per hour
    _run_counts[user_id].append(now)
    _run_counts[user_id] = [t for t in _run_counts[user_id] if t > hour_ago]
    if len(_run_counts[user_id]) > THRESHOLDS["runs_per_hour"]:
        alerts.append(
            f"HIGH_RUN_RATE: {len(_run_counts[user_id])} runs/hr "
            f"for user {user_id} (threshold={THRESHOLDS['runs_per_hour']})"
        )

    # Token spike
    if tokens_used > THRESHOLDS["tokens_per_run"]:
        alerts.append(
            f"TOKEN_SPIKE: {tokens_used:,} tokens in one run "
            f"(threshold={THRESHOLDS['tokens_per_run']:,})"
        )

    # Unknown external domain
    for url in external_urls:
        import re
        match = re.search(r"https?://([^/]+)", url)
        if match:
            domain = match.group(1)
            if domain not in KNOWN_EXTERNAL_DOMAINS:
                alerts.append(
                    f"UNKNOWN_EGRESS: agent contacted unknown domain {domain!r}"
                )

    # Error rate
    if had_error:
        _error_counts[user_id] += 1
    if _error_counts[user_id] > THRESHOLDS["errors_per_hour"]:
        alerts.append(
            f"HIGH_ERROR_RATE: {_error_counts[user_id]} errors "
            f"for user {user_id} (threshold={THRESHOLDS['errors_per_hour']})"
        )

    # Emit alerts
    for alert in alerts:
        logger.warning(json.dumps({"event": "anomaly_detected", "alert": alert,
                                   "user_id": user_id}))

    return alerts
```

---

## Vulnerable Pattern 3 — Logs Contain Raw Sensitive Data

```python
# ❌ VULNERABLE: full tool args and results logged — secrets and PII in log files
def log_tool_call_vuln(tool_name: str, args: dict, result: Any) -> None:
    logger.info(f"Tool called: {tool_name} args={args} result={result}")
    # args may contain: {"password": "[EXAMPLE_PASSWORD]", "ssn": "[EXAMPLE_SSN]", "token": "sk-..."}
    # result may contain: full DB rows with salary, email, health data
    # These now live in your log aggregation system — Splunk, Datadog, CloudWatch
    # Everyone with log access can read production secrets
```

**What breaks:** Logs are often less tightly controlled than production secrets. They are copied to analytics systems, developer laptops, and monitoring dashboards. Secrets and PII in logs violate data minimisation principles, GDPR, and HIPAA — and dramatically expand your breach surface.

**Hardened implementation — redact before logging; log shapes not values:**

```python
import re

_LOG_REDACT_PATTERNS = [
    (re.compile(r"sk-[A-Za-z0-9]{20,}"),        "[REDACTED_API_KEY]"),
    (re.compile(r"xoxb-[0-9]+-[A-Za-z0-9-]+"),  "[REDACTED_SLACK_TOKEN]"),
    (re.compile(r"postgresql://[^\s'\"]+"),       "[REDACTED_DB_URL]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),       "[REDACTED_SSN]"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b"),
                                                  "[REDACTED_EMAIL]"),
]

def redact_for_log(text: str) -> str:
    """Apply regex redaction before any string reaches the log system."""
    for pattern, replacement in _LOG_REDACT_PATTERNS:
        text = pattern.sub(replacement, text)
    return text

def log_tool_call_secure(tool_name: str, args: dict, result: Any) -> None:
    """Log tool call metadata without sensitive content."""
    safe_args = {
        k: ("[REDACTED]" if any(s in k.lower()
            for s in {"password","token","key","secret","ssn","dob"})
            else redact_for_log(str(v)[:200]))
        for k, v in args.items()
    }
    # Log shape of result, not content
    result_summary = {
        "type": type(result).__name__,
        "length": len(str(result)),
        "is_list": isinstance(result, list),
        "list_length": len(result) if isinstance(result, list) else None,
    }
    logger.info(json.dumps({
        "event": "tool_call",
        "tool_name": tool_name,
        "args": safe_args,
        "result_summary": result_summary,
    }))
```

---

## The Observability Minimum

Every agent you ship to production needs these four capabilities before the first user touches it:

| Capability | What it enables |
|-----------|-----------------|
| **Structured per-step logs** with `request_id` | Reconstruct any run end-to-end |
| **User and role in every log record** | Determine who triggered what |
| **Redacted args + result summaries** | Audit without leaking sensitive data |
| **Anomaly thresholds** on runs/hr, tokens/run, egress domains, error rate | Detect incidents without a human watching every run |

---

## Framework Variants

### LangChain — `BaseCallbackHandler` for structured logging

```python
from langchain_core.callbacks import BaseCallbackHandler
import json, uuid, time, logging

logger = logging.getLogger("agent.audit")

class AuditCallbackHandler(BaseCallbackHandler):
    def __init__(self, user_id: str, user_role: str):
        self.user_id    = user_id
        self.user_role  = user_role
        self.request_id = str(uuid.uuid4())
        self.step       = 0

    def on_tool_start(self, serialized, input_str, **kwargs):
        self.step += 1
        self._t0 = time.monotonic()
        logger.info(json.dumps({
            "event": "tool_start",
            "request_id": self.request_id,
            "user_id": self.user_id,
            "user_role": self.user_role,
            "step": self.step,
            "tool": serialized.get("name"),
            # Log redacted args — never raw passwords / tokens (CFG-H02)
            "args_preview": "[redacted]",
        }))

    def on_tool_end(self, output, **kwargs):
        logger.info(json.dumps({
            "event": "tool_end",
            "request_id": self.request_id,
            "user_id": self.user_id,
            "step": self.step,
            "duration_ms": round((time.monotonic() - self._t0) * 1000, 1),
            "result_len": len(str(output)),
        }))

    def on_tool_error(self, error, **kwargs):
        logger.error(json.dumps({
            "event": "tool_error",
            "request_id": self.request_id,
            "user_id": self.user_id,
            "step": self.step,
            "error": type(error).__name__,
        }))
```

### LangGraph — audit node in every graph

```python
import json
import logging
import time
from langgraph.graph import StateGraph
from typing import TypedDict

logger = logging.getLogger("agent.audit")

class AuditedState(TypedDict):
    request_id: str      # set at graph entry
    user_id: str
    user_role: str
    messages: list
    audit_trail: list    # append-only log of every step

def make_audit_node(tool_node_fn):
    """Wrap any tool node with before/after audit records."""
    def audited_node(state: AuditedState) -> AuditedState:
        entry = {"step": len(state["audit_trail"]) + 1,
                 "tool": tool_node_fn.__name__,
                 "ts_start": time.time()}
        result_state = tool_node_fn(state)
        entry["ts_end"]      = time.time()
        entry["duration_ms"] = round((entry["ts_end"] - entry["ts_start"]) * 1000, 1)
        entry["status"]      = "ok"
        logger.info(json.dumps({**entry,
                                 "request_id": state["request_id"],
                                 "user_id": state["user_id"]}))
        return {**result_state, "audit_trail": state["audit_trail"] + [entry]}
    return audited_node
```

---

## Try It Yourself → [Open Lab 10 locally](../labs/10-show-your-work.ipynb)

The lab has four exercises:

1. **No logs** — run an agent with only `print` statements; try to reconstruct what it did; observe what is missing
2. **Structured logging** — add `request_id`, `user_id`, tool args, and result summaries; reconstruct the full run from logs
3. **Anomaly detection** — simulate a high-volume user and an unknown egress domain; watch the threshold alerts fire
4. **Sensitive data in logs** — log raw tool args containing a password and SSN; apply redaction; verify clean log output

No API key required — all exercises use mock agents and in-memory log stores.

---

## Checklist

Before deploying any agent to production:

- [ ] **Every tool call** produces a structured JSON log record with `request_id`, `user_id`, `user_role`, `tool_name`, step number, and timestamp (CFG-H01)
- [ ] **Tool arguments** are redacted before logging — sensitive keys (`password`, `token`, `key`, `ssn`) replaced with `[REDACTED]` (CFG-H02)
- [ ] **Tool results** logged as summaries (type, length, shape) — never raw content (CFG-H02)
- [ ] **request_id** is generated once per run and included in every log record for that run — enables full reconstruction (CFG-H01)
- [ ] **Run completion** logged with status (`completed` / `incomplete` / `budget_exceeded`), total steps, and total tokens (CFG-H01)
- [ ] **Anomaly thresholds** configured for: runs/hour per user, tokens per run, unknown egress domains, error rate per user (CFG-H03)
- [ ] **Alerts** route to an on-call channel with enough context to triage without accessing production data (CFG-H04)
- [ ] **Log retention** meets your compliance requirements — minimum 90 days for most regulated industries (CFG-H05)
- [ ] **Logs are tested** — at least one integration test verifies that a tool call produces the expected log record fields (CFG-H01)

---

## Key Takeaway

An agent that acts without leaving a trace is a liability you cannot manage. You cannot detect incidents you cannot see. You cannot scope breaches you cannot reconstruct. You cannot satisfy regulators or customers with logs that say "agent started" and "agent completed." **Structured per-step logging with correlation IDs, redacted sensitive data, and anomaly thresholds is not observability gold-plating — it is the minimum viable audit trail for any agent that acts on real data in the real world.**

---

## You've Reached the Core Ten — Keep Going

Congratulations on completing chapters 01–10 of the **AI Security Development Guide**.

You now have the builder's toolkit for securing AI agents:

| Ch | Topic | Core defence |
|----|-------|-------------|
| 01 | Prompt injection | Structural separation — bound untrusted input |
| 02 | Tool attack surface | Server-side validation — parameterise, allowlist, sandbox, SSRF controls |
| 03 | Secrets in prompts | Keep secrets out of model context entirely |
| 04 | Memory poisoning | Tenant isolation + sanitised writes + trust labelling |
| 05 | Least privilege | Role-based tool registry + scoped sub-agent delegation |
| 06 | Multi-agent trust | Auth between agents + separation + sanitise at handoff |
| 07 | Output handling | Escape at the sink — XSS, SQL, shell, second-order injection |
| 08 | Autonomy controls | Step limit + token budget + rate limit + HITL confirmation |
| 09 | Plugin supply chain | Inspect + pin + scope + isolate + validate output + MCP auth |
| 10 | Observability | Structured logs + correlation IDs + anomaly detection |

### Continue with ASI expansions

| Ch | Topic | OWASP |
|----|-------|-------|
| [11](./11-sandbox-the-code.md) | Sandbox the Code | ASI05 |
| [12](./12-stop-the-cascade.md) | Stop the Cascade | ASI08 |
| [13](./13-dont-rubber-stamp.md) | Don't Rubber-Stamp | ASI09 |
| [14](./14-catch-the-rogue.md) | Catch the Rogue | ASI10 |

> **Companion Red Guide:** See [COMPANION.md](../COMPANION.md) — the attacker's perspective on every chapter above.

---

*OWASP references: [ASI02 Tool Misuse](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) · [ASI10 Rogue Agents](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) · [CFG-H01–H05](../TEST-CATALOG.md)*
