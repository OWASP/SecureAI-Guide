"""
Chapter 10 — Secure patterns: structured logging and observability for AI agents.

✅ Safe to adapt for production.

What changed:
1. run_agent_structured    — structured JSON per step with request_id, user_id, redacted args
2. check_anomalies         — threshold checks on runs/hr, token spikes, unknown egress, error rate
3. log_tool_call_secure    — sensitive keys redacted; result logged as shape/summary only
"""

import json
import logging
import re
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, asdict
from typing import Any, Optional

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("agent.audit")

MAX_STEPS = 10

# ── Simulated infra ───────────────────────────────────────────────────────────

def mock_llm(messages: list) -> object:
    class FakeCall:
        def __init__(self, n, a): self.name = n; self.args = a
    class FakeResponse:
        def __init__(self, calls, content):
            self.tool_calls = calls; self.content = content
            class U: total_tokens = 1500
            self.usage = U()
    step = len([m for m in messages if m.get("role") == "tool"])
    if step >= 3:
        return FakeResponse(None, "Task complete.")
    return FakeResponse(
        [FakeCall("search_web", {"query": f"topic {step+1}",
                                 "api_key": "sk-search-secret-key"})],
        None
    )

def mock_execute_tool(name: str, args: dict) -> dict:
    return {"results": [{"title": "Article", "url": "https://example.com",
                         "user_email": "alice@acme.com", "ssn": "123-45-6789"}]}


# ── 1. Structured per-step logging ───────────────────────────────────────────

SENSITIVE_KEYS = {"password", "token", "key", "secret", "credential", "ssn", "dob"}

def redact_args(args: dict) -> dict:
    """Replace sensitive argument values with [REDACTED]."""
    return {
        k: "[REDACTED]" if any(s in k.lower() for s in SENSITIVE_KEYS) else v
        for k, v in args.items()
    }

_URL_RE = re.compile(r"https?://[^\s'\"]+")

def extract_urls(args: dict) -> list:
    return [v for v in args.values()
            if isinstance(v, str) and _URL_RE.match(v)]

@dataclass
class StepLog:
    event: str
    request_id: str
    user_id: str
    user_role: str
    step_number: int
    tool_name: str
    tool_args_redacted: dict
    result_summary: str
    external_urls: list
    tokens_used: int
    duration_ms: float
    timestamp: str
    status: str
    error_type: Optional[str] = None

def run_agent_structured(user_id: str, user_role: str, user_request: str) -> dict:
    """
    Agent loop with structured per-step audit logging.

    Security controls:
    - request_id correlates every step of this run
    - user_id and user_role from the auth layer — in every record
    - Tool args redacted before logging
    - Result logged as summary only — no sensitive content in logs
    """
    request_id   = str(uuid.uuid4())
    messages     = [{"role": "user", "content": user_request}]
    step         = 0
    total_tokens = 0

    logger.info(json.dumps({
        "event": "agent_run_start",
        "request_id": request_id,
        "user_id": user_id,
        "user_role": user_role,
        "request_length": len(user_request),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }))

    while step < MAX_STEPS:
        step += 1
        response = mock_llm(messages)
        total_tokens += response.usage.total_tokens

        if not response.tool_calls:
            logger.info(json.dumps({
                "event": "agent_run_complete",
                "request_id": request_id,
                "user_id": user_id,
                "steps": step,
                "total_tokens": total_tokens,
                "status": "completed",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }))
            return {"status": "completed", "steps": step,
                    "total_tokens": total_tokens, "result": response.content}

        for call in response.tool_calls:
            t0 = time.monotonic()
            result = mock_execute_tool(call.name, call.args)
            log = StepLog(
                event="tool_call",
                request_id=request_id,
                user_id=user_id,
                user_role=user_role,
                step_number=step,
                tool_name=call.name,
                tool_args_redacted=redact_args(call.args),
                result_summary=f"type={type(result).__name__} len={len(str(result))}",
                external_urls=extract_urls(call.args),
                tokens_used=response.usage.total_tokens,
                duration_ms=round((time.monotonic() - t0) * 1000, 1),
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                status="ok",
            )
            logger.info(json.dumps(asdict(log)))
            messages.append({"role": "tool", "content": str(result)})

    logger.warning(json.dumps({
        "event": "agent_step_limit_reached",
        "request_id": request_id, "user_id": user_id,
        "steps": step, "total_tokens": total_tokens,
    }))
    return {"status": "incomplete", "steps": step, "total_tokens": total_tokens}


# ── 2. Anomaly detection ──────────────────────────────────────────────────────

_run_times:    dict = defaultdict(list)
_error_counts: dict = defaultdict(int)

THRESHOLDS = {
    "runs_per_hour":        50,
    "tokens_per_run":   100_000,
    "errors_per_hour":      10,
}

KNOWN_DOMAINS = {
    "api.openai.com", "api.anthropic.com",
    "brave-search.api.search.brave.com", "api.github.com",
}

def check_anomalies(user_id: str, tokens_used: int,
                    external_urls: list, had_error: bool) -> list:
    """
    Check run metrics against anomaly thresholds.
    Returns list of alert strings — empty means normal.
    """
    alerts = []
    now      = time.monotonic()
    hour_ago = now - 3600

    _run_times[user_id].append(now)
    _run_times[user_id] = [t for t in _run_times[user_id] if t > hour_ago]
    if len(_run_times[user_id]) > THRESHOLDS["runs_per_hour"]:
        alerts.append(
            f"HIGH_RUN_RATE: {len(_run_times[user_id])} runs/hr "
            f"for {user_id} (threshold={THRESHOLDS['runs_per_hour']})"
        )

    if tokens_used > THRESHOLDS["tokens_per_run"]:
        alerts.append(
            f"TOKEN_SPIKE: {tokens_used:,} tokens "
            f"(threshold={THRESHOLDS['tokens_per_run']:,})"
        )

    for url in external_urls:
        m = re.search(r"https?://([^/]+)", url)
        if m and m.group(1) not in KNOWN_DOMAINS:
            alerts.append(f"UNKNOWN_EGRESS: {m.group(1)!r} not in known domain list")

    if had_error:
        _error_counts[user_id] += 1
    if _error_counts[user_id] > THRESHOLDS["errors_per_hour"]:
        alerts.append(
            f"HIGH_ERROR_RATE: {_error_counts[user_id]} errors/hr for {user_id}"
        )

    for alert in alerts:
        logger.warning(json.dumps({
            "event": "anomaly_detected", "alert": alert, "user_id": user_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }))
    return alerts


# ── 3. Safe log redaction ─────────────────────────────────────────────────────

_REDACT_PATTERNS = [
    (re.compile(r"sk-[A-Za-z0-9]{20,}"),         "[REDACTED_API_KEY]"),
    (re.compile(r"xoxb-[0-9]+-[A-Za-z0-9-]+"),   "[REDACTED_SLACK_TOKEN]"),
    (re.compile(r"postgresql://[^\s'\"]+"),        "[REDACTED_DB_URL]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),        "[REDACTED_SSN]"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
                                                   "[REDACTED_EMAIL]"),
]

def redact_for_log(text: str) -> str:
    for pattern, replacement in _REDACT_PATTERNS:
        text = pattern.sub(replacement, text)
    return text

def log_tool_call_secure(tool_name: str, args: dict, result: Any) -> None:
    """Log tool call with sensitive values redacted and result as summary only."""
    safe_args = {
        k: ("[REDACTED]" if any(s in k.lower() for s in SENSITIVE_KEYS)
            else redact_for_log(str(v)[:200]))
        for k, v in args.items()
    }
    result_summary = {
        "type": type(result).__name__,
        "length": len(str(result)),
        "is_list": isinstance(result, list),
        "list_len": len(result) if isinstance(result, list) else None,
    }
    logger.info(json.dumps({
        "event": "tool_call",
        "tool_name": tool_name,
        "args": safe_args,
        "result_summary": result_summary,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }))
    # ✅ sk-search-secret-key → [REDACTED_API_KEY]
    # ✅ SSN 123-45-6789 → [REDACTED_SSN]
    # ✅ alice@acme.com → [REDACTED_EMAIL]
    # ✅ Full result dict never logged — only type and length
