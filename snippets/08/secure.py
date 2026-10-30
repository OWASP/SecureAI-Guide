"""
Chapter 08 — Secure patterns: autonomy controls for AI agents.

✅ Safe to adapt for production.

What changed:
1. run_agent_secure             — hard step ceiling; structured incomplete result on breach
2. run_agent_with_budget        — token budget enforced before each LLM call; cost ceiling in USD
3. execute_tools_rate_limited   — per-tool sliding-window rate limiter + per-run ceiling
4. execute_with_hitl            — irreversible actions confirmed by human; blast radius capped in code
"""

import time
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from threading import Lock
from typing import Callable

# ── shared constants ─────────────────────────────────────────────────────────

MAX_STEPS    = 15
WARN_STEPS   = 10
TOKEN_BUDGET = 50_000
COST_PER_1K  = 0.01       # $ per 1k tokens
MAX_COST_USD = 0.50        # hard spend ceiling per run

# ── shared mock LLM ──────────────────────────────────────────────────────────

_STEP_COUNTER = {"n": 0}

def mock_llm(messages: list) -> object:
    """Mock that stops cleanly at step 8 — well within MAX_STEPS."""
    _STEP_COUNTER["n"] += 1
    n = _STEP_COUNTER["n"]

    class FakeCall:
        def __init__(self, name, args): self.name = name; self.args = args

    class FakeResponse:
        def __init__(self, tool_calls, content, tokens):
            self.tool_calls = tool_calls
            self.content    = content
            class Usage: total_tokens = tokens
            self.usage = Usage()

    if n >= 8:
        return FakeResponse(None, f"Task complete in {n} steps.", 800)
    return FakeResponse([FakeCall("search_web", {"query": f"topic {n}"})],
                        None, 1200)

def mock_execute_tool(name: str, args: dict) -> str:
    return f"[result of {name}({args})]"


# ── 1. Hard step ceiling ──────────────────────────────────────────────────────

def run_agent_secure(user_request: str, max_steps: int = MAX_STEPS) -> dict:
    """
    Agent loop with a hard step ceiling.

    Security controls:
    - Loop exits when steps >= max_steps — no infinite iteration possible
    - Soft warning logged at WARN_STEPS for observability
    - Returns structured dict: callers know status, step count, and result
    """
    messages = [{"role": "user", "content": user_request}]
    steps    = 0
    _STEP_COUNTER["n"] = 0

    while steps < max_steps:
        steps += 1

        if steps == WARN_STEPS:
            print(f"  [WARN] Approaching step limit: {steps}/{max_steps}")

        response = mock_llm(messages)

        if not response.tool_calls:
            return {"status": "completed", "steps": steps, "result": response.content}

        for call in response.tool_calls:
            result = mock_execute_tool(call.name, call.args)
            messages.append({"role": "tool", "content": result})

    # Hard limit reached
    return {
        "status": "incomplete",
        "steps": steps,
        "result": "Agent reached the maximum step limit. Please refine the request.",
    }
    # ✅ Impossible task → returns {"status": "incomplete"} after MAX_STEPS
    # ✅ Never runs indefinitely; partial state clearly flagged


# ── 2. Token budget enforcement ───────────────────────────────────────────────

def run_agent_with_budget(user_request: str) -> dict:
    """
    Agent loop with token budget enforced before each LLM call.

    Security controls:
    - Token count accumulated per step
    - Pre-call estimate aborts the run before exceeding TOKEN_BUDGET
    - Separate USD cost ceiling provides a business-level hard stop
    - All limits return structured results with usage metrics
    """
    messages    = [{"role": "user", "content": user_request}]
    tokens_used = 0
    steps       = 0
    _STEP_COUNTER["n"] = 0

    while steps < MAX_STEPS:
        steps += 1

        # Estimate context size before calling — abort if already over budget
        est_tokens = sum(len(m.get("content", "")) // 4 for m in messages)
        if tokens_used + est_tokens > TOKEN_BUDGET:
            return {
                "status": "budget_exceeded",
                "tokens_used": tokens_used,
                "cost_usd": round(tokens_used / 1000 * COST_PER_1K, 4),
                "result": "Token budget reached. Request was too large to complete.",
            }

        response     = mock_llm(messages)
        tokens_used += response.usage.total_tokens
        cost         = tokens_used / 1000 * COST_PER_1K

        if cost > MAX_COST_USD:
            return {
                "status": "cost_limit_reached",
                "tokens_used": tokens_used,
                "cost_usd": round(cost, 4),
                "result": "Cost limit reached. The request has been stopped.",
            }

        if not response.tool_calls:
            return {
                "status": "completed",
                "steps": steps,
                "tokens_used": tokens_used,
                "cost_usd": round(cost, 4),
                "result": response.content,
            }

        for call in response.tool_calls:
            result = mock_execute_tool(call.name, call.args)
            messages.append({"role": "tool", "content": result})

    return {"status": "incomplete", "steps": steps, "tokens_used": tokens_used}


# ── 3. Per-tool rate limiter ──────────────────────────────────────────────────

TOOL_RATE_LIMITS = {
    "search_web":     {"calls_per_minute": 10, "max_per_run": 20},
    "send_email":     {"calls_per_minute": 2,  "max_per_run": 5},
    "query_database": {"calls_per_minute": 30, "max_per_run": 50},
    "default":        {"calls_per_minute": 20, "max_per_run": 40},
}

class ToolRateLimiter:
    """Sliding-window rate limiter per tool per agent run."""

    def __init__(self):
        self._call_times: dict = defaultdict(list)
        self._run_counts: dict = defaultdict(int)
        self._lock = Lock()

    def check_and_record(self, tool_name: str) -> None:
        """Raises RuntimeError if either rate limit would be exceeded."""
        limits = TOOL_RATE_LIMITS.get(tool_name, TOOL_RATE_LIMITS["default"])
        cpm    = limits["calls_per_minute"]
        max_r  = limits["max_per_run"]

        with self._lock:
            now = time.monotonic()

            if self._run_counts[tool_name] >= max_r:
                raise RuntimeError(
                    f"tool_run_limit_exceeded: {tool_name!r} (limit={max_r}/run)"
                )

            cutoff = now - 60.0
            self._call_times[tool_name] = [
                t for t in self._call_times[tool_name] if t > cutoff
            ]
            if len(self._call_times[tool_name]) >= cpm:
                oldest = self._call_times[tool_name][0]
                wait   = 60.0 - (now - oldest)
                raise RuntimeError(
                    f"tool_rate_limit_exceeded: {tool_name!r} "
                    f"({cpm}/min). Retry in {wait:.1f}s."
                )

            self._call_times[tool_name].append(now)
            self._run_counts[tool_name] += 1

def execute_tools_rate_limited(tool_calls: list, limiter: ToolRateLimiter) -> list:
    """
    Execute tool calls through the rate limiter.

    Security control: raises before contacting the external API if any limit is exceeded.
    """
    results = []
    for call in tool_calls:
        limiter.check_and_record(call.name)   # raises if over limit
        results.append(mock_execute_tool(call.name, call.args))
    return results
    # ✅ >max_per_run email calls → RuntimeError before any email is sent
    # ✅ Burst of search_web calls → RuntimeError after 10/min threshold


# ── 4. Human-in-the-loop for irreversible actions ────────────────────────────

class ActionRisk(Enum):
    SAFE         = "safe"
    REVERSIBLE   = "reversible"
    IRREVERSIBLE = "irreversible"

TOOL_RISK: dict[str, ActionRisk] = {
    "search_web":     ActionRisk.SAFE,
    "read_file":      ActionRisk.SAFE,
    "query_database": ActionRisk.SAFE,
    "write_file":     ActionRisk.REVERSIBLE,
    "update_record":  ActionRisk.REVERSIBLE,
    "delete_records": ActionRisk.IRREVERSIBLE,
    "send_email":     ActionRisk.IRREVERSIBLE,
    "make_payment":   ActionRisk.IRREVERSIBLE,
    "execute_shell":  ActionRisk.IRREVERSIBLE,
}

MAX_IRREVERSIBLE_ROWS   = 100
MAX_IRREVERSIBLE_EMAILS = 3

@dataclass
class PendingAction:
    tool_name: str
    args: dict
    risk: ActionRisk
    preview: str

def _classify(tool_name: str, args: dict) -> PendingAction:
    risk    = TOOL_RISK.get(tool_name, ActionRisk.IRREVERSIBLE)
    preview = f"{tool_name}({', '.join(f'{k}={v!r}' for k, v in args.items())})"
    return PendingAction(tool_name=tool_name, args=args, risk=risk, preview=preview)

def execute_with_hitl(
    tool_calls: list,
    confirm_fn: Callable[[list[PendingAction]], bool],
    limiter: ToolRateLimiter,
) -> list:
    """
    Execute tool calls with human-in-the-loop gate on irreversible actions.

    Security controls:
    - Blast radius cap enforced BEFORE confirmation is requested
    - Irreversible actions batched and sent to confirm_fn (UI / Slack / approval API)
    - Rejected actions raise PermissionError — agent loop surfaces this as an error
    - Unknown tools default to IRREVERSIBLE — fail closed
    """
    pending      = [_classify(c.name, c.args) for c in tool_calls]
    irreversible = [a for a in pending if a.risk == ActionRisk.IRREVERSIBLE]

    # Blast radius cap — enforce before asking for human approval
    for action in irreversible:
        if "delete" in action.tool_name:
            limit = int(action.args.get("limit", 0))
            if limit > MAX_IRREVERSIBLE_ROWS:
                raise ValueError(
                    f"blast_radius_exceeded: proposed deleting {limit} rows "
                    f"(cap={MAX_IRREVERSIBLE_ROWS})"
                )

    email_count = sum(1 for a in irreversible if "email" in a.tool_name)
    if email_count > MAX_IRREVERSIBLE_EMAILS:
        raise ValueError(
            f"blast_radius_exceeded: proposed sending {email_count} emails "
            f"(cap={MAX_IRREVERSIBLE_EMAILS})"
        )

    # Human confirmation gate
    if irreversible:
        approved = confirm_fn(irreversible)
        if not approved:
            raise PermissionError("human_rejected_irreversible_actions")

    # Execute all approved actions through rate limiter
    results = []
    for action in pending:
        limiter.check_and_record(action.tool_name)
        results.append(mock_execute_tool(action.tool_name, action.args))
    return results
    # ✅ delete 40,000 rows → blast_radius_exceeded before confirmation is even shown
    # ✅ User rejects → PermissionError — no action taken
