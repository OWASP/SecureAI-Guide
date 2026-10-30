"""
Chapter 08 — Vulnerable patterns: no autonomy controls on agent execution.

⚠️  DO NOT USE IN PRODUCTION — intentionally insecure for learning purposes.

What's wrong:
1. run_agent_vuln              — no step limit; loops indefinitely on impossible tasks
2. run_agent_no_budget_vuln    — token usage tracked but never enforced; unbounded spend
3. execute_tools_no_rate_limit — tool calls fire as fast as the model requests; no burst control
4. run_cleanup_vuln            — irreversible actions (delete, send) execute without confirmation
"""

import time
from collections import defaultdict

# ── shared mock LLM ──────────────────────────────────────────────────────────

_STEP_COUNTER = {"n": 0}

def mock_llm_looping(messages: list) -> object:
    """Simulates a model that always finds 'one more thing' to check."""
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

    # After 30 steps pretend it finishes — simulates a very long loop
    if n >= 30:
        return FakeResponse(None, f"Research complete after {n} steps.", n * 800)
    # Otherwise keep calling tools
    return FakeResponse([FakeCall("search_web", {"query": f"topic {n}"})],
                        None, 1200)

def mock_execute_tool(name: str, args: dict) -> str:
    return f"[result of {name}({args})]"


# ── 1. No step limit ──────────────────────────────────────────────────────────

# ❌ VULNERABLE: while True with no iteration ceiling
def run_agent_vuln(user_request: str) -> str:
    """Agent loop with no step counter — runs until the model decides to stop."""
    messages = [{"role": "user", "content": user_request}]
    _STEP_COUNTER["n"] = 0

    while True:                        # ← no ceiling
        response = mock_llm_looping(messages)

        if response.tool_calls:
            for call in response.tool_calls:
                result = mock_execute_tool(call.name, call.args)
                messages.append({"role": "tool", "content": result})
        else:
            return response.content
    # If the task is impossible, this runs forever (or until infra timeout)
    # In this mock: runs 30 steps before completing — real agents can run 800+


# ── 2. No token or cost budget ────────────────────────────────────────────────

# ❌ VULNERABLE: usage tracked but never enforced
def run_agent_no_budget_vuln(user_request: str) -> str:
    messages    = [{"role": "user", "content": user_request}]
    total_tokens = 0
    _STEP_COUNTER["n"] = 0

    while True:
        response      = mock_llm_looping(messages)
        total_tokens += response.usage.total_tokens
        # We know the cost — but we never stop because of it
        # print(f"  tokens so far: {total_tokens}")  # cost invisible to runtime

        if response.tool_calls:
            for call in response.tool_calls:
                result = mock_execute_tool(call.name, call.args)
                messages.append({"role": "tool", "content": result})
        else:
            return response.content
    # Mock runs 30 steps × 1200 tokens = 36,000 tokens — real runs can be 2M+


# ── 3. No rate limit on tool calls ───────────────────────────────────────────

CALL_LOG = []   # records every tool call made

# ❌ VULNERABLE: tools called as fast as the model requests them
def execute_tools_no_rate_limit(tool_calls: list) -> list:
    results = []
    for call in tool_calls:
        CALL_LOG.append({"tool": call.name, "time": time.monotonic()})
        result = mock_execute_tool(call.name, call.args)
        results.append(result)
    return results
    # 15 steps × 3 tool calls/step = 45 calls in seconds
    # External APIs get hammered → rate-limit errors → model retries → more calls


# ── 4. Irreversible actions without confirmation ─────────────────────────────

DELETED_ROWS  = []
EMAILS_SENT   = []

def mock_delete_records(table: str, filter_col: str, filter_val: str, limit: int = 99999) -> str:
    """Simulates a delete — records what was deleted."""
    rows = [f"row_{i}" for i in range(min(limit, 40000))]  # up to 40k rows
    DELETED_ROWS.extend(rows)
    return f"Deleted {len(rows)} rows from {table} where {filter_col}={filter_val!r}"

def mock_send_email(to: str, subject: str, body: str) -> str:
    EMAILS_SENT.append({"to": to, "subject": subject})
    return f"Email sent to {to}"

def mock_llm_cleanup(messages: list) -> object:
    """Simulates an agent that plans a cleanup involving deletes and emails."""
    class FakeCall:
        def __init__(self, name, args): self.name = name; self.args = args
    class FakeResponse:
        def __init__(self, calls): self.tool_calls = calls; self.content = None
        class usage: total_tokens = 500

    step = len([m for m in messages if m.get("role") == "tool"])
    if step == 0:
        return FakeResponse([FakeCall("delete_records",
            {"table": "orders", "filter_col": "status",
             "filter_val": "old", "limit": 40000})])
    if step == 1:
        return FakeResponse([FakeCall("send_email",
            {"to": "all-staff@company.com", "subject": "Cleanup done",
             "body": "40,000 old records deleted."})])
    class Done:
        tool_calls = None
        content = "Cleanup complete."
        class usage: total_tokens = 200
    return Done()

# ❌ VULNERABLE: delete and send fire immediately, no confirmation, no cap
def run_cleanup_vuln(user_request: str) -> str:
    messages = [{"role": "user", "content": user_request}]
    DELETED_ROWS.clear()
    EMAILS_SENT.clear()

    while True:
        response = mock_llm_cleanup(messages)
        if response.tool_calls:
            for call in response.tool_calls:
                if call.name == "delete_records":
                    result = mock_delete_records(**call.args)
                elif call.name == "send_email":
                    result = mock_send_email(**call.args)
                else:
                    result = mock_execute_tool(call.name, call.args)
                messages.append({"role": "tool", "content": result})
        else:
            return response.content
    # User says "clean up old records" → 40,000 rows deleted, email sent — no review
