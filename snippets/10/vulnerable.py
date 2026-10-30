"""
Chapter 10 — Vulnerable patterns: no observability on agent execution.

⚠️  DO NOT USE IN PRODUCTION — intentionally insecure for learning purposes.

What's wrong:
1. run_agent_no_logs_vuln     — print statements only; no structure, no correlation, no user context
2. run_agent_no_monitoring_vuln — no anomaly thresholds; runaway and exfiltration go undetected
3. log_tool_call_vuln         — raw tool args and results logged; secrets and PII in log files
"""

import time
import logging

# Basic unstructured logger
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("agent")

# ── Simulated infra ───────────────────────────────────────────────────────────

def mock_llm(messages: list) -> object:
    class FakeCall:
        def __init__(self, name, args): self.name = name; self.args = args
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
    """Returns a mock result that contains PII."""
    return {"results": [{"title": "Article", "url": "https://example.com",
                         "user_email": "alice@acme.com", "ssn": "123-45-6789"}]}

MAX_STEPS = 10

# ── 1. Unstructured logging ───────────────────────────────────────────────────

# ❌ VULNERABLE: only print/unstructured log statements
def run_agent_no_logs_vuln(user_request: str) -> str:
    """Agent with no structured logging — impossible to reconstruct after the fact."""
    print("Agent starting...")     # no user_id, no request_id
    messages = [{"role": "user", "content": user_request}]
    steps = 0

    while steps < MAX_STEPS:
        steps += 1
        response = mock_llm(messages)

        if not response.tool_calls:
            print("Agent done.")  # no step count, no token total
            return response.content

        for call in response.tool_calls:
            print(f"Calling tool: {call.name}")  # no args, no request_id, no timestamp
            result = mock_execute_tool(call.name, call.args)
            messages.append({"role": "tool", "content": str(result)})

    return "incomplete"
    # Incident investigation: IMPOSSIBLE
    # - Who triggered this? Unknown.
    # - What args were passed? Unknown.
    # - What data was returned? Unknown.
    # - Which external URLs were contacted? Unknown.


# ── 2. No anomaly monitoring ──────────────────────────────────────────────────

RUN_COUNTS = {}   # user_id → count — never checked against a threshold

# ❌ VULNERABLE: runs increment but are never checked
def run_agent_no_monitoring_vuln(user_id: str, user_request: str) -> str:
    RUN_COUNTS[user_id] = RUN_COUNTS.get(user_id, 0) + 1
    # No check: is this user making 500 runs/hour?
    # No check: is this run consuming 1M tokens?
    # No check: is the agent contacting an unusual domain?
    return run_agent_no_logs_vuln(user_request)
    # Attack: compromised account runs agent 500 times/hour exfiltrating data
    # No alert fires. Nobody notices until the customer reports it.


# ── 3. Raw sensitive data in logs ─────────────────────────────────────────────

# ❌ VULNERABLE: logs full tool args and results including secrets and PII
def log_tool_call_vuln(tool_name: str, args: dict, result: object) -> None:
    # Full args — may contain API keys, passwords, SSNs
    logger.info(f"Tool called: {tool_name} args={args} result={result}")
    # In production this goes to Splunk / Datadog / CloudWatch
    # Everyone with log access can now read: sk-search-secret-key, SSNs, emails
