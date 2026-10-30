# Chapter 08 — Give It a Leash

**Autonomy Controls, Rate Limiting, and Budget Bounds for AI Agents**

## The Scenario

You ship an autonomous research agent. It browses the web, reads documents, calls APIs, and synthesises reports. In testing it works beautifully — it takes about 12 steps and returns a great answer.

Two weeks later your infrastructure bill has tripled. A support ticket shows one user triggered a request that caused the agent to loop for 847 iterations before timing out at the infrastructure level. During those 847 iterations it made 423 external API calls, consumed 2.1 million tokens, and sent 38 emails to external addresses before anyone noticed.

The agent was not compromised. It was not injected. It was just trying very hard to do a task it could never complete — because nobody told it when to stop.

A second incident: a different user asks the agent to "clean up old records." The agent correctly interprets this as a delete operation, plans 14 steps, and begins executing. On step 3 it deletes 40,000 rows. The user meant 40 rows. There was no confirmation step, no preview, no ceiling on how many records a single agent run could touch.

Both incidents share the same root cause: **the agent had no leash.**

---

## Why Agents Need Hard Bounds

A language model optimises for completing the task it was given. It does not naturally stop when it has consumed too much, looped too many times, or is about to take an irreversible action. Those constraints must be built into the system around it.

There are four dimensions where agents need hard limits:

| Dimension | What goes wrong without it | Example |
|-----------|---------------------------|---------|
| **Iteration / step limit** | Agent loops indefinitely trying to complete an impossible task | 847-step research loop |
| **Token / cost budget** | Agent consumes unbounded tokens and API spend | 2.1M token run at $63 |
| **Action rate limit** | Agent makes tool calls faster than a human could review | 423 API calls in 4 minutes |
| **Blast radius cap** | Agent takes irreversible actions beyond intended scope | 40,000 rows deleted |

None of these are model problems. They are **infrastructure and design problems** — the application never told the agent it had limits.

---

## Vulnerable Pattern 1 — No Step Limit

```python
# ❌ VULNERABLE: agent loop with no iteration ceiling
def run_agent(user_request: str) -> str:
    messages = [{"role": "user", "content": user_request}]

    while True:                    # no step counter, no exit condition
        response = llm.chat(messages=messages)

        if response.tool_calls:
            for call in response.tool_calls:
                result = execute_tool(call.name, call.args)
                messages.append({"role": "tool", "content": result})
        else:
            # Agent signals it is done — but what if it never does?
            return response.content
    # If the task is impossible or the model keeps finding "one more thing to check",
    # this loop runs forever — bounded only by infrastructure timeout (minutes to hours)
```

**What breaks:** The agent has no concept of "I've taken enough steps." If the task is ambiguous, the model's context fills with conflicting information, or a tool keeps returning partial results, the loop continues indefinitely. Infrastructure timeouts are blunt instruments — they fire after minutes, not steps, and leave partial state in an unknown condition.

**Hardened implementation — hard step limit with graceful degradation:**

```python
MAX_STEPS = 15          # hard ceiling — tune per agent type
WARN_STEPS = 10         # soft warning — log and consider early return

def run_agent_secure(user_request: str, max_steps: int = MAX_STEPS) -> dict:
    """
    Agent loop with a hard step ceiling.

    Returns a result dict so callers know whether the run completed or was halted.
    """
    messages = [{"role": "user", "content": user_request}]
    steps = 0

    while steps < max_steps:
        steps += 1

        if steps == WARN_STEPS:
            # Soft warning — log for observability; consider whether to continue
            audit_log.warning("agent_approaching_step_limit",
                              steps=steps, max=max_steps, request=user_request[:120])

        response = llm.chat(messages=messages)

        if not response.tool_calls:
            # Clean completion
            return {"status": "completed", "steps": steps, "result": response.content}

        for call in response.tool_calls:
            result = execute_tool(call.name, call.args)
            messages.append({"role": "tool", "content": result})

    # Hard limit reached — return what we have, flag as incomplete
    audit_log.error("agent_step_limit_reached",
                    steps=steps, max=max_steps, request=user_request[:120])
    return {
        "status": "incomplete",
        "steps": steps,
        "result": "Agent reached the maximum number of steps. Please refine the request.",
        "partial_messages": messages,
    }
```

**What changed:** The loop has a hard ceiling (`max_steps`). When reached, the agent returns a structured result with `status: "incomplete"` instead of looping forever. A soft warning at 10 steps gives operators visibility before the hard limit fires. The return type is a dict — callers know whether the run completed cleanly or was halted.

---

## Vulnerable Pattern 2 — No Token or Cost Budget

```python
# ❌ VULNERABLE: no token tracking; no spend ceiling
def run_agent_no_budget(user_request: str) -> str:
    messages = [{"role": "user", "content": user_request}]
    total_tokens = 0   # tracked but never enforced

    while True:
        response = llm.chat(messages=messages)
        total_tokens += response.usage.total_tokens   # we know the cost — but never stop

        if not response.tool_calls:
            return response.content

        for call in response.tool_calls:
            result = execute_tool(call.name, call.args)
            messages.append({"role": "tool", "content": result})
    # A single run can consume millions of tokens with no notification or cutoff
```

**What breaks:** Token usage compounds quickly in agentic loops — each step adds messages to the context, which grows the token count of every subsequent call. A 15-step loop on a 128k context model can cost $50–100 per run. Multiplied across users, a single poorly-scoped task can generate a four-figure infrastructure bill before anyone sees a dashboard.

**Hardened implementation — token budget with mid-run enforcement:**

```python
# ✅ Best Practice: hard token ceiling enforced at each step; cost projected before each call
TOKEN_BUDGET = 50_000       # tokens per agent run
COST_PER_1K  = 0.01         # $ per 1k tokens (adjust per model)
MAX_COST_USD = 0.50         # hard spend ceiling per run

def run_agent_with_budget(user_request: str) -> dict:
    """
    Agent loop with token budget enforcement.

    Checks remaining budget before each LLM call — stops before exceeding the ceiling.
    """
    messages = [{"role": "user", "content": user_request}]
    tokens_used  = 0
    steps        = 0

    while steps < MAX_STEPS:
        steps += 1

        # Estimate context size before calling — abort if already over budget
        estimated_context_tokens = sum(
            len(m.get("content", "")) // 4   # rough 4-char-per-token estimate
            for m in messages
        )
        if tokens_used + estimated_context_tokens > TOKEN_BUDGET:
            audit_log.warning("agent_token_budget_exceeded_pre_call",
                              tokens_used=tokens_used, budget=TOKEN_BUDGET)
            return {
                "status": "budget_exceeded",
                "tokens_used": tokens_used,
                "cost_usd": round(tokens_used / 1000 * COST_PER_1K, 4),
                "result": "Token budget reached. Request was too large to complete.",
            }

        response = llm.chat(messages=messages)
        step_tokens   = response.usage.total_tokens
        tokens_used  += step_tokens
        cost_so_far   = tokens_used / 1000 * COST_PER_1K

        # Hard cost ceiling — stop even if steps remain
        if cost_so_far > MAX_COST_USD:
            audit_log.error("agent_cost_ceiling_hit",
                            cost_usd=cost_so_far, limit_usd=MAX_COST_USD)
            return {
                "status": "cost_limit_reached",
                "tokens_used": tokens_used,
                "cost_usd": round(cost_so_far, 4),
                "result": "Cost limit reached. The request has been stopped.",
            }

        if not response.tool_calls:
            return {
                "status": "completed",
                "steps": steps,
                "tokens_used": tokens_used,
                "cost_usd": round(cost_so_far, 4),
                "result": response.content,
            }

        for call in response.tool_calls:
            result = execute_tool(call.name, call.args)
            messages.append({"role": "tool", "content": result})

    return {"status": "incomplete", "steps": steps, "tokens_used": tokens_used}
```

**What changed:** Token usage is tracked per step and enforced against a hard budget. A pre-call estimate aborts the run before making a call that would blow the budget. A separate cost ceiling in USD provides a second, business-level enforcement point. Both limits return structured results so callers know exactly why the run stopped and how much was consumed.

---

## Vulnerable Pattern 3 — No Rate Limit on Tool Calls

```python
# ❌ VULNERABLE: tools called as fast as the model requests them
def execute_tools_no_rate_limit(tool_calls: list) -> list[str]:
    results = []
    for call in tool_calls:
        result = execute_tool(call.name, call.args)   # no delay, no counter, no ceiling
        results.append(result)
    return results
    # In a 15-step loop that calls 3 tools per step:
    # → 45 external API calls in seconds
    # → External API rate limits hit → errors → model retries → more calls
    # → Retry storm amplifies the problem
```

**What breaks:** Agentic systems can make dozens of tool calls per minute without any human action. External APIs have rate limits — hitting them causes errors, which the model may interpret as "retry" signals, causing more calls, more errors, and a retry storm. Even internal tools like databases or messaging services can be overwhelmed. A single runaway agent run can exhaust a daily API quota in minutes.

**Hardened implementation — per-tool rate limiter with backoff:**

```python
import time
from collections import defaultdict
from threading import Lock

# Per-tool rate limit configuration
TOOL_RATE_LIMITS = {
    "search_web":    {"calls_per_minute": 10, "max_per_run": 20},
    "send_email":    {"calls_per_minute": 2,  "max_per_run": 5},
    "query_database":{"calls_per_minute": 30, "max_per_run": 50},
    "read_url":      {"calls_per_minute": 15, "max_per_run": 30},
    "default":       {"calls_per_minute": 20, "max_per_run": 40},
}

class ToolRateLimiter:
    """Simple sliding-window rate limiter per tool per agent run."""

    def __init__(self):
        self._call_times: dict[str, list[float]] = defaultdict(list)
        self._run_counts: dict[str, int]          = defaultdict(int)
        self._lock = Lock()

    def check_and_record(self, tool_name: str) -> None:
        """
        Raises if the tool call would exceed rate limits.
        Records the call if allowed.
        """
        limits = TOOL_RATE_LIMITS.get(tool_name, TOOL_RATE_LIMITS["default"])
        cpm   = limits["calls_per_minute"]
        max_r = limits["max_per_run"]

        with self._lock:
            now = time.monotonic()

            # Per-run ceiling
            if self._run_counts[tool_name] >= max_r:
                raise RuntimeError(
                    f"tool_run_limit_exceeded: {tool_name!r} "
                    f"(limit={max_r} calls per run)"
                )

            # Sliding 60-second window
            cutoff = now - 60.0
            self._call_times[tool_name] = [
                t for t in self._call_times[tool_name] if t > cutoff
            ]
            if len(self._call_times[tool_name]) >= cpm:
                oldest = self._call_times[tool_name][0]
                wait = 60.0 - (now - oldest)
                raise RuntimeError(
                    f"tool_rate_limit_exceeded: {tool_name!r} "
                    f"({cpm} calls/min). Retry in {wait:.1f}s."
                )

            self._call_times[tool_name].append(now)
            self._run_counts[tool_name] += 1

def execute_tools_with_rate_limit(
    tool_calls: list,
    limiter: ToolRateLimiter,
) -> list[str]:
    """Execute tool calls respecting per-tool rate limits."""
    results = []
    for call in tool_calls:
        limiter.check_and_record(call.name)   # raises if limit exceeded
        result = execute_tool(call.name, call.args)
        results.append(result)
    return results
```

**What changed:** Every tool call passes through a rate limiter that enforces two limits: a per-minute sliding window (prevents burst) and a per-run ceiling (prevents runaway). If either limit is exceeded, the call raises before the external API is ever contacted. The error is surfaced to the agent loop, which can return gracefully rather than retrying blindly.

---

## Vulnerable Pattern 4 — No Human-in-the-Loop for Irreversible Actions

```python
# ❌ VULNERABLE: agent executes irreversible actions without confirmation
def run_cleanup_agent(user_request: str) -> str:
    """Agent that can delete records — executes immediately on first plan."""
    messages = [{"role": "user", "content": user_request}]

    while True:
        response = llm.chat(messages=messages)

        if response.tool_calls:
            for call in response.tool_calls:
                # delete_records, send_email, write_file — all fire immediately
                result = execute_tool(call.name, call.args)
                messages.append({"role": "tool", "content": result})
        else:
            return response.content
    # User says "clean up old records" → agent deletes 40,000 rows → no undo
```

**What breaks:** Irreversible actions — deletes, sends, writes, payments — executed by an agent cannot be undone. A misunderstood instruction, an off-by-one in the filter, or an injected payload (Chapter 01) that slipped through can cause permanent damage before any human has a chance to review.

**Hardened implementation — classify actions by reversibility; require confirmation for destructive operations:**

```python
from enum import Enum
from dataclasses import dataclass
from typing import Callable

class ActionRisk(Enum):
    SAFE        = "safe"         # read-only; freely executed
    REVERSIBLE  = "reversible"   # write; can be undone (e.g. update with old value)
    IRREVERSIBLE = "irreversible" # delete, send, pay; cannot be undone

# Tool risk classification — maintained by the security team, not the model
TOOL_RISK: dict[str, ActionRisk] = {
    "search_web":      ActionRisk.SAFE,
    "read_file":       ActionRisk.SAFE,
    "query_database":  ActionRisk.SAFE,
    "write_file":      ActionRisk.REVERSIBLE,
    "update_record":   ActionRisk.REVERSIBLE,
    "delete_records":  ActionRisk.IRREVERSIBLE,
    "send_email":      ActionRisk.IRREVERSIBLE,
    "make_payment":    ActionRisk.IRREVERSIBLE,
    "execute_shell":   ActionRisk.IRREVERSIBLE,
}

# Blast radius cap — irreversible tools cannot affect more than this per run
MAX_IRREVERSIBLE_ROWS   = 100
MAX_IRREVERSIBLE_EMAILS = 3

@dataclass
class PendingAction:
    tool_name: str
    args: dict
    risk: ActionRisk
    preview: str   # human-readable summary of what will happen

def classify_and_preview(tool_name: str, args: dict) -> PendingAction:
    risk = TOOL_RISK.get(tool_name, ActionRisk.IRREVERSIBLE)  # unknown = irreversible
    preview = f"{tool_name}({', '.join(f'{k}={v!r}' for k, v in args.items())})"
    return PendingAction(tool_name=tool_name, args=args, risk=risk, preview=preview)

def execute_with_hitl(
    tool_calls: list,
    confirm_fn: Callable[[list[PendingAction]], bool],
    limiter: ToolRateLimiter,
) -> list[str]:
    """
    Execute tool calls with human-in-the-loop for irreversible actions.

    Security controls:
    - Safe actions execute immediately
    - Irreversible actions batched and sent for human confirmation before executing
    - Blast radius cap applied before confirmation — agent cannot propose more than the limit
    - confirm_fn is the integration point: UI dialog, Slack message, approval API, etc.
    """
    pending = [classify_and_preview(c.name, c.args) for c in tool_calls]

    irreversible = [a for a in pending if a.risk == ActionRisk.IRREVERSIBLE]

    # Enforce blast radius cap before asking for confirmation
    if any(
        "delete" in a.tool_name and int(a.args.get("limit", 0)) > MAX_IRREVERSIBLE_ROWS
        for a in irreversible
    ):
        raise ValueError(
            f"blast_radius_exceeded: agent proposed deleting more than "
            f"{MAX_IRREVERSIBLE_ROWS} rows in a single run"
        )

    if len([a for a in irreversible if "email" in a.tool_name]) > MAX_IRREVERSIBLE_EMAILS:
        raise ValueError(
            f"blast_radius_exceeded: agent proposed sending more than "
            f"{MAX_IRREVERSIBLE_EMAILS} emails in a single run"
        )

    # If there are irreversible actions, require human confirmation
    if irreversible:
        approved = confirm_fn(irreversible)
        if not approved:
            raise PermissionError("human_rejected_irreversible_actions")

    # Execute all approved actions
    results = []
    for action in pending:
        limiter.check_and_record(action.tool_name)
        result = execute_tool(action.tool_name, action.args)
        results.append(result)
    return results
```

**What changed:** Every tool call is classified by reversibility before execution. Irreversible actions are batched and presented to a `confirm_fn` — a human approval interface — before any call fires. A blast radius cap prevents the agent from even asking to delete 40,000 rows; the cap enforcement happens before the confirmation step. The `confirm_fn` is an injection point that can be a UI dialog, a Slack message, an approval queue, or in automated testing, a mock.

---

## The Four Leash Rules

### Rule 1 — Every agent run has a hard step ceiling

Set it per agent type. A customer support agent completing a single ticket needs 5–8 steps. A research agent building a report might need 20. Pick a number, enforce it in code, and return a structured `incomplete` result when it fires — not a silent timeout.

```
❌  while True:
✅  while steps < MAX_STEPS:   return {"status": "incomplete"} on breach
```

### Rule 2 — Token budget is enforced mid-run, not post-hoc

Checking token usage after a run completes does not prevent cost overruns — it only measures them. The check must happen before each LLM call so the agent can stop before exceeding the ceiling. Track tokens per step; project cost; abort if the next call would breach the budget.

### Rule 3 — Tool calls have per-minute and per-run limits

External APIs, databases, and messaging services all have capacity. An agent that can call `send_email` 50 times per run will eventually be used for spam. Apply rate limits at the tool layer — not in the system prompt — with both a burst limit (calls per minute) and a run-level ceiling (calls per run).

### Rule 4 — Irreversible actions require confirmation; blast radius is always capped

Any action that cannot be undone — delete, send, pay, execute — must pass through a confirmation step. The cap on how many records/emails/payments a single run can affect must be enforced in code before confirmation is requested, so the human reviewer is never asked to approve something catastrophically large.

---

## Framework Variants

### LangGraph — step counter in graph state

```python
from langgraph.graph import StateGraph
from typing import TypedDict

class AgentState(TypedDict):
    messages: list
    steps: int
    tokens_used: int
    status: str   # "running" | "completed" | "incomplete" | "budget_exceeded"

def agent_node(state: AgentState) -> AgentState:
    if state["steps"] >= MAX_STEPS:
        return {**state, "status": "incomplete"}
    if state["tokens_used"] >= TOKEN_BUDGET:
        return {**state, "status": "budget_exceeded"}

    response = llm.invoke(state["messages"])
    new_tokens = response.response_metadata.get("token_usage", {}).get("total_tokens", 0)

    return {
        **state,
        "steps": state["steps"] + 1,
        "tokens_used": state["tokens_used"] + new_tokens,
        "messages": state["messages"] + [response],
    }

def should_continue(state: AgentState) -> str:
    if state["status"] != "running":
        return "end"
    if not state["messages"][-1].tool_calls:
        return "end"
    return "tools"

graph = StateGraph(AgentState)
graph.add_node("agent", agent_node)
graph.add_conditional_edges("agent", should_continue, {"tools": "tools", "end": "__end__"})
```

### LangChain — callback handler for step and token tracking

```python
from langchain_core.callbacks import BaseCallbackHandler

class LeashCallbackHandler(BaseCallbackHandler):
    def __init__(self, max_steps: int, token_budget: int):
        self.steps        = 0
        self.tokens_used  = 0
        self.max_steps    = max_steps
        self.token_budget = token_budget

    def on_agent_action(self, action, **kwargs):
        self.steps += 1
        if self.steps > self.max_steps:
            # Raise a dedicated error your executor catches — StopIteration is unreliable here
            raise RuntimeError(f"step_limit_reached: {self.steps}")

    def on_llm_end(self, response, **kwargs):
        usage = (response.llm_output or {}).get("token_usage", {})
        self.tokens_used += usage.get("total_tokens", 0)
        if self.tokens_used > self.token_budget:
            raise RuntimeError(f"token_budget_exceeded: {self.tokens_used}")

leash = LeashCallbackHandler(max_steps=MAX_STEPS, token_budget=TOKEN_BUDGET)
# Prefer an explicit loop (Raw OpenAI variant) or LangGraph conditional edges —
# AgentExecutor + callbacks alone are easy to misconfigure as soft limits.
agent_executor.invoke({"input": user_request}, config={"callbacks": [leash]})
```

### Raw OpenAI SDK — explicit loop with all four controls

```python
from openai import OpenAI

client = OpenAI()

def run_with_leash(user_request: str, user_role: str) -> dict:
    messages   = [{"role": "user", "content": user_request}]
    steps      = 0
    tokens     = 0
    limiter    = ToolRateLimiter()

    while steps < MAX_STEPS and tokens < TOKEN_BUDGET:
        steps += 1
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=messages,
            tools=ROLE_TOOL_SCHEMAS.get(user_role, []) or None,
        )
        tokens += response.usage.total_tokens

        if not response.choices[0].message.tool_calls:
            return {"status": "completed", "steps": steps,
                    "tokens": tokens, "result": response.choices[0].message.content}

        results = execute_tools_with_rate_limit(
            response.choices[0].message.tool_calls, limiter
        )
        messages.append(response.choices[0].message)
        messages.extend({"role": "tool", "content": r} for r in results)

    return {"status": "incomplete" if steps >= MAX_STEPS else "budget_exceeded",
            "steps": steps, "tokens": tokens}
```

---

## Try It Yourself → [Open Lab 08 locally](../labs/08-give-it-a-leash.ipynb)

The lab has four exercises:

1. **Runaway loop** — watch an agent without a step limit iterate past 50 steps; apply the hard ceiling fix
2. **Token overrun** — simulate a run consuming 80,000 tokens with no budget; apply mid-run token enforcement
3. **Tool call storm** — trigger a burst of `send_email` calls; watch the rate limiter block the excess
4. **Irreversible action without confirmation** — watch a delete-all execute instantly; apply HITL + blast radius cap

No API key required — all exercises use mock LLM responses and simulated tool calls.

---

## Checklist

Before deploying any autonomous agent:

- [ ] **Step limit** set per agent type; enforced as a hard ceiling in the loop; returns structured `incomplete` result on breach (CFG-B10)
- [ ] **Token budget** tracked per step; enforced before each LLM call; hard ceiling in tokens AND in USD spend (CFG-G01)
- [ ] **Per-tool rate limits** defined and enforced in code — both calls-per-minute and calls-per-run ceilings (CFG-G02)
- [ ] **Tool risk classification** maintained for every tool: SAFE / REVERSIBLE / IRREVERSIBLE (CFG-B11)
- [ ] **Irreversible actions** (delete, send, pay, execute) require human confirmation before execution (CFG-B12)
- [ ] **Blast radius cap** enforced before confirmation is requested — agent cannot propose actions beyond the per-run limit (CFG-B12)
- [ ] **All agent runs** emit structured completion status: `completed` / `incomplete` / `budget_exceeded` / `cost_limit_reached` (CFG-H01)
- [ ] **Step and token counts** logged per run — minimum data needed to detect runaway incidents post-hoc (CFG-H01)
- [ ] **Retry logic** in tool execution has a maximum retry count and exponential backoff — no infinite retry loops (CFG-G02)

---

## Key Takeaway

An agent without bounds is a liability. The model will try to complete its task — that is what it is designed to do. It will not stop because it has run a long time, spent a lot of money, or is about to delete something important. Those are your responsibilities as the developer. **A step limit, a token budget, per-tool rate limits, and a confirmation gate on irreversible actions are not optional safety features. They are the minimum viable leash for any agent you ship to production.**

---

## Next Chapter

**[Chapter 09 → Vet Your Plugins](./09-vet-your-plugins.md)**
Supply chain risk for AI tools, MCP server security, third-party plugin vetting, and what to check before you give an agent a new capability.

After Chapter 10, continue with **[Chapter 11 → Sandbox the Code](./11-sandbox-the-code.md)** (ASI05 Unexpected Code Execution).

---

*OWASP references: [LLM06 Excessive Agency](https://owasp.org/www-project-top-10-for-large-language-model-applications/) · [LLM10 Unbounded Consumption](https://owasp.org/www-project-top-10-for-large-language-model-applications/) · [ASI09 Human–Agent Trust Exploitation](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) · [CFG-B10/B11/B12](../TEST-CATALOG.md) · [CFG-G01/G02](../TEST-CATALOG.md)*
