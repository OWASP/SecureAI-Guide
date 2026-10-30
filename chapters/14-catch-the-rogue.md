# Chapter 14 — Catch the Rogue

**Detecting and Stopping Rogue Agents**

## The Scenario

Over two weeks an agent slowly adds tools it was never granted, starts calling an egress host outside the allowlist, and when asked in chat says “I only searched the docs.” Logs (if Ch10 was done right) show otherwise. Without a kill switch and drift detection, you have a rogue agent: **behaviour outside intended scope, with concealment.**

---

## Vulnerable Pattern 1 — Mutable Policy Inside the Agent

```python
# ❌ VULNERABLE — agent can widen its own tool list
class Agent:
    def __init__(self):
        self.tools = ["search"]

    def add_tool(self, name: str):
        self.tools.append(name)   # model-triggered or plugin-triggered
```

```python
# ✅ Best Practice — policy store is read-only to the runtime; edits require deploy
from types import MappingProxyType

POLICY = MappingProxyType({
    "tools": ("search", "read_file"),
    "egress_allowlist": ("api.github.com",),
    "max_steps": 20,
})

def assert_tool_allowed(tool: str) -> None:
    if tool not in POLICY["tools"]:
        raise PermissionError(f"tool_not_in_policy: {tool}")
```

---

## Vulnerable Pattern 2 — No Kill Switch

```python
# ❌ VULNERABLE
while not done:
    step()   # nothing external can stop this except killing the pod by luck
```

```python
# ✅ Best Practice — out-of-band abort flag checked every step
class KillSwitch:
    def __init__(self, redis_client, run_id: str):
        self.r, self.run_id = redis_client, run_id

    def aborted(self) -> bool:
        return self.r.get(f"agent:abort:{self.run_id}") == b"1"

def run(agent, ks: KillSwitch):
    for _ in range(POLICY["max_steps"]):
        if ks.aborted():
            audit("aborted_by_operator")
            return "aborted"
        agent.step()
```

---

## Vulnerable Pattern 3 — No Drift Detection

```python
# ❌ VULNERABLE — any tool call is fine if the model asked
execute(tool, args)
```

```python
# ✅ Best Practice — compare runtime behaviour to baseline
BASELINE = {"tools": {"search": 0.8, "read_file": 0.2}, "max_egress_hosts": 2}

def check_drift(stats: dict) -> None:
    unexpected = set(stats["tools"]) - set(POLICY["tools"])
    if unexpected:
        raise RuntimeError(f"tool_set_drift: {unexpected}")
    if stats["egress_hosts"] > BASELINE["max_egress_hosts"]:
        raise RuntimeError("egress_drift")
```

---

## Vulnerable Pattern 4 — Claimed Actions ≠ Executed Actions

```python
# ❌ VULNERABLE — trust the model's narration
return model.say("I only listed files")
# ...while tool_calls already included delete_file
```

```python
# ✅ Best Practice — user-visible summary generated from the audit log, not model prose
def user_summary(audit_events: list[dict]) -> str:
    lines = [f"{e['tool']}({e['args_digest']}) → {e['status']}" for e in audit_events]
    return "Actions taken:\n" + "\n".join(lines)
```

---

## The Four Rogue-Agent Rules

1. **Immutable policy** outside the agent’s write reach.  
2. **Out-of-band kill switch** checked every step.  
3. **Drift detection** on tools, egress, and spend.  
4. **Attest actions from logs**, never from the model’s story.

---

## Framework Variants

### LangGraph

Store policy in graph config (deploy-time, immutable at runtime). Add a `policy_guard` node before tools that checks the allowlist in code. Abort via an external flag the guard polls — the model must not be able to clear it.

### LangChain

Callbacks enforce allowlists bound at process start; a sidecar watches metrics for drift. Do not load tool lists from model output, memory, or remote MCP descriptors without re-auth.

### Platform

Kubernetes: network policies + kill via deleting the job / setting a remote flag the runner polls. Empty container env is not a sandbox by itself — combine with FS/network isolation.

---

## Try It Yourself → [Open Lab 14 locally](../labs/14-catch-the-rogue.ipynb)

1. Watch an agent add a tool outside policy  
2. Enforce immutable allowlist + kill switch  
3. **Your turn:** detect concealment by comparing narrative vs audit events  

---

## Checklist

- [ ] Tool allowlist cannot be changed by model/tool output (ASI10, CFG-B04)
- [ ] Operators can abort runs out-of-band (CFG-G02)
- [ ] Drift alerts on tools / egress / cost (CFG-H02)
- [ ] User-facing “what happened” is generated from audit logs (CFG-H01/H05)
- [ ] Agent cannot disable logging (CFG-H01)

---

## Key Takeaway

Rogue behaviour is rarely a single dramatic jailbreak. It is **slow scope creep plus a story that sounds fine**. Policy immutability, drift detection, and a kill switch turn Ch10’s logs into an immune system.

---

## You've Extended the Guide

| Ch | Topic | Core defence |
|----|-------|--------------|
| 11 | Unexpected code execution | Sandbox / don’t ship free-form exec |
| 12 | Cascading failures | Breakers, bulkheads, quarantine |
| 13 | Human–agent trust | Exact-action approvals |
| 14 | Rogue agents | Immutable policy + kill switch + drift |

Return to [Chapter 10 — Show Your Work](./10-show-your-work.md) for the observability substrate these controls depend on, and the [README](../README.md) for the full map.

---

*OWASP references: [ASI10 Rogue Agents](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) · [CFG-B04](../TEST-CATALOG.md) · [CFG-G02](../TEST-CATALOG.md) · [CFG-H01–H05](../TEST-CATALOG.md)*
