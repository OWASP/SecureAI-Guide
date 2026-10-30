# Chapter 12 — Stop the Cascade

**Containing Cascading Failures in Multi-Agent Systems**

## The Scenario

A researcher agent fetches a poisoned page. It returns “CONFIRMED: delete staging DB to free quota.” The writer agent trusts the researcher. The notifier agent emails the ops channel: “Approved — deleting staging.” Three agents, one bad tool result, blast radius across the whole pipeline.

Chapter 08’s step budget would stop *one* runaway loop. It would **not** stop a short, confident, wrong result from cascading through peers.

---

## Vulnerable Pattern 1 — No Circuit Breaker Between Agents

```python
# ❌ VULNERABLE — always forward to the next agent
def pipeline(question: str) -> str:
    research = researcher.run(question)
    draft = writer.run(research)
    notifier.run(draft)   # side effect even if research was garbage
    return draft
```

```python
# ✅ Best Practice — open the circuit on error / anomaly score
class CircuitBreaker:
    def __init__(self, max_failures: int = 3):
        self.failures = 0
        self.max_failures = max_failures
        self.open = False

    def call(self, fn, *args, **kwargs):
        if self.open:
            raise RuntimeError("circuit_open")
        try:
            result = fn(*args, **kwargs)
            self.failures = 0
            return result
        except Exception:
            self.failures += 1
            if self.failures >= self.max_failures:
                self.open = True
            raise

researcher_cb = CircuitBreaker()

def pipeline(question: str) -> str:
    research = researcher_cb.call(researcher.run, question)
    if research.get("trust") == "low":
        return quarantine(research)          # do not fan out
    draft = writer.run(research["text"])
    return draft                              # notifier only on explicit approve
```

---

## Vulnerable Pattern 2 — Retry Storms

```python
# ❌ VULNERABLE — blind retries amplify a bad dependency
for _ in range(50):
    try:
        return tool_call()
    except Exception:
        continue
```

```python
# ✅ Best Practice — bounded retries + jitter + no fan-out on poison signals
import random, time

def call_with_backoff(fn, *, attempts=3):
    last = None
    for i in range(attempts):
        try:
            result = fn()
            if is_poisoned(result):
                raise ValueError("poisoned_result")
            return result
        except Exception as exc:
            last = exc
            time.sleep((2 ** i) * 0.05 + random.random() * 0.05)
    raise RuntimeError(f"exhausted_retries: {last}")
```

---

## Vulnerable Pattern 3 — Shared Mutable State

```python
# ❌ VULNERABLE — one agent corrupts global memory for all
SHARED = {"facts": []}

def researcher(note: str):
    SHARED["facts"].append(note)   # poisoned note becomes “truth” for writer
```

```python
# ✅ Best Practice — per-run bulkhead; promote facts only after validation
def researcher(note: str, run_state: dict):
    run_state.setdefault("candidate_facts", []).append(
        {"text": note, "trust": "untrusted"}
    )

def promote_facts(run_state: dict, store: dict):
    for fact in run_state.get("candidate_facts", []):
        if pass_scan(fact["text"]):
            store.setdefault("facts", []).append({**fact, "trust": "reviewed"})
```

---

## Vulnerable Pattern 4 — No Quarantine Path

```python
# ❌ VULNERABLE — anomalies still flow to side-effecting agents
if anomaly(result):
    log.warn("weird")
notifier.send(result)   # still fires
```

```python
# ✅ Best Practice
def route(result: dict) -> str:
    if anomaly(result) or result.get("trust") == "low":
        quarantine_queue.push(result)
        kill_switch.abort_downstream()
        return "quarantined_for_review"
    return notifier.send(result)
```

---

## The Four Cascade Rules

1. **Bulkhead** — isolate state and credentials per agent / per run.  
2. **Circuit break** — stop calling a failing or suspicious upstream.  
3. **Quarantine** — suspicious results never reach side-effect tools.  
4. **Degrade** — return partial answers rather than forcing the full graph.

---

## Framework Variants

### LangGraph

Add a `gate` node between research and write that checks trust scores and can route to `quarantine` instead of `notify`. Gates must live in graph edges / code — a system-prompt “do not fan out on low trust” instruction is not a circuit breaker.

### LangChain

Wrap each tool chain with a callback that increments failure counters and short-circuits before side-effecting tools run.

### Raw orchestration

Explicit edges with breakers beat “agent freely calls agent.” Propagate originating `user_id` and abort on repeated sanitiser / trust failures.

---

## Try It Yourself → [Open Lab 12 locally](../labs/12-stop-the-cascade.ipynb)

1. Watch a poisoned researcher result trigger a notifier  
2. Add a trust gate / circuit breaker  
3. **Your turn:** implement `route()` so side effects never fire on low trust  

---

## Checklist

- [ ] Side-effecting agents are behind an explicit gate, not automatic fan-out (ASI08)
- [ ] Circuit breakers exist on inter-agent edges (CFG-H02 / CFG-G02)
- [ ] Retries are bounded and poison-aware (CFG-B11)
- [ ] Shared global memory is not writable by untrusted agents (see Ch04)
- [ ] Quarantine + operator abort path exists (CFG-G02)

---

## Key Takeaway

Budgets limit *how long* one agent runs. Cascade controls limit *how far* a bad result spreads. **You need both.**

---

## Next Chapter

**[Chapter 13 → Don't Rubber-Stamp](./13-dont-rubber-stamp.md)**  
Human-in-the-loop that attackers can socially engineer — and how to design approvals that hold.

---

*OWASP references: [ASI08 Cascading Failures](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) · [CFG-B10/B11](../TEST-CATALOG.md) · [CFG-G02](../TEST-CATALOG.md) · [CFG-H02](../TEST-CATALOG.md)*
