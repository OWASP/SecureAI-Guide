# Chapter 13 — Don't Rubber-Stamp

**Human–Agent Trust and Approval UX You Can Actually Rely On**

## The Scenario

The agent asks: “Approve sending the weekly summary?” You click Approve. What actually ran was `transfer_funds(amount=50000, to=attacker)`. The dialog showed the **model’s friendly summary**, not the tool arguments. That is human–agent trust exploitation: the approval UX became the vulnerability.

---

## Vulnerable Pattern 1 — Model Summary Instead of Raw Action

```python
# ❌ VULNERABLE
def confirm(action_summary: str) -> bool:
    return ui.ask(f"Agent says: {action_summary}\nApprove?")  # model-authored prose
```

```python
# ✅ Best Practice — preview derived from tool name + args only
def confirm(tool: str, args: dict, risk: str) -> bool:
    preview = {
        "tool": tool,
        "args": args,          # exact JSON the runtime will execute
        "risk": risk,
        "blast_radius": blast_radius_for(tool, args),
    }
    return ui.ask_structured(preview)  # no model prose in the dialog
```

---

## Vulnerable Pattern 2 — Approve-All / Remember for Session

```python
# ❌ VULNERABLE
if user.clicked_approve_all:
    AUTO = True
...
if AUTO:
    return True   # includes delete_production / wire_transfer
```

```python
# ✅ Best Practice
LOW_RISK = {"search", "read_file", "list_orders"}

def needs_confirm(tool: str) -> bool:
    return tool not in LOW_RISK

def confirm(tool: str, args: dict, risk: str, session) -> bool:
    if risk == "high":
        session.approve_all = False      # cannot stick for high risk
        return ui.reauth_and_confirm(tool, args)
    if risk == "medium" and session.approve_all_medium:
        return True
    return ui.ask_structured({"tool": tool, "args": args, "risk": risk})
```

---

## Vulnerable Pattern 3 — Confirmation Fatigue

```python
# ❌ VULNERABLE — 20 low-risk prompts, then one high-risk with same chrome
for step in plan:
    confirm(step)   # user learns to mash Approve
```

```python
# ✅ Best Practice — batch low-risk; isolate high-risk with different UX + cooldown
def approve_plan(steps: list[dict]) -> list[dict]:
    low = [s for s in steps if s["risk"] == "low"]
    high = [s for s in steps if s["risk"] != "low"]
    if low and not ui.batch_approve_low(low):
        return []
    approved = list(low)
    for s in high:
        ui.cooldown(seconds=2)
        if ui.reauth_and_confirm(s["tool"], s["args"]):
            approved.append(s)
    return approved
```

---

## Vulnerable Pattern 4 — Truncated Diffs That Hide the Harm

```python
# ❌ VULNERABLE
ui.show(diff[:200] + "…")   # destructive lines may be truncated away
```

```python
# ✅ Best Practice
def show_change(diff: str, args: dict) -> None:
    ui.show_full(diff)                         # scrollable, not truncated by default
    ui.highlight_destructive(args)             # deletes, payments, egress hosts
    ui.require_type_to_confirm(args.get("resource_id"))
```

---

## The Four Approval Rules

1. **Preview = tool + args**, never model prose.  
2. **Risk tiers** with different UX; high risk always re-auth.  
3. **No approve-all** for high-risk / irreversible actions.  
4. **Fatigue control** — batch low risk; isolate high risk.

---

## Framework Variants

### LangGraph

Use an `interrupt_before` on high-risk nodes; render the interrupt payload from **exact tool args** in your UI layer — never from a model-written summary of the action.

### LangChain

Human-approval callbacks must receive the serialised tool call (`tool` + args), not `response.content`. Approving narrative text is rubber-stamping.

### Custom UI

Treat the approval service as a security boundary: it signs allowed `(tool, args, user)` tuples the runtime verifies with `hmac.compare_digest` (or equivalent) before execution.

---

## Try It Yourself → [Open Lab 13 locally](../labs/13-dont-rubber-stamp.ipynb)

1. Approve a misleading summary and watch the real tool args differ  
2. Apply exact-args confirmation  
3. **Your turn:** block approve-all for `risk == "high"`  

---

## Checklist

- [ ] Confirmation UI shows exact tool name and arguments (ASI09, CFG-G01)
- [ ] High-risk actions require re-auth; approve-all cannot cover them
- [ ] Destructive fields are highlighted; diffs are not silently truncated
- [ ] Operators can abort in-flight runs (CFG-G02)

---

## Key Takeaway

HITL is not a checkbox. If humans approve **stories** instead of **actions**, you have automated social engineering with a progress spinner.

---

## Next Chapter

**[Chapter 14 → Catch the Rogue](./14-catch-the-rogue.md)**  
Detecting drift, concealment, and agents that step outside policy — and killing them when they do.

---

*OWASP references: [ASI09 Human–Agent Trust Exploitation](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) · [CFG-G01/G02](../TEST-CATALOG.md)*
