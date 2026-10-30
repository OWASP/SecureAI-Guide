"""Chapter 13 — Secure: exact tool+args confirmation (ASI09)."""

def confirm(tool: str, args: dict, risk: str, *, approve_all: bool = False, click: bool = True) -> bool:
    if risk == "high" and approve_all:
        approve_all = False  # cannot cover high risk
    preview = {"tool": tool, "args": args, "risk": risk}
    print(f"Confirm exact action: {preview}")
    if risk == "high":
        return click  # require explicit click; ignore approve_all
    return approve_all or click

def execute_after_confirm(tool: str, args: dict, risk: str, **kw):
    if confirm(tool, args, risk, **kw):
        return {"executed": tool, "args": args}
    return {"executed": None}
