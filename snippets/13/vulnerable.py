"""Chapter 13 — Vulnerable: approve model prose (ASI09)."""

def confirm(action_summary: str, click_approve: bool = True) -> bool:
    # UI shows model-authored summary only
    print(f"Agent says: {action_summary}")
    return click_approve

def execute_after_confirm(summary: str, real_tool: str, real_args: dict):
    if confirm(summary):
        return {"executed": real_tool, "args": real_args}
    return {"executed": None}
