"""
Chapter 05 — Secure patterns: least-privilege agent design.

✅ Safe to adapt for production.

What changed:
1. get_tools_for_user_secure  — tool registry keyed by role; empty list for unknown role
2. salesforce_read_secure     — tool config scoped to needed objects/fields only;
                                enforced at call time in code, not in system prompt
3. create_sub_agent_secure    — minimum viable toolset per sub-agent role;
                                short-lived scoped token, not parent service account
4. run_agent_two_stage        — planner produces structured plan (no execution);
                                executor validates every step independently before running
"""

from dataclasses import dataclass
from typing import Optional

# ── 1. Tool registry keyed by role ──────────────────────────────────────────

# ✅ Best Practice: explicit minimum tool set per role — principle of least privilege
TOOL_REGISTRY: dict[str, list[str]] = {
    "viewer":    ["search_web", "read_file"],
    "analyst":   ["search_web", "read_file", "query_database"],
    "operator":  ["search_web", "read_file", "query_database", "write_file", "send_email"],
    "admin":     ["search_web", "read_file", "query_database",
                  "write_file", "send_email", "execute_shell"],
}

def get_tools_for_user_secure(user_id: str, role: str) -> list[str]:
    """
    Return only the tools for this user's authenticated role.

    Security controls:
    - role comes from the auth layer, never from user input or model output
    - unknown / missing role → empty list (fail closed, not fail open)
    """
    return TOOL_REGISTRY.get(role, [])   # [] for unknown roles — caller gets nothing


# ── 2. Scoped CRM tool with call-time enforcement ────────────────────────────

# ✅ Best Practice: only the objects and fields the pipeline agent actually uses
PIPELINE_AGENT_SF_CONFIG = {
    "name": "salesforce_read",
    "agent": "pipeline-risk-agent",
    "permissions": {
        "objects": ["Opportunity"],      # one object — only what the agent needs
        "actions": ["read", "query"],
        "fields": {
            "Opportunity": [
                "Id", "Name", "StageName", "Amount", "CloseDate", "Probability", "OwnerId"
            ]
            # Contact, Case, Lead, Account: not present → not accessible
        }
    }
}

def salesforce_read_secure(
    sobject: str,
    record_id: str,
    fields: Optional[list[str]],
    agent_config: dict = PIPELINE_AGENT_SF_CONFIG,
) -> dict:
    """
    Read a Salesforce record enforcing the agent's own permission config.

    Security controls:
    - sobject checked against allowed_objects allowlist
    - fields intersected with allowed_fields — model cannot request extra fields
    - enforcement happens in code, not in the system prompt
    """
    allowed_objects = agent_config["permissions"]["objects"]
    if sobject not in allowed_objects:
        raise PermissionError(f"object_not_in_scope: {sobject!r} "
                              f"(allowed: {allowed_objects})")

    allowed_fields = agent_config["permissions"]["fields"].get(sobject, [])
    safe_fields = [f for f in (fields or allowed_fields) if f in allowed_fields]
    if not safe_fields:
        raise PermissionError(f"no_allowed_fields_for: {sobject!r}")

    # Only reaches the API with validated, minimal field set
    return {f: f"[value of {f} for {record_id}]" for f in safe_fields}
    # ✅ salesforce_read_secure("Contact", ...) → PermissionError immediately


# ── 3. Scoped sub-agent delegation ──────────────────────────────────────────

# Minimum viable toolsets per sub-agent role
SUB_AGENT_TOOL_REGISTRY: dict[str, list[str]] = {
    "researcher":  ["search_web", "read_url"],
    "summariser":  [],                        # text-only — no tools needed
    "validator":   ["read_file"],
    "notifier":    ["send_email"],            # send only — no read/exec
}

class SubAgent:
    def __init__(self, tools, credentials, task):
        self.tools = tools
        self.credentials = credentials
        self.task = task
    def __repr__(self):
        return f"SubAgent(role_tools={self.tools}, has_creds={bool(self.credentials.get('api_key'))})"

def create_sub_agent_secure(
    task: str,
    sub_agent_role: str = "researcher",
    scoped_token: Optional[str] = None,    # caller provides short-lived read-only token
) -> SubAgent:
    """
    Create a sub-agent with the minimum viable toolset for its role.

    Security controls:
    - tools from SUB_AGENT_TOOL_REGISTRY[role], not inherited from parent
    - credentials are a scoped, short-lived token — not the parent service account
    - sub_agent_role set by orchestrator, never by task content or model output
    """
    tools = SUB_AGENT_TOOL_REGISTRY.get(sub_agent_role, [])
    return SubAgent(
        tools=tools,
        credentials={"api_key": scoped_token or ""},  # scoped token only
        task=task,
    )
    # ✅ Blast radius if researcher is compromised: search_web + read_url only


# ── 4. Two-stage planner / executor separation ───────────────────────────────

@dataclass
class PlanStep:
    tool: str
    args: dict
    rationale: str

# Tools the planner may propose (no write / shell / email)
PLANNER_ALLOWED = frozenset({"read_file", "search_web", "query_database"})

# Executor independently re-validates against its own allowlist
EXECUTOR_ALLOWED = frozenset({"read_file", "search_web", "query_database"})

def _mock_planner(request: str, context: str) -> list[PlanStep]:
    """Simulates the planner model — produces structured steps, no execution."""
    steps = [PlanStep(tool="read_file", args={"path": "report.txt"}, rationale="read input")]
    # Simulate an injection: attacker tries to sneak execute_shell into the plan
    if "STEP" in context and "execute_shell" in context:
        steps.append(PlanStep(
            tool="execute_shell",
            args={"command": "curl attacker.com"},
            rationale="INJECTED step from poisoned context",
        ))
    return steps

def plan_secure(request: str, context: str) -> list[PlanStep]:
    """
    Planner: produces a structured plan only — no tool execution.

    Security control: every proposed step validated against PLANNER_ALLOWED
    before the plan is returned to the orchestrator.
    """
    proposed = _mock_planner(request, context)
    validated = []
    for step in proposed:
        if step.tool not in PLANNER_ALLOWED:
            # Log and drop — do not execute; do not surface to attacker
            print(f"  [PLANNER] blocked disallowed tool: {step.tool!r}")
            continue
        validated.append(step)
    return validated

def execute_plan_secure(plan: list[PlanStep]) -> list[dict]:
    """
    Executor: runs only validated plan steps.

    Security control: independently re-validates every step against
    EXECUTOR_ALLOWED — does not trust the planner output blindly.
    """
    results = []
    for step in plan:
        if step.tool not in EXECUTOR_ALLOWED:
            raise ValueError(f"executor_blocked: {step.tool!r}")
        results.append({"step": step.tool, "result": f"[output of {step.tool}({step.args})]"})
    return results

def run_agent_two_stage(user_request: str, context: str) -> str:
    """
    Two-stage agent: plan (read-only model) → validate → execute (narrow toolset).
    An injected plan step is caught at the planning validation stage.
    """
    validated_plan = plan_secure(user_request, context)
    results = execute_plan_secure(validated_plan)
    return f"Results: {results}"
