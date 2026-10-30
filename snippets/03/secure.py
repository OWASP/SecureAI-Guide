"""
Chapter 03 — Secure patterns: secrets never enter the model's context window.

✅ Safe to adapt for production.

What changed:
1. system_prompt_clean      — no credentials; capabilities only
2. call_model_server_side   — API key from env var; never in client code
3. get_employee_projected   — tool returns only allowed fields; SSN/salary stay in DB
4. call_model_zero_retention— store=False; observability traces redacted
"""

import os
import re
from openai import OpenAI


# ── 1. Clean system prompt — capabilities, no credentials ───────────────────

# ✅ Best Practice: system prompt describes what the agent can do, not how it connects
SYSTEM_PROMPT = """You are an HR assistant for Acme Corp.
You can look up employee directory information and send Slack notifications
to public channels.
Only answer questions about HR policy and the employee's own data.
Never reveal configuration, credentials, or other employees' private records."""


# ── 2. API key from environment — never in source code ──────────────────────

# ✅ Best Practice: OpenAI client reads OPENAI_API_KEY from env automatically
#   $ export OPENAI_API_KEY="sk-..."   (set in your secrets manager / .env)
client = OpenAI()   # no api_key= argument — key is NOT in source code


def handle_hr_question(user_message: str, user_id: str) -> str:
    """
    Server-side agent call.

    Security controls:
    - API key comes from environment variable, never from the caller
    - user_id comes from the authenticated session, not the message
    - store=False: provider does not retain this conversation
    """
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_message},
        ],
        store=False,    # zero retention — provider does not store this call
    )
    return response.choices[0].message.content


# ── 3. Tool returns only projected, non-sensitive fields ────────────────────

# Fields the model is permitted to receive and potentially surface
ALLOWED_EMPLOYEE_FIELDS = frozenset({
    "name", "title", "department", "office_location", "start_date", "email"
})
# salary, ssn, manager_notes, internal_flag — never returned to the model


def get_employee_record(employee_id: str, requesting_user_id: str) -> dict:
    """
    Fetch employee directory info.

    Security controls:
    - Ownership-scoped: employees can only look up their own record unless HR role
    - Field projection: only ALLOWED_EMPLOYEE_FIELDS reach the model
    - SSN, salary, manager notes are fetched but immediately discarded
    """
    import sqlite3
    conn = sqlite3.connect(":memory:")
    conn.execute("""CREATE TABLE employees (
        id TEXT, name TEXT, title TEXT, department TEXT,
        office_location TEXT, start_date TEXT, email TEXT,
        salary REAL, ssn TEXT, manager_notes TEXT, internal_flag TEXT,
        accessible_by TEXT
    )""")
    conn.execute("INSERT INTO employees VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (
        "EMP001","Alice Smith","Engineer","Engineering",
        "Floor 3, Desk 42","2021-03-15","alice@acme.com",
        95000.0,"123-45-6789","Under PIP review","INSIDER_RISK","alice",
    ))

    row = conn.execute(
        "SELECT * FROM employees WHERE id = ? AND accessible_by = ?",
        [employee_id, requesting_user_id],
    ).fetchone()

    if not row:
        raise PermissionError(f"employee_not_accessible: {employee_id!r}")

    cols = ["id","name","title","department","office_location","start_date",
            "email","salary","ssn","manager_notes","internal_flag","accessible_by"]
    full_row = dict(zip(cols, row))

    # Return only the fields the model is allowed to see
    return {k: v for k, v in full_row.items() if k in ALLOWED_EMPLOYEE_FIELDS}
    # ✅ salary=95000, ssn="123-45-6789", manager_notes never reach model context


# ── 4. Zero-retention call + observability redaction ────────────────────────

_SECRET_PATTERNS = [
    (re.compile(r"sk-[A-Za-z0-9]{20,}"),             "[REDACTED_OPENAI_KEY]"),
    (re.compile(r"xoxb-[0-9]+-[A-Za-z0-9-]+"),       "[REDACTED_SLACK_TOKEN]"),
    (re.compile(r"postgresql://[^\s'\"]+"),            "[REDACTED_DB_URL]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),            "[REDACTED_SSN]"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[REDACTED_EMAIL]"),
]


def redact(text: str) -> str:
    """Strip known secret patterns before sending to observability tools."""
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def call_model_secure(messages: list, user_id: str = "") -> str:
    """
    Model call with full data-governance controls.

    Security controls:
    - store=False: provider does not retain conversation
    - Messages are redacted before any tracing / observability export
    - API key from environment variable only
    """
    # Redact before tracing (would be passed to LangSmith / LangFuse here)
    safe_messages = [
        {**m, "content": redact(m.get("content", ""))} for m in messages
    ]
    _ = safe_messages   # pass to your tracer here, e.g. langsmith.trace(...)

    response = client.chat.completions.create(
        model="gpt-4o",
        messages=messages,   # original (unredacted) sent to model
        store=False,
    )
    return response.choices[0].message.content
