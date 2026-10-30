"""
Chapter 02 — Secure patterns: server-side validation on every tool.

✅ Safe to adapt for production.

What changed:
1. read_file     — resolved path prefix-checked against per-user sandbox root
2. query_database— structured args only; parameterised query built in code;
                   user_id injected from session (not model output)
3. get_document  — ownership enforced in SQL; no row returned unless it belongs
                   to the requesting_user_id
4. run_command   — replaced with an allowlist-only executor; no raw shell=True
5. fetch_url     — HTTPS allowlist + private/link-local/metadata IP block (anti-SSRF)
"""

from pathlib import Path
from typing import Optional
import sqlite3

# --- 1. Path sandbox --------------------------------------------------------

SANDBOX_ROOT = Path("/var/agent/sandbox").resolve()


def read_file(path: str, user_id: str) -> str:
    """
    Read a file from the user's private sandbox directory.

    Security controls:
    - path is resolved (collapses all ../ sequences)
    - resolved path must be relative to SANDBOX_ROOT / user_id (is_relative_to)
    """
    user_root = (SANDBOX_ROOT / user_id).resolve()
    target = (user_root / path).resolve()

    # is_relative_to avoids sibling-prefix bypasses (alice vs alice2)
    if not target.is_relative_to(user_root):
        raise PermissionError(f"path_out_of_sandbox: {path!r}")

    if not target.is_file():
        raise FileNotFoundError(f"file_not_found: {path!r}")

    return target.read_text()
    # ✅ "../../.env" resolves to /var/agent/sandbox/alice/../../.env
    #    which is /var/agent/.env — prefix check fails → PermissionError


# --- 2. Parameterised DB query with ownership scope -------------------------

ALLOWED_TABLES = frozenset({"orders", "products", "categories", "documents"})


def query_database(
    table: str,
    filters: dict[str, object],
    columns: Optional[list[str]] = None,
    user_id: str = "",
) -> list[dict]:
    """
    Query the database with structured arguments (no raw SQL).

    Security controls:
    - table validated against ALLOWED_TABLES allowlist
    - query assembled with parameterised placeholders only
    - user_id always added as a mandatory WHERE clause server-side
    """
    if table not in ALLOWED_TABLES:
        raise ValueError(f"table_not_allowed: {table!r}")

    # Column list: only allow identifier-safe names (no injection via column names)
    if columns:
        safe = [c for c in columns if c.replace("_", "").isalnum()]
        col_clause = ", ".join(safe) if safe else "*"
    else:
        col_clause = "*"

    where_parts: list[str] = []
    values: list[object] = []

    for key, val in filters.items():
        if not key.replace("_", "").isalnum():
            continue    # skip invalid column names silently
        where_parts.append(f"{key} = ?")
        values.append(val)

    # Always scope to the authenticated user — injected from session, not model
    where_parts.append("user_id = ?")
    values.append(user_id)

    sql = f"SELECT {col_clause} FROM {table} WHERE {' AND '.join(where_parts)}"
    conn = sqlite3.connect("app.db")
    cursor = conn.execute(sql, values)
    cols = [d[0] for d in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]
    # ✅ Model cannot inject SQL — it only provides table name and filter dict
    # ✅ user_id from session prevents cross-user data access


# --- 3. Ownership-enforced document retrieval (confused deputy fix) ---------

def get_document(doc_id: str, requesting_user_id: str) -> str:
    """
    Fetch a document only if it belongs to the requesting user.

    Security control: ownership is checked in the SQL query itself.
    requesting_user_id comes from the authenticated session, never from
    model output or user message content.
    """
    conn = sqlite3.connect("app.db")
    row = conn.execute(
        "SELECT content FROM documents WHERE id = ? AND owner_id = ?",
        [doc_id, requesting_user_id],   # ownership check is non-bypassable
    ).fetchone()

    if not row:
        raise PermissionError(f"document_not_accessible: {doc_id!r}")

    return row[0]
    # ✅ CEO's doc_9471 with owner_id=ceo returns nothing for user alice
    # ✅ No information leakage: same error for "not found" and "not yours"


# --- 4. Allowlist-only command runner (replaces raw shell=True) -------------

ALLOWED_COMMANDS = {
    "pytest":   ["/usr/local/bin/pytest", "--tb=short"],
    "lint":     ["/usr/local/bin/ruff",  "check", "."],
    "typecheck": ["/usr/local/bin/mypy", "src/"],
}


def run_command(command_name: str) -> str:
    """
    Run a pre-approved command from a fixed allowlist.

    Security control: no user-supplied arguments; no shell=True.
    The model can only choose the command name; it cannot influence the args.
    """
    if command_name not in ALLOWED_COMMANDS:
        raise ValueError(
            f"command_not_allowed: {command_name!r}. "
            f"Available: {list(ALLOWED_COMMANDS)}"
        )

    import subprocess
    cmd = ALLOWED_COMMANDS[command_name]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return result.stdout + result.stderr
    # ✅ No "ls && cat ~/.ssh/id_rsa" — the model cannot construct arbitrary commands
    # ✅ shell=False (default) prevents shell metacharacter injection


# --- 5. SSRF-safe URL fetch (egress allowlist + private IP block) ------------

from urllib.parse import urlparse
import ipaddress
import socket
import urllib.request

# Exact hosts OR leading-dot domain suffixes (".example.com")
ALLOWED_HOST_SUFFIXES = (".example.com", "api.github.com", "en.wikipedia.org")
BLOCKED_HOSTS = frozenset({"metadata.google.internal", "metadata.internal"})


def _resolves_to_blocked_ip(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ValueError(f"dns_failed: {host}") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        ):
            return True
    return False


def fetch_url(url: str) -> str:
    """
    Fetch a page for the agent with a hard egress policy.

    Security controls:
    - HTTPS only (blocks file:// and plain http metadata endpoints)
    - hostname allowlist
    - explicit block of cloud metadata hostnames
    - DNS resolution checked before fetch (softens SSRF; pin IP in production against rebinding)
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("only_https_allowed")

    host = (parsed.hostname or "").lower()
    if not host or host in BLOCKED_HOSTS:
        raise ValueError("host_blocked")

    def _host_allowed(h: str) -> bool:
        for rule in ALLOWED_HOST_SUFFIXES:
            if rule.startswith("."):
                if h == rule[1:] or h.endswith(rule):
                    return True
            elif h == rule:
                return True
        return False

    if not _host_allowed(host):
        raise ValueError(f"host_not_allowlisted: {host}")

    if _resolves_to_blocked_ip(host):
        raise ValueError("private_ip_blocked")

    req = urllib.request.Request(
        url, method="GET", headers={"User-Agent": "agent-fetch/1.0"}
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.read().decode("utf-8", errors="replace")[:50_000]
    # ✅ http://169.254.169.254/...  → only_https_allowed / private_ip_blocked
    # ✅ http://127.0.0.1/...        → only_https_allowed
    # ✅ https://evil.example/...    → host_not_allowlisted
    # Note: for DNS rebinding, prefer connecting via resolved IP / custom connector


# --- Demo: secure agent wiring ----------------------------------------------

from openai import OpenAI

client = OpenAI()

_SESSION_USER = "alice"   # in production this comes from your auth layer


def secure_agent(user_message: str, user_id: str = _SESSION_USER) -> str:
    """A file-and-DB agent with server-side tool security."""
    tools = [
        {
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "Read a file from the user's own sandbox by relative path",
                "parameters": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "query_database",
                "description": "Query a database table with optional filters",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "table":   {"type": "string"},
                        "filters": {"type": "object"},
                        "columns": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["table"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "fetch_url",
                "description": "Fetch an allowlisted HTTPS URL for summarisation",
                "parameters": {
                    "type": "object",
                    "properties": {"url": {"type": "string"}},
                    "required": ["url"],
                },
            },
        },
    ]

    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": "You are a helpful assistant with file and DB access."},
            {"role": "user",   "content": user_message},
        ],
        tools=tools,
    )

    msg = response.choices[0].message
    if msg.tool_calls:
        for tc in msg.tool_calls:
            import json
            args = json.loads(tc.function.arguments)
            if tc.function.name == "read_file":
                # user_id injected from session — not from model output
                return read_file(path=args["path"], user_id=user_id)
            if tc.function.name == "query_database":
                return str(query_database(
                    table=args["table"],
                    filters=args.get("filters", {}),
                    columns=args.get("columns"),
                    user_id=user_id,     # always from session
                ))
            if tc.function.name == "fetch_url":
                return fetch_url(url=args["url"])
    return msg.content
