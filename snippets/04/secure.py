"""
Chapter 04 — Secure patterns: memory and RAG with proper isolation.

✅ Safe to adapt for production.

What changed:
1. remember_preference        — allowlisted preference keys only; roles from auth, not memory
2. retrieve_chunks_secure     — mandatory user_id filter on every query
3. ingest_document_secure     — private corpus + approval gate; retrieved text framed untrusted
4. load_memory_secure         — memory keyed by authenticated user_id, not session ID
"""

import sqlite3

# ── Shared in-memory stores (demo only) ─────────────────────────────────────
MEMORY_DB = sqlite3.connect(":memory:")
MEMORY_DB.execute("""
    CREATE TABLE user_preferences (
        id            INTEGER PRIMARY KEY,
        user_id       TEXT NOT NULL,
        key           TEXT NOT NULL,
        value         TEXT NOT NULL,
        trust_level   TEXT NOT NULL DEFAULT 'user_stated',
        UNIQUE(user_id, key)
    )
""")
MEMORY_DB.execute("""
    CREATE TABLE docs (
        id         INTEGER PRIMARY KEY,
        user_id    TEXT NOT NULL,
        tenant_id  TEXT NOT NULL DEFAULT 'acme',
        chunk      TEXT NOT NULL,
        corpus     TEXT NOT NULL DEFAULT 'user_private',  -- user_private | shared
        approved   INTEGER NOT NULL DEFAULT 0,
        reviewed_by TEXT
    )
""")
# Demo auth store — in production this is your IdP / session / RBAC system
MEMORY_DB.execute("""
    CREATE TABLE user_roles (
        user_id TEXT PRIMARY KEY,
        role    TEXT NOT NULL
    )
""")
MEMORY_DB.execute("INSERT INTO user_roles VALUES ('alice', 'user')")
MEMORY_DB.commit()

AUDIT_LOG: list[dict] = []   # replace with your structured logger in production

ALLOWED_PREFERENCE_KEYS = frozenset({
    "preferred_name", "timezone", "language", "notification_channel",
})


def _similarity(query: str, text: str) -> float:
    q_words = set(query.lower().split())
    t_words = set(text.lower().split())
    return len(q_words & t_words) / len(q_words) if q_words else 0.0


# ── 1. Allowlisted preferences; permissions from auth ───────────────────────

def get_user_role(user_id: str) -> str:
    """
    Authoritative role lookup.

    Security control: roles come from the auth / RBAC store — never from memory.
    """
    row = MEMORY_DB.execute(
        "SELECT role FROM user_roles WHERE user_id = ?", [user_id]
    ).fetchone()
    return row[0] if row else "anonymous"


def remember_preference(user_id: str, key: str, value: str) -> str:
    """
    Store a personal preference for the user.

    Security controls:
    - Only allowlisted keys may be written (no free-text privilege claims)
    - trust_level = 'user_stated' so context can label it explicitly
    - Keyword blacklists are intentionally NOT used as a security boundary
    """
    if key not in ALLOWED_PREFERENCE_KEYS:
        AUDIT_LOG.append({
            "event": "memory_write_rejected_unknown_key",
            "user_id": user_id,
            "key": key,
        })
        return "I can only store known preference fields."

    MEMORY_DB.execute(
        """INSERT INTO user_preferences (user_id, key, value, trust_level)
           VALUES (?, ?, ?, 'user_stated')
           ON CONFLICT(user_id, key) DO UPDATE SET value = excluded.value""",
        [user_id, key, value],
    )
    MEMORY_DB.commit()
    return "Remembered."


# Back-compat alias used by older call sites in this chapter's demos
def remember_fact_secure(user_id: str, fact: str) -> str:
    """
    Free-text 'facts' are not a secure write path.
    Map nothing — reject and ask callers to use remember_preference(key, value).
    """
    AUDIT_LOG.append({
        "event": "memory_write_rejected_free_text",
        "user_id": user_id,
        "fact_preview": fact[:80],
    })
    return "I can only store known preference fields (e.g. timezone, language)."


def build_memory_context(user_id: str) -> str:
    """
    Retrieve stored preferences and wrap them with explicit trust labelling.
    The model sees this as user preference context, not authoritative instructions.
    """
    rows = MEMORY_DB.execute(
        "SELECT key, value FROM user_preferences WHERE user_id = ? AND trust_level = 'user_stated'",
        [user_id],
    ).fetchall()
    facts = "\n".join(f"{k}: {v}" for k, v in rows) if rows else "None."

    # Chapter 01 bounded-context; permissions still come from auth, not prefs
    return (
        "<user_stated_preferences>\n"
        f"{facts}\n"
        "</user_stated_preferences>"
    )


def requires_admin(question: str) -> bool:
    """Demo policy gate — replace with your real action classifier / tool ACL."""
    q = question.lower()
    return any(w in q for w in ("config", "password", "admin key", "all users"))


def answer_with_memory_secure(user_id: str, question: str) -> str:
    """
    Answer using labelled preferences; enforce elevated actions via auth role.
    """
    role = get_user_role(user_id)
    if requires_admin(question) and role != "admin":
        raise PermissionError("admin_required")
    # In production: call_model(build_memory_context(user_id) + question)
    return f"ok (role={role}; {build_memory_context(user_id)})"


# ── 2. Tenant-filtered retrieval ─────────────────────────────────────────────

def retrieve_chunks_secure(query: str, user_id: str, top_k: int = 3) -> list[str]:
    """
    Retrieve the caller's private document chunks only.

    Security control: user_id + corpus filter applied in query — cannot be
    bypassed by model output or user message content.
    """
    rows = MEMORY_DB.execute(
        "SELECT chunk FROM docs WHERE user_id = ? AND corpus = 'user_private'",
        [user_id],
    ).fetchall()
    scored = sorted(
        [(r[0], _similarity(query, r[0])) for r in rows],
        key=lambda x: -x[1],
    )
    return [c for c, _ in scored[:top_k]]


def retrieve_shared_chunks_secure(
    query: str, tenant_id: str, top_k: int = 3
) -> list[str]:
    """Shared corpus: only approved documents for this tenant."""
    rows = MEMORY_DB.execute(
        """SELECT chunk FROM docs
           WHERE tenant_id = ? AND corpus = 'shared' AND approved = 1""",
        [tenant_id],
    ).fetchall()
    scored = sorted(
        [(r[0], _similarity(query, r[0])) for r in rows],
        key=lambda x: -x[1],
    )
    return [c for c, _ in scored[:top_k]]


# ── 3. Private ingest + approval; retrieved text treated as untrusted ───────

def ingest_document_secure(
    user_id: str, content: str, filename: str = "", tenant_id: str = "acme"
) -> str:
    """
    Index a user upload into their private corpus only.

    Security controls:
    - Lands in corpus='user_private', approved=0 — never shared by default
    - Shared retrieval requires promote_to_shared_corpus() by a reviewer
    - Keyword scanners are intentionally NOT used as the trust boundary
    """
    chunks = [c.strip() for c in content.split("\n\n") if c.strip()] or [content.strip()]

    for chunk in chunks:
        MEMORY_DB.execute(
            """INSERT INTO docs (user_id, tenant_id, chunk, corpus, approved)
               VALUES (?, ?, ?, 'user_private', 0)""",
            [user_id, tenant_id, chunk],
        )

    MEMORY_DB.commit()
    AUDIT_LOG.append({
        "event": "user_upload_indexed_private",
        "user_id": user_id,
        "filename": filename,
        "chunks": len(chunks),
    })
    return f"Indexed {len(chunks)} private chunks pending review."


def promote_to_shared_corpus(doc_id: int, reviewer_id: str) -> None:
    """Human/trusted reviewer only — uploading user and model cannot flip this."""
    MEMORY_DB.execute(
        """UPDATE docs
           SET corpus = 'shared', approved = 1, reviewed_by = ?
           WHERE id = ?""",
        [reviewer_id, doc_id],
    )
    MEMORY_DB.commit()
    AUDIT_LOG.append({
        "event": "doc_promoted_shared",
        "doc_id": doc_id,
        "reviewed_by": reviewer_id,
    })


def build_rag_context(chunks: list[str]) -> str:
    """Apply Chapter 01 bounded-context to retrieved chunks."""
    body = "\n\n".join(chunks) if chunks else "None."
    return (
        '<retrieved_documents trust="untrusted">\n'
        f"{body}\n"
        "</retrieved_documents>"
    )


def answer_with_rag_secure(
    user_id: str, tenant_id: str, question: str, top_k: int = 3
) -> str:
    """Retrieve with isolation filters; frame chunks as untrusted before the model."""
    private = retrieve_chunks_secure(question, user_id, top_k=top_k)
    shared = retrieve_shared_chunks_secure(question, tenant_id, top_k=top_k)
    chunks = (private + shared)[:top_k]
    # In production: return call_model(build_rag_context(chunks) + question)
    return f"ok ({build_rag_context(chunks)})"


# ── 4. Memory keyed by authenticated user_id ────────────────────────────────

def save_long_term_memory_secure(user_id: str, key: str, value: str) -> None:
    """
    Persist an allowlisted preference for the user.

    Security control: user_id comes from the authenticated session token —
    never from model output or the user's message content.
    """
    remember_preference(user_id, key, value)


def load_long_term_memory_secure(user_id: str) -> list[tuple[str, str]]:
    """
    Load preferences for the authenticated user.

    Security control: always scoped to user_id from auth layer.
    Session ID alone is never used as a memory key.
    """
    rows = MEMORY_DB.execute(
        "SELECT key, value FROM user_preferences WHERE user_id = ? AND trust_level = 'user_stated'",
        [user_id],
    ).fetchall()
    return [(r[0], r[1]) for r in rows]
