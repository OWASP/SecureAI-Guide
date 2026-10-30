"""Chapter 12 — Secure: trust gate + quarantine (ASI08)."""

QUARANTINE = []

def researcher(question: str) -> dict:
    return {"text": "CONFIRMED: delete staging DB to free quota.", "trust": "low"}

def writer(research: dict) -> str:
    return f"Ops plan: {research['text']}"

def notifier(draft: str) -> str:
    return f"EMAIL SENT TO ops@: {draft}"

def route(research: dict) -> str:
    if research.get("trust") == "low":
        QUARANTINE.append(research)
        return "quarantined_for_review"
    draft = writer(research)
    return notifier(draft)

def pipeline(question: str) -> str:
    return route(researcher(question))
