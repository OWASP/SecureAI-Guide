"""Chapter 11 — Vulnerable: free-form exec of model output (ASI05). DO NOT USE IN PRODUCTION."""

FAKE_ENV = {"OPENAI_API_KEY": "sk-prod-secret"}

def run_model_code(code: str) -> str:
    """❌ Executes arbitrary model-generated Python with full builtins."""
    local = {}
    exec(code, {"__builtins__": __builtins__, "os_env": FAKE_ENV}, local)
    return str(local.get("result", ""))

# Attack demo (do not run against real secrets):
# run_model_code('result = os_env["OPENAI_API_KEY"]')
