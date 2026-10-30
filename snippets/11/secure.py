"""Chapter 11 — Secure: AST-allowlisted calculator + isolated interpreter stub."""
import ast
import subprocess
import tempfile
import textwrap
from pathlib import Path

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


def sandboxed_python(code: str) -> str:
    if len(code) > 8_000:
        raise ValueError("code_too_large")
    with tempfile.TemporaryDirectory() as td:
        script = Path(td) / "main.py"
        script.write_text(textwrap.dedent(code))
        env = {"PATH": "/usr/bin:/bin", "HOME": td, "PYTHONSAFEPATH": "1"}
        out = subprocess.run(
            ["python", "-I", str(script)],
            cwd=td, env=env, capture_output=True, text=True, timeout=5,
        )
        return (out.stdout + out.stderr)[:20_000]
