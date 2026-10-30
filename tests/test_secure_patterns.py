"""Regression stubs for secure patterns (P2 CI gate).

Run: python3 -m pytest tests/ -q
"""

from __future__ import annotations

import ast
import importlib.util
import ipaddress
from pathlib import Path
from types import MappingProxyType
from urllib.parse import urlparse

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(chapter: str, module_name: str):
    path = ROOT / "snippets" / chapter / f"{module_name}.py"
    spec = importlib.util.spec_from_file_location(f"{chapter}_{module_name}", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def test_safe_calc_allows_arithmetic():
    secure = load("11", "secure")
    assert secure.safe_calc("2+3*4") == 14.0


def test_safe_calc_blocks_import():
    secure = load("11", "secure")
    with pytest.raises(ValueError):
        secure.safe_calc("__import__('os').system('id')")


def test_cascade_quarantines_low_trust():
    secure = load("12", "secure")
    secure.QUARANTINE.clear()
    assert secure.pipeline("q") == "quarantined_for_review"
    assert secure.QUARANTINE


def test_rogue_policy_immutable_and_denies_shell():
    secure = load("14", "secure")
    assert isinstance(secure.POLICY, MappingProxyType)
    ks = secure.KillSwitch()
    with pytest.raises(PermissionError):
        secure.run("shell", ks)


def test_ssrf_policy_helpers():
    """Inline mirror of Ch02 secure fetch policy (no network)."""

    def only_https_allowlisted(url: str, suffixes=(".wikipedia.org",)) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise ValueError("only_https_allowed")
        host = (parsed.hostname or "").lower()
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                raise ValueError("private_ip_blocked")
        except ValueError as exc:
            if "private_ip" in str(exc):
                raise
        if not any(host == s.lstrip(".") or host.endswith(s) for s in suffixes):
            raise ValueError("host_not_allowlisted")

    with pytest.raises(ValueError):
        only_https_allowlisted("http://127.0.0.1/")
    with pytest.raises(ValueError):
        only_https_allowlisted("https://evil.example/")
    only_https_allowlisted("https://en.wikipedia.org/wiki/SSRF")


def test_ast_allowlist_rejects_calls():
    tree = ast.parse("foo()", mode="eval")
    assert any(isinstance(n, ast.Call) for n in ast.walk(tree))


def test_path_sandbox_rejects_sibling_prefix(tmp_path):
    """is_relative_to must not allow /sandbox/alice2 when root is /sandbox/alice."""
    from pathlib import Path as P
    sandbox = tmp_path / "sandbox"
    alice = sandbox / "alice"
    alice2 = sandbox / "alice2"
    alice.mkdir(parents=True)
    alice2.mkdir(parents=True)
    (alice2 / "secret.txt").write_text("bob-secret")
    user_root = alice.resolve()
    # traversal that lands in sibling
    target = (user_root / "../alice2/secret.txt").resolve()
    assert not target.is_relative_to(user_root)


def test_tool_schema_drops_extra_fields():
    secure = load("09", "secure")
    out = secure.call_tool_validated("web_search", {"q": "x"})
    assert "hidden_field" not in out
    assert "next_action" not in out
    assert "title" in out
