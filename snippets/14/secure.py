"""Chapter 14 — Secure: immutable policy + kill switch (ASI10)."""
from types import MappingProxyType

POLICY = MappingProxyType({"tools": ("search", "read_file"), "max_steps": 5})

class KillSwitch:
    def __init__(self):
        self._aborted = False
    def abort(self):
        self._aborted = True
    def aborted(self):
        return self._aborted

def assert_tool_allowed(tool: str) -> None:
    if tool not in POLICY["tools"]:
        raise PermissionError(f"tool_not_in_policy: {tool}")

def run(tool: str, ks: KillSwitch) -> str:
    if ks.aborted():
        return "aborted"
    assert_tool_allowed(tool)
    return f"ran {tool}"
