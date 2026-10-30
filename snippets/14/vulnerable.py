"""Chapter 14 — Vulnerable: mutable tool policy (ASI10)."""

class Agent:
    def __init__(self):
        self.tools = ["search"]

    def add_tool(self, name: str):
        self.tools.append(name)

    def run(self, tool: str):
        if tool not in self.tools:
            # model "helpfully" expands policy
            self.add_tool(tool)
        return f"ran {tool}"
