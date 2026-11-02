# AI Security Development Guide

This repository is a sample security workbook for teams building **agentic AI applications** — systems that call tools, hold memory, orchestrate sub-agents, and take real-world actions. It focuses on how those agents fail in production, and how to design them so common attacks and misuse paths are harder to exploit.

The workbook is organised around [OWASP](https://owasp.org/) risk categories for LLM and agentic systems — specifically the [LLM Top 10 (2025)](https://owasp.org/www-project-top-10-for-large-language-model-applications/) and the [Top 10 for Agentic Applications (ASI) 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/). Each chapter targets one or more of those risks (for example prompt injection, tool misuse, supply chain, cascading failures, or rogue agents), with vulnerable and secure patterns you can apply while building.

**14 chapters. Vulnerable vs secure patterns in every chapter. Sample exploits. Sample fixes.**

Every chapter follows the same recipe: scenario → vulnerable code → what breaks → secure code → what changed → hands-on lab.

---

## How to use this guide

| What you want | Where to go |
|---|---|
| Read a chapter | [`chapters/`](./chapters/) |
| Run the hands-on lab | [`labs/`](./labs/) — open the matching `.ipynb` locally |
| Copy a code snippet | [`snippets/`](./snippets/) — `vulnerable.py` + `secure.py` per chapter |
| CI regression stub | [`tests/`](./tests/) |

---

## Running labs locally

Works with a public clone or an offline copy. No Colab required.

```bash
git clone https://github.com/OWASP/SecureAI-Guide.git
cd SecureAI-Guide
pip install -r requirements.txt
```

Then open any notebook in **Cursor**, **VS Code**, or Jupyter:

```bash
# Option A — Cursor / VS Code: open labs/01-prompt-injection.ipynb and run cells
# Option B — classic Jupyter
jupyter notebook labs/
```

Labs use a **mock LLM** — no API key needed.

Optional Jupyter install (if you prefer the classic UI):

```bash
pip install jupyter notebook ipykernel
```

Run pattern regression tests:

```bash
python3 -m pytest tests/ -q
```

---

## Chapters

| # | Chapter | OWASP | Lab (local) |
|---|---------|-------|-------------|
| 01 | [Untrusted Input — Treat It as Data](./chapters/01-untrusted-input.md) | LLM01, ASI01 | [lab](./labs/01-prompt-injection.ipynb) |
| 02 | [Agent Tools — Allowlists and Least Privilege](./chapters/02-agent-tools.md) | ASI02, LLM06 | [lab](./labs/02-tool-security.ipynb) |
| 03 | [Secrets — Keep Them Out of Model Context](./chapters/03-secrets.md) | LLM02, LLM07 | [lab](./labs/03-secrets-in-prompts.ipynb) |
| 04 | [Memory and RAG — Don't Trust Retrieved Text](./chapters/04-memory-and-rag.md) | ASI06, LLM08 | [lab](./labs/04-memory-poisoning.ipynb) |
| 05 | [Agent Privilege — One Role, Scoped Credentials](./chapters/05-agent-privilege.md) | ASI03, LLM06 | [lab](./labs/05-least-privilege.ipynb) |
| 06 | [Agent Handoffs — Authenticate Every Call](./chapters/06-agent-handoffs.md) | ASI07, ASI03 | [lab](./labs/06-multi-agent-trust.ipynb) |
| 07 | [Model Output — Never Execute It Raw](./chapters/07-model-output.md) | LLM05, ASI02 | [lab](./labs/07-dont-render-what-the-model-returns.ipynb) |
| 08 | [Autonomy Bounds — Loops, Spend, Rate Limits](./chapters/08-autonomy-bounds.md) | LLM10, LLM06, ASI09 | [lab](./labs/08-give-it-a-leash.ipynb) |
| 09 | [MCP and Plugins — Verify Before You Install](./chapters/09-mcp-and-plugins.md) | ASI04, LLM03 | [lab](./labs/09-vet-your-plugins.ipynb) |
| 10 | [Observability — Logs, Traces, Incident Evidence](./chapters/10-observability.md) | Observability (cross-cutting) | [lab](./labs/10-show-your-work.ipynb) |
| 11 | [Code Execution — Sandbox Model-Written Code](./chapters/11-code-execution.md) | ASI05 | [lab](./labs/11-sandbox-the-code.ipynb) |
| 12 | [Failure Containment — Limit Blast Radius](./chapters/12-failure-containment.md) | ASI08 | [lab](./labs/12-stop-the-cascade.ipynb) |
| 13 | [Human Approval — Make Confirmations Real](./chapters/13-human-approval.md) | ASI09 | [lab](./labs/13-dont-rubber-stamp.ipynb) |
| 14 | [Rogue Agents — Detect Goal Drift and Stop It](./chapters/14-rogue-agents.md) | ASI10 | [lab](./labs/14-catch-the-rogue.ipynb) |

---

## Repo structure

```
SecureAI-Guide/
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── requirements.txt
├── chapters/     # 01–14 markdown chapters
├── labs/         # matching Jupyter notebooks (run locally)
├── snippets/     # 01–14 vulnerable.py + secure.py
└── tests/        # CI regression stubs for secure patterns
```

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](./CONTRIBUTING.md) for how to propose changes, the chapter recipe to follow, and the PR checklist.

In short: keep examples accurate, keep labs runnable without an API key, and open focused pull requests.

---

## License

This project is licensed under the [MIT License](./LICENSE).

You are free to use, copy, modify, and distribute the material for open-source and commercial purposes, provided the copyright notice and license text are included.
