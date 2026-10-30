# Contributing

Thanks for helping improve this workbook. Contributions that make the material clearer, more accurate, or more hands-on for builders are welcome.

## Ways to contribute

- Fix typos, broken links, or outdated OWASP mappings
- Improve vulnerable / secure code samples for clarity or correctness
- Strengthen labs (especially blank “your turn” exercises and asserts)
- Add framework variants that match patterns already used in a chapter
- Report issues when a “secure” example is still bypassable in an important way

## Before you open a PR

1. Keep the chapter recipe: scenario → vulnerable → what breaks → secure → what changed → lab
2. Prefer local notebooks — do not reintroduce Colab-as-primary badges
3. Label intentionally insecure code clearly (`vulnerable.py`, `❌`, DO NOT USE IN PRODUCTION)
4. Do not add real secrets, live API keys, or exploit payloads aimed at third-party systems
5. Run tests when you touch snippets or shared helpers:

```bash
pip install -r requirements.txt
python3 -m pytest tests/ -q
```

## Pull request checklist

- [ ] Change is scoped to one concern (docs, one chapter, or one lab)
- [ ] New or updated code is runnable without an API key where labs are involved
- [ ] OWASP IDs in the chapters table stay consistent with chapter content if you remap risks
- [ ] Vulnerable examples remain educational — not copy-paste production advice

## Reporting security issues in this repo

If you find a mistake in a pattern labeled secure (for example a bypass in a sandbox check), open an issue or PR describing the gap and a suggested fix. Treat that as a content defect, not a vulnerability disclosure against a live service.
