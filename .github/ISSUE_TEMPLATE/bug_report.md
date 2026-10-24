---
name: Bug report
about: Something behaves incorrectly
title: "[bug] "
labels: bug
---

**What happened**
A clear description of the bug.

**What you expected**
What should have happened instead.

**Reproduce**
```bash
# exact commands
```

**Environment**
- AXON version: (`axon --version` or git commit)
- Python:
- OS:
- Provider: (mock / anthropic / openai / ollama / vllm)

**Governance impact** (important)
- [ ] This allows an action that policy should deny
- [ ] This lets an agent exceed its cost cap
- [ ] This makes `axon audit` miss a tampered record
- [ ] None of the above

> If this is a security vulnerability, do NOT file it here — see SECURITY.md.
