# Scoped Rules for Scanner & Intel Service (Owner: Dev 3)

Scope:
- Only edit files inside `services/scanner-intel/`.
- Invariant 3: Check plans, detection rules, and graphs are computed strictly by code.
- Invariant 4: Ollama output MUST be schema-locked JSON (enums and regex-validated purls only).
- When `ENABLE_OLLAMA=false`, the service MUST seamlessly fall back to deterministic rule-only analysis.
- Test command: `pytest services/scanner-intel/tests -v`
