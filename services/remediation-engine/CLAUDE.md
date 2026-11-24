# Scoped Rules for Remediation Engine Service (Owner: Dev 4)

Scope:
- Only edit files inside `services/remediation-engine/`.
- Invariant 2: Strict order `remediate -> verify -> approve -> open PR`.
- Invariant 3: Score formula must strictly be the contextual model `(T * M_reach * M_scope) + G` with `T = 50 * (CVSS / 10) + 30 * EPSS + 20 * KEV`, capped at 59 for verified-unreachable or non-production findings; it lives in an identical block in `services/scanner-intel/app/vuln/risk.py` and `app/agents/prioritizer.py` (a parity test enforces it).
- Invariant 4: Gemini sees validated JSON and evidence IDs only—NEVER raw repository code.
- GITHUB_WRITER_PRIVATE_KEY_PATH is mounted here ONLY and only used post-approval.
- Test command: `pytest services/remediation-engine/tests -v`
