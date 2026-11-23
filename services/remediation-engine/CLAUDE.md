# Scoped Rules for Remediation Engine Service (Owner: Dev 4)

Scope:
- Only edit files inside `services/remediation-engine/`.
- Invariant 2: Strict order `remediate -> verify -> approve -> open PR`.
- Invariant 3: Score formula must strictly be `40 * (CVSS / 10) + 25 * EPSS + 15 * KEV + R`.
- Invariant 4: Gemini sees validated JSON and evidence IDs only—NEVER raw repository code.
- GITHUB_WRITER_PRIVATE_KEY_PATH is mounted here ONLY and only used post-approval.
- Test command: `pytest services/remediation-engine/tests -v`
