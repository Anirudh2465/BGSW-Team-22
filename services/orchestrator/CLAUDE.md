# Scoped Rules for Orchestrator Service (Owner: Dev 2)

Scope:
- Only edit files inside `services/orchestrator/`.
- Invariant 2: Human approval only permitted for patches that already built cleanly and passed tests (`verified`).
- Invariant 5: Orchestrator MUST NEVER mount or communicate with `/var/run/docker.sock`. Only HTTP calls to `launcher`.
- Invariant 6: Stateless stage handoff: `GuardianState` stores `commit_sha` and SHA-256 artifact hashes—NEVER container paths.
- Ensure all 9 gates are deterministic Python checks (never LLMs as gate judges).
- Keep `approval_gate_node` completely side-effect-free before `interrupt()`.
- Test command: `pytest services/orchestrator/tests -v`
