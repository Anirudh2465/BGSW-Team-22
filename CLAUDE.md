# Supply Chain Guardian — Root AI Instructions & Invariants

This repository is a microservice monorepo for **Supply Chain Guardian**, an automated, sandboxed software supply chain security vulnerability auditing and remediation platform.

## Global Rules for AI Assistants (Claude Code / Antigravity)

1. **Service Boundaries**: Never edit files outside your explicitly assigned service directory unless requested by the user.
2. **Contracts Package Freeze**: Never modify `packages/contracts/` without team coordination. The shared schemas are frozen.
3. **Preserve the Six Core Architecture Invariants**:
   - **Invariant 1 (Resolve, then scan offline)**: Dependency resolution occurs in Stage 2 behind an allowlist proxy; Stage 3 scanning runs strictly with `--network=none`.
   - **Invariant 2 (Verify before approval)**: Strict pipeline order: `remediate -> verify -> approve -> open PR`. Humans only review patches that already built cleanly and passed tests.
   - **Invariant 3 (Code decides safety)**: Check plans, deterministic risk scores (CVSS/EPSS/KEV/Reachability formula), policy verdicts (OPA), and fix candidate lists are computed strictly by code.
   - **Invariant 4 (No free text crosses model boundaries)**: Local Ollama outputs enums/regex-validated purls only; Gemini receives validated JSON and evidence IDs only—never raw repository source code.
   - **Invariant 5 (Single Docker socket owner)**: Only `services/launcher` has access to `/var/run/docker.sock`. Neither orchestrator, scanner-intel, remediation-engine, nor web may access the socket.
   - **Invariant 6 (Stateless stage handoff)**: `GuardianState` stores `commit_sha` and SHA-256 artifact hashes—never container paths or live volume mounts.
4. **Deterministic Gate Checks**: Never use an LLM as a gate judge. All 9 gates in the orchestrator graph are deterministic Python rule checks.
5. **Pre-Approval Verification**: Never skip `verifier_agent` before `approval_gate_node`.
6. **Side-Effect-Free Approvals**: Keep `approval_gate_node` completely side-effect-free before `interrupt()`.
7. **Golden Fixture Verification**: Test against `packages/contracts/fixtures/` before declaring any task complete.
