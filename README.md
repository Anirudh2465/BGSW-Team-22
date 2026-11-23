# Supply Chain Guardian

> Autonomous, sandboxed software supply chain vulnerability detection, verification, and remediation platform.

Supply Chain Guardian translates the **Rectified Architecture** into an isolated, microservice monorepo operated with strict security invariants.

---

## Architecture Overview

```
                      +-------------------+
                      |   Next.js 15 Web  |
                      |    (Port 3000)    |
                      +---------+---------+
                                | REST / WebSocket
                      +---------v---------+
                      |   Orchestrator    | <--- LangGraph 9-node / 9-gate state machine
                      |    (Port 8000)    | <--- PostgreSQL 16 (Checkpoints + Hash Chain)
                      +----+---------+----+
                           |         |
         Dedicated Network |         | Core Bridge Network
                           |         |
         +-----------------v-+     +-v-----------------------+     +------------------------+
         |  Launcher Service |     |  Scanner & Intel Engine |     |   Remediation Engine   |
         |    (Port 8001)    |     |       (Port 8002)       |     |       (Port 8003)      |
         +---------+---------+     +-------------------------+     +------------------------+
                   |
       Docker Engine / gVisor
       (Exclusive Socket Owner)
                   |
   +---------------+---------------+---------------+
   |               |               |               |
Stage 1:        Stage 2:        Stage 3:        Stage 4:
Hardened Clone  Dependency      Offline Scan    Re-clone, Patch,
(--depth 1)     Resolution      (--network=none) Build & Verify
```

---

## The 6 Core Security Invariants

1. **Resolve, then scan offline**: Dependency resolution runs in Stage 2 behind an egress-logging allowlist proxy. Stage 3 vulnerability scanning runs strictly with `--network=none`.
2. **Verify before approval**: Strict pipeline order: `remediate -> verify -> approve -> open PR`. Humans only review and sign off on patches that have already built cleanly and passed all tests.
3. **Code decides safety**: Check plans, deterministic risk scores, policy verdicts, and fix candidate lists are computed strictly by deterministic Python rules and Open Policy Agent (OPA).
4. **No free text crosses model boundaries**: Local Ollama produces enum/regex-validated purls; Gemini receives validated JSON and evidence IDs only—never raw repository source code.
5. **Single Docker socket owner**: Only `services/launcher` has access to `/var/run/docker.sock`. Neither orchestrator, scanner-intel, remediation-engine, nor the web dashboard may mount or talk to the Docker socket.
6. **Stateless stage handoff**: `GuardianState` stores `commit_sha` and SHA-256 artifact hashes—never container paths, temporary directory paths, or live volume mounts.

---

## Monorepo Directory Structure

```text
├── .github/workflows/ci.yml           # CI validation pipeline
├── CLAUDE.md                          # Root AI invariants & guidelines
├── docker-compose.yml                 # Monorepo container topology
├── Makefile                           # Development & evaluation tasks
├── packages/
│   └── contracts/                     # Frozen shared state, enums, & golden test fixtures
├── services/
│   ├── launcher/                      # Docker socket holder & sandbox execution plane
│   ├── orchestrator/                  # LangGraph 9-node/9-gate engine, DB & audit chain
│   ├── scanner-intel/                 # Cartographer, discover, detector, reachability
│   ├── remediation-engine/            # Prioritizer, OPA policy, remediator, verifier, reporter
│   └── web/                           # Next.js 15 dashboard & React Flow visualizer
├── infra/postgres/                    # Database init & LangGraph checkpoint schema
└── tests/                             # Golden repos, red-team attack repos & eval runner
```

---

## Quickstart

### 1. Prerequisites
- Docker Engine 24+ & Docker Compose v2
- Python 3.12+
- Node.js 20+ (for local web dashboard development)

### 2. Configure Environment
```bash
cp .env.example .env
```

### 3. Start Monorepo Services
```bash
# Start all microservices in background (without local Ollama)
make up-no-ollama

# Or start with local Qwen2.5-Coder-7B Ollama model
make up
```

### 4. Run Test Suite
```bash
make test-all
```

### 5. Run Golden & Red-Team Evaluation
```bash
make eval-golden
```
