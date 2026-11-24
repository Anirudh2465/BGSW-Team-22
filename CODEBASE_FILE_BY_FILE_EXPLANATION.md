# Supply Chain Guardian — Comprehensive Codebase File-by-File Reference

This document provides a complete, exhaustive, file-by-file technical reference for the entire **Supply Chain Guardian** monorepo (`d:\BGSW`). Every configuration, contract, microservice module, pipeline stage, detector, agent, user interface component, and evaluation fixture is detailed below.

---

## Table of Contents
1. [Architecture & System Overview](#1-architecture--system-overview)
2. [Root Configurations & Infrastructure](#2-root-configurations--infrastructure)
3. [Frozen Contracts (`packages/contracts`)](#3-frozen-contracts-packagescontracts)
4. [Launcher Microservice (`services/launcher`)](#4-launcher-microservice-serviceslauncher)
5. [Orchestrator Microservice (`services/orchestrator`)](#5-orchestrator-microservice-servicesorchestrator)
6. [Scanner-Intel Microservice (`services/scanner-intel`)](#6-scanner-intel-microservice-servicesscanner-intel)
7. [Remediation-Engine Microservice (`services/remediation-engine`)](#7-remediation-engine-microservice-servicesremediation-engine)
8. [Web Application (`services/web`)](#8-web-application-servicesweb)
9. [Evaluation, Benchmark & Red-Team Suite (`tests/`)](#9-evaluation-benchmark--red-team-suite-tests)
10. [Architectural Security Invariants Mapping](#10-architectural-security-invariants-mapping)

---

## 1. Architecture & System Overview

Supply Chain Guardian is an enterprise-grade autonomous supply-chain security platform. The monorepo is partitioned into 5 backend microservices and 1 frontend application, communicating via typed Pydantic contracts, REST APIs, and WebSockets:

```
d:/BGSW/
├── Root Configs & Infrastructure   ── Docker, Postgres SQL, Make, Env
├── packages/contracts              ── Frozen Pydantic schemas, state models, events
├── services/launcher               ── Docker-socket owner, sandboxes (Stage 1-4), proxies
├── services/orchestrator           ── LangGraph state machine, 9 gates, Ed25519 audit chain
├── services/scanner-intel          ── Dependency cartography, Grype/OSV consensus, detectors
├── services/remediation-engine     ── Risk scoring, OPA policy, patchers, sandbox verifier
├── services/web                    ── Next.js 15, React Flow dependency graph, approval UI
└── tests/                          ── Golden repos, 5 red-team attack targets, eval runner
```

---

## 2. Root Configurations & Infrastructure

### [`.dockerignore`](file:///d:/BGSW/.dockerignore)
- **Path**: `d:/BGSW/.dockerignore`
- **Purpose**: Defines files and directories excluded from container build contexts.
- **Key Exclusions**: `node_modules`, `.next`, `.git`, `.venv`, `__pycache__`, local test databases, and IDE metadata.
- **Security Impact**: Prevents leaking local host secrets, `.env` files, or binary artifacts into Docker images, keeping images lean.

### [`.env`](file:///d:/BGSW/.env) & [`.env.example`](file:///d:/BGSW/.env.example)
- **Path**: `d:/BGSW/.env`
- **Purpose**: Environment variables configuring all monorepo microservices and Docker containers.
- **Key Parameters**:
  - `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`: Credentials for PostgreSQL 16.
  - `GEMINI_API_KEY`: API key for Google Gemini model calls (fact-sheet grounded summaries).
  - `SCANNER_INTEL_URL`, `REMEDIATION_ENGINE_URL`, `LAUNCHER_URL`: Internal microservice network endpoints.
  - `STAGE4_TIMEOUT_S`: Wall-clock timeout (600 seconds) for dynamic patch verification.

### [`docker-compose.yml`](file:///d:/BGSW/docker-compose.yml) & [`docker-compose.override.yml.example`](file:///d:/BGSW/docker-compose.override.yml.example)
- **Path**: `d:/BGSW/docker-compose.yml`
- **Purpose**: Multi-container Docker orchestration defining the 6 monorepo services and isolated network bridges:
  1. `postgres`: PostgreSQL 16 relational database with healthchecks.
  2. `launcher`: Container with `/var/run/docker.sock` mounted; isolated on the internal `launcher-net`.
  3. `orchestrator`: LangGraph pipeline coordinator listening on port `8000`.
  4. `scanner-intel`: Cartography, SBOM consensus, and vulnerability assessment on port `8002`.
  5. `remediation-engine`: Policy evaluation, risk scoring, and patch generation on port `8003`.
  6. `web`: Next.js 15 interactive dashboard listening on port `3000`.
- **Architectural Guarantee**: Only `launcher` holds the Docker daemon socket; no sibling service can spawn containers.

### [`Makefile`](file:///d:/BGSW/Makefile)
- **Path**: `d:/BGSW/Makefile`
- **Purpose**: Developer commands for building, running, and verifying the stack.
- **Key Targets**:
  - `make test`: Executes all 288+ unit tests across the 5 monorepo services.
  - `make eval-golden`: Runs `tests/eval_runner.py` against the 4 golden and 5 red-team benchmark targets.
  - `make docker-up`: Builds and starts all containers in detached mode.

### [`conftest.py`](file:///d:/BGSW/conftest.py)
- **Path**: `d:/BGSW/conftest.py`
- **Purpose**: Root Pytest configuration ensuring proper Python path resolution across monorepo packages.

### [`infra/postgres/001_init.sql`](file:///d:/BGSW/infra/postgres/001_init.sql)
- **Path**: `d:/BGSW/infra/postgres/001_init.sql`
- **Purpose**: Core SQL schema executed on PostgreSQL initialization.
- **Key Tables**:
  - `runs`: Pipeline execution metadata (run ID, target repository URL, commit hash, status, timings).
  - `artifacts`: Content-addressable storage (CAS) table holding binary and JSON artifacts indexed by SHA-256.
  - `findings`: Universal vulnerability records (CVEs, anomalies, risk scores, reachability tiers).
  - `dependency_edges`: Adjacency list storing the full dependency graph edges.
  - `audit_log`: Cryptographic, append-only log with Ed25519 signatures and parent SHA-256 hashes.
  - `remediations`: Candidate patches, unified diffs, and verification outcomes.

### [`infra/postgres/002_checkpoints.sql`](file:///d:/BGSW/infra/postgres/002_checkpoints.sql)
- **Path**: `d:/BGSW/infra/postgres/002_checkpoints.sql`
- **Purpose**: PostgreSQL storage schema for LangGraph state persistence.
- **Key Tables**: `checkpoints`, `checkpoint_blobs`, and `checkpoint_writes` enabling pipeline resumption and state replay.

---

## 3. Frozen Contracts (`packages/contracts`)

This package houses the shared, immutable Pydantic schemas. Any change here requires coordinated updates across all services.

### [`guardian_contracts/state.py`](file:///d:/BGSW/packages/contracts/guardian_contracts/state.py)
- **Path**: `d:/BGSW/packages/contracts/guardian_contracts/state.py`
- **Purpose**: Defines the monolithic pipeline state passed between LangGraph nodes.
- **Key Models**:
  - `PipelineState`: Universal state holding `run_id`, `repo_url`, `commit_sha`, stage artifact hashes, findings, gate results, and approval status.
  - `Finding`: Represents an identified vulnerability or anomaly (`id`, `kind`, `purl`, `score`, `reach_tier`, `evidence`, `status`).
  - `Evidence`: Provenance pointer containing `tool`, `artifact_sha256`, and creation timestamp.
  - `Remediation`: Automated fix proposal (`candidates`, `chosen`, `patch_sha256`, `state`, `validation`).
  - `Approval`: Human sign-off record (`approved`, `approver_id`, `signature`, `timestamp`).

### [`guardian_contracts/api_schemas.py`](file:///d:/BGSW/packages/contracts/guardian_contracts/api_schemas.py)
- **Path**: `d:/BGSW/packages/contracts/guardian_contracts/api_schemas.py`
- **Purpose**: REST request and response schemas exchanged between microservices.
- **Key Schemas**: `CloneRequest`/`Response`, `ResolveRequest`/`Response`, `ScanRequest`/`Response`, `PrioritizeRequest`/`Response`, `PolicyRequest`/`Response`, `RemediateRequest`/`Response`, `VerifyRequest`/`Response`.

### [`guardian_contracts/enums.py`](file:///d:/BGSW/packages/contracts/guardian_contracts/enums.py)
- **Path**: `d:/BGSW/packages/contracts/guardian_contracts/enums.py`
- **Purpose**: Type-safe enumerations for `FindingKind` (`cve`, `typosquat`, `install_hook`, `agent_config`), `RiskBand` (`Critical`, `High`, `Medium`, `Low`), `PolicyVerdict` (`PASS`, `BLOCK`), and `RemediationState` (`draft`, `verified`, `no_safe_fix`, `escalated`).

### [`guardian_contracts/events.py`](file:///d:/BGSW/packages/contracts/guardian_contracts/events.py)
- **Path**: `d:/BGSW/packages/contracts/guardian_contracts/events.py`
- **Purpose**: Event payload models pushed over WebSockets and SSE to the frontend UI (`PipelineStepEvent`, `GateResultEvent`, `ApprovalRequiredEvent`).

### [`guardian_contracts/tool_interface.py`](file:///d:/BGSW/packages/contracts/guardian_contracts/tool_interface.py)
- **Path**: `d:/BGSW/packages/contracts/guardian_contracts/tool_interface.py`
- **Purpose**: Abstract base classes defining scanner tool wrappers and artifact storage clients.

### [`packages/contracts/fixtures/`](file:///d:/BGSW/packages/contracts/fixtures/)
- **Path**: `d:/BGSW/packages/contracts/fixtures/`
- **Purpose**: Static JSON mock fixtures (`log4shell_findings.json`, `stage1_clone_out.json`, `stage2_resolve_out.json`, `stage3_scan_out.json`, `stage4_verify_out.json`, `verified_remediation.json`) used for offline serialization tests.

---

## 4. Launcher Microservice (`services/launcher`)

The Launcher is the **sole possessor of Docker privileges** in the system. It builds, runs, monitors, and cleans up throwaway sandbox containers for stages 1 through 4.

### [`app/main.py`](file:///d:/BGSW/services/launcher/app/main.py)
- **Path**: `d:/BGSW/services/launcher/app/main.py`
- **Purpose**: FastAPI server exposing endpoints for running sandbox execution stages:
  - `POST /stage1/clone`: Triggers sandboxed git clone.
  - `POST /stage2/resolve`: Triggers dependency resolution behind the proxy.
  - `POST /stage3/scan`: Triggers offline multi-scanner execution.
  - `POST /stage4/verify`: Triggers dynamic sandbox patch verification.

### [`app/docker_runner.py`](file:///d:/BGSW/services/launcher/app/docker_runner.py)
- **Path**: `d:/BGSW/services/launcher/app/docker_runner.py`
- **Purpose**: Low-level Docker client managing sandbox containers.
- **Capabilities**:
  - Enforces CPU limits (`2.0` cores), memory caps (`4 GB`), and execution timeouts.
  - Configures network isolation (`none`, or attached to the restricted egress proxy).
  - Streams execution logs and guarantees container cleanup via `try/finally` blocks.

### [`app/allowlist.py`](file:///d:/BGSW/services/launcher/app/allowlist.py)
- **Path**: `d:/BGSW/services/launcher/app/allowlist.py`
- **Purpose**: Strict domain allowlists for Stage 1 (GitHub, GitLab) and Stage 2 (Maven Central, npmjs.org, PyPI). All other outbound traffic is rejected.

### [`app/artifacts.py`](file:///d:/BGSW/services/launcher/app/artifacts.py)
- **Path**: `d:/BGSW/services/launcher/app/artifacts.py`
- **Purpose**: File-based and in-memory artifact manager storing tarballs and outputs before transferring them to the orchestrator.

### [`app/tarballs.py`](file:///d:/BGSW/services/launcher/app/tarballs.py)
- **Path**: `d:/BGSW/services/launcher/app/tarballs.py`
- **Purpose**: Deterministic tar archive generator with normalized timestamps (`mtime=0`) to ensure byte-level SHA-256 reproducibility.

### [`app/proxy/egress_proxy.py`](file:///d:/BGSW/services/launcher/app/proxy/egress_proxy.py)
- **Path**: `d:/BGSW/services/launcher/app/proxy/egress_proxy.py`
- **Purpose**: Lightweight HTTP CONNECT forward proxy running inside the launcher network, enforcing domain allowlists for Stage 1 and Stage 2.

### [`app/proxy/sinkhole.py`](file:///d:/BGSW/services/launcher/app/proxy/sinkhole.py)
- **Path**: `d:/BGSW/services/launcher/app/proxy/sinkhole.py`
- **Purpose**: DNS/HTTP sinkhole that intercepts and logs all unauthorized outbound traffic from install scripts during Stage 2's hook-observation pass.

### [`app/stages/stage1_clone.py`](file:///d:/BGSW/services/launcher/app/stages/stage1_clone.py)
- **Path**: `d:/BGSW/services/launcher/app/stages/stage1_clone.py`
- **Purpose**: Executes Stage 1 in a minimal `git` container.
- **Checks**:
  - Clones repository at exact commit SHA.
  - Enforces 50 MB byte limit and 10,000 file count limit.
  - `check_symlink_safety()`: Validates that no symlinks resolve outside the repository tree.

### [`app/stages/stage2_resolve.py`](file:///d:/BGSW/services/launcher/app/stages/stage2_resolve.py)
- **Path**: `d:/BGSW/services/launcher/app/stages/stage2_resolve.py`
- **Purpose**: Executes Stage 2 dependency resolution.
- **Mechanics**: Runs native package managers (`mvn dependency:tree`, `npm install --package-lock-only`, `pip install --dry-run`) behind the egress proxy to generate locked trees. Records hook traffic into sinkhole logs.

### [`app/stages/stage3_scan.py`](file:///d:/BGSW/services/launcher/app/stages/stage3_scan.py)
- **Path**: `d:/BGSW/services/launcher/app/stages/stage3_scan.py`
- **Purpose**: Executes Stage 3 multi-scanner analysis inside a fully offline container (`--network=none`).
- **Scanners Run**: Syft (SBOM), Trivy (CVEs), cdxgen, TruffleHog (secrets), and JavaParser (`ClassGraphExtractor.java`).

### [`app/stages/stage4_verify.py`](file:///d:/BGSW/services/launcher/app/stages/stage4_verify.py)
- **Path**: `d:/BGSW/services/launcher/app/stages/stage4_verify.py`
- **Purpose**: Executes Stage 4 dynamic patch verification inside an isolated container.
- **Steps**:
  1. Applies unified diff via `git apply --check` and `git apply`.
  2. Runs ecosystem build (`mvn test-compile`, `npm ci --ignore-scripts`, `pip install`).
  3. Executes test suite (`mvn test`, `npm test`, `pytest`).
  4. Generates post-patch SBOM and verifies version resolution.

### [`sandbox-images/`](file:///d:/BGSW/services/launcher/sandbox-images/)
- **Path**: `d:/BGSW/services/launcher/sandbox-images/`
- **Purpose**: Standalone Dockerfiles for the throwaway sandboxes:
  - `clone.Dockerfile`: Alpine + Git + OpenSSH.
  - `resolve.Dockerfile`: Multi-runtime image (JDK 17, Node 20, Python 3.12) with build tools.
  - `scan.Dockerfile`: Pinned offline scanners (Syft 1.18.1, Trivy 0.58.1, TruffleHog 3.88.0, JavaParser 3.26.2).
  - `verify.Dockerfile`: Multi-ecosystem compilation and test runner environment.
  - `javaparser/ClassGraphExtractor.java`: Compiles against JavaParser to traverse ASTs and extract class inheritance, method calls, and type references.

---

## 5. Orchestrator Microservice (`services/orchestrator`)

The Orchestrator is the central nervous system. It runs the **LangGraph state machine**, coordinates all microservices, manages PostgreSQL persistence, and enforces the cryptographic audit chain.

### [`app/main.py`](file:///d:/BGSW/services/orchestrator/app/main.py)
- **Path**: `d:/BGSW/services/orchestrator/app/main.py`
- **Purpose**: FastAPI entrypoint exposing `/runs` (trigger scan), `/runs/{id}` (status), `/runs/{id}/approve` (human sign-off), and `/ws` (real-time WebSocket updates).

### [`app/graph/builder.py`](file:///d:/BGSW/services/orchestrator/app/graph/builder.py)
- **Path**: `d:/BGSW/services/orchestrator/app/graph/builder.py`
- **Purpose**: Builds the LangGraph `StateGraph` linking all 9 nodes and their conditional edges.

### [`app/graph/nodes.py`](file:///d:/BGSW/services/orchestrator/app/graph/nodes.py)
- **Path**: `d:/BGSW/services/orchestrator/app/graph/nodes.py`
- **Purpose**: Implements the execution logic for each node in the pipeline:
  1. `node_clone`: Invokes Launcher Stage 1 $\rightarrow$ evaluates `clone_integrity_gate`.
  2. `node_resolve`: Invokes Launcher Stage 2 $\rightarrow$ evaluates `hook_observation_gate`.
  3. `node_scan`: Invokes Launcher Stage 3 $\rightarrow$ evaluates `manifest_lockfile_gate`.
  4. `node_match`: Calls Scanner-Intel to build dependency graph $\rightarrow$ evaluates `sbom_generation_gate`.
  5. `node_prioritize`: Calls Scanner-Intel / Remediation-Engine scoring $\rightarrow$ evaluates `vulnerability_consensus_gate` & `grounding_gate`.
  6. `node_policy`: Calls Policy Agent (OPA Rego) $\rightarrow$ evaluates `policy_consistency_gate`.
  7. `node_remediate`: Calls Remediator Agent to construct candidate manifest patches.
  8. `node_verify`: Calls Launcher Stage 4 & Verifier Agent $\rightarrow$ evaluates `remediation_verification_gate`.
  9. `node_finalize`: Signs audit record with Ed25519 $\rightarrow$ evaluates `audit_immutability_gate`.

### [`app/graph/routing.py`](file:///d:/BGSW/services/orchestrator/app/graph/routing.py)
- **Path**: `d:/BGSW/services/orchestrator/app/graph/routing.py`
- **Purpose**: Conditional routing logic. If any gate fails (e.g. symlink escape or unverified patch), routing immediately branches to abort or escalate.

### [`app/graph/checkpoint.py`](file:///d:/BGSW/services/orchestrator/app/graph/checkpoint.py)
- **Path**: `d:/BGSW/services/orchestrator/app/graph/checkpoint.py`
- **Purpose**: LangGraph checkpointer storing state snapshots into PostgreSQL tables `checkpoints` and `checkpoint_blobs`.

### [`app/clients.py`](file:///d:/BGSW/services/orchestrator/app/clients.py)
- **Path**: `d:/BGSW/services/orchestrator/app/clients.py`
- **Purpose**: Typed HTTP clients implementing retry policies and timeouts for communicating with Launcher, Scanner-Intel, and Remediation-Engine.

### [`app/confirm.py`](file:///d:/BGSW/services/orchestrator/app/confirm.py)
- **Path**: `d:/BGSW/services/orchestrator/app/confirm.py`
- **Purpose**: Human approval validation. Verifies that approvals contain valid reviewer identities, nonces, and acceptable risk justifications.

### [`app/db/audit_chain.py`](file:///d:/BGSW/services/orchestrator/app/db/audit_chain.py)
- **Path**: `d:/BGSW/services/orchestrator/app/db/audit_chain.py`
- **Purpose**: Implements the **Ed25519 Cryptographic Audit Log** (Architectural Invariant 6).
- **Functionality**: Hashes each pipeline event with SHA-256, links it to `parent_hash`, and signs the block using a private Ed25519 key. Verifies audit chain integrity on read.

### [`app/db/artifacts.py`](file:///d:/BGSW/services/orchestrator/app/db/artifacts.py)
- **Path**: `d:/BGSW/services/orchestrator/app/db/artifacts.py`
- **Purpose**: Content-Addressable Storage (CAS) client storing binary/text blobs in PostgreSQL keyed by `sha256(content)`.

### [`app/db/run_store.py`](file:///d:/BGSW/services/orchestrator/app/db/run_store.py)
- **Path**: `d:/BGSW/services/orchestrator/app/db/run_store.py`
- **Purpose**: SQL query layer for reading and updating run records and findings.

### [`app/db/graph_store.py`](file:///d:/BGSW/services/orchestrator/app/db/graph_store.py) & [`app/db/neo4j_store.py`](file:///d:/BGSW/services/orchestrator/app/db/neo4j_store.py)
- **Path**: `d:/BGSW/services/orchestrator/app/db/graph_store.py`
- **Purpose**: Persistence layer for dependency graph edges in PostgreSQL, with optional export to Neo4j graph database.

### [`app/scheduler/daily_monitor.py`](file:///d:/BGSW/services/orchestrator/app/scheduler/daily_monitor.py)
- **Path**: `d:/BGSW/services/orchestrator/app/scheduler/daily_monitor.py`
- **Purpose**: Background cron task that periodically re-evaluates monitored repositories against newly published CVE and EPSS feeds.

---

## 6. Scanner-Intel Microservice (`services/scanner-intel`)

Scanner-Intel handles **dependency parsing**, **SBOM generation**, **vulnerability consensus matching**, **supply-chain anomaly detection**, and **static AST reachability**.

### [`app/main.py`](file:///d:/BGSW/services/scanner-intel/app/main.py)
- **Path**: `d:/BGSW/services/scanner-intel/app/main.py`
- **Purpose**: FastAPI server exposing endpoints:
  - `POST /cartographer/build-graph`: Constructs dependency graph from manifests.
  - `POST /vuln/assess`: Merges SBOM, scanner outputs, and enrichment feeds.
  - `POST /detect`: Executes the 4 supply chain anomaly detectors.
  - `POST /reachability/scan`: Runs static AST reachability analysis.
  - `POST /vuln/rescan`: Post-patch verification rescan.

### [`app/agents/cartographer.py`](file:///d:/BGSW/services/scanner-intel/app/agents/cartographer.py)
- **Path**: `d:/BGSW/services/scanner-intel/app/agents/cartographer.py`
- **Purpose**: Dispatches manifest and lockfile parsing to ecosystem-specific cartographers to build a unified NetworkX dependency graph.

### [`app/cartographer/`](file:///d:/BGSW/services/scanner-intel/app/cartographer/)
- **`maven.py`**: Parses Maven `pom.xml` and `mvn dependency:tree` JSON.
- **`npm.py`**: Parses `package.json` and `package-lock.json` (v1, v2, v3).
- **`pypi.py`**: Parses `requirements.txt`, `Pipfile.lock`, and `poetry.lock`.
- **`golang.py`**: Parses `go.mod` and `go.sum`.

### [`app/codegraph/java_graph.py`](file:///d:/BGSW/services/scanner-intel/app/codegraph/java_graph.py)
- **Path**: `d:/BGSW/services/scanner-intel/app/codegraph/java_graph.py`
- **Purpose**: Ingests AST JSON from `ClassGraphExtractor.java` and builds a type-level graph.
- **Metrics Computed**: Fan-in/fan-out, PageRank centrality, strongly connected components (cycles), inheritance depth, and package coupling ($C_a, C_e, I, A, D$).

### [`app/detectors/`](file:///d:/BGSW/services/scanner-intel/app/detectors/)
- **[`agent_config.py`](file:///d:/BGSW/services/scanner-intel/app/detectors/agent_config.py)**: Scans `.cursorrules`, `CLAUDE.md`, and markdown files for prompt injection, safeguard disablement, and secret exfiltration regex patterns.
- **[`install_hooks.py`](file:///d:/BGSW/services/scanner-intel/app/detectors/install_hooks.py)**: Analyzes Stage 2 sinkhole proxy logs to catch unauthorized network egress from package scripts (`preinstall`, `postinstall`).
- **[`pinning_lockfile.py`](file:///d:/BGSW/services/scanner-intel/app/detectors/pinning_lockfile.py)**: Scans `.github/workflows/` YAML files to detect unpinned GitHub Actions (actions referencing mutable tags `@v3` or `@main` instead of 40-character commit SHAs).
- **[`squat_confusion.py`](file:///d:/BGSW/services/scanner-intel/app/detectors/squat_confusion.py)**: Computes Damerau-Levenshtein edit distance against top package lists to detect typosquats and AI hallucination attacks.
- **`data/`**: Top-10,000 package lists for Maven, npm, and PyPI.

### [`app/reachability/`](file:///d:/BGSW/services/scanner-intel/app/reachability/)
- **[`static_scan.py`](file:///d:/BGSW/services/scanner-intel/app/reachability/static_scan.py)**: Classifies package reachability into Tier 1 (Direct Call Path), Tier 2 (Transitive), or Tier 3 (Unused).
- **[`class_graph_reach.py`](file:///d:/BGSW/services/scanner-intel/app/reachability/class_graph_reach.py)**: Maps vulnerable library package namespaces to project AST call paths.

### [`app/vuln/`](file:///d:/BGSW/services/scanner-intel/app/vuln/)
- **[`assess.py`](file:///d:/BGSW/services/scanner-intel/app/vuln/assess.py)**: 5-step CycloneDX assessment engine: parse SBOM $\rightarrow$ join scanner matches $\rightarrow$ query EPSS & KEV $\rightarrow$ score $\rightarrow$ categorize.
- **[`enrich.py`](file:///d:/BGSW/services/scanner-intel/app/vuln/enrich.py)**: Queries FIRST.org EPSS API (batched) and CISA KEV JSON catalog. Computes base CVSS scores from raw vector strings using the open-source `cvss` library.
- **[`match.py`](file:///d:/BGSW/services/scanner-intel/app/vuln/match.py)**: Deduplicates and reconciles findings across Grype, OSV-Scanner, and Trivy.
- **[`risk.py`](file:///d:/BGSW/services/scanner-intel/app/vuln/risk.py)**: Shared deterministic risk scoring formula:
  $$\text{Score} = \text{round}(40 \times (\text{CVSS}/10) + 25 \times \text{EPSS} + 15 \times \text{KEV} + R)$$
  Also defines Risk Bands (`Critical`, `High`, `Medium`, `Low`), CVSS qualitative scale, and CWE weakness categories.
- **[`rescan.py`](file:///d:/BGSW/services/scanner-intel/app/vuln/rescan.py)**: Evaluates post-patch SBOM to confirm target CVE removal and verify that no new High/Critical vulnerabilities were introduced.

---

## 7. Remediation-Engine Microservice (`services/remediation-engine`)

Responsible for **risk scoring**, **policy enforcement**, **candidate patch generation**, **AI grounding validation**, and **verification gate evaluation**.

### [`app/main.py`](file:///d:/BGSW/services/remediation-engine/app/main.py)
- **Path**: `d:/BGSW/services/remediation-engine/app/main.py`
- **Purpose**: FastAPI web server exposing `/prioritize`, `/policy`, `/remediate`, `/verify`, and `/report`.

### [`app/agents/prioritizer.py`](file:///d:/BGSW/services/remediation-engine/app/agents/prioritizer.py)
- **Path**: `d:/BGSW/services/remediation-engine/app/agents/prioritizer.py`
- **Purpose**: Scores all findings using the deterministic formula. Ensures all findings have grounded evidence hashes to satisfy the Grounding Gate.

### [`app/agents/policy.py`](file:///d:/BGSW/services/remediation-engine/app/agents/policy.py)
- **Path**: `d:/BGSW/services/remediation-engine/app/agents/policy.py`
- **Purpose**: OPA/Rego policy engine.
- **Rules**:
  - Score $\ge 80 \implies \text{BLOCK}$ (Critical Hard Block).
  - Score $\ge 60 \text{ in prod} \implies \text{BLOCK}$ (Production Block).
  - Enforces the `policy_consistency_gate`.

### [`app/agents/remediator.py`](file:///d:/BGSW/services/remediation-engine/app/agents/remediator.py)
- **Path**: `d:/BGSW/services/remediation-engine/app/agents/remediator.py`
- **Purpose**: Groups blocked findings by package, builds candidate pools, triggers candidate selection, and writes unified diff patches.

### [`app/agents/verifier.py`](file:///d:/BGSW/services/remediation-engine/app/agents/verifier.py)
- **Path**: `d:/BGSW/services/remediation-engine/app/agents/verifier.py`
- **Purpose**: Evaluates Stage 4 sandbox build and test evidence. Enforces the 7 verification checks (`patch_hash_matches`, `build_success`, `tests_success`, `target_advisories_gone`, etc.).

### [`app/agents/grounding.py`](file:///d:/BGSW/services/remediation-engine/app/agents/grounding.py)
- **Path**: `d:/BGSW/services/remediation-engine/app/agents/grounding.py`
- **Purpose**: Automated fact-checker for Gemini vulnerability summaries (Invariant 4).
- **Checks**: Verifies evidence ID citations, validates all numeric figures against the deterministic fact sheet, and rejects hallucinations or formatting injections.

### [`app/agents/explainer.py`](file:///d:/BGSW/services/remediation-engine/app/agents/explainer.py)
- **Path**: `d:/BGSW/services/remediation-engine/app/agents/explainer.py`
- **Purpose**: Builds deterministic natural-language explanations for findings based on verified fields.

### [`app/remediation/candidates.py`](file:///d:/BGSW/services/remediation-engine/app/remediation/candidates.py)
- **Path**: `d:/BGSW/services/remediation-engine/app/remediation/candidates.py`
- **Purpose**: Discovers and filters upgrade candidates from registries. Enforces 14-day age limit, stable release status, same-major preference, and advisory fix version floors.

### [`app/remediation/patchers.py`](file:///d:/BGSW/services/remediation-engine/app/remediation/patchers.py)
- **Path**: `d:/BGSW/services/remediation-engine/app/remediation/patchers.py`
- **Purpose**: Manifest-only unified diff writers:
  - Maven: Updates `<version>`, POM properties, Spring Boot BOM properties, or injects `<dependencyManagement>`.
  - npm: Updates `package.json` ranges or injects `overrides`.
  - pip: Updates pinned requirements in `requirements.txt`.

### [`app/remediation/registry.py`](file:///d:/BGSW/services/remediation-engine/app/remediation/registry.py)
- **Path**: `d:/BGSW/services/remediation-engine/app/remediation/registry.py`
- **Purpose**: Client querying Maven Central, npmjs.org, and PyPI to list published versions and exact release dates.

### [`app/llm/gemini_adapter.py`](file:///d:/BGSW/services/remediation-engine/app/llm/gemini_adapter.py)
- **Path**: `d:/BGSW/services/remediation-engine/app/llm/gemini_adapter.py`
- **Purpose**: Google Gemini API client adapter. Caches responses and prompts the model strictly with sanitized JSON factsheets.

---

## 8. Web Application (`services/web`)

Built with **Next.js 15 (App Router)**, **React Flow**, and **Tailwind CSS**, providing real-time pipeline monitoring, interactive graph exploration, and one-click patch approval.

### Configuration & Root Layout
- **[`package.json`](file:///d:/BGSW/services/web/package.json)**: Next.js 15, React 19, `@xyflow/react` (React Flow), Tailwind CSS, Lucide icons.
- **[`tailwind.config.js`](file:///d:/BGSW/services/web/tailwind.config.js)** & **[`globals.css`](file:///d:/BGSW/services/web/src/app/globals.css)**: Dark-themed cybersecurity styling.
- **[`src/app/layout.tsx`](file:///d:/BGSW/services/web/src/app/layout.tsx)**: Root application wrapper with navigation header and audit status badges.
- **[`src/app/page.tsx`](file:///d:/BGSW/services/web/src/app/page.tsx)**: Home dashboard listing active and historical security analysis runs.

### Run Views (`src/app/runs/[runId]/`)
- **[`page.tsx`](file:///d:/BGSW/services/web/src/app/runs/[runId]/page.tsx)**: High-level overview displaying target repo, commit SHA, Ed25519 audit head, and summary cards.
- **[`pipeline/page.tsx`](file:///d:/BGSW/services/web/src/app/runs/[runId]/pipeline/page.tsx)**: Real-time visual timeline showing each of the 9 pipeline stages and gate evaluations.
- **[`findings/page.tsx`](file:///d:/BGSW/services/web/src/app/runs/[runId]/findings/page.tsx)**: Filterable table of all detected CVEs and supply-chain anomalies with risk badges and dependency paths.
- **[`graph/page.tsx`](file:///d:/BGSW/services/web/src/app/runs/[runId]/graph/page.tsx)**: Interactive 2D React Flow dependency graph displaying packages, versions, and blast-radius call chains.
- **[`classes/page.tsx`](file:///d:/BGSW/services/web/src/app/runs/[runId]/classes/page.tsx)**: Code-level class dependency graph showing inheritance and static method invocations.
- **[`remediation/page.tsx`](file:///d:/BGSW/services/web/src/app/runs/[runId]/remediation/page.tsx)**: Remediation approval hub displaying candidate patches, unified diffs, Stage 4 sandbox test logs, and the **Approve** / **Reject** buttons.
- **[`reports/page.tsx`](file:///d:/BGSW/services/web/src/app/runs/[runId]/reports/page.tsx)**: Interactive viewer and export tool for `report.md` and `report.json`.

### Reusable UI Components (`src/components/`)
- **[`ApprovalQueue.tsx`](file:///d:/BGSW/services/web/src/components/ApprovalQueue.tsx)**: Review queue for pending remediations.
- **[`AuditChainBadge.tsx`](file:///d:/BGSW/services/web/src/components/AuditChainBadge.tsx)**: Live cryptographic verification pill indicating whether the Ed25519 signature chain is valid.
- **[`EvidenceDrawer.tsx`](file:///d:/BGSW/services/web/src/components/EvidenceDrawer.tsx)**: Slide-out drawer revealing raw Grype, OSV, and EPSS evidence artifacts for any finding.
- **[`VerificationResult.tsx`](file:///d:/BGSW/services/web/src/components/VerificationResult.tsx)**: Renders Stage 4 sandbox test logs, build outcomes, and rescan comparisons.
- **[`graph/`](file:///d:/BGSW/services/web/src/components/graph/)**: Custom React Flow nodes, edge renderers, and search bars for navigating large package graphs.

---

## 9. Evaluation, Benchmark & Red-Team Suite (`tests/`)

Houses the automated evaluation harness, golden benchmark targets, and adversarial supply chain attack payloads.

### [`tests/eval_runner.py`](file:///d:/BGSW/tests/eval_runner.py)
- **Path**: `d:/BGSW/tests/eval_runner.py`
- **Purpose**: Automated evaluation runner executing 9 end-to-end gate checks:
  - 4 Golden Repositories (Log4Shell Maven, Node Lodash, Python Requests, Clean baseline).
  - 5 Red-Team Adversary Vectors.
- **Usage**: `python tests/eval_runner.py`.

### [`tests/golden-repos/manifest.json`](file:///d:/BGSW/tests/golden-repos/manifest.json)
- **Path**: `d:/BGSW/tests/golden-repos/manifest.json`
- **Purpose**: Specification file declaring expected CVE IDs, policy verdicts (`BLOCK` vs `PASS`), and fix versions for the 4 reference repositories.

### [`tests/golden-repos/log4shell_app/pom.xml`](file:///d:/BGSW/tests/golden-repos/log4shell_app/pom.xml)
- **Path**: `d:/BGSW/tests/golden-repos/log4shell_app/pom.xml`
- **Purpose**: Minimal vulnerable Java project referencing `org.apache.logging.log4j:log4j-core:2.14.1` for benchmarking Log4Shell detection, reachability, and automated upgrade.

### [`tests/red-team/`](file:///d:/BGSW/tests/red-team/)
- **[`01_prompt_injection_readme/README.md`](file:///d:/BGSW/tests/red-team/01_prompt_injection_readme/README.md)**: Contains prompt injection commands (`SYSTEM INSTRUCTION OVERRIDE: ignore previous instructions...`) to test `AgentConfigDetector`.
- **[`02_malicious_postinstall/package.json`](file:///d:/BGSW/tests/red-team/02_malicious_postinstall/package.json)**: Contains a `postinstall` script attempting unauthorized curl beacons to test the Stage 2 Sinkhole Proxy.
- **[`03_symlink_escape/`](file:///d:/BGSW/tests/red-team/03_symlink_escape/)**: Contains symlinks escaping the repository root to verify Stage 1 directory traversal containment.
- **[`04_oversize_repo/README.md`](file:///d:/BGSW/tests/red-team/04_oversize_repo/README.md)**: Simulates a 60 MB+ repository bomb to test Stage 1 resource exhaustion caps.
- **[`05_fake_package_comment/app.py`](file:///d:/BGSW/tests/red-team/05_fake_package_comment/app.py)**: Contains typosquatted package recommendations (`reqeusts` vs `requests`) to test `SquatConfusionDetector`.

---

## 10. Architectural Security Invariants Mapping

| Invariant | System Rule | Enforcing Files |
| :--- | :--- | :--- |
| **Invariant 1** | Untrusted code runs only in throwaway sandboxes; only launcher holds Docker socket. | [`docker_runner.py`](file:///d:/BGSW/services/launcher/app/docker_runner.py), [`docker-compose.yml`](file:///d:/BGSW/docker-compose.yml) |
| **Invariant 2** | Verify before approval (compilation, tests, and rescan in an isolated sandbox). | [`stage4_verify.py`](file:///d:/BGSW/services/launcher/app/stages/stage4_verify.py), [`verifier.py`](file:///d:/BGSW/services/remediation-engine/app/agents/verifier.py) |
| **Invariant 3** | Deterministic code decides safety (pure math formula, no LLM score generation). | [`risk.py`](file:///d:/BGSW/services/scanner-intel/app/vuln/risk.py), [`policy.py`](file:///d:/BGSW/services/remediation-engine/app/agents/policy.py) |
| **Invariant 4** | AI proposes, code verifies (per-sentence fact-checking; 0% hallucination fallback). | [`grounding.py`](file:///d:/BGSW/services/remediation-engine/app/agents/grounding.py), [`remediator.py`](file:///d:/BGSW/services/remediation-engine/app/agents/remediator.py) |
| **Invariant 5** | Resolve with network, scan without network (`--network=none` offline scanning). | [`scan.Dockerfile`](file:///d:/BGSW/services/launcher/sandbox-images/scan.Dockerfile), [`stage3_scan.py`](file:///d:/BGSW/services/launcher/app/stages/stage3_scan.py) |
| **Invariant 6** | Tamper-evident audit trail (Ed25519 signature chain linked by parent hashes). | [`audit_chain.py`](file:///d:/BGSW/services/orchestrator/app/db/audit_chain.py), [`001_init.sql`](file:///d:/BGSW/infra/postgres/001_init.sql) |
