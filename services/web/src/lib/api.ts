// Typed client for the orchestrator gateway.
// NEXT_PUBLIC_* values are inlined at build time; the browser calls the orchestrator directly.

export const ORCHESTRATOR_URL =
  process.env.NEXT_PUBLIC_ORCHESTRATOR_URL?.replace(/\/$/, "") || "http://localhost:8000";
export const ORCHESTRATOR_WS_URL =
  process.env.NEXT_PUBLIC_ORCHESTRATOR_WS_URL?.replace(/\/$/, "") ||
  ORCHESTRATOR_URL.replace(/^http/, "ws");

export interface Evidence {
  id: string;
  tool: string;
  artifact_sha256: string;
}

export interface Finding {
  id: string;
  kind: string;
  purl: string;
  path: string[];
  evidence: Evidence[];
  status: "confirmed" | "unconfirmed";
  reach_tier?: 1 | 2 | 3 | null;
  score?: number | null;
  explanation?: string | null;
}

export interface Remediation {
  finding_id: string;
  candidates: string[];
  chosen?: number | null;
  patch_sha256?: string | null;
  validation?: Record<string, unknown> | null;
  retry_count: number;
  state: "draft" | "verified" | "no_safe_fix" | "escalated";
}

export interface Confirmation {
  child_run_id: string;
  status: "queued" | "running" | "passed" | "failed";
  finding_ids: string[];
  user_id: string;
  target: string;
  started_at?: string;
  finished_at?: string;
  failed?: string[];
  checks?: { name: string; passed: boolean; detail?: unknown }[];
  pull_request?: { status: string; pr_url?: string | null; reason?: string | null };
}

export interface AssistRecord {
  at: string;
  user_id: string;
  state: Remediation["state"];
  summary?: string | null;
  advice?: { code: string; text: string } | null;
  decided_by?: string | null;
  gemini_status?: string | null;
}

export interface AwaitingVerification {
  finding_id: string;
  patch_sha256: string;
  target?: string | null;
  retry_count: number;
  previous_failed?: string[] | null;
}

/** A verified remediation waiting at the approval interrupt. */
export interface PendingApproval {
  finding_id: string;
  patch_sha256: string;
  target?: string | null;
  retry_count: number;
  warning?: string | null;
}

export interface GateResult {
  gate: string;
  passed: boolean;
  reason?: string | null;
  error?: string;
  action?: string | null;
  attempt?: number;
  [key: string]: unknown;
}

export type CoverageStatus = "scanned" | "single_source" | "skipped";
export type RunStatus = "queued" | "running" | "awaiting_approval" | "resuming" | "completed" | "stopped" | "error";

export interface RunData {
  run_id: string;
  status: RunStatus;
  error?: string | null;
  current_node?: string | null;
  repo_url: string;
  commit_sha: string;
  source_sha256: string;
  architecture_profile: Record<string, any>;
  check_plan: string[];
  sbom_ref?: string | null;
  coverage: Record<string, CoverageStatus>;
  dep_graph_summary: Record<string, any>;
  findings: Record<string, Finding>;
  policy_verdicts: Record<string, "PASS" | "BLOCK">;
  remediations: Record<string, Remediation>;
  approvals: Record<string, { decision: "APPROVED" | "REJECTED" | "PENDING"; user_id?: string | null; patch_sha256?: string | null }>;
  pending_approvals?: PendingApproval[];
  /** Draft fixes waiting for a human to click "Verify fix" (nothing is verified automatically). */
  awaiting_verification?: AwaitingVerification[];
  /** The patch being verified right now, if any. */
  verifying?: { patch_sha256: string; finding_ids: string[]; user_id: string; started_at: string } | null;
  kind?: "pipeline" | "confirmation";
  parent_run_id?: string | null;
  /** Confirmation runs started by "Accept", keyed by patch SHA-256. */
  confirmations?: Record<string, Confirmation>;
  /** "Ask Gemini" results, keyed by finding ID. */
  assists?: Record<string, AssistRecord>;
  decisions?: Record<string, { decision: "APPROVED" | "REJECTED"; user_id: string; patch_sha256: string; at?: string }>;
  gate_results: GateResult[];
  final_report?: {
    markdown_sha256?: string;
    sarif_sha256?: string;
    vex_sha256?: string;
    pr_url?: string | null;
    pull_requests?: { patch_sha256: string; status: string; pr_url?: string | null; reason?: string | null }[];
    kind?: string;
    passed?: boolean;
    failed?: string[];
  };
  audit_chain_head: string;
  artifacts?: Record<string, RunArtifact>;
}

/** One separately stored, content-addressed artifact (SBOM, package graph, class graph). */
export interface RunArtifact {
  sha256: string;
  media_type: string;
  filename?: string;
  title?: string;
  download?: string;
  size?: number;
  [key: string]: unknown;
}

// ---------------------------------------------------------------- class graph
export type ClassRelationship = "extends" | "implements" | "field" | "instantiates" | "method" | "calls" | "uses" | "annotation";

export interface ClassNode {
  id: string;
  name: string;
  simple_name: string;
  package: string;
  kind: "class" | "interface" | "enum" | "record" | "annotation" | "type" | "external";
  external: boolean;
  jdk?: boolean;
  stereotype: string;
  abstract?: boolean;
  file?: string;
  line?: number;
  end_line?: number;
  loc?: number;
  methods?: number;
  fields?: number;
  constructors?: number;
  annotations?: string[];
  outer?: string | null;
  test?: boolean;
  fan_in: number;
  fan_out: number;
  external_deps?: number;
  pagerank?: number;
  rank?: number;
  cycle?: number | null;
  layer?: number;
  inheritance_depth?: number;
  subtypes?: number;
}

export interface ClassLink {
  source: string;
  target: string;
  relationship: ClassRelationship;
  relationships: ClassRelationship[];
  counts: Record<string, number>;
  weight: number;
  external: boolean;
  line?: number;
}

export interface ClassPackage {
  id: string;
  package: string;
  classes: number;
  tests: number;
  afferent: number;
  efferent: number;
  instability: number;
  abstractness: number;
  distance: number;
  in_cycle: boolean;
  loc: number;
}

export interface ClassGraph {
  nodes: ClassNode[];
  links: ClassLink[];
  graph: {
    schema: string;
    language: string;
    status: string;
    tool?: { name?: string; version?: string; extractor_version?: string; language_level?: string };
    metrics: Record<string, any>;
    cycles: string[][];
    package_cycles: string[][];
    packages: ClassPackage[];
    package_links: { source: string; target: string; weight: number }[];
    top_unresolved?: { name: string; count: number }[];
    parse_errors?: { path: string; error: string }[];
  };
}

export interface GraphNode {
  id: string;
  kind: "application" | "module" | "library";
  label?: string;
  name?: string;
  version?: string;
  ecosystem?: string;
  scope?: string;
  sources?: string[];
  single_source?: boolean;
  resolved?: boolean;
  direct?: boolean;
  depth?: number | null;
  path?: string[];
}

export interface GraphLink {
  source: string;
  target: string;
  relationship: "module" | "depends_on" | "unresolved";
  scope?: string;
}

export interface DepGraph {
  nodes: GraphNode[];
  links: GraphLink[];
  graph?: { root?: string; metrics?: Record<string, any>; sbom_sha256?: string };
}

export interface RunGraph {
  run_id: string;
  dep_graph: DepGraph;
  coverage: Record<string, CoverageStatus>;
  sbom_ref?: string | null;
}

export interface Neo4jInfo {
  enabled: boolean;
  export: { exported?: boolean; reason?: string; components?: number; edges?: number };
  browser_url: string;
  queries: { title: string; cypher: string; url: string }[];
}

export interface RunSummary {
  run_id: string;
  status: RunStatus;
  repo_url: string;
  commit_sha: string;
  findings_count: number;
  final_report?: RunData["final_report"] | null;
  kind?: "pipeline" | "confirmation";
  parent_run_id?: string | null;
}

export interface RunEventRecord {
  event_type: string;
  run_id: string;
  timestamp?: string;
  seq?: number;
  payload: Record<string, any>;
}

export interface OrchestratorHealth {
  status: string;
  service: string;
  artifact_backend?: string;
  neo4j_enabled?: boolean;
  audit_chain_head?: string;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${ORCHESTRATOR_URL}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
    cache: "no-store",
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      detail = (await res.json()).detail ?? detail;
    } catch {
      /* not JSON */
    }
    throw new Error(`${res.status} ${detail}`);
  }
  return res.json() as Promise<T>;
}

export const fetchRuns = () => request<RunSummary[]>("/runs").catch(() => [] as RunSummary[]);

export const fetchRun = (runId: string) => request<RunData>(`/runs/${encodeURIComponent(runId)}`);

export const fetchGraph = (runId: string) => request<RunGraph>(`/runs/${encodeURIComponent(runId)}/graph`);

export const fetchNeo4j = (runId: string) => request<Neo4jInfo>(`/runs/${encodeURIComponent(runId)}/neo4j`);

export const fetchEvents = (runId: string, since = 0) =>
  request<RunEventRecord[]>(`/runs/${encodeURIComponent(runId)}/events?since=${since}`);

export const fetchClassGraph = (runId: string) => request<ClassGraph>(`/runs/${encodeURIComponent(runId)}/class-graph`);

export const artifactDownloadUrl = (runId: string, name: string) =>
  `${ORCHESTRATOR_URL}/runs/${encodeURIComponent(runId)}/artifacts/${encodeURIComponent(name)}`;

export const fetchHealth = () => request<OrchestratorHealth>("/health");

export const sbomDownloadUrl =(runId: string) => `${ORCHESTRATOR_URL}/runs/${encodeURIComponent(runId)}/sbom`;

export const createRun = (repoUrl: string, commitSha: string = "HEAD") =>
  request<{ run_id: string; status: RunStatus }>("/runs", {
    method: "POST",
    body: JSON.stringify({ repo_url: repoUrl, commit_sha: commitSha || "HEAD" }),
  });

export const approvePatch = (
  runId: string,
  findingId: string,
  patchSha256: string,
  decision: "APPROVED" | "REJECTED" = "APPROVED",
  userId = "dashboard-user",
) =>
  request<{ status: "recorded" | "resumed" }>(`/runs/${encodeURIComponent(runId)}/approve`, {
    method: "POST",
    body: JSON.stringify({ finding_id: findingId, decision, user_id: userId, patch_sha256: patchSha256 }),
  });

/** Accept a verified fix: re-runs the whole pipeline on the patched source; approval + PR only if it passes. */
export const acceptFix = (runId: string, findingId: string, patchSha256: string, userId = "dashboard-user") =>
  request<{ status: "started" | "already_running"; confirmation: Confirmation }>(
    `/runs/${encodeURIComponent(runId)}/remediations/${encodeURIComponent(findingId)}/accept`,
    { method: "POST", body: JSON.stringify({ user_id: userId, patch_sha256: patchSha256 }) },
  );

/** Verify one draft fix in the sandbox (build, tests, re-resolve, rescan) -- only on this explicit request. */
export const verifyFix = (runId: string, findingId: string, userId = "dashboard-user") =>
  request<{ status: string; patch_sha256: string; finding_ids: string[] }>(
    `/runs/${encodeURIComponent(runId)}/remediations/${encodeURIComponent(findingId)}/verify`,
    { method: "POST", body: JSON.stringify({ user_id: userId }) },
  );

/** Close a paused run: unverified / undecided fixes are recorded as deferred and the reports are written. */
export const finishRun = (runId: string, userId = "dashboard-user") =>
  request<{ status: string }>(`/runs/${encodeURIComponent(runId)}/finish`, { method: "POST", body: JSON.stringify({ user_id: userId }) });

/** Ask Gemini to remediate one finding (code-built candidates; Gemini picks and explains; then verify). */
export const askGemini = (runId: string, findingId: string, userId = "dashboard-user") =>
  request<{ status: string; remediation: Remediation; assist: Record<string, unknown> }>(
    `/runs/${encodeURIComponent(runId)}/findings/${encodeURIComponent(findingId)}/ask-ai`,
    { method: "POST", body: JSON.stringify({ user_id: userId }) },
  );

/** One sandbox step's log (secrets scrubbed) from a verification bundle of this run. */
export async function fetchVerifyLog(runId: string, bundleSha256: string, step: string): Promise<string> {
  const res = await fetch(
    `${ORCHESTRATOR_URL}/runs/${encodeURIComponent(runId)}/verify-log/${encodeURIComponent(bundleSha256)}/${encodeURIComponent(step)}`,
    { cache: "no-store" },
  );
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.text();
}

/** The exact patch (unified diff) a remediation refers to, by its SHA-256. */
export async function fetchPatch(runId: string, patchSha256: string): Promise<string> {
  const res = await fetch(`${ORCHESTRATOR_URL}/runs/${encodeURIComponent(runId)}/patches/${encodeURIComponent(patchSha256)}`, {
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.text();
}

export const isTerminal = (status?: RunStatus) => status === "completed" || status === "stopped" || status === "error";
