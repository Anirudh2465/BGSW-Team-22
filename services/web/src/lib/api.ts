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
export type RunStatus = "queued" | "running" | "completed" | "stopped" | "error";

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
  approvals: Record<string, unknown>;
  gate_results: GateResult[];
  final_report?: {
    markdown_sha256?: string;
    sarif_sha256?: string;
    vex_sha256?: string;
    pr_url?: string;
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

export const approvePatch = (runId: string, findingId: string, patchSha256: string, userId = "dashboard-user") =>
  request(`/runs/${encodeURIComponent(runId)}/approve`, {
    method: "POST",
    body: JSON.stringify({ finding_id: findingId, decision: "APPROVED", user_id: userId, patch_sha256: patchSha256 }),
  });

export const isTerminal = (status?: RunStatus) => status === "completed" || status === "stopped" || status === "error";
