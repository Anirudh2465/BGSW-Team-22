-- Supply Chain Guardian - Initial Core Database Schema

CREATE TABLE IF NOT EXISTS artifacts (
    sha256 TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    media_type TEXT NOT NULL,
    content BYTEA NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_artifacts_run_id ON artifacts (run_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_stage ON artifacts (stage);

CREATE TABLE IF NOT EXISTS findings (
    run_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    data JSONB NOT NULL,
    score INT,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (run_id, finding_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_run_id ON findings (run_id);
CREATE INDEX IF NOT EXISTS idx_findings_score ON findings (score);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings (status);

CREATE TABLE IF NOT EXISTS dependency_edges (
    id BIGSERIAL PRIMARY KEY,
    run_id TEXT NOT NULL,
    source_purl TEXT NOT NULL,
    target_purl TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_dep_edges_run_id ON dependency_edges (run_id);
CREATE INDEX IF NOT EXISTS idx_dep_edges_source ON dependency_edges (source_purl);
CREATE INDEX IF NOT EXISTS idx_dep_edges_target ON dependency_edges (target_purl);

CREATE TABLE IF NOT EXISTS audit_log (
    seq BIGSERIAL PRIMARY KEY,
    run_id TEXT NOT NULL,
    node_name TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    ed25519_sig TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_log_run_id ON audit_log (run_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_entry_hash ON audit_log (entry_hash);
