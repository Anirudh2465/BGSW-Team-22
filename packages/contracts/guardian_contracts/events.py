from typing import Any, Dict, Optional, Literal
from pydantic import BaseModel, Field

class WebSocketEvent(BaseModel):
    event_type: Literal["node_progress", "gate_result", "audit", "run_status", "error"]
    run_id: str
    timestamp: str
    payload: Dict[str, Any]

class NodeProgressEvent(BaseModel):
    run_id: str
    node_name: str
    status: Literal["started", "running", "completed", "failed"]
    duration_ms: Optional[int] = None
    details: Optional[Dict[str, Any]] = None

class GateResultEvent(BaseModel):
    run_id: str
    gate_name: str
    passed: bool
    reason: str
    metrics: Dict[str, Any] = Field(default_factory=dict)

class AuditEvent(BaseModel):
    seq: int
    run_id: str
    node_name: str
    payload_sha256: str
    prev_hash: str
    entry_hash: str
    ed25519_sig: str
    created_at: str
