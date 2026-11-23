import os
import sys
import json
import hashlib
from typing import List, Dict, Any, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519

GENESIS_HASH = "0" * 64

class AuditChainManager:
    """Tamper-evident hash chain with Ed25519 signatures for all state machine transitions."""

    def __init__(self, private_key_hex: str = None):
        self._chain: List[Dict[str, Any]] = []
        # Generate or load Ed25519 private key
        if private_key_hex and len(private_key_hex) == 64:
            seed = bytes.fromhex(private_key_hex)
            self._priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        else:
            self._priv_key = ed25519.Ed25519PrivateKey.generate()
        self._pub_key = self._priv_key.public_key()

    def record_transition(self, run_id: str, node_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        payload_json = json.dumps(payload, sort_keys=True)
        payload_sha256 = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()

        seq = len(self._chain) + 1
        prev_hash = self._chain[-1]["entry_hash"] if self._chain else GENESIS_HASH

        entry_material = f"{seq}:{run_id}:{node_name}:{payload_sha256}:{prev_hash}".encode("utf-8")
        entry_hash = hashlib.sha256(entry_material).hexdigest()

        # Sign entry_hash with Ed25519
        sig_bytes = self._priv_key.sign(entry_hash.encode("utf-8"))
        ed25519_sig = sig_bytes.hex()

        entry = {
            "seq": seq,
            "run_id": run_id,
            "node_name": node_name,
            "payload_sha256": payload_sha256,
            "prev_hash": prev_hash,
            "entry_hash": entry_hash,
            "ed25519_sig": ed25519_sig,
        }
        self._chain.append(entry)
        return entry

    def get_chain_head(self) -> str:
        return self._chain[-1]["entry_hash"] if self._chain else GENESIS_HASH

    def get_entries(self, run_id: str = None) -> List[Dict[str, Any]]:
        if run_id:
            return [e for e in self._chain if e["run_id"] == run_id]
        return list(self._chain)

    def verify_chain(self, run_id: str = None) -> Tuple[bool, List[str]]:
        entries = self.get_entries(run_id)
        if not entries:
            return True, ["Chain is empty or valid genesis"]

        errors = []
        expected_prev = GENESIS_HASH
        for e in entries:
            # 1. Verify prev_hash
            if e["prev_hash"] != expected_prev:
                errors.append(f"Broken hash link at seq {e['seq']}: expected {expected_prev}, got {e['prev_hash']}")

            # 2. Recompute entry_hash
            material = f"{e['seq']}:{e['run_id']}:{e['node_name']}:{e['payload_sha256']}:{e['prev_hash']}".encode("utf-8")
            recomputed = hashlib.sha256(material).hexdigest()
            if recomputed != e["entry_hash"]:
                errors.append(f"Tampered entry_hash at seq {e['seq']}")

            # 3. Verify Ed25519 signature
            try:
                sig_bytes = bytes.fromhex(e["ed25519_sig"])
                self._pub_key.verify(sig_bytes, e["entry_hash"].encode("utf-8"))
            except Exception as ex:
                errors.append(f"Invalid Ed25519 signature at seq {e['seq']}: {ex}")

            expected_prev = e["entry_hash"]

        return len(errors) == 0, errors

audit_chain = AuditChainManager()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Verify Supply Chain Guardian Audit Chain")
    parser.add_argument("--verify", type=str, help="Run ID to verify")
    args = parser.parse_args()
    valid, details = audit_chain.verify_chain(args.verify)
    print(f"Audit Chain Verification: {'PASSED' if valid else 'FAILED'}")
    for d in details:
        print(f"  - {d}")
    sys.exit(0 if valid else 1)
