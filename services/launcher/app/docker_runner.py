import os
import shutil
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("launcher.docker_runner")

class DockerRunner:
    """Manages container runtime execution with gVisor (runsc) or hardened runc fallback."""

    def __init__(self):
        self.runtime = os.getenv("SANDBOX_RUNTIME", "runsc")
        self.cpu_limit = "2.0"
        self.memory_limit = "4g"
        self.pids_limit = 100
        self.docker_available = shutil.which("docker") is not None

    def get_runtime_flags(self, network_mode: str = "none") -> Dict[str, Any]:
        flags = {
            "runtime": self.runtime if self.runtime == "runsc" else "runc",
            "cpus": self.cpu_limit,
            "memory": self.memory_limit,
            "pids_limit": self.pids_limit,
            "network": network_mode,
            "security_opt": ["no-new-privileges:true"],
            "cap_drop": ["ALL"],
        }
        if network_mode == "none":
            flags["network_mode"] = "none"
        return flags

    def verify_runtime_health(self) -> Dict[str, Any]:
        return {
            "docker_available": self.docker_available,
            "configured_runtime": self.runtime,
            "active_runtime": self.runtime if self.docker_available else "emulated",
            "limits": {
                "cpus": self.cpu_limit,
                "memory": self.memory_limit,
                "pids": self.pids_limit,
            }
        }
