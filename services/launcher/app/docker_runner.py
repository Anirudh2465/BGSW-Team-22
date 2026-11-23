"""Sandbox executor: the only code in Guardian that talks to the Docker socket (Invariant 5).

Every stage runs as a throwaway container:
- gVisor (`runsc`) runtime, or hardened `runc` when SANDBOX_RUNTIME=runc
- read-only root, writable tmpfs work dirs, all capabilities dropped,
  no-new-privileges, non-root user, CPU / RAM / PID / time limits
- inputs are streamed in as a tar on stdin and outputs streamed back as a tar on
  stdout, so no host path is ever bind-mounted into a sandbox
- network is either `none` (Stage 3) or a fresh *internal* Docker network whose
  only reachable peer is this launcher's per-run egress proxy
"""

import logging
import os
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .allowlist import ALLOWLISTED_IMAGES, pinned_digest

logger = logging.getLogger("launcher.docker_runner")

PROXY_ALIAS = "guardian-egress"


class SandboxError(RuntimeError):
    pass


@dataclass
class EgressConfig:
    """Proxy ports (on the launcher) a sandbox may use. Empty means --network=none."""
    allowlist_port: Optional[int] = None
    sinkhole_port: Optional[int] = None

    @property
    def enabled(self) -> bool:
        return self.allowlist_port is not None or self.sinkhole_port is not None


@dataclass
class SandboxResult:
    exit_code: int
    output_tar: bytes
    stderr: str
    timed_out: bool = False
    duration_ms: int = 0
    network_mode: str = "none"
    image_id: str = ""
    flags: List[str] = field(default_factory=list)


class DockerRunner:
    """Manages container execution with gVisor (runsc) or hardened runc fallback."""

    def __init__(self):
        self.runtime = os.getenv("SANDBOX_RUNTIME", "runsc")
        self.cpu_limit = os.getenv("SANDBOX_CPUS", "2.0")
        self.memory_limit = os.getenv("SANDBOX_MEMORY", "4g")
        self.pids_limit = int(os.getenv("SANDBOX_PIDS", "512"))
        self.workspace_size = os.getenv("SANDBOX_WORKSPACE_SIZE", "2g")
        self.docker_bin = shutil.which("docker")
        self.docker_available = self.docker_bin is not None
        self.self_container = os.getenv("LAUNCHER_CONTAINER_NAME", "guardian-launcher")

    # ------------------------------------------------------------ inspection
    def get_runtime_flags(self, network_mode: str = "none") -> Dict[str, object]:
        flags = {
            "runtime": "runsc" if self.runtime == "runsc" else "runc",
            "cpus": self.cpu_limit,
            "memory": self.memory_limit,
            "pids_limit": self.pids_limit,
            "network": network_mode,
            "read_only": True,
            "security_opt": ["no-new-privileges:true"],
            "cap_drop": ["ALL"],
        }
        if network_mode == "none":
            flags["network_mode"] = "none"
        return flags

    def verify_runtime_health(self) -> Dict[str, object]:
        runtimes: List[str] = []
        daemon_ok = False
        if self.docker_available:
            try:
                out = self._docker(["info", "--format", "{{range $k, $v := .Runtimes}}{{$k}} {{end}}"], timeout=10)
                runtimes = out.stdout.decode().split()
                daemon_ok = out.returncode == 0
            except Exception:
                daemon_ok = False
        return {
            "docker_available": self.docker_available,
            "daemon_reachable": daemon_ok,
            "configured_runtime": self.runtime,
            "runtime_installed": self.runtime in runtimes if daemon_ok else False,
            "limits": {"cpus": self.cpu_limit, "memory": self.memory_limit, "pids": self.pids_limit},
        }

    def resolve_image(self, stage: str) -> str:
        """Map a stage to its allowlisted image and return the immutable image ID."""
        tag = ALLOWLISTED_IMAGES.get(stage)
        if not tag:
            raise SandboxError(f"No allowlisted image for stage {stage!r}")
        res = self._docker(["image", "inspect", "--format", "{{.Id}}", tag], timeout=30)
        if res.returncode != 0:
            raise SandboxError(f"Sandbox image {tag} is not built. Run `make sandbox-images`.")
        image_id = res.stdout.decode().strip()
        expected = pinned_digest(stage)
        if expected and image_id != expected:
            raise SandboxError(f"Image {tag} is {image_id}, but {expected} is pinned; refusing to run")
        return image_id

    # ------------------------------------------------------------- execution
    def run(self, stage: str, script: str, input_tar: Optional[bytes] = None,
            env: Optional[Dict[str, str]] = None, egress: Optional[EgressConfig] = None,
            timeout_s: int = 600) -> SandboxResult:
        if not self.docker_available:
            raise SandboxError("Docker CLI not found in launcher; sandboxes cannot run")
        image_id = self.resolve_image(stage)
        name = f"guardian-sbx-{stage}-{uuid.uuid4().hex[:10]}"
        network = "none"
        created_network = False
        env = dict(env or {})

        if egress and egress.enabled:
            if stage == "scan":
                raise SandboxError("Security Invariant Violation: Stage 3 scan MUST run with --network=none")
            network = f"{name}-net"
            self._checked(["network", "create", "--internal", "--label", "guardian.sandbox=1", network])
            created_network = True
            try:
                self._checked(["network", "connect", "--alias", PROXY_ALIAS, network, self.self_container])
            except SandboxError:
                self._docker(["network", "rm", network], timeout=30)
                raise
            if egress.allowlist_port:
                proxy = f"http://{PROXY_ALIAS}:{egress.allowlist_port}"
                for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
                    env[key] = proxy
                env["GUARDIAN_PROXY_HOST"] = PROXY_ALIAS
                env["GUARDIAN_PROXY_PORT"] = str(egress.allowlist_port)
            if egress.sinkhole_port:
                env["GUARDIAN_SINKHOLE_PROXY"] = f"http://{PROXY_ALIAS}:{egress.sinkhole_port}"
            env["NO_PROXY"] = ""

        flags = [
            "--rm", "-i", "--name", name,
            "--read-only",
            "--tmpfs", f"/workspace:rw,exec,size={self.workspace_size},mode=1777",
            "--tmpfs", "/tmp:rw,size=512m,mode=1777",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
            "--pids-limit", str(self.pids_limit),
            "--cpus", str(self.cpu_limit),
            "--memory", self.memory_limit,
            "--user", "10001:10001",
            "--network", network,
            "--label", "guardian.sandbox=1",
        ]
        if self.runtime == "runsc":
            flags += ["--runtime", "runsc"]
        env.setdefault("HOME", "/workspace/home")
        for key, value in sorted(env.items()):
            flags += ["-e", f"{key}={value}"]

        cmd = ["run", *flags, image_id, "sh", "-c", script]
        started = time.monotonic()
        timed_out = False
        try:
            proc = self._docker(cmd, input_bytes=input_tar or b"", timeout=timeout_s)
            exit_code, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            self._docker(["kill", name], timeout=30)
            exit_code, stdout, stderr = 124, b"", (exc.stderr or b"")
        finally:
            if created_network:
                self._docker(["network", "disconnect", "-f", network, self.self_container], timeout=30)
                self._docker(["network", "rm", network], timeout=30)

        return SandboxResult(
            exit_code=exit_code,
            output_tar=stdout,
            stderr=stderr.decode("utf-8", errors="replace")[-20000:],
            timed_out=timed_out,
            duration_ms=int((time.monotonic() - started) * 1000),
            network_mode="none" if network == "none" else "internal+proxy",
            image_id=image_id,
            flags=flags,
        )

    # --------------------------------------------------------------- helpers
    def _docker(self, args: List[str], input_bytes: Optional[bytes] = None, timeout: int = 60):
        return subprocess.run([self.docker_bin, *args], input=input_bytes, capture_output=True, timeout=timeout)

    def _checked(self, args: List[str]):
        res = self._docker(args, timeout=60)
        if res.returncode != 0:
            raise SandboxError(f"docker {' '.join(args[:2])} failed: {res.stderr.decode(errors='replace')[:500]}")
        return res
