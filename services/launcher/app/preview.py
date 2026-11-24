"""Live app previews: build and run a repo in a sandbox and open it in the browser (http://localhost:<port>).

Same isolation as the stage sandboxes: allowlisted image, read-only root, no capabilities, CPU/RAM/PID
limits, a fresh *internal* network whose only exit is this launcher's allowlist proxy (registries, for the
build). Nothing is published from the sandbox itself: the launcher forwards one of its own ports
(published by docker compose on 127.0.0.1 only) to the app's port 8080 inside that network.

If the project uses MySQL or PostgreSQL, a throwaway database container is started first and the app shares
its network namespace, so the app's ``localhost:3306`` / ``localhost:5432`` reaches it unchanged. Credentials
and the database name are read from the project's Spring datasource settings when present; ``*.sql`` files at
the repo root are loaded on first start. Previews stop by themselves after ``PREVIEW_TTL_S``; at most one per
port in ``PREVIEW_PORTS`` runs at a time.
"""

import io
import logging
import os
import re
import select
import socket
import subprocess
import tarfile
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from .docker_runner import PROXY_ALIAS, DockerRunner, SandboxError
from .proxy.egress_proxy import EgressProxy
from .stages.stage4_verify import MAVEN_DEPENDENCY_PLUGIN, READY_PATTERN, plan_build, health_manifests
from .tarballs import read_members

logger = logging.getLogger("launcher.preview")

PREVIEW_PORTS = [int(p) for p in os.getenv("PREVIEW_PORTS", "18080,18081").split(",") if p.strip()]
PREVIEW_TTL_S = int(os.getenv("PREVIEW_TTL_S", "1800"))
APP_PORT = 8080
DB_IMAGES = {"mysql": os.getenv("PREVIEW_MYSQL_IMAGE", "mysql:8.0"),
             "postgres": os.getenv("PREVIEW_POSTGRES_IMAGE", "postgres:16-alpine")}

PREVIEW_SCRIPT = r"""
set -u
mkdir -p "$HOME" /workspace/src /workspace/m2
tar -xzmf - -C /workspace/src
cd /workspace/src
echo "[guardian] building ($GUARDIAN_ECOSYSTEMS)"
if [ "$GUARDIAN_KIND" = maven ]; then
  cat > "$HOME/settings.xml" <<EOF
<settings><proxies>
<proxy><id>g-https</id><active>true</active><protocol>https</protocol><host>$GUARDIAN_PROXY_HOST</host><port>$GUARDIAN_PROXY_PORT</port></proxy>
<proxy><id>g-http</id><active>true</active><protocol>http</protocol><host>$GUARDIAN_PROXY_HOST</host><port>$GUARDIAN_PROXY_PORT</port></proxy>
</proxies></settings>
EOF
  export MAVEN_OPTS="-Xmx1024m"
  cd "$GUARDIAN_DIR" && mvn -B -q -s "$HOME/settings.xml" -Dmaven.repo.local=/workspace/m2 -DskipTests package || exit 3
  JAR=""
  for j in $(find . -path '*/target/*.jar' -not -name '*-sources.jar' -not -name '*-javadoc.jar' -not -name 'original-*' | sort); do
    if unzip -p "$j" META-INF/MANIFEST.MF 2>/dev/null | grep -q '^Main-Class:'; then JAR="$j"; break; fi
  done
  [ -n "$JAR" ] || { echo "[guardian] no runnable jar"; exit 4; }
  echo "[guardian] starting $JAR on port 8080"
  exec java -Xmx768m -jar "$JAR" --server.port=8080 --server.address=0.0.0.0
elif [ "$GUARDIAN_KIND" = npm ]; then
  cd "$GUARDIAN_DIR"
  export npm_config_proxy="$HTTP_PROXY" npm_config_https_proxy="$HTTPS_PROXY" npm_config_audit=false npm_config_fund=false
  { [ -f package-lock.json ] && npm ci --ignore-scripts; } || npm install --ignore-scripts || exit 3
  npm run --if-present build || exit 3
  echo "[guardian] starting npm start on port 8080"
  PORT=8080 HOST=0.0.0.0 exec npm start
elif [ "$GUARDIAN_KIND" = pypi ]; then
  cd "$GUARDIAN_DIR"
  python3 -m venv /workspace/venv && /workspace/venv/bin/pip install -q -r "$GUARDIAN_REQS" || exit 3
  echo "[guardian] starting on port 8080"
  if [ -f manage.py ]; then exec /workspace/venv/bin/python manage.py runserver 0.0.0.0:8080 --noreload; fi
  for f in app.py main.py; do
    [ -f "$f" ] && PORT=8080 FLASK_RUN_PORT=8080 FLASK_RUN_HOST=0.0.0.0 exec /workspace/venv/bin/python "$f"
  done
  echo "[guardian] no manage.py, app.py or main.py"; exit 4
fi
echo "[guardian] nothing to run"; exit 4
"""


def _sql_files(members: Dict[str, bytes]) -> Dict[str, bytes]:
    """Root-level *.sql files (e.g. schema / seed data) to load into the throwaway database."""
    return {p: d for p, d in members.items() if "/" not in p and p.lower().endswith(".sql") and len(d) < 20_000_000}


def detect_database(members: Dict[str, bytes]) -> Optional[Dict[str, str]]:
    """mysql / postgres from the manifests, with credentials from Spring datasource settings when present."""
    manifests = b" ".join(d for p, d in members.items() if p.endswith(("pom.xml", "package.json", "build.gradle"))
                          or "requirements" in p).lower()
    if b"mysql" in manifests:
        kind = "mysql"
    elif b"postgresql" in manifests or b"psycopg" in manifests or b'"pg"' in manifests:
        kind = "postgres"
    else:
        return None
    props = b"\n".join(d for p, d in members.items()
                       if re.search(r"(^|/)application[^/]*\.(properties|ya?ml)$", p) and "/test/" not in p)
    text = props.decode("utf-8", errors="replace")

    def prop(key: str) -> Optional[str]:
        m = re.search(rf"^\s*{re.escape(key)}\s*[=:]\s*(\S+)", text, re.M)
        return m.group(1).strip().strip("'\"") if m and "${" not in m.group(1) else None

    url = prop("spring.datasource.url") or prop("url") or ""
    db = re.search(r"//[^/]+/([A-Za-z0-9_\-]+)", url)
    return {"kind": kind, "database": db.group(1) if db else "app",
            "user": prop("spring.datasource.username") or prop("username") or ("root" if kind == "mysql" else "postgres"),
            "password": prop("spring.datasource.password") or prop("password") or "guardian"}


class Preview:
    def __init__(self, preview_id: str, label: str, port: int):
        self.id, self.label, self.port = preview_id, label, port
        self.status = "starting"     # starting -> building -> running | crashed | stopped | error
        self.error: Optional[str] = None
        self.started_at = time.time()
        self.expires_at = self.started_at + PREVIEW_TTL_S
        self.network = f"guardian-preview-{preview_id}"
        self.app_name = f"guardian-preview-app-{preview_id}"
        self.db_name: Optional[str] = None
        self.database: Optional[Dict[str, str]] = None
        self.proc: Optional[subprocess.Popen] = None
        self.proxy: Optional[EgressProxy] = None
        self.listener: Optional[socket.socket] = None
        self.stop_event = threading.Event()
        self.alias = f"guardian-app-{preview_id}"   # unique: the launcher sits on every preview network
        self.last_log = ""

    def as_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "label": self.label, "port": self.port, "url": f"http://localhost:{self.port}",
                "status": self.status, "error": self.error, "started_at": self.started_at,
                "expires_at": self.expires_at,
                "database": {k: v for k, v in (self.database or {}).items() if k != "password"} or None}


class PreviewManager:
    def __init__(self, runner: Optional[DockerRunner] = None):
        self.runner = runner or DockerRunner()
        self.previews: Dict[str, Preview] = {}
        self.lock = threading.Lock()

    # ------------------------------------------------------------------ API
    def start(self, source_tar: bytes, label: str) -> Dict[str, Any]:
        with self.lock:
            self._reap()
            used = {p.port for p in self.previews.values() if p.status in ("starting", "building", "running")}
            free = [p for p in PREVIEW_PORTS if p not in used]
            if not free:
                raise SandboxError(f"at most {len(PREVIEW_PORTS)} apps can run at once: stop one first")
            pv = Preview(uuid.uuid4().hex[:10], label, free[0])
            self.previews[pv.id] = pv
        threading.Thread(target=self._run, args=(pv, source_tar), name=f"preview-{pv.id}", daemon=True).start()
        return pv.as_dict()

    def get(self, preview_id: str, log_lines: int = 200) -> Optional[Dict[str, Any]]:
        pv = self.previews.get(preview_id)
        if not pv:
            return None
        if time.time() > pv.expires_at and pv.status in ("starting", "building", "running"):
            self.stop(preview_id, reason="time limit reached")
        out = pv.as_dict()
        out["log"] = self._logs(pv, log_lines)
        return out

    def stop(self, preview_id: str, reason: str = "stopped") -> bool:
        pv = self.previews.get(preview_id)
        if not pv:
            return False
        pv.stop_event.set()
        if pv.status in ("starting", "building", "running"):
            pv.status = "stopped"
            pv.error = None if reason == "stopped" else reason
        self._teardown(pv)
        return True

    # ------------------------------------------------------------------ internals
    def _reap(self):
        for pid, pv in list(self.previews.items()):
            if time.time() > pv.expires_at and pv.status in ("starting", "building", "running"):
                self.stop(pid, reason="time limit reached")

    def _docker(self, args: List[str], timeout: int = 120, input_bytes: Optional[bytes] = None):
        return self.runner._docker(args, input_bytes=input_bytes, timeout=timeout)

    def _base_flags(self, name: str) -> List[str]:
        r = self.runner
        flags = ["--name", name, "--label", "guardian.sandbox=1", "--label", "guardian.preview=1",
                 "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                 "--pids-limit", str(r.pids_limit), "--cpus", str(r.cpu_limit), "--memory", r.memory_limit]
        if r.runtime == "runsc":
            flags += ["--runtime", "runsc"]
        return flags

    def _run(self, pv: Preview, source_tar: bytes):
        try:
            members = read_members(source_tar)
            paths = health_manifests(members)
            if not paths:
                raise SandboxError("no pom.xml, package.json or requirements file: nothing to run")
            plan = plan_build(paths, members)
            kind = "maven" if "maven" in plan["ecosystems"] else "npm" if plan["npm_dirs"] else "pypi"
            directory = plan["maven_dir"] if kind == "maven" else (plan["npm_dirs"][0] if kind == "npm"
                                                                   else os.path.dirname(plan["pypi_reqs"][0]) or ".")
            image = self.runner.resolve_image("verify")

            self._docker(["network", "create", "--internal", "--label", "guardian.preview=1", pv.network], 60)
            r = self._docker(["network", "connect", "--alias", PROXY_ALIAS, pv.network, self.runner.self_container], 60)
            if r.returncode != 0:
                raise SandboxError(f"launcher could not join the preview network: {r.stderr.decode()[:200]}")
            pv.proxy = EgressProxy(mode="allowlist")
            proxy_port = pv.proxy.start()
            proxy = f"http://{PROXY_ALIAS}:{proxy_port}"

            pv.database = detect_database(members)
            if pv.database:
                self._start_database(pv, _sql_files(members))

            env = {"HOME": "/workspace/home", "HTTP_PROXY": proxy, "HTTPS_PROXY": proxy, "http_proxy": proxy,
                   "https_proxy": proxy, "NO_PROXY": "localhost,127.0.0.1", "GUARDIAN_PROXY_HOST": PROXY_ALIAS,
                   "GUARDIAN_PROXY_PORT": str(proxy_port), "GUARDIAN_KIND": kind, "GUARDIAN_DIR": directory,
                   "GUARDIAN_ECOSYSTEMS": " ".join(plan["ecosystems"]),
                   "GUARDIAN_REQS": os.path.basename(plan["pypi_reqs"][0]) if plan["pypi_reqs"] else ""}
            flags = ["run", "-i", *self._base_flags(pv.app_name), "--read-only",
                     "--tmpfs", f"/workspace:rw,exec,size={self.runner.workspace_size},mode=1777",
                     "--tmpfs", "/tmp:rw,exec,size=512m,mode=1777", "--user", "10001:10001"]
            if pv.db_name:
                flags += ["--network", f"container:{pv.db_name}"]   # app's localhost:3306/5432 = the database
            else:
                flags += ["--network", pv.network, "--network-alias", pv.alias]
            for k, v in sorted(env.items()):
                flags += ["-e", f"{k}={v}"]
            pv.status = "building"
            pv.proc = subprocess.Popen([self.runner.docker_bin, *flags, image, "sh", "-c", PREVIEW_SCRIPT],
                                       stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            pv.proc.stdin.write(source_tar)
            pv.proc.stdin.close()
            threading.Thread(target=self._forward, args=(pv,), daemon=True).start()
            self._watch(pv)
        except Exception as exc:  # noqa: BLE001 - shown in the dashboard
            logger.exception("preview %s failed", pv.id)
            pv.status, pv.error = "error", f"{type(exc).__name__}: {exc}"[:500]
            self._teardown(pv)

    def _start_database(self, pv: Preview, sql: Dict[str, bytes]):
        db = pv.database
        image = DB_IMAGES[db["kind"]]
        if self._docker(["image", "inspect", image], 30).returncode != 0:
            pull = self._docker(["pull", image], 600)
            if pull.returncode != 0:
                raise SandboxError(f"could not pull {image}: {pull.stderr.decode()[:200]}")
        pv.db_name = f"guardian-preview-db-{pv.id}"
        if db["kind"] == "mysql":
            env = {"MYSQL_DATABASE": db["database"], "MYSQL_ROOT_PASSWORD": db["password"]}
            if db["user"] != "root":
                env.update({"MYSQL_USER": db["user"], "MYSQL_PASSWORD": db["password"]})
            data = "/var/lib/mysql"
        else:
            env = {"POSTGRES_DB": db["database"], "POSTGRES_USER": db["user"], "POSTGRES_PASSWORD": db["password"]}
            data = "/var/lib/postgresql/data"
        flags = ["create", *self._base_flags(pv.db_name), "--cap-add", "CHOWN", "--cap-add", "SETUID",
                 "--cap-add", "SETGID", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER",
                 "--tmpfs", f"{data}:rw,size=1g", "--tmpfs", "/tmp:rw,size=256m", "--tmpfs", "/run:rw,size=64m",
                 "--network", pv.network, "--network-alias", pv.alias]
        for k, v in sorted(env.items()):
            flags += ["-e", f"{k}={v}"]
        r = self._docker([*flags, image], 60)
        if r.returncode != 0:
            raise SandboxError(f"database container: {r.stderr.decode()[:200]}")
        if sql:  # loaded by the image's entrypoint on first start
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w") as tf:
                for name, data_bytes in sorted(sql.items()):
                    info = tarfile.TarInfo(name)
                    info.size, info.mode = len(data_bytes), 0o644
                    tf.addfile(info, io.BytesIO(data_bytes))
            self._docker(["cp", "-", f"{pv.db_name}:/docker-entrypoint-initdb.d/"], 60, input_bytes=buf.getvalue())
        r = self._docker(["start", pv.db_name], 60)
        if r.returncode != 0:
            raise SandboxError(f"database did not start: {r.stderr.decode()[:200]}")
        ready_cmd = (["mysqladmin", "ping", "-h", "127.0.0.1", f"-p{db['password']}", "--silent"] if db["kind"] == "mysql"
                     else ["pg_isready", "-U", db["user"]])
        for _ in range(90):  # wait for the database before the app starts connecting
            if self._docker(["exec", pv.db_name, *ready_cmd], 15).returncode == 0:
                return
            time.sleep(2)
        raise SandboxError("database did not become ready in 3 minutes")

    def _watch(self, pv: Preview):
        ready = re.compile(READY_PATTERN)
        while not pv.stop_event.is_set():
            if pv.proc and pv.proc.poll() is not None:
                if pv.status != "stopped":
                    pv.status = "crashed"
                    pv.error = {3: "the build failed", 4: "no runnable app found"}.get(pv.proc.returncode,
                                                                                    f"exited with code {pv.proc.returncode}")
                self._teardown(pv)
                return
            if pv.status == "building" and ready.search(self._logs(pv, 400)):
                pv.status = "running"
            if time.time() > pv.expires_at:
                self.stop(pv.id, reason="time limit reached")
                return
            time.sleep(2)

    def _forward(self, pv: Preview):
        """localhost:<port> on the Docker host -> launcher:<port> (compose) -> guardian-app:8080 (preview net)."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", pv.port))
        srv.listen(32)
        srv.settimeout(1.0)
        pv.listener = srv
        while not pv.stop_event.is_set():
            try:
                client, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._pipe, args=(pv, client), daemon=True).start()
        try:
            srv.close()
        except OSError:
            pass

    def _pipe(self, pv: Preview, client: socket.socket):
        try:
            upstream = socket.create_connection((pv.alias, APP_PORT), timeout=10)
        except OSError:
            client.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n"
                           b"The app is still starting (or has stopped). Refresh in a few seconds.\n")
            client.close()
            return
        socks = [client, upstream]
        try:
            while not pv.stop_event.is_set():
                readable, _, _ = select.select(socks, [], [], 1.0)
                for s in readable:
                    data = s.recv(65536)
                    if not data:
                        return
                    (upstream if s is client else client).sendall(data)
        except OSError:
            pass
        finally:
            for s in socks:
                try:
                    s.close()
                except OSError:
                    pass

    def _logs(self, pv: Preview, lines: int) -> str:
        if not self.runner.docker_bin:
            return pv.last_log
        r = self._docker(["logs", "--tail", str(lines), pv.app_name], 20)
        text = (r.stdout + r.stderr).decode("utf-8", errors="replace") if r.returncode == 0 else ""
        return (text or pv.last_log)[-60_000:]

    def _teardown(self, pv: Preview):
        pv.stop_event.set()
        if not pv.last_log:
            pv.last_log = self._logs(pv, 400)   # keep the log visible after the container is removed
        for name in filter(None, [pv.app_name, pv.db_name]):
            self._docker(["rm", "-f", name], 60)
        if pv.proc and pv.proc.poll() is None:
            pv.proc.kill()
        if pv.listener:
            try:
                pv.listener.close()
            except OSError:
                pass
        if pv.proxy:
            pv.proxy.stop()
            pv.proxy = None
        self._docker(["network", "disconnect", "-f", pv.network, self.runner.self_container], 30)
        self._docker(["network", "rm", pv.network], 30)


preview_manager = PreviewManager()
