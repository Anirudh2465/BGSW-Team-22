"""Logging forward proxy for sandbox egress (Stages 1, 2 and 4).

Two modes:
- ``allowlist``: CONNECT/HTTP requests to allowlisted registries and git hosts are
  relayed; everything else gets 403. Upstream addresses must be public, so an
  allowlisted name can never be used to reach the core network.
- ``sinkhole``: nothing is relayed; every attempt is logged to a SinkholeLogger.
  Used for the hook-observe pass, where install scripts run.

Each stage run starts its own proxy instance on an ephemeral port, so its log
belongs to exactly one run.
"""

import asyncio
import ipaddress
import logging
import socket
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from ..allowlist import is_domain_allowed
from .sinkhole import SinkholeLogger

logger = logging.getLogger("launcher.egress_proxy")

ALLOWED_PORTS = {80, 443}
HEADER_LIMIT = 64 * 1024
IDLE_TIMEOUT_S = 120


class EgressProxy:
    """Forward proxy enforcing a strict allowlist of package registries and git hosts."""

    def __init__(self, port: int = 0, mode: str = "allowlist", sinkhole: Optional[SinkholeLogger] = None,
                 bind_host: str = "0.0.0.0"):
        if mode not in ("allowlist", "sinkhole"):
            raise ValueError(f"Unknown proxy mode: {mode}")
        self.mode = mode
        self.port = port
        self.bind_host = bind_host
        self.sinkhole = sinkhole or SinkholeLogger()
        self.access_logs: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._server: Optional[asyncio.base_events.Server] = None
        self._thread: Optional[threading.Thread] = None
        self._ready = threading.Event()

    # ---------------------------------------------------------------- policy
    def check_request(self, target_host: str, method: str = "GET", path: str = "/", port: int = 443) -> bool:
        allowed = self.mode == "allowlist" and port in ALLOWED_PORTS and is_domain_allowed(target_host)
        record = {
            "target_host": target_host,
            "port": port,
            "method": method,
            "path": path[:256],
            "allowed": allowed,
            "mode": self.mode,
            "timestamp": time.time(),
        }
        with self._lock:
            self.access_logs.append(record)
        if not allowed:
            if self.mode == "sinkhole":
                self.sinkhole.log_egress_attempt(target_host, port, f"{method} {target_host}:{port}{path}")
            logger.warning("Blocked egress (%s mode) to %s:%s", self.mode, target_host, port)
        return allowed

    def get_logs(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.access_logs)

    def clear_logs(self):
        with self._lock:
            self.access_logs.clear()

    # ---------------------------------------------------------------- server
    def start(self) -> int:
        """Start serving in a background thread; returns the bound port."""
        self._thread = threading.Thread(target=self._run, name=f"egress-proxy-{self.mode}", daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=10):
            raise RuntimeError("Egress proxy failed to start")
        return self.port

    def stop(self):
        if self._loop and self._server:
            self._loop.call_soon_threadsafe(self._server.close)
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread:
            self._thread.join(timeout=5)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()

    def _run(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._server = self._loop.run_until_complete(
            asyncio.start_server(self._handle, self.bind_host, self.port, limit=HEADER_LIMIT)
        )
        self.port = self._server.sockets[0].getsockname()[1]
        self._ready.set()
        try:
            self._loop.run_forever()
        finally:
            self._loop.close()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=15)
        except Exception:
            writer.close()
            return
        try:
            request_line = head.split(b"\r\n", 1)[0].decode("latin-1")
            method, target, _version = request_line.split(" ", 2)
            host, port, path = _parse_target(method, target)
        except Exception:
            await _respond(writer, 400, "Bad Request")
            return

        if not self.check_request(host, method, path, port):
            await _respond(writer, 403, "Forbidden by Guardian egress policy")
            return

        upstream = await _open_public(host, port)
        if upstream is None:
            await _respond(writer, 502, "Upstream not public or unreachable")
            return
        up_reader, up_writer = upstream

        if method.upper() == "CONNECT":
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
        else:
            rest = head.split(b"\r\n", 1)[1]
            up_writer.write(f"{method} {path} HTTP/1.1\r\n".encode("latin-1") + rest)
            await up_writer.drain()

        await asyncio.gather(_pipe(reader, up_writer), _pipe(up_reader, writer), return_exceptions=True)


def _parse_target(method: str, target: str) -> Tuple[str, int, str]:
    if method.upper() == "CONNECT":
        host, _, port = target.rpartition(":")
        return host.strip("[]").lower(), int(port), ""
    parts = urlsplit(target)
    if parts.scheme != "http" or not parts.hostname:
        raise ValueError("Only absolute http:// URLs are proxied without CONNECT")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return parts.hostname.lower(), parts.port or 80, path


async def _open_public(host: str, port: int):
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return None
    for family, _, _, _, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if not ip.is_global:
            logger.warning("Refusing non-public upstream %s for %s", ip, host)
            continue
        try:
            return await asyncio.wait_for(asyncio.open_connection(sockaddr[0], port), timeout=15)
        except Exception:
            continue
    return None


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while True:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=IDLE_TIMEOUT_S)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def _respond(writer: asyncio.StreamWriter, status: int, reason: str):
    body = reason.encode()
    writer.write(f"HTTP/1.1 {status} {reason}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
    try:
        await writer.drain()
    finally:
        writer.close()
