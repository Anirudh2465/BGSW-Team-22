"""Agent-config detector: instructions planted in files that AI coding assistants read automatically.

Files such as ``.cursorrules``, ``CLAUDE.md``, ``AGENTS.md``, Copilot instructions and MCP server
configs are fed to coding agents as trusted instructions. An attacker who lands one in a repository
(or a dependency's template) can steer every developer's assistant. Rules, all code:

- hidden Unicode: zero-width, bidirectional-control and "tag" characters that hide text from reviewers
- instruction override ("ignore previous instructions", "you are now ...")
- disabling safeguards (security checks, tests, approvals, code review)
- secret exfiltration (sending tokens, keys, .env or credentials somewhere)
- download-and-run (``curl ... | sh``, ``iwr ... | iex``)
- long base64 blobs (encoded payloads)
- MCP servers launched from unpinned packages (``npx pkg`` / ``uvx pkg`` without a version) or with
  a download-and-run command

One finding per (file, rule). Score 80 (starting value; not in the architecture table).
This module is self-contained (no relative imports): ``tests/eval_runner.py`` loads it by file path.
"""

import hashlib
import json
import posixpath
import re
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from guardian_contracts.state import Evidence, Finding

TOOL = "agent_config_detector"
SCORE = 80

HIDDEN_CHARS = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿\U000e0000-\U000e007f]")

RULES: List[Tuple[str, str, "re.Pattern"]] = [
    ("instruction_override", "tries to override the assistant's instructions",
     re.compile(r"ignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier|system)\s+(instructions|prompts?|rules)"
                r"|disregard\s+(all\s+|any\s+)?(previous|prior|above|your)\s+(instructions|rules)"
                r"|system\s+instruction\s+override|you\s+are\s+now\s+(in\s+)?(developer|dan|unrestricted|jailbreak)",
                re.I)),
    ("disable_safeguards", "tells the assistant to switch off safety checks",
     re.compile(r"(disable|skip|bypass|turn\s+off|ignore)\s+(all\s+)?(the\s+)?(security|safety)\s+(checks?|scans?|review)"
                r"|bypass\s+(human\s+)?(approval|review)|(skip|disable)\s+(the\s+)?(tests|code\s+review|signature\s+checks?)"
                r"|mark\s+all\s+findings\s+as\s+pass|--no-verify", re.I)),
    ("secret_exfiltration", "asks for secrets to be sent elsewhere",
     re.compile(r"(send|post|upload|exfiltrate|forward|transmit|leak)\b[^\n]{0,80}\b(secrets?|tokens?|api[_\s-]?keys?|"
                r"credentials|passwords?|\.env\b|ssh\s+keys?|id_rsa|aws_secret)", re.I)),
    ("download_and_run", "downloads and runs a script",
     re.compile(r"(curl|wget)\s[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh|python3?)\b|iwr\s[^\n|]*\|\s*iex|"
                r"Invoke-WebRequest[^\n|]*\|\s*Invoke-Expression", re.I)),
    ("encoded_payload", "contains a long base64 blob",
     re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")),
]

MCP_FILES = (".mcp.json", "mcp.json")
UNPINNED_LAUNCHERS = {"npx", "uvx", "pnpx", "bunx"}


def _finding(path: str, rule: str, what: str, sha: str, line: int, extra: str = "") -> Finding:
    purl = "pkg:generic/" + path.replace("%", "%25").replace("/", "%2F")
    return Finding(
        id=hashlib.sha256(f"agent_config:{purl}:{rule}".encode("utf-8")).hexdigest(),
        kind="agent_config",
        purl=purl,
        path=[path] + ([f"line {line}"] if line else []),
        evidence=[Evidence(id=f"agent_rule:{rule}:{path}:{line}", tool=TOOL, artifact_sha256=sha)],
        status="confirmed",
        score=SCORE,
        explanation=(f"{path} {what}{(': ' + extra) if extra else ''}. Coding assistants read this file as trusted "
                     "instructions, so review and remove it."),
    )


def _line(text: str, start: int) -> int:
    return text.count("\n", 0, start) + 1


def _mcp_servers(data) -> Iterable[Tuple[str, dict]]:
    if not isinstance(data, dict):
        return []
    servers = data.get("mcpServers") or data.get("servers") or (data.get("mcp") or {}).get("servers") or {}
    return [(k, v) for k, v in servers.items() if isinstance(v, dict)] if isinstance(servers, dict) else []


def _unpinned_package(args: List[str]) -> Optional[str]:
    for a in args:
        if not isinstance(a, str) or a.startswith("-"):
            continue
        spec = a
        bare = spec[1:] if spec.startswith("@") else spec
        if "@" in bare or "==" in spec or spec.startswith(("./", "/", "file:")):
            return None
        return spec
    return None


class AgentConfigDetector:
    def check_config_content(self, content: str, file_path: str, artifact_sha256: str) -> List[Finding]:
        findings: List[Finding] = []
        content = content[1:] if content.startswith("﻿") else content  # a leading byte-order mark is normal
        hidden = HIDDEN_CHARS.search(content)
        if hidden:
            count = len(HIDDEN_CHARS.findall(content))
            findings.append(_finding(file_path, "hidden_unicode", "contains hidden Unicode characters", artifact_sha256,
                                     _line(content, hidden.start()), f"{count} invisible character(s), starting with "
                                     f"U+{ord(hidden.group(0)):04X}"))
        visible = HIDDEN_CHARS.sub("", content)
        for rule, what, pattern in RULES:
            m = pattern.search(visible)
            if m:
                snippet = re.sub(r"\s+", " ", m.group(0))[:80]
                findings.append(_finding(file_path, rule, what, artifact_sha256, _line(visible, m.start()),
                                         f"'{snippet}'" if rule != "encoded_payload" else f"{len(m.group(0))} characters"))
        if posixpath.basename(file_path) in MCP_FILES or file_path.endswith(("/mcp.json", "settings.json")):
            findings += self._mcp(content, file_path, artifact_sha256)
        return findings

    def _mcp(self, content: str, path: str, sha: str) -> List[Finding]:
        try:
            data = json.loads(content)
        except ValueError:
            return []
        out: List[Finding] = []
        for name, server in _mcp_servers(data):
            command = str(server.get("command", ""))
            args = [a for a in server.get("args") or [] if isinstance(a, str)]
            full = " ".join([command] + args)
            line = _line(content, max(content.find(f'"{name}"'), 0))
            if posixpath.basename(command) in UNPINNED_LAUNCHERS:
                pkg = _unpinned_package(args)
                if pkg:
                    out.append(_finding(path, f"mcp_unpinned:{name}", f"starts the MCP server '{name}' with "
                                        f"'{posixpath.basename(command)} {pkg}' and no version", sha, line,
                                        "every start can fetch a new, possibly hijacked release; pin it "
                                        f"('{pkg}@<version>')"))
            if RULES[3][2].search(full):
                out.append(_finding(path, f"mcp_download_and_run:{name}", f"starts the MCP server '{name}' by "
                                    "downloading and running a script", sha, line, full[:100]))
        return out

    def check_files(self, files: Dict[str, bytes], artifact_sha256: str) -> List[Finding]:
        out: List[Finding] = []
        for path, raw in sorted(files.items()):
            out += self.check_config_content(raw.decode("utf-8", errors="replace"), path, artifact_sha256)
        return out
