"""Digest-pinned image allowlist and domain allowlist."""

# Digest-pinned worker container images
ALLOWLISTED_IMAGES = {
    "clone": "guardian-sandbox-clone:latest@sha256:7f4c9c7f99999999999999999999999999999999999999999999999999999999",
    "resolve": "guardian-sandbox-resolve:latest@sha256:8a5b1c8888888888888888888888888888888888888888888888888888888888",
    "scan": "guardian-sandbox-scan:latest@sha256:9c6d3e7777777777777777777777777777777777777777777777777777777777",
    "verify": "guardian-sandbox-verify:latest@sha256:0d1e5f6666666666666666666666666666666666666666666666666666666666",
}

# Domain allowlist for outbound HTTP proxy in Stage 1, Stage 2, and Stage 4
ALLOWLISTED_EGRESS_DOMAINS = [
    # Git Remotes
    "github.com",
    "api.github.com",
    "gitlab.com",
    # Java Maven Central
    "repo.maven.apache.org",
    "repo1.maven.org",
    # JavaScript npm
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    # Python PyPI
    "pypi.org",
    "files.pythonhosted.org",
    # Go Modules
    "proxy.golang.org",
    "sum.golang.org",
    # Rust Crates
    "crates.io",
    "static.crates.io",
]

def is_domain_allowed(host: str) -> bool:
    host_clean = host.split(":")[0].lower().strip()
    return any(host_clean == d or host_clean.endswith("." + d) for d in ALLOWLISTED_EGRESS_DOMAINS)
