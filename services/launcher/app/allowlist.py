"""Sandbox image allowlist and egress domain allowlist."""

import os
from typing import Optional

SANDBOX_IMAGE_VERSION = os.getenv("SANDBOX_IMAGE_VERSION", "0.1.0")

# Only these images may ever be started by the launcher. They are built locally
# (`make sandbox-images`) and resolved to an immutable image ID before each run.
# Set SANDBOX_IMAGE_DIGEST_<STAGE> (e.g. SANDBOX_IMAGE_DIGEST_SCAN=sha256:...) to pin
# the exact image ID; the launcher then refuses any other build of that tag.
ALLOWLISTED_IMAGES = {
    "clone": f"guardian-sandbox-clone:{SANDBOX_IMAGE_VERSION}",
    "resolve": f"guardian-sandbox-resolve:{SANDBOX_IMAGE_VERSION}",
    "scan": f"guardian-sandbox-scan:{SANDBOX_IMAGE_VERSION}",
    "verify": f"guardian-sandbox-verify:{SANDBOX_IMAGE_VERSION}",
}


def pinned_digest(stage: str) -> Optional[str]:
    value = os.getenv(f"SANDBOX_IMAGE_DIGEST_{stage.upper()}", "").strip()
    return value or None


# Domain allowlist for the outbound HTTP proxy in Stage 1, Stage 2 and Stage 4
ALLOWLISTED_EGRESS_DOMAINS = [
    # Git remotes
    "github.com",
    "api.github.com",
    "codeload.github.com",
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
    # Go modules
    "proxy.golang.org",
    "sum.golang.org",
    # Rust crates
    "crates.io",
    "static.crates.io",
    "index.crates.io",
]


# Container registries (and the hosts they serve image layers from) and Sigstore, allowed only for a
# resolve run that scans base images. Some registries redirect layer downloads to other CDN hosts;
# such a download is blocked and logged by the proxy, and the image is recorded as "fail".
IMAGE_REGISTRY_DOMAINS = [
    "docker.io", "registry-1.docker.io", "auth.docker.io", "production.cloudflare.docker.com",
    "ghcr.io", "pkg-containers.githubusercontent.com",
    "gcr.io", "pkg.dev", "registry.k8s.io",
    "mcr.microsoft.com",
    "quay.io",
    "cgr.dev",
]
SIGSTORE_DOMAINS = ["rekor.sigstore.dev", "fulcio.sigstore.dev", "tuf-repo-cdn.sigstore.dev"]


def _matches(host: str, domains) -> bool:
    host_clean = host.split(":")[0].lower().strip().rstrip(".")
    return any(host_clean == d or host_clean.endswith("." + d) for d in domains)


def is_domain_allowed(host: str, extra_domains=()) -> bool:
    return _matches(host, ALLOWLISTED_EGRESS_DOMAINS) or (bool(extra_domains) and _matches(host, extra_domains))
