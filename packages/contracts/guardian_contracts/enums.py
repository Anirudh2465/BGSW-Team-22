from enum import Enum, IntEnum

class FindingKind(str, Enum):
    CVE = "cve"
    TYPOSQUAT = "typosquat"
    SLOPSQUAT = "slopsquat"
    CONFUSION = "confusion"
    INSTALL_HOOK = "install_hook"
    LOCKFILE = "lockfile"
    PINNING = "pinning"
    AGENT_CONFIG = "agent_config"

class ReachTier(IntEnum):
    TIER_1 = 1  # Call graph path confirmed
    TIER_2 = 2  # AST / Tree-sitter import detected
    TIER_3 = 3  # ripgrep mention / string match

class PolicyVerdict(str, Enum):
    PASS = "PASS"
    BLOCK = "BLOCK"

class StageName(str, Enum):
    CLONE = "clone"
    RESOLVE = "resolve"
    SCAN = "scan"
    VERIFY = "verify"

class RemediationState(str, Enum):
    DRAFT = "draft"
    VERIFIED = "verified"
    NO_SAFE_FIX = "no_safe_fix"
    ESCALATED = "escalated"

class ApprovalDecision(str, Enum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    PENDING = "PENDING"
