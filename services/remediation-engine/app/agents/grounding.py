"""Grounding for Gemini explanations: what the model may see, and which of its sentences may be shown.

Facts (Invariant 4). ``build_facts`` turns a scored finding into JSON made by code: kind, package
purl, advisory IDs, CVSS / EPSS / KEV, score and band, reachability tier, fixed version, dependency
path and the evidence IDs the model may cite. Every string must match a strict pattern, and the
finding's existing explanation is never included: detector explanations can quote repository text
(a planted "ignore previous instructions" in an agent-config file), which must not reach the model.

Grounding gate (code, no LLM judge), per sentence:
- it cites at least one ID, and every cited ID is one of that finding's evidence IDs
- every number in it (CVSS 10.0, EPSS 94%, version 2.17.1, score 99) appears in the finding's facts
- plain text within the length limit: no links, markup, code or instruction-like text
A finding's explanation is shown only when at least one sentence passes and none fails.
"""

import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from guardian_contracts.state import Finding

SAFE = re.compile(r"^[A-Za-z0-9._:/@+%=~#\-\[\]>(),' ]{1,240}$")
ADVISORY = re.compile(r"^(CVE-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3}|[A-Z]{2,10}-[\w.-]{2,40})$")
NUMBER = re.compile(r"\d+(?:\.\d+)*")
MAX_SENTENCES = 3
MAX_CHARS = 280
FORBIDDEN = re.compile(r"https?://|www\.|<[a-z/!]|`|\*\*|^#|\]\(|ignore (all |previous )|as an ai", re.I)
REACH_TEXT = {1: "tier 1: application code calls or instantiates classes of this library (type-level evidence)",
              2: "tier 2: application code references this library but no call was found",
              3: "tier 3: the library is only mentioned in the code"}
REACH_UNKNOWN = "not determined (neutral; does not mean safe)"
FIELD_NAMES = re.compile(r"\b(fixed_version|risk_band|risk_score|evidence_ids|finding_id|epss_probability|in_cisa_kev|"
                         r"dependency_path|reachability_evidence|weakness_category)\b")
GEMINI_TOOL = "gemini"


def _safe(value: Any) -> Optional[str]:
    if isinstance(value, str) and SAFE.match(value):
        return value
    return None


def band(score: Optional[int]) -> str:
    s = score or 0
    return "Critical" if s >= 80 else "High" if s >= 60 else "Medium" if s >= 30 else "Low"


def build_facts(f: Finding, entry: Optional[Dict[str, Any]], score: Optional[int]) -> Dict[str, Any]:
    """Validated JSON facts for one finding (nothing copied from the repository as free text)."""
    evidence_ids = [e.id for e in f.evidence if _safe(e.id) and e.tool != GEMINI_TOOL]
    facts: Dict[str, Any] = {
        "finding_id": f.id,
        "kind": f.kind,
        "package": _safe(f.purl),
        "status": f.status,
        "risk_score": score,
        "risk_band": band(score),
        "evidence_ids": evidence_ids,
        "dependency_path": [p for p in (_safe(x) for x in f.path[:6]) if p],
    }
    if f.kind == "cve":
        reach_ev = next((e.id for e in f.evidence if e.tool == "reachability"), None)
        facts["reachability"] = REACH_TEXT.get(f.reach_tier, REACH_UNKNOWN)
        if reach_ev:
            facts["reachability_evidence"] = reach_ev
    if entry:
        adv = entry.get("advisory_id")
        facts["advisory"] = adv if isinstance(adv, str) and ADVISORY.match(adv) else None
        facts["aliases"] = [a for a in entry.get("aliases") or [] if isinstance(a, str) and ADVISORY.match(a)][:5]
        if isinstance(entry.get("cvss_score"), (int, float)) and not isinstance(entry.get("cvss_score"), bool):
            facts["cvss"] = float(entry["cvss_score"])
        if isinstance(entry.get("epss"), (int, float)) and not isinstance(entry.get("epss"), bool):
            facts["epss_probability"] = round(float(entry["epss"]), 4)
        facts["in_cisa_kev"] = entry.get("kev") == 1
        fix = entry.get("fix") or {}
        facts["fixed_version"] = _safe(fix.get("lowest_fixed_version")) if isinstance(fix, dict) else None
        cat = entry.get("weakness_category")
        facts["weakness_category"] = _safe(cat)
        facts["cwes"] = [c for c in entry.get("cwes") or [] if isinstance(c, str) and re.match(r"^CWE-\d+$", c)][:5]
    return {k: v for k, v in facts.items() if v not in (None, [], "")}


def allowed_numbers(facts: Dict[str, Any]) -> Set[str]:
    """Number tokens a sentence about this finding may contain."""
    out: Set[str] = {"100"}  # "out of 100"
    # The finding ID is a SHA-256: its digit runs must not count as allowed numbers.
    text = repr({k: v for k, v in facts.items() if k != "finding_id"})
    out.update(NUMBER.findall(text))
    for t in list(out):  # versions and IDs: allow their parts too ("2.17.1" -> "2", "17", "2.17")
        parts = t.split(".")
        out.update(parts)
        out.update(".".join(parts[:i]) for i in range(2, len(parts)))
    if "cvss" in facts:
        c = facts["cvss"]
        out.update({f"{c:.1f}", f"{c:g}"})
    if "epss_probability" in facts:
        p = facts["epss_probability"]
        for v in (p, p * 100):
            out.update({f"{v:.0f}", f"{v:.1f}", f"{v:.2f}", f"{v:g}", f"{round(v, 2):g}", f"{round(v, 1):g}"})
    return out


def check_sentence(sentence: Dict[str, Any], evidence_ids: Set[str], numbers: Set[str]) -> Optional[str]:
    """None when the sentence is grounded, else the reason it is rejected."""
    text = sentence.get("text")
    cites = sentence.get("cites")
    if not isinstance(text, str) or not text.strip():
        return "empty"
    if len(text) > MAX_CHARS:
        return "too long"
    if "\n" in text or FORBIDDEN.search(text):
        return "contains markup, links or instruction-like text"
    if not isinstance(cites, list) or not cites:
        return "no citation"
    unknown = [c for c in cites if c not in evidence_ids]
    if unknown:
        return f"cites unknown evidence {unknown[0]!r}"
    bad = [n for n in NUMBER.findall(text) if n not in numbers]
    if bad:
        return f"number {bad[0]} is not in the facts"
    field = FIELD_NAMES.search(text)
    if field:
        return f"mentions the field name {field.group(0)!r}"
    return None


def ground(sentences: Iterable[Dict[str, Any]], facts: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[str]]:
    """(accepted sentences, rejection reasons). All-or-nothing: any rejected sentence rejects the finding."""
    ids = set(facts.get("evidence_ids") or [])
    nums = allowed_numbers(facts)
    sents = list(sentences)[:MAX_SENTENCES + 1]
    if len(sents) > MAX_SENTENCES:
        return [], [f"more than {MAX_SENTENCES} sentences"]
    accepted, reasons = [], []
    for s in sents:
        why = check_sentence(s, ids, nums)
        if why:
            reasons.append(why)
        else:
            accepted.append({"text": s["text"].strip(), "cites": list(dict.fromkeys(s["cites"]))})
    if reasons or not accepted:
        return [], reasons or ["no sentences"]
    return accepted, []


def render(sentences: List[Dict[str, Any]]) -> str:
    """One line for the explanation: each sentence followed by its citations in brackets."""
    return " ".join(f"{s['text'].rstrip()} [{', '.join(s['cites'])}]" for s in sentences)
