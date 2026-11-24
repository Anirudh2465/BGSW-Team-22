"""Reachability tier of a vulnerable Maven component, from the JavaParser class dependency graph.

Tiers follow the rectified architecture, applied to *type-level* evidence:

  tier 1  a production (non-test) application class calls, instantiates, extends or implements a type
          from the component's packages                                          -> R = 20
  tier 2  the application references such a type in another way (field, method signature,
          annotation), or only test code uses it                                  -> R = 12
  None    no reference found, the class graph is missing, or the component's packages are unknown
          or ambiguous                                                             -> R = 12 ("not determined")

Type-level evidence shows the application uses the library's classes, not that it reaches the
vulnerable function, so it can only raise risk. Nothing here yields R = 0: only a completed
call-graph analysis that finds no path may lower a score, and that analysis is not run yet.
Use through another library (log4j-api calling into log4j-core) is "not determined", never "safe".
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .java_packages import attribute, package_index

TIER1_KINDS = {"calls", "instantiates", "extends", "implements"}
MAX_EXAMPLES = 3


@dataclass
class Reach:
    tier: Optional[int]
    reason: str
    examples: List[str] = field(default_factory=list)  # "OwnerController -instantiates-> Foo"
    classes: int = 0                                    # application classes that reference the component


def _short(fqn: str) -> str:
    return fqn.rsplit(".", 1)[-1]


class ReachabilityIndex:
    def __init__(self, payload: Optional[Dict[str, Any]], maven_components: Iterable[Tuple[str, str]]):
        payload = payload or {}
        graph = payload.get("graph") or {}
        nodes = {n.get("id"): n for n in payload.get("nodes") or [] if isinstance(n, dict)}
        self.status = graph.get("status") or ("ok" if nodes else "missing")
        self.app_classes = sum(1 for n in nodes.values() if not n.get("external"))
        self.available = self.status == "ok" and self.app_classes > 0
        self.index = package_index(maven_components)
        # component -> list of (source class, target type, relationships, source is test code)
        self.uses: Dict[Tuple[str, str], List[Tuple[str, str, Set[str], bool]]] = {}
        for link in payload.get("links") or []:
            target = nodes.get(link.get("target")) or {}
            source = nodes.get(link.get("source")) or {}
            if not target.get("external") or target.get("jdk") or source.get("external"):
                continue
            for comp in attribute(link["target"], self.index):
                kinds = set(link.get("relationships") or [link.get("relationship", "uses")])
                self.uses.setdefault(comp, []).append((link["source"], link["target"], kinds, bool(source.get("test"))))

    def reach(self, group: str, artifact: str) -> Reach:
        if not self.available:
            return Reach(None, f"not determined: class graph {self.status}")
        if not self.index.get((group, artifact)):
            return Reach(None, "not determined: the library's Java packages are unknown")
        uses = self.uses.get((group, artifact)) or []
        if not uses:
            return Reach(None, "not determined: application code does not reference this library directly "
                               "(it may still be used through another library)")
        prod_strong = sorted((s, t, k) for s, t, k, test in uses if not test and k & TIER1_KINDS)
        classes = len({s for s, _, _, _ in uses})
        if prod_strong:
            ex = [f"{_short(s)} -{sorted(k & TIER1_KINDS)[0]}-> {t}" for s, t, k in prod_strong[:MAX_EXAMPLES]]
            return Reach(1, f"application code calls or instantiates classes of this library "
                            f"({len({s for s, _, _ in prod_strong})} class(es)); type-level evidence, the "
                            "vulnerable function itself was not traced", ex, classes)
        only_tests = all(test for _, _, _, test in uses)
        ordered = sorted(uses, key=lambda u: (u[3], u[0], u[1]))  # production classes first
        ex = [f"{_short(s)} -{sorted(k)[0]}-> {t}" for s, t, k, _ in ordered[:MAX_EXAMPLES]]
        why = "referenced only from test code" if only_tests else "referenced (types, fields or annotations) but no call"
        return Reach(2, f"{why} in {classes} class(es)", ex, classes)
