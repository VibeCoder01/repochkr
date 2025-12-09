"""
Risk scoring utilities.

Scoring is intentionally simple: weight severities and add a small boost for
runtime dependencies to surface the most critical upgrades first.
"""

from __future__ import annotations

from typing import Dict, List

SEVERITY_WEIGHTS = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 1,
    "UNKNOWN": 1,
}


def severity_rank(severity: str) -> int:
    return SEVERITY_WEIGHTS.get(severity.upper(), 1)


def dependency_risk(dep: Dict, vulns: List[Dict]) -> int:
    if not vulns:
        return 0
    weight = max(severity_rank(v.get("severity", "LOW")) for v in vulns)
    scope_boost = 1 if dep.get("scope") == "runtime" else 0
    return weight + scope_boost


def repo_risk(deps_with_vulns: List[Dict]) -> Dict[str, int]:
    score = 0
    highest = "LOW"
    vuln_count = 0
    for item in deps_with_vulns:
        vulns = item.get("vulnerabilities", [])
        if not vulns:
            continue
        vuln_count += 1
        dep_score = dependency_risk(item["dependency"], vulns)
        score += dep_score
        sev = max((v.get("severity", "LOW") for v in vulns), key=severity_rank)
        if severity_rank(sev) > severity_rank(highest):
            highest = sev
    return {"risk_score": score, "highest_severity": highest, "vulnerable_dependencies": vuln_count}
