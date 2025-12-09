"""
Vulnerability lookup module using an OSV-style API.

The lookup keeps an in-memory cache for the duration of the process to avoid
re-querying the same (ecosystem, package, version) tuples.
"""

from __future__ import annotations

import os
import time
from typing import Dict, List, Optional

import requests

OSV_API = os.getenv("OSV_API", "https://api.osv.dev/v1/query")

Severity = str
VulnRecord = Dict[str, object]


class VulnerabilityLookup:
    def __init__(self, api_url: str = OSV_API):
        self.api_url = api_url
        self.cache: Dict[tuple, List[VulnRecord]] = {}
        self.session = requests.Session()

    def lookup(self, ecosystem: str, name: str, version: str) -> List[VulnRecord]:
        key = (ecosystem.lower(), name.lower(), version)
        if key in self.cache:
            return self.cache[key]
        if not name or not version or version == "*":
            self.cache[key] = []
            return []
        payload = {"version": version, "package": {"ecosystem": ecosystem, "name": name}}
        tries = 0
        while tries < 3:
            resp = self.session.post(self.api_url, json=payload, timeout=30)
            if resp.status_code == 400:
                # OSV returns 400 for invalid package/version combos; treat as no vulns
                self.cache[key] = []
                return []
            if resp.status_code in (429, 503):
                time.sleep(2 ** tries)
                tries += 1
                continue
            resp.raise_for_status()
            break
        data = resp.json()
        vulns = []
        for v in data.get("vulns", []):
            aliases = v.get("aliases") or []
            summary = v.get("summary", "") or v.get("details", "")
            severity = "UNKNOWN"
            score = None
            for s in v.get("severity", []):
                severity = s.get("type", severity)
                try:
                    score = float(s.get("score"))
                except (TypeError, ValueError):
                    score = None
            affected_range = ""
            fixed_versions: set[str] = set()
            for aff in v.get("affected", []):
                ranges = aff.get("ranges", [])
                if ranges:
                    events = ranges[0].get("events", [])
                    parts = []
                    for ev in events:
                        if "introduced" in ev:
                            parts.append(f">={ev['introduced']}")
                        if "fixed" in ev:
                            parts.append(f"<{ev['fixed']}")
                            fixed_versions.add(ev["fixed"])
                    affected_range = " ".join(parts)
                fixed_versions.update(aff.get("versions", []))
            vuln = {
                "id": v.get("id") or aliases[0] if aliases else "",
                "summary": summary,
                "severity": severity,
                "cvss_score": score,
                "affected_range": affected_range,
                "fixed_versions": sorted(fixed_versions),
                "reference_url": v.get("references", [{}])[0].get("url", ""),
            }
            vulns.append(vuln)
        self.cache[key] = vulns
        return vulns

    def bulk_lookup(self, deps: List[Dict[str, str]]) -> Dict[str, List[VulnRecord]]:
        """Lookup vulnerabilities for each dependency and return indexed results."""
        results: Dict[str, List[VulnRecord]] = {}
        for dep in deps:
            key = f"{dep['ecosystem']}|{dep['name']}|{dep['version']}"
            results[key] = self.lookup(dep["ecosystem"], dep["name"], dep["version"])
        return results
