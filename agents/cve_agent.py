#!/usr/bin/env python3
"""
CVE Agent — Autonomous CVE + CISA KEV Ingestion and Asset-Aware Prioritization.
Cross-references live NVD v2.0 & CISA Known Exploited Vulnerabilities against
actual system inventory, with deterministic offline fallback scoring.
"""

import asyncio
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
import json
from typing import Any, Dict, List, Optional, Set, Tuple

import requests

from config.settings import Settings
from utils.llm_helper import call_groq_json
from utils.logger import get_logger
from utils.security import sanitize_input, validate_cve_format

logger = get_logger(__name__)
settings = Settings()


class CVESeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class CVEEntry:
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    published_date: str
    modified_date: str
    affected_systems: List[str]
    exploitability: str
    in_cisa_kev: bool
    remediation_priority: int
    mitre_techniques: List[str]
    threat_intelligence: Dict[str, Any]
    risk_score: float


DEFAULT_OFFLINE_CVES: List[Dict[str, Any]] = [
    {
        "cve_id": "CVE-2024-6387",
        "description": (
            "RegreSSHion unauthenticated remote code execution signal handler "
            "race condition in OpenSSH/Linux servers"
        ),
        "cvss_score": 8.1,
        "severity": "HIGH",
        "published_date": "2024-07-01T00:00:00Z",
        "modified_date": "2024-07-05T00:00:00Z",
        "affected_products": ["ubuntu", "openssh"],
        "exploitability": "HIGH",
        "in_cisa_kev": True,
    },
    {
        "cve_id": "CVE-2024-10979",
        "description": "PostgreSQL PL/Perl environment variable privilege escalation and arbitrary code execution",
        "cvss_score": 8.8,
        "severity": "HIGH",
        "published_date": "2024-11-14T00:00:00Z",
        "modified_date": "2024-11-15T00:00:00Z",
        "affected_products": ["postgresql"],
        "exploitability": "MEDIUM",
        "in_cisa_kev": False,
    },
    {
        "cve_id": "CVE-2024-50603",
        "description": "Unauthenticated remote command execution in Aviatrix Controller API",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "published_date": "2024-11-19T00:00:00Z",
        "modified_date": "2024-11-20T00:00:00Z",
        "affected_products": ["aviatrix"],
        "exploitability": "HIGH",
        "in_cisa_kev": True,
    },
]


class CVEAgent:
    """Autonomous CVE prioritization agent grounded in asset inventory and CISA KEV."""

    def __init__(self, system_inventory: Optional[Dict[str, List[str]]] = None):
        self.session = requests.Session()
        self.session.headers.update(
            {"User-Agent": "AI-SOC-CVEAgent/1.0", "Accept": "application/json"}
        )
        self.system_inventory = system_inventory or self._load_system_inventory()

    def _load_system_inventory(self) -> Dict[str, List[str]]:
        return {
            "web-servers": ["nginx/1.24.0", "apache/2.4.58"],
            "databases": ["mysql/8.0.36", "postgresql/15.4"],
            "os": ["ubuntu/22.04", "windows/server2022", "openssh/9.2p1"],
            "containers": ["docker/25.0.3", "kubernetes/1.29.2"],
        }

    def _fetch_cisa_kev_ids(self, timeout: float = 5.0) -> Set[str]:
        try:
            resp = self.session.get(settings.CISA_KEV_URL, timeout=timeout)
            resp.raise_for_status()
            vulns = resp.json().get("vulnerabilities", [])
            return {v.get("cveID", "") for v in vulns if v.get("cveID")}
        except Exception as exc:
            logger.info(f"CISA KEV live fetch skipped/offline ({exc}); using cached KEV flags")
            return set()

    def _fetch_live_nvd_cves(self, kev_ids: Set[str], limit: int = 10, timeout: float = 6.0) -> List[Dict[str, Any]]:
        try:
            resp = self.session.get(
                settings.NVD_API_URL, params={"resultsPerPage": limit}, timeout=timeout
            )
            resp.raise_for_status()
            items = resp.json().get("vulnerabilities", [])
            parsed: List[Dict[str, Any]] = []
            for item in items:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                if not validate_cve_format(cve_id):
                    continue
                descriptions = cve.get("descriptions", [])
                desc = next(
                    (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
                    "",
                )
                metrics = cve.get("metrics", {})
                cvss_score = 5.0
                severity = "MEDIUM"
                for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if metrics.get(metric_key):
                        cvss_data = metrics[metric_key][0].get("cvssData", {})
                        cvss_score = float(cvss_data.get("baseScore", 5.0))
                        severity = str(
                            cvss_data.get("baseSeverity")
                            or metrics[metric_key][0].get("baseSeverity", "MEDIUM")
                        ).upper()
                        break

                in_kev = cve_id in kev_ids
                parsed.append(
                    {
                        "cve_id": cve_id,
                        "description": sanitize_input(desc, 1500),
                        "cvss_score": cvss_score,
                        "severity": severity,
                        "published_date": cve.get("published", ""),
                        "modified_date": cve.get("lastModified", ""),
                        "affected_products": self._extract_product_tokens(desc),
                        "exploitability": "HIGH" if in_kev or cvss_score >= 9.0 else "MEDIUM",
                        "in_cisa_kev": in_kev,
                    }
                )
            return parsed
        except Exception as exc:
            logger.info(f"NVD live feed unavailable ({exc}); using deterministic CVE baseline")
            return []

    def _extract_product_tokens(self, description: str) -> List[str]:
        desc_lower = description.lower()
        known = [
            "nginx",
            "apache",
            "mysql",
            "postgresql",
            "ubuntu",
            "windows",
            "openssh",
            "docker",
            "kubernetes",
        ]
        return [tok for tok in known if tok in desc_lower]

    async def ingest_cve_feeds(
        self, custom_cves: Optional[List[Dict[str, Any]]] = None, fetch_live: bool = False
    ) -> List[Dict[str, Any]]:
        if custom_cves:
            return self._deduplicate_cves(custom_cves)

        if fetch_live:
            kev_ids = await asyncio.to_thread(self._fetch_cisa_kev_ids)
            live_cves = await asyncio.to_thread(self._fetch_live_nvd_cves, kev_ids)
            if live_cves:
                return self._deduplicate_cves(live_cves)

        return self._deduplicate_cves(DEFAULT_OFFLINE_CVES)

    def _deduplicate_cves(self, cves: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen: Dict[str, Dict[str, Any]] = {}
        for cve in cves:
            cve_id = str(cve.get("cve_id", "")).strip()
            if not cve_id:
                continue
            if cve_id not in seen or str(cve.get("modified_date", "")) > str(
                seen[cve_id].get("modified_date", "")
            ):
                seen[cve_id] = cve
        return list(seen.values())

    def _identify_affected_systems(self, cve_data: Dict[str, Any]) -> List[str]:
        affected_systems: List[str] = []
        affected_products = [str(p).lower() for p in cve_data.get("affected_products", [])]
        desc_lower = str(cve_data.get("description", "")).lower()

        for category, products in self.system_inventory.items():
            for product in products:
                prod_name = product.split("/")[0].lower()
                if prod_name in affected_products or prod_name in desc_lower:
                    affected_systems.append(f"{category}:{product}")
        return sorted(set(affected_systems))

    def _fallback_risk_scoring(
        self, cve_data: Dict[str, Any], affected_systems: List[str]
    ) -> float:
        """
        Inventory-aware risk scoring: an actively exploited CVE on software we actually run
        outranks a CVSS 9.8 CVE on software absent from our environment.
        """
        cvss = float(cve_data.get("cvss_score", 0.0))
        score = cvss * 5.5  # Max 55 points from raw CVSS alone

        exploitability = str(cve_data.get("exploitability", "")).upper()
        if exploitability == "HIGH":
            score += 10
        elif exploitability == "MEDIUM":
            score += 5

        if cve_data.get("in_cisa_kev", False):
            score += 15

        if affected_systems:
            score += 25
        else:
            score *= 0.65  # Discount CVEs absent from our CMDB/asset inventory

        return round(min(score, 100.0), 1)

    async def assess_risk_with_ai(
        self, cve_data: Dict[str, Any], affected_systems: List[str]
    ) -> Tuple[float, Dict[str, Any]]:
        det_score = self._fallback_risk_scoring(cve_data, affected_systems)
        prompt = (
            f"Assess CVE risk for our environment in JSON:\n"
            f"CVE: {json.dumps(cve_data)}\n"
            f"Matched Inventory Assets: {affected_systems}\n"
            "Return JSON keys: risk_score (0-100), remediation_priority (1-5), "
            "mitre_attack_techniques (list of T-codes), threat_intelligence_summary (dict), "
            "recommended_actions (list of strings)."
        )
        ai = call_groq_json(
            "You are a vulnerability management engineer. Weight asset presence and CISA KEV heavily.",
            prompt,
            max_tokens=800,
        )
        if not ai:
            priority = 1 if det_score >= 85 else (2 if det_score >= 70 else (3 if det_score >= 50 else 4))
            return det_score, {
                "remediation_priority": priority,
                "threat_intelligence_summary": {
                    "mode": "deterministic_inventory_kev_scorer",
                    "in_cisa_kev": bool(cve_data.get("in_cisa_kev", False)),
                },
            }

        blended = round((det_score * 0.6) + (float(ai.get("risk_score", det_score)) * 0.4), 1)
        return min(blended, 100.0), ai

    def map_to_mitre_attack(self, cve_data: Dict[str, Any], ai_analysis: Dict[str, Any]) -> List[str]:
        techniques = list(ai_analysis.get("mitre_attack_techniques", []))
        if not techniques:
            description = str(cve_data.get("description", "")).lower()
            keyword_map = {
                "T1190": ["remote", "unauthenticated", "rce", "web", "controller"],
                "T1068": ["privilege", "escalation", "elevation"],
                "T1059": ["code execution", "command", "script"],
                "T1003": ["credential", "password", "hash"],
            }
            for tech, words in keyword_map.items():
                if any(w in description for w in words):
                    techniques.append(tech)
        return sorted(set(techniques))

    async def prioritize_vulnerabilities(self, cves: List[Dict[str, Any]]) -> List[CVEEntry]:
        prioritized: List[CVEEntry] = []
        for cve in cves:
            affected = self._identify_affected_systems(cve)
            risk_score, ai_analysis = await self.assess_risk_with_ai(cve, affected)
            mitre = self.map_to_mitre_attack(cve, ai_analysis)
            prioritized.append(
                CVEEntry(
                    cve_id=str(cve.get("cve_id")),
                    description=str(cve.get("description", "")),
                    severity=str(cve.get("severity", "MEDIUM")).upper(),
                    cvss_score=float(cve.get("cvss_score", 0.0)),
                    published_date=str(cve.get("published_date", "")),
                    modified_date=str(cve.get("modified_date", "")),
                    affected_systems=affected,
                    exploitability=str(cve.get("exploitability", "UNKNOWN")),
                    in_cisa_kev=bool(cve.get("in_cisa_kev", False)),
                    remediation_priority=int(ai_analysis.get("remediation_priority", 3)),
                    mitre_techniques=mitre,
                    threat_intelligence=ai_analysis.get("threat_intelligence_summary", {}),
                    risk_score=risk_score,
                )
            )
        prioritized.sort(key=lambda x: x.risk_score, reverse=True)
        return prioritized

    def generate_cve_report(self, prioritized_cves: List[CVEEntry]) -> Dict[str, Any]:
        return {
            "report_id": f"CVE-REPORT-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_cves": len(prioritized_cves),
                "in_inventory_count": sum(1 for c in prioritized_cves if c.affected_systems),
                "cisa_kev_count": sum(1 for c in prioritized_cves if c.in_cisa_kev),
                "critical_count": sum(1 for c in prioritized_cves if c.severity == "CRITICAL"),
                "high_count": sum(1 for c in prioritized_cves if c.severity == "HIGH"),
                "avg_risk_score": round(
                    sum(c.risk_score for c in prioritized_cves) / len(prioritized_cves), 1
                )
                if prioritized_cves
                else 0.0,
            },
            "prioritized_cves": [asdict(c) for c in prioritized_cves[:10]],
        }

    async def run(
        self,
        cves: Optional[List[Dict[str, Any]]] = None,
        fetch_live: bool = False,
    ) -> Dict[str, Any]:
        ingested = await self.ingest_cve_feeds(custom_cves=cves, fetch_live=fetch_live)
        prioritized = await self.prioritize_vulnerabilities(ingested)
        return self.generate_cve_report(prioritized)


if __name__ == "__main__":
    print(json.dumps(asyncio.run(CVEAgent().run()), indent=2))
