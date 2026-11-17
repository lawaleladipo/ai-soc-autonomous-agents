#!/usr/bin/env python3
"""
Threat Hunting Agent — Hypothesis-Driven Proactive Threat Discovery Mapped to MITRE ATT&CK.
"""

import asyncio
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional

from utils.llm_helper import call_groq_json
from utils.logger import get_logger

logger = get_logger(__name__)


class HuntStatus(Enum):
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


@dataclass
class HuntHypothesis:
    hypothesis_id: str
    key: str
    name: str
    description: str
    mitre_techniques: List[str]
    threat_category: str
    priority: int
    data_sources: List[str]
    search_queries: List[str]
    expected_indicators: List[str]
    confidence_threshold: float


@dataclass
class HuntResult:
    hunt_id: str
    hypothesis: Dict[str, Any]
    execution_timestamp: str
    status: str
    findings: List[Dict[str, Any]]
    iocs_discovered: List[str]
    affected_systems: List[str]
    confidence_score: float
    false_positive_likelihood: float
    mitre_mappings: List[str]
    recommendations: List[str]
    timeline: List[Dict[str, Any]]
    ai_analysis: Dict[str, Any]
    execution_time_seconds: float


DEFAULT_TELEMETRY_EVENTS: List[Dict[str, Any]] = [
    {
        "timestamp": "2025-08-14T11:16:02",
        "data_source": "windows_events",
        "event_id": 5156,
        "host": "payment-gateway",
        "source_ip": "10.10.4.25",
        "dest_ip": "10.10.4.100",
        "dest_port": 445,
        "process": "powershell.exe",
        "user": "admin",
    },
    {
        "timestamp": "2025-08-14T11:16:09",
        "data_source": "windows_events",
        "event_id": 5156,
        "host": "customer-db",
        "source_ip": "10.10.4.25",
        "dest_ip": "10.10.4.101",
        "dest_port": 445,
        "process": "powershell.exe",
        "user": "admin",
    },
    {
        "timestamp": "2025-08-14T11:17:00",
        "data_source": "process_logs",
        "event_id": 4688,
        "host": "payment-gateway",
        "process": "procdump.exe",
        "command_line": "procdump.exe -ma lsass.exe C:\\Windows\\Temp\\dump.dmp",
        "user": "admin",
    },
    {
        "timestamp": "2025-08-14T11:18:12",
        "data_source": "network_logs",
        "host": "payment-gateway",
        "source_ip": "10.10.4.25",
        "dns_query_type": "TXT",
        "domain": "suspicious-domain.com",
        "response_length": 240,
    },
]


class ThreatHuntingAgent:
    """Executes structured MITRE ATT&CK threat-hunting hypotheses over telemetry datasets."""

    def __init__(self):
        self.hunt_hypotheses = self._load_hunt_hypotheses()

    def _load_hunt_hypotheses(self) -> Dict[str, HuntHypothesis]:
        return {
            "lateral_movement_smb": HuntHypothesis(
                hypothesis_id="HUNT-001",
                key="lateral_movement_smb",
                name="Lateral Movement via SMB",
                description="Detect rapid SMB fan-out across internal hosts on TCP/445",
                mitre_techniques=["T1021.002", "T1135"],
                threat_category="LATERAL_MOVEMENT",
                priority=8,
                data_sources=["windows_events", "network_logs"],
                search_queries=["event_id:5156 AND dest_port:445", "net_use"],
                expected_indicators=["multiple_smb_connections", "admin_shares"],
                confidence_threshold=0.7,
            ),
            "privilege_escalation_tokens": HuntHypothesis(
                hypothesis_id="HUNT-002",
                key="privilege_escalation_tokens",
                name="Token Manipulation for Privilege Escalation",
                description="Hunt for SeDebugPrivilege / SeImpersonatePrivilege token abuse",
                mitre_techniques=["T1134", "T1134.001"],
                threat_category="PRIVILEGE_ESCALATION",
                priority=9,
                data_sources=["windows_events", "process_logs"],
                search_queries=["event_id:4648", "sedebugprivilege OR seimpersonateprivilege"],
                expected_indicators=["token_creation", "privilege_changes"],
                confidence_threshold=0.8,
            ),
            "persistence_scheduled_tasks": HuntHypothesis(
                hypothesis_id="HUNT-003",
                key="persistence_scheduled_tasks",
                name="Persistence via Scheduled Tasks",
                description="Identify suspicious scheduled task creation for persistence",
                mitre_techniques=["T1053.005"],
                threat_category="PERSISTENCE",
                priority=7,
                data_sources=["windows_events", "process_logs"],
                search_queries=["event_id:4698", "schtasks OR register-scheduledtask"],
                expected_indicators=["suspicious_task_creation"],
                confidence_threshold=0.65,
            ),
            "c2_dns_tunneling": HuntHypothesis(
                hypothesis_id="HUNT-004",
                key="c2_dns_tunneling",
                name="Command & Control via DNS Tunneling",
                description="Identify oversized TXT records and encoded DNS C2 channels",
                mitre_techniques=["T1071.004", "T1572"],
                threat_category="COMMAND_CONTROL",
                priority=8,
                data_sources=["network_logs"],
                search_queries=["dns_query_type:txt AND response_length:>100"],
                expected_indicators=["long_dns_queries", "encoded_data"],
                confidence_threshold=0.7,
            ),
            "credential_dumping": HuntHypothesis(
                hypothesis_id="HUNT-005",
                key="credential_dumping",
                name="Credential Dumping Activities",
                description="Hunt for LSASS memory dumping, Mimikatz, or SAM shadow access",
                mitre_techniques=["T1003", "T1003.001"],
                threat_category="CREDENTIAL_ACCESS",
                priority=9,
                data_sources=["process_logs", "windows_events"],
                search_queries=["lsass.exe AND procdump", "mimikatz OR sekurlsa", "vssadmin"],
                expected_indicators=["lsass_access", "shadow_copy_creation"],
                confidence_threshold=0.8,
            ),
        }

    def select_hypothesis_for_alert(self, alert: Dict[str, Any]) -> str:
        """Select the highest-signal follow-up hunt hypothesis given an alert's tradecraft."""
        corpus = json.dumps(alert, default=str).lower()
        if "powershell" in corpus or "command_injection" in corpus or "lsass" in corpus:
            return "credential_dumping"
        if "privilege" in corpus or "token" in corpus:
            return "privilege_escalation_tokens"
        if "dns" in corpus or "exfiltration" in corpus:
            return "c2_dns_tunneling"
        return "lateral_movement_smb"

    def _match_term(self, term: str, event: Dict[str, Any], event_str: str) -> bool:
        if ":" in term:
            field, value = term.split(":", 1)
            field = field.strip()
            value = value.strip()
            if value.startswith(">"):
                try:
                    return float(event.get(field, 0)) > float(value[1:])
                except (TypeError, ValueError):
                    return False
            return value in str(event.get(field, "")).lower()
        return term in event_str

    def _search_events(self, query: str, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        matches: List[Dict[str, Any]] = []
        q_lower = query.lower()
        for event in events:
            event_str = json.dumps(event, default=str).lower()
            if " and " in q_lower:
                terms = [t.strip() for t in q_lower.split(" and ")]
                ok = all(self._match_term(t, event, event_str) for t in terms)
            elif " or " in q_lower:
                terms = [t.strip() for t in q_lower.split(" or ")]
                ok = any(self._match_term(t, event, event_str) for t in terms)
            else:
                ok = self._match_term(q_lower, event, event_str)
            if ok:
                enriched = dict(event)
                enriched["query_matched"] = query
                matches.append(enriched)
        return matches

    def _deduplicate_and_correlate(
        self, findings: List[Dict[str, Any]], hypothesis: HuntHypothesis
    ) -> List[Dict[str, Any]]:
        unique: List[Dict[str, Any]] = []
        seen = set()
        for f in findings:
            sig = hashlib.md5(
                json.dumps(
                    {k: f.get(k) for k in ("timestamp", "host", "source_ip", "dest_ip", "process", "event_id")},
                    sort_keys=True,
                ).encode()
            ).hexdigest()
            if sig not in seen:
                seen.add(sig)
                unique.append(f)

        groups: Dict[str, List[Dict[str, Any]]] = {}
        for f in unique:
            pivot = (
                str(f.get("source_ip", "unknown"))
                if hypothesis.threat_category == "LATERAL_MOVEMENT"
                else str(f.get("user") or f.get("host") or "unknown")
            )
            groups.setdefault(pivot, []).append(f)

        correlated: List[Dict[str, Any]] = []
        for pivot, items in groups.items():
            for item in items:
                item["correlation_key"] = pivot
                item["related_events_count"] = len(items)
                correlated.append(item)
        return correlated

    def _extract_iocs(self, findings: List[Dict[str, Any]]) -> List[str]:
        iocs = set()
        for f in findings:
            if f.get("source_ip"):
                iocs.add(f"ip:{f['source_ip']}")
            if f.get("dest_ip"):
                iocs.add(f"ip:{f['dest_ip']}")
            if f.get("domain"):
                iocs.add(f"domain:{f['domain']}")
            if f.get("process"):
                iocs.add(f"process:{f['process']}")
        return sorted(iocs)

    async def execute_hunt(
        self,
        hypothesis_key: str = "lateral_movement_smb",
        events: Optional[List[Dict[str, Any]]] = None,
    ) -> HuntResult:
        start = datetime.now()
        if hypothesis_key not in self.hunt_hypotheses:
            # Allow lookup by hypothesis_id (e.g. HUNT-001) as well
            by_id = {h.hypothesis_id: k for k, h in self.hunt_hypotheses.items()}
            hypothesis_key = by_id.get(hypothesis_key, "")
            if hypothesis_key not in self.hunt_hypotheses:
                raise ValueError(f"Unknown hunt hypothesis '{hypothesis_key}'")

        hypothesis = self.hunt_hypotheses[hypothesis_key]
        telemetry = events if events is not None else DEFAULT_TELEMETRY_EVENTS
        scoped = [
            e
            for e in telemetry
            if not e.get("data_source") or e.get("data_source") in hypothesis.data_sources
        ]

        raw_matches: List[Dict[str, Any]] = []
        for q in hypothesis.search_queries:
            raw_matches.extend(self._search_events(q, scoped))

        correlated = self._deduplicate_and_correlate(raw_matches, hypothesis)
        timeline = sorted(correlated, key=lambda x: str(x.get("timestamp", "")))
        iocs = self._extract_iocs(correlated)
        hosts = sorted({str(f["host"]) for f in correlated if f.get("host")})

        ai_analysis = call_groq_json(
            "You are a senior threat hunter. Return JSON keys: threat_detected (bool), "
            "confidence_score (0-1), attack_progression_stage, recommended_containment_actions (list), "
            "suggested_follow_up_hunts (list).",
            f"Hypothesis: {asdict(hypothesis)}\nCorrelated Findings: {json.dumps(correlated[:10])}",
            max_tokens=900,
        ) or {
            "threat_detected": len(correlated) > 0,
            "confidence_score": 0.85 if len(correlated) >= 2 else (0.72 if correlated else 0.1),
            "attack_progression_stage": hypothesis.threat_category,
            "recommended_containment_actions": (
                [
                    f"Isolate impacted hosts ({', '.join(hosts) or 'targeted segment'})",
                    "Rotate exposed credentials and revoke active Kerberos/session tokens",
                ]
                if correlated
                else ["No active indicators matched; keep hypothesis scheduled"]
            ),
            "suggested_follow_up_hunts": ["credential_dumping", "c2_dns_tunneling"],
        }

        return HuntResult(
            hunt_id=f"HUNT-RUN-{start.strftime('%Y%m%d-%H%M%S')}-{hypothesis.hypothesis_id}",
            hypothesis=asdict(hypothesis),
            execution_timestamp=start.isoformat(),
            status=HuntStatus.COMPLETED.value,
            findings=correlated,
            iocs_discovered=iocs,
            affected_systems=hosts,
            confidence_score=float(ai_analysis.get("confidence_score", 0.75)),
            false_positive_likelihood=0.15 if len(correlated) >= 2 else 0.35,
            mitre_mappings=hypothesis.mitre_techniques,
            recommendations=list(ai_analysis.get("recommended_containment_actions", [])),
            timeline=timeline,
            ai_analysis=ai_analysis,
            execution_time_seconds=round((datetime.now() - start).total_seconds(), 4),
        )

    async def run(
        self,
        hypothesis_key: str = "lateral_movement_smb",
        events: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        result = await self.execute_hunt(hypothesis_key=hypothesis_key, events=events)
        return asdict(result)


HuntAgent = ThreatHuntingAgent

if __name__ == "__main__":
    print(json.dumps(asyncio.run(ThreatHuntingAgent().run()), indent=2))
