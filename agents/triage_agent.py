#!/usr/bin/env python3
"""
Alert Triage Agent — Context-Aware Alert Prioritization, False-Positive Suppression,
SLA Calculation, and Workload-Balanced Analyst Routing.
"""

import asyncio
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from enum import Enum
import json
from typing import Any, Dict, List, Optional

import pandas as pd

from config.settings import Settings
from utils.llm_helper import call_groq_json
from utils.logger import get_logger
from utils.security import is_time_in_window, sanitize_input

logger = get_logger(__name__)
settings = Settings()


class TriagePriority(Enum):
    P1_CRITICAL = "P1_CRITICAL"
    P2_HIGH = "P2_HIGH"
    P3_MEDIUM = "P3_MEDIUM"
    P4_LOW = "P4_LOW"
    P5_INFO = "P5_INFO"


@dataclass
class TriageResult:
    alert_id: str
    original_alert: Dict[str, Any]
    triage_timestamp: str
    priority: str
    confidence_score: float
    false_positive_probability: float
    business_impact: str
    technical_severity: str
    recommended_actions: List[str]
    escalation_required: bool
    estimated_effort_hours: float
    similar_alerts: List[str]
    contextual_analysis: Dict[str, Any]
    ai_summary: str
    next_steps: List[str]
    sla_deadline: str
    assigned_analyst: Optional[str] = None


DEFAULT_SAMPLE_ALERTS: List[Dict[str, Any]] = [
    {
        "alert_id": "ALERT-DEMO-001",
        "alert_type": "malware_detection",
        "severity": "CRITICAL",
        "source_ip": "185.220.101.45",
        "description": "Encoded PowerShell execution detected on payment-gateway handling PCI-DSS financial-data",
        "affected_systems": ["payment-gateway"],
        "timestamp": "2025-08-14T11:15:00",
    },
    {
        "alert_id": "ALERT-DEMO-002",
        "alert_type": "network_scan",
        "severity": "MEDIUM",
        "source_system": "vulnerability-scanner",
        "description": "Scheduled maintenance compliance port check from internal scanner",
        "affected_systems": ["dev-web-01"],
        "timestamp": "2025-08-14T02:30:00",
    },
]


class AlertTriageAgent:
    """Bounded SOC triage specialist combining FP windows, asset impact, priority matrices, and routing."""

    def __init__(self):
        self.alert_history = self._load_alert_history()
        self.false_positive_patterns = self._load_fp_patterns()
        self.business_context = self._load_business_context()
        self.analyst_workload = self._load_analyst_workload()

    def _load_alert_history(self) -> pd.DataFrame:
        sample_data = [
            {
                "alert_id": "HIST-001",
                "alert_type": "brute_force",
                "source_ip": "185.220.101.45",
                "severity": "HIGH",
                "resolution": "true_positive",
                "resolution_time_hours": 2.0,
            },
            {
                "alert_id": "HIST-002",
                "alert_type": "network_scan",
                "source_ip": "10.0.5.10",
                "severity": "MEDIUM",
                "resolution": "false_positive",
                "resolution_time_hours": 0.25,
            },
        ]
        return pd.DataFrame(sample_data)

    def _load_fp_patterns(self) -> Dict[str, Any]:
        return {
            "common_patterns": [
                "automated_backup_process",
                "scheduled_maintenance",
                "legitimate_admin_activity",
                "antivirus_update",
                "patch_management",
            ],
            "time_based_fps": {
                "maintenance_window": {"start": "02:00", "end": "04:00"},
                "backup_window": {"start": "23:00", "end": "01:00"},
            },
            "source_based_fps": {
                "trusted_internal_tools": ["backup-server", "monitoring-system"],
                "known_scanners": ["vulnerability-scanner", "compliance-check"],
            },
        }

    def _load_business_context(self) -> Dict[str, Any]:
        return {
            "critical_systems": [
                "payment-gateway",
                "customer-db",
                "web-frontend",
                "api-gateway",
                "auth-service",
            ],
            "business_hours": {"start": 9, "end": 17},
            "high_value_assets": [
                "financial-data",
                "customer-pii",
                "intellectual-property",
            ],
            "compliance_requirements": ["PCI-DSS", "GDPR", "SOX", "HIPAA"],
        }

    def _load_analyst_workload(self) -> Dict[str, Any]:
        return {
            "analysts": {
                "alice": {
                    "current_alerts": 3,
                    "skill_level": "senior",
                    "specialization": "malware",
                },
                "bob": {
                    "current_alerts": 5,
                    "skill_level": "intermediate",
                    "specialization": "network",
                },
                "charlie": {
                    "current_alerts": 2,
                    "skill_level": "senior",
                    "specialization": "forensics",
                },
            },
            "team_capacity": {"max_alerts_per_analyst": 8, "escalation_threshold": 6},
        }

    def _parse_event_datetime(self, alert_data: Dict[str, Any]) -> datetime:
        ts = alert_data.get("timestamp")
        if isinstance(ts, str) and ts.strip():
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
            except ValueError:
                pass
        return datetime.now()

    def _sanitize_alert_data(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            k: sanitize_input(v) if isinstance(v, str) else v
            for k, v in alert_data.items()
        }

    def _assess_false_positive_likelihood(
        self, alert_data: Dict[str, Any], event_dt: datetime
    ) -> Dict[str, Any]:
        fp_score = 0.0
        indicators: List[str] = []

        desc = str(alert_data.get("description", "")).lower()
        msg = str(alert_data.get("message", "")).lower()
        combined = f"{desc} {msg}"

        for pattern in self.false_positive_patterns["common_patterns"]:
            phrase = pattern.replace("_", " ")
            if phrase in combined:
                fp_score += 0.35
                indicators.append(f"Matched benign operational pattern: {pattern}")

        event_time = event_dt.time()
        for window_name, window in self.false_positive_patterns["time_based_fps"].items():
            if is_time_in_window(event_time, window["start"], window["end"]):
                fp_score += 0.25
                indicators.append(f"Occurred inside {window_name} ({window['start']}-{window['end']})")

        source_system = str(alert_data.get("source_system", "")).lower()
        for category, systems in self.false_positive_patterns["source_based_fps"].items():
            if any(s in source_system for s in systems):
                fp_score += 0.40
                indicators.append(f"Source matches allowlisted {category}: {source_system}")

        prob = round(min(fp_score, 0.95), 2)
        return {
            "probability": prob,
            "indicators": indicators,
            "confidence": 0.8 if indicators else 0.35,
        }

    def _analyze_business_impact(
        self, alert_data: Dict[str, Any], event_dt: datetime
    ) -> Dict[str, Any]:
        impact_score = 0
        factors: List[str] = []

        for system in alert_data.get("affected_systems", []):
            if any(crit in str(system).lower() for crit in self.business_context["critical_systems"]):
                impact_score += 50
                factors.append(f"Critical asset affected: {system}")

        desc = str(alert_data.get("description", "")).lower()
        for asset in self.business_context["high_value_assets"]:
            if asset in desc or asset.replace("-", " ") in desc:
                impact_score += 25
                factors.append(f"High-value data asset referenced: {asset}")

        for req in self.business_context["compliance_requirements"]:
            if req.lower() in desc:
                impact_score += 20
                factors.append(f"Regulated scope affected: {req}")

        bh = self.business_context["business_hours"]
        if bh["start"] <= event_dt.hour <= bh["end"]:
            impact_score += 15
            factors.append("Occurred during peak business hours")

        if impact_score >= 70:
            level = "CRITICAL"
        elif impact_score >= 50:
            level = "HIGH"
        elif impact_score >= 30:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {"score": impact_score, "level": level, "factors": factors}

    def _assess_technical_severity(
        self, alert_data: Dict[str, Any], ai_analysis: Dict[str, Any]
    ) -> str:
        base_map = {"CRITICAL": 50, "HIGH": 35, "MEDIUM": 20, "LOW": 10, "INFO": 5}
        base_sev = str(alert_data.get("severity", "MEDIUM")).upper()
        score = float(base_map.get(base_sev, 20))
        ai_score = float(ai_analysis.get("technical_severity_score", score * 1.6))
        cvss = float(alert_data.get("cvss_score", 0.0))
        total = score + (ai_score * 0.4) + (cvss * 3.0)

        if total >= 75:
            return "CRITICAL"
        if total >= 55:
            return "HIGH"
        if total >= 35:
            return "MEDIUM"
        return "LOW"

    def _calculate_priority(
        self,
        ai_analysis: Dict[str, Any],
        business_impact: Dict[str, Any],
        tech_severity: str,
        fp_probability: float,
    ) -> str:
        if fp_probability >= 0.75 and business_impact.get("level") in ("LOW", "MEDIUM"):
            return "P5_INFO" if fp_probability >= 0.85 else "P4_LOW"

        matrix = {
            ("CRITICAL", "CRITICAL"): "P1_CRITICAL",
            ("CRITICAL", "HIGH"): "P1_CRITICAL",
            ("HIGH", "CRITICAL"): "P1_CRITICAL",
            ("CRITICAL", "MEDIUM"): "P2_HIGH",
            ("CRITICAL", "LOW"): "P2_HIGH",
            ("HIGH", "HIGH"): "P2_HIGH",
            ("MEDIUM", "CRITICAL"): "P2_HIGH",
            ("MEDIUM", "HIGH"): "P2_HIGH",
            ("HIGH", "MEDIUM"): "P2_HIGH",
            ("MEDIUM", "MEDIUM"): "P3_MEDIUM",
            ("LOW", "HIGH"): "P3_MEDIUM",
            ("HIGH", "LOW"): "P3_MEDIUM",
            ("MEDIUM", "LOW"): "P4_LOW",
            ("LOW", "MEDIUM"): "P4_LOW",
            ("LOW", "LOW"): "P5_INFO",
        }
        det_priority = matrix.get((tech_severity, business_impact.get("level", "LOW")), "P3_MEDIUM")
        ai_priority = str(ai_analysis.get("recommended_priority", det_priority))

        ranks = {"P1_CRITICAL": 5, "P2_HIGH": 4, "P3_MEDIUM": 3, "P4_LOW": 2, "P5_INFO": 1}
        if fp_probability >= 0.7:
            return det_priority
        return ai_priority if ranks.get(ai_priority, 3) > ranks.get(det_priority, 3) else det_priority

    def _analyze_historical_patterns(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        if self.alert_history.empty:
            return {"pattern_match": False, "confidence": 0.0}
        alert_type = str(alert_data.get("alert_type", "")).lower()
        source_ip = str(alert_data.get("source_ip", ""))
        mask = (self.alert_history["alert_type"].str.lower() == alert_type) | (
            self.alert_history["source_ip"] == source_ip
        )
        matched = self.alert_history[mask]
        if matched.empty:
            return {"pattern_match": False, "confidence": 0.0}
        fp_rate = len(matched[matched["resolution"] == "false_positive"]) / len(matched)
        return {
            "pattern_match": True,
            "similar_count": int(len(matched)),
            "false_positive_rate": round(float(fp_rate), 2),
            "avg_resolution_time": round(float(matched["resolution_time_hours"].mean()), 2),
        }

    def _should_escalate(
        self, priority: str, fp_assessment: Dict[str, Any], business_impact: Dict[str, Any]
    ) -> bool:
        if fp_assessment.get("probability", 0.0) > 0.7:
            return False
        if priority == "P1_CRITICAL" or business_impact.get("level") == "CRITICAL":
            return True
        if priority == "P2_HIGH":
            return True
        return False

    def _suggest_analyst(self, alert_data: Dict[str, Any]) -> Optional[str]:
        analysts = self.analyst_workload["analysts"]
        cap = self.analyst_workload["team_capacity"]["max_alerts_per_analyst"]
        available = {
            name: info for name, info in analysts.items() if info["current_alerts"] < cap
        }
        if not available:
            return None

        corpus = f"{alert_data.get('alert_type', '')} {alert_data.get('description', '')}".lower()
        specialized = [
            name
            for name, info in available.items()
            if info.get("specialization", "").lower() in corpus
        ]
        chosen = (
            min(specialized, key=lambda n: available[n]["current_alerts"])
            if specialized
            else min(available.keys(), key=lambda n: available[n]["current_alerts"])
        )
        analysts[chosen]["current_alerts"] += 1
        return chosen

    def _calculate_sla_deadline(self, priority: str, base_dt: datetime) -> str:
        sla_hours = {
            "P1_CRITICAL": 1,
            "P2_HIGH": 4,
            "P3_MEDIUM": 24,
            "P4_LOW": 72,
            "P5_INFO": 168,
        }
        return (base_dt + timedelta(hours=sla_hours.get(priority, 24))).isoformat()

    def _default_recommendations(self, alert_data: Dict[str, Any], fp_prob: float) -> List[str]:
        if fp_prob > 0.7:
            return [
                "Verify scheduled maintenance/scanner change ticket before closing",
                "Tune detection rule exclusion scope if recurring benign activity",
            ]
        atype = str(alert_data.get("alert_type", "")).lower()
        if "malware" in atype or "command" in atype:
            return [
                "Isolate affected host and capture process lineage",
                "Check lateral movement from host across internal SMB/SSH peers",
            ]
        if "brute" in atype:
            return [
                "Block offending source IP and verify MFA enforcement",
                "Audit successful authentications from same ASN/subnet",
            ]
        return ["Correlate host, identity, and network telemetry around alert timestamp"]

    async def triage_alert(self, alert_data: Dict[str, Any]) -> TriageResult:
        try:
            clean = self._sanitize_alert_data(alert_data)
            event_dt = self._parse_event_datetime(clean)
            fp_assessment = self._assess_false_positive_likelihood(clean, event_dt)
            business_impact = self._analyze_business_impact(clean, event_dt)
            pattern_analysis = self._analyze_historical_patterns(clean)

            ai_analysis = call_groq_json(
                "You are a senior SOC triage engineer. Return JSON keys: summary, "
                "confidence_score (0-1), technical_severity_score (0-100), "
                "recommended_priority (P1_CRITICAL..P5_INFO), immediate_actions (list), "
                "next_steps (list), estimated_investigation_time_hours (float).",
                f"Alert: {json.dumps(clean)}\nBusiness Impact: {json.dumps(business_impact)}\n"
                f"FP Assessment: {json.dumps(fp_assessment)}",
                max_tokens=900,
            ) or {}

            tech_severity = self._assess_technical_severity(clean, ai_analysis)
            priority = self._calculate_priority(
                ai_analysis, business_impact, tech_severity, fp_assessment["probability"]
            )
            escalate = self._should_escalate(priority, fp_assessment, business_impact)
            should_route = escalate or priority in ("P1_CRITICAL", "P2_HIGH", "P3_MEDIUM")
            assigned = self._suggest_analyst(clean) if should_route else None
            recs = sorted(
                set(
                    list(ai_analysis.get("immediate_actions", []))
                    + self._default_recommendations(clean, fp_assessment["probability"])
                )
            )
            summary = ai_analysis.get("summary") or (
                f"Triaged as {priority} (Tech={tech_severity}, Business={business_impact['level']}, "
                f"FP={fp_assessment['probability']:.2f})."
            )

            return TriageResult(
                alert_id=str(clean.get("alert_id", f"TRIAGE-{event_dt.strftime('%Y%m%d-%H%M%S')}")),
                original_alert=clean,
                triage_timestamp=datetime.now().isoformat(),
                priority=priority,
                confidence_score=float(ai_analysis.get("confidence_score", 0.82)),
                false_positive_probability=fp_assessment["probability"],
                business_impact=business_impact["level"],
                technical_severity=tech_severity,
                recommended_actions=recs,
                escalation_required=escalate,
                estimated_effort_hours=round(float(ai_analysis.get("estimated_investigation_time_hours", 1.5)), 2),
                similar_alerts=[],
                contextual_analysis={
                    "fp_assessment": fp_assessment,
                    "business_context": business_impact,
                    "pattern_analysis": pattern_analysis,
                },
                ai_summary=summary,
                next_steps=list(ai_analysis.get("next_steps", recs[:2])),
                sla_deadline=self._calculate_sla_deadline(priority, event_dt),
                assigned_analyst=assigned,
            )
        except Exception as exc:
            logger.error(f"Triage fallback triggered: {exc}")
            return self._create_fallback_triage_result(alert_data, str(exc))

    def _create_fallback_triage_result(
        self, alert_data: Dict[str, Any], error_msg: str
    ) -> TriageResult:
        now = datetime.now()
        return TriageResult(
            alert_id=str(alert_data.get("alert_id", f"TRIAGE-FALLBACK-{now.strftime('%H%M%S')}")),
            original_alert=alert_data,
            triage_timestamp=now.isoformat(),
            priority="P3_MEDIUM",
            confidence_score=0.1,
            false_positive_probability=0.5,
            business_impact="UNKNOWN",
            technical_severity="UNKNOWN",
            recommended_actions=[f"Manual analyst review required ({error_msg})"],
            escalation_required=True,
            estimated_effort_hours=1.0,
            similar_alerts=[],
            contextual_analysis={"error": error_msg},
            ai_summary=f"Fallback triage engaged: {error_msg}",
            next_steps=["Manual analyst review required"],
            sla_deadline=(now + timedelta(hours=4)).isoformat(),
            assigned_analyst=None,
        )

    async def batch_triage(self, alerts: List[Dict[str, Any]]) -> List[TriageResult]:
        results = [await self.triage_alert(a) for a in alerts]
        order = {"P1_CRITICAL": 5, "P2_HIGH": 4, "P3_MEDIUM": 3, "P4_LOW": 2, "P5_INFO": 1}
        results.sort(key=lambda r: order.get(r.priority, 0), reverse=True)
        return results

    def generate_triage_report(self, results: List[TriageResult]) -> Dict[str, Any]:
        priorities = [r.priority for r in results]
        breakdown = {p: priorities.count(p) for p in sorted(set(priorities))}
        suppressed = sum(1 for r in results if r.false_positive_probability > 0.7)
        return {
            "report_id": f"TRIAGE-REPORT-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_alerts": len(results),
                "priority_breakdown": breakdown,
                "escalation_required_count": sum(1 for r in results if r.escalation_required),
                "likely_false_positives_suppressed": suppressed,
            },
            "results": [asdict(r) for r in results],
        }

    async def run(self, alerts: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        batch = alerts if alerts is not None else DEFAULT_SAMPLE_ALERTS
        triaged = await self.batch_triage(batch)
        return self.generate_triage_report(triaged)


TriageAgent = AlertTriageAgent

if __name__ == "__main__":
    print(json.dumps(asyncio.run(AlertTriageAgent().run()), indent=2))
