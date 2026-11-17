#!/usr/bin/env python3
"""
Threat Detection Agent — Hybrid Signature, Behavioral Baseline, IoC & AI Log Analyzer.
"""

import asyncio
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
import hashlib
import ipaddress
import json
import re
from typing import Any, Dict, List, Optional, Tuple

from utils.llm_helper import call_groq_json
from utils.logger import get_logger
from utils.security import sanitize_input, validate_ip_address
from utils.threat_intel import ThreatIntelligence

logger = get_logger(__name__)


class ThreatType(Enum):
    MALWARE = "MALWARE"
    PHISHING = "PHISHING"
    BRUTE_FORCE = "BRUTE_FORCE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    ANOMALOUS_BEHAVIOR = "ANOMALOUS_BEHAVIOR"


@dataclass
class ThreatAlert:
    alert_id: str
    timestamp: str
    threat_type: str
    severity: str
    confidence: float
    source_ip: Optional[str]
    destination_ip: Optional[str]
    affected_systems: List[str]
    indicators: List[str]
    mitre_techniques: List[str]
    raw_logs: List[str]
    analysis: Dict[str, Any]
    remediation_steps: List[str]
    false_positive_probability: float


DEFAULT_SAMPLE_LOGS: List[Dict[str, str]] = [
    {
        "message": "Aug 14 10:30:00 payment-gateway sshd[1234]: Failed password for root from 185.220.101.45 port 22 ssh2",
        "source": "auth.log",
    },
    {
        "message": (
            "2025-08-14 11:15:22 [WARN] host=payment-gateway user=admin executed: "
            "powershell.exe -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwA="
        ),
        "source": "edr.log",
    },
]


class ThreatDetectionAgent:
    """Hybrid threat detection agent combining deterministic signatures, baselines, IoCs, and LLM."""

    def __init__(self):
        self.threat_intel = ThreatIntelligence()
        self.detection_rules = self._load_detection_rules()
        self.baseline_behavior = {
            "normal_login_hours": {"start": 8, "end": 18},
            "trusted_ips": ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"],
        }

    def _load_detection_rules(self) -> Dict[str, Any]:
        return {
            "brute_force": {
                "pattern": r"Failed (?:password|login|authentication).*from\s+(\d+\.\d+\.\d+\.\d+)",
                "severity": "HIGH",
                "threat_type": "BRUTE_FORCE",
                "mitre": ["T1110"],
            },
            "privilege_escalation": {
                "pattern": r"(?:sudo|su|runas).*(?:root|administrator|SeDebugPrivilege)",
                "severity": "HIGH",
                "threat_type": "PRIVILEGE_ESCALATION",
                "mitre": ["T1548", "T1134"],
            },
            "malicious_commands": {
                "patterns": [
                    r"powershell(?:\.exe)?\s+.*-enc\s+[A-Za-z0-9+/=]{16,}",
                    r"cmd\.exe.*\/c\s+.*&",
                    r"(?:wget|curl)\s+.*\|\s*(?:bash|sh)",
                    r"nc\s+.*-e\s+\/bin\/(?:bash|sh)",
                ],
                "severity": "CRITICAL",
                "threat_type": "COMMAND_INJECTION",
                "mitre": ["T1059.001", "T1059.004"],
            },
            "data_exfiltration": {
                "patterns": [
                    r"scp\s+-r\s+\/.*",
                    r"tar\s+-czf\s+\/tmp\/.*",
                    r"(?:ftp|sftp).*put\s+.*",
                ],
                "severity": "HIGH",
                "threat_type": "DATA_EXFILTRATION",
                "mitre": ["T1560", "T1048"],
            },
        }

    def _apply_detection_rules(self, log_entry: str) -> List[Dict[str, Any]]:
        matches: List[Dict[str, Any]] = []
        bf = re.search(self.detection_rules["brute_force"]["pattern"], log_entry, re.IGNORECASE)
        if bf:
            matches.append(
                {
                    "rule": "brute_force",
                    "severity": "HIGH",
                    "threat_type": "BRUTE_FORCE",
                    "indicator": bf.group(1),
                    "mitre": ["T1110"],
                    "description": "Authentication brute-force pattern matched",
                }
            )

        if re.search(
            self.detection_rules["privilege_escalation"]["pattern"], log_entry, re.IGNORECASE
        ):
            matches.append(
                {
                    "rule": "privilege_escalation",
                    "severity": "HIGH",
                    "threat_type": "PRIVILEGE_ESCALATION",
                    "mitre": ["T1548"],
                    "description": "Privileged command invocation matched",
                }
            )

        for pat in self.detection_rules["malicious_commands"]["patterns"]:
            if re.search(pat, log_entry, re.IGNORECASE):
                matches.append(
                    {
                        "rule": "malicious_command",
                        "severity": "CRITICAL",
                        "threat_type": "COMMAND_INJECTION",
                        "mitre": ["T1059.001"],
                        "description": "Encoded/piped command execution matched",
                    }
                )

        for pat in self.detection_rules["data_exfiltration"]["patterns"]:
            if re.search(pat, log_entry, re.IGNORECASE):
                matches.append(
                    {
                        "rule": "data_exfiltration",
                        "severity": "HIGH",
                        "threat_type": "DATA_EXFILTRATION",
                        "mitre": ["T1048"],
                        "description": "Archive staging or bulk file transfer matched",
                    }
                )
        return matches

    def _detect_behavioral_anomaly(self, log_entry: str) -> List[Dict[str, Any]]:
        anomalies: List[Dict[str, Any]] = []
        for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", log_entry):
            try:
                ip_obj = ipaddress.ip_address(ip)
                is_trusted = any(
                    ip_obj in ipaddress.ip_network(net)
                    for net in self.baseline_behavior["trusted_ips"]
                )
                if not is_trusted and not ip_obj.is_private:
                    anomalies.append(
                        {
                            "type": "untrusted_external_ip",
                            "severity": "MEDIUM",
                            "indicator": ip,
                            "description": f"External IP outside trusted CIDRs: {ip}",
                        }
                    )
            except ValueError:
                continue
        return anomalies

    async def _check_threat_intelligence(self, log_entry: str) -> List[Dict[str, Any]]:
        matches: List[Dict[str, Any]] = []
        for ip in set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", log_entry)):
            if validate_ip_address(ip):
                intel = await self.threat_intel.check_ip(ip)
                if intel.get("malicious"):
                    matches.append(
                        {
                            "type": "malicious_ip",
                            "severity": "HIGH",
                            "indicator": ip,
                            "mitre": ["T1071"],
                            "description": f"Known malicious IP in threat intel: {ip}",
                        }
                    )
        for file_hash in set(re.findall(r"\b[a-fA-F0-9]{32,64}\b", log_entry)):
            intel = await self.threat_intel.check_hash(file_hash)
            if intel.get("malicious"):
                matches.append(
                    {
                        "type": "malicious_hash",
                        "severity": "CRITICAL",
                        "indicator": file_hash,
                        "mitre": ["T1204"],
                        "description": f"Known malicious file hash: {file_hash}",
                    }
                )
        return matches

    async def analyze_log_entry(
        self, log_entry: str, log_source: str = "syslog"
    ) -> Optional[ThreatAlert]:
        clean_log = sanitize_input(log_entry)
        rule_matches = self._apply_detection_rules(clean_log)
        anomalies = self._detect_behavioral_anomaly(clean_log)
        intel_matches = await self._check_threat_intelligence(clean_log)
        combined = rule_matches + anomalies + intel_matches

        ai_analysis = call_groq_json(
            "You are a SOC detection analyst. Return JSON keys: threat_detected (bool), "
            "threat_type, confidence_score (0-1), severity, indicators (list), "
            "mitre_techniques (list), recommended_actions (list), affected_systems (list), "
            "false_positive_likelihood (0-1).",
            f"Source: {log_source}\nLog: {clean_log}",
            max_tokens=700,
        ) or {}

        if not combined and not ai_analysis.get("threat_detected", False):
            return None

        severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        max_sev = "INFO"
        mitre_set = set(ai_analysis.get("mitre_techniques", []))
        indicators_set = set(ai_analysis.get("indicators", []))
        inferred_type = ai_analysis.get("threat_type")

        for item in combined:
            sev = item.get("severity", "INFO")
            if severity_rank.get(sev, 0) > severity_rank.get(max_sev, 0):
                max_sev = sev
            if item.get("indicator"):
                indicators_set.add(item["indicator"])
            for m in item.get("mitre", []):
                mitre_set.add(m)
            if not inferred_type and item.get("threat_type"):
                inferred_type = item["threat_type"]

        ai_sev = str(ai_analysis.get("severity", "INFO")).upper()
        if severity_rank.get(ai_sev, 0) > severity_rank.get(max_sev, 0):
            max_sev = ai_sev

        affected = list(ai_analysis.get("affected_systems", []))
        if not affected:
            host_match = re.search(r"host=([a-zA-Z0-9._-]+)", clean_log)
            if host_match:
                affected = [host_match.group(1)]
            else:
                sshd_host = re.search(r"^\w+\s+\d+\s+[\d:]+\s+([a-zA-Z0-9._-]+)\s+", clean_log)
                if sshd_host:
                    affected = [sshd_host.group(1)]

        base_conf = float(ai_analysis.get("confidence_score", 0.72 if rule_matches else 0.55))
        if rule_matches or intel_matches:
            base_conf = min(round(base_conf + 0.2, 2), 1.0)

        remediation = list(ai_analysis.get("recommended_actions", [])) or self._default_remediation(
            max_sev, rule_matches
        )
        src_ip = self._extract_ip(clean_log, (r"from\s+(\d+\.\d+\.\d+\.\d+)", r"src[=:](\d+\.\d+\.\d+\.\d+)"))
        dst_ip = self._extract_ip(clean_log, (r"to\s+(\d+\.\d+\.\d+\.\d+)", r"dst[=:](\d+\.\d+\.\d+\.\d+)"))

        alert_id = (
            f"THREAT-{datetime.now().strftime('%Y%m%d-%H%M%S')}-"
            f"{hashlib.md5(clean_log.encode()).hexdigest()[:8]}"
        )
        return ThreatAlert(
            alert_id=alert_id,
            timestamp=datetime.now().isoformat(),
            threat_type=inferred_type or "ANOMALOUS_BEHAVIOR",
            severity=max_sev,
            confidence=base_conf,
            source_ip=src_ip,
            destination_ip=dst_ip,
            affected_systems=affected,
            indicators=sorted(indicators_set),
            mitre_techniques=sorted(mitre_set),
            raw_logs=[clean_log],
            analysis={"deterministic_matches": combined, "ai_analysis": ai_analysis, "source": log_source},
            remediation_steps=remediation,
            false_positive_probability=float(ai_analysis.get("false_positive_likelihood", 0.15 if rule_matches else 0.35)),
        )

    def _extract_ip(self, text: str, patterns: Tuple[str, ...]) -> Optional[str]:
        for pat in patterns:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                return m.group(1)
        return None

    def _default_remediation(self, severity: str, rule_matches: List[Dict[str, Any]]) -> List[str]:
        steps: List[str] = []
        if severity == "CRITICAL":
            steps.extend(["Isolate affected host from production network", "Capture volatile memory & process tree"])
        elif severity == "HIGH":
            steps.extend(["Review authentication & session logs on target host", "Block malicious source indicator"])
        for m in rule_matches:
            if m.get("rule") == "brute_force":
                steps.append("Enforce MFA and temporary source IP rate-limiting")
            elif m.get("rule") == "malicious_command":
                steps.append("Terminate encoded shell process and inspect parent binary")
        return sorted(set(steps))

    async def process_log_batch(self, log_entries: List[Dict[str, str]]) -> List[ThreatAlert]:
        tasks = [
            self.analyze_log_entry(entry.get("message", ""), entry.get("source", "syslog"))
            for entry in log_entries
        ]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]

    async def run(self, logs: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]:
        batch = logs if logs is not None else DEFAULT_SAMPLE_LOGS
        alerts = await self.process_log_batch(batch)
        return {
            "processed_logs": len(batch),
            "threats_detected": len(alerts),
            "alerts": [asdict(a) for a in alerts],
        }


ThreatAgent = ThreatDetectionAgent

if __name__ == "__main__":
    print(json.dumps(asyncio.run(ThreatDetectionAgent().run()), indent=2))
