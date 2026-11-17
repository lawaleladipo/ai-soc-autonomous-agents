"""
AI SOC Autonomous Agents — FastAPI Gateway & Multi-Agent Investigation Orchestrator.

Exposes five bounded specialist agents (/cve/run, /threat/run, /triage/run, /hunt/run, /doc/run)
plus an end-to-end coordinated pipeline (/pipeline/investigate) that suppresses maintenance/scanner
false positives before launching proactive MITRE ATT&CK hunts and executive/forensic documentation.
"""

from datetime import datetime
import secrets
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from agents import (
    AlertTriageAgent,
    CVEAgent,
    DocumentationAgent,
    DocumentType,
    IncidentData,
    ThreatDetectionAgent,
    ThreatHuntingAgent,
)
from config.settings import Settings
from utils.logger import get_logger

logger = get_logger("AI-SOC-Gateway")
settings = Settings()

app = FastAPI(
    title="AI SOC Autonomous Agents",
    version="1.0.0",
    description="Bounded multi-agent SecOps microservice with deterministic priority matrices, "
    "maintenance-window FP suppression, asset-aware CVE/KEV scoring, and end-to-end orchestration.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


def require_api_key(
    api_key: Optional[str] = Header(default=None, alias="api-key"),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> str:
    provided = api_key or x_api_key or ""
    expected = Settings().API_KEY
    if not provided or not secrets.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return provided


class CVERunRequest(BaseModel):
    cves: Optional[List[Dict[str, Any]]] = None
    fetch_live: bool = False


class ThreatRunRequest(BaseModel):
    logs: Optional[List[Dict[str, str]]] = None


class TriageRunRequest(BaseModel):
    alerts: Optional[List[Dict[str, Any]]] = None


class HuntRunRequest(BaseModel):
    hypothesis_key: str = "lateral_movement_smb"
    events: Optional[List[Dict[str, Any]]] = None


class DocRunRequest(BaseModel):
    incident: Optional[Dict[str, Any]] = None
    document_type: str = "INCIDENT_REPORT"
    persist_files: bool = True


class InvestigatePipelineRequest(BaseModel):
    logs: List[Dict[str, str]] = Field(
        default_factory=lambda: [
            {
                "message": "2025-08-14 11:15:22 [WARN] host=payment-gateway user=admin executed: "
                "powershell.exe -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwA= from 185.220.101.45",
                "source": "edr.log",
            }
        ]
    )
    telemetry_events: Optional[List[Dict[str, Any]]] = None
    persist_reports: bool = False


@app.get("/health")
async def health_check() -> Dict[str, Any]:
    cfg = Settings()
    return {
        "status": "ok",
        "service": "AI SOC Autonomous Agents",
        "version": "1.0.0",
        "llm_configured": bool(cfg.GROQ_API_KEY),
        "llm_model": cfg.GROQ_MODEL,
        "agents": ["cve", "threat", "triage", "hunt", "doc", "pipeline"],
    }


@app.post("/cve/run")
async def run_cve_agent(
    payload: CVERunRequest = CVERunRequest(),
    _auth: str = Depends(require_api_key),
) -> Dict[str, Any]:
    agent = CVEAgent()
    return await agent.run(cves=payload.cves, fetch_live=payload.fetch_live)


@app.post("/threat/run")
async def run_threat_agent(
    payload: ThreatRunRequest = ThreatRunRequest(),
    _auth: str = Depends(require_api_key),
) -> Dict[str, Any]:
    agent = ThreatDetectionAgent()
    return await agent.run(logs=payload.logs)


@app.post("/triage/run")
async def run_triage_agent(
    payload: TriageRunRequest = TriageRunRequest(),
    _auth: str = Depends(require_api_key),
) -> Dict[str, Any]:
    agent = AlertTriageAgent()
    return await agent.run(alerts=payload.alerts)


@app.post("/hunt/run")
async def run_hunt_agent(
    payload: HuntRunRequest = HuntRunRequest(),
    _auth: str = Depends(require_api_key),
) -> Dict[str, Any]:
    agent = ThreatHuntingAgent()
    try:
        return await agent.run(hypothesis_key=payload.hypothesis_key, events=payload.events)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/doc/run")
async def run_doc_agent(
    payload: DocRunRequest = DocRunRequest(),
    _auth: str = Depends(require_api_key),
) -> Dict[str, Any]:
    agent = DocumentationAgent()
    return await agent.run(
        incident=payload.incident,
        document_type=payload.document_type,
        persist_files=payload.persist_files,
    )


@app.post("/pipeline/investigate")
async def run_investigation_pipeline(
    payload: InvestigatePipelineRequest = InvestigatePipelineRequest(),
    _auth: str = Depends(require_api_key),
) -> Dict[str, Any]:
    """
    End-to-end coordinated SOC workflow:
    1. ThreatDetectionAgent extracts alerts, MITRE techniques & IoCs from raw logs.
    2. AlertTriageAgent evaluates maintenance/scanner FP suppression, business impact & analyst routing.
    3. Restraint Gate: Only escalated P1/P2 alerts with FP probability <= 0.7 trigger ThreatHuntingAgent
       and full Incident Report generation — preventing noisy cascades on benign maintenance events.
    """
    threat_agent = ThreatDetectionAgent()
    triage_agent = AlertTriageAgent()
    hunt_agent = ThreatHuntingAgent()
    doc_agent = DocumentationAgent()

    detected = await threat_agent.process_log_batch(payload.logs)
    if not detected:
        return {
            "pipeline_status": "clean_no_threats",
            "logs_evaluated": len(payload.logs),
            "alerts_detected": 0,
            "hunts_executed": [],
            "incident_reports": [],
        }

    triage_inputs = [
        {
            "alert_id": a.alert_id,
            "alert_type": a.threat_type,
            "severity": a.severity,
            "source_ip": a.source_ip,
            "affected_systems": a.affected_systems,
            "description": f"{a.threat_type} ({', '.join(a.mitre_techniques)}): {' '.join(a.raw_logs)}",
            "timestamp": a.timestamp,
        }
        for a in detected
    ]
    triaged = await triage_agent.batch_triage(triage_inputs)

    hunts_executed: List[Dict[str, Any]] = []
    reports_generated: List[Dict[str, Any]] = []

    for alert_obj, triage_res in zip(detected, triaged):
        if not triage_res.escalation_required or triage_res.false_positive_probability > 0.7:
            continue

        hyp_key = hunt_agent.select_hypothesis_for_alert(triage_res.original_alert)
        hunt_res = await hunt_agent.execute_hunt(
            hypothesis_key=hyp_key, events=payload.telemetry_events
        )
        hunts_executed.append(
            {
                "triggered_by_alert": triage_res.alert_id,
                "hypothesis_key": hyp_key,
                "findings_count": len(hunt_res.findings),
                "iocs_discovered": hunt_res.iocs_discovered,
            }
        )

        combined_mitre = sorted(set(alert_obj.mitre_techniques + hunt_res.mitre_mappings))
        combined_iocs = sorted(set(alert_obj.indicators + hunt_res.iocs_discovered))
        combined_hosts = sorted(set(alert_obj.affected_systems + hunt_res.affected_systems))

        incident = IncidentData(
            incident_id=f"INC-{triage_res.alert_id[-8:]}",
            title=f"{alert_obj.threat_type} on {', '.join(combined_hosts) or 'Enterprise Host'}",
            description=triage_res.ai_summary,
            severity=triage_res.technical_severity,
            status="OPEN_ESCALATED",
            detection_time=alert_obj.timestamp,
            containment_time=None,
            resolution_time=None,
            affected_systems=combined_hosts,
            attack_vectors=[alert_obj.threat_type],
            mitre_techniques=combined_mitre,
            iocs=combined_iocs,
            timeline=[
                {"timestamp": alert_obj.timestamp, "description": raw}
                for raw in alert_obj.raw_logs
            ]
            + [
                {
                    "timestamp": str(f.get("timestamp", datetime.now().isoformat())),
                    "description": f"Hunt {hyp_key} matched {f.get('query_matched')}",
                }
                for f in hunt_res.findings[:5]
            ],
            evidence=[{"type": "log_and_hunt_correlation", "alert_id": alert_obj.alert_id}],
            impact_assessment={
                "business_impact": triage_res.business_impact,
                "data_compromise": "Under active investigation",
            },
            response_actions=triage_res.recommended_actions,
            lessons_learned=["Automated multi-agent triage + hypothesis hunt completed"],
            recommendations=hunt_res.recommendations,
        )
        doc = await doc_agent.generate_incident_report(
            incident,
            document_type=DocumentType.INCIDENT_REPORT,
            persist_files=payload.persist_reports,
        )
        reports_generated.append(doc)

    return {
        "pipeline_status": "escalated" if hunts_executed else "triaged_suppressed",
        "logs_evaluated": len(payload.logs),
        "alerts_detected": len(detected),
        "triage_results": [
            {
                "alert_id": t.alert_id,
                "priority": t.priority,
                "false_positive_probability": t.false_positive_probability,
                "escalation_required": t.escalation_required,
                "assigned_analyst": t.assigned_analyst,
                "sla_deadline": t.sla_deadline,
            }
            for t in triaged
        ],
        "hunts_executed": hunts_executed,
        "incident_reports": reports_generated,
    }
