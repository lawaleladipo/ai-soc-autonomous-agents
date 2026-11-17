from datetime import time
from fastapi.testclient import TestClient

from agents.triage_agent import AlertTriageAgent
from app import app
from config.settings import Settings
from utils.security import is_time_in_window

client = TestClient(app)
AUTH_HEADERS = {"X-API-Key": Settings().API_KEY}


def test_cross_midnight_backup_window_math():
    # 23:30 and 00:30 MUST both match 23:00 -> 01:00; 14:00 must not
    assert is_time_in_window(time(23, 30), "23:00", "01:00")
    assert is_time_in_window(time(0, 30), "23:00", "01:00")
    assert not is_time_in_window(time(14, 0), "23:00", "01:00")


def test_health_and_api_key_enforcement():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"

    unauth = client.post("/triage/run", json={})
    assert unauth.status_code == 401


def test_inventory_matched_kev_outranks_uninstalled_critical_cve():
    # CVE-2024-6387 (CVSS 8.1, KEV=True, matches ubuntu/openssh in inventory)
    # vs CVE-2024-50603 (CVSS 9.8, KEV=True, aviatrix NOT in inventory)
    resp = client.post("/cve/run", headers=AUTH_HEADERS, json={"fetch_live": False})
    assert resp.status_code == 200
    ranked = resp.json()["prioritized_cves"]
    assert ranked[0]["cve_id"] == "CVE-2024-6387"
    assert len(ranked[0]["affected_systems"]) > 0
    assert ranked[-1]["cve_id"] == "CVE-2024-50603"


def test_triage_suppresses_scanner_during_cross_midnight_backup_window():
    resp = client.post(
        "/triage/run",
        headers=AUTH_HEADERS,
        json={
            "alerts": [
                {
                    "alert_id": "FP-MIDNIGHT-01",
                    "alert_type": "port_scan",
                    "severity": "MEDIUM",
                    "source_system": "vulnerability-scanner",
                    "description": "Automated backup process and scheduled maintenance check",
                    "affected_systems": ["staging-box-1"],
                    "timestamp": "2025-08-14T23:45:00",
                }
            ]
        },
    )
    assert resp.status_code == 200
    res = resp.json()["results"][0]
    assert res["false_positive_probability"] >= 0.75
    assert res["escalation_required"] is False
    assert res["priority"] in ("P4_LOW", "P5_INFO")


def test_analyst_routing_respects_specialization_and_capacity():
    triage = AlertTriageAgent()
    triage.analyst_workload["analysts"]["alice"]["current_alerts"] = 8  # At max capacity (8)
    chosen = triage._suggest_analyst({"alert_type": "malware_detection", "description": "malware"})
    # Alice specializes in malware but is at max capacity -> falls back to lowest queue (charlie=2)
    assert chosen == "charlie"


def test_doc_agent_renders_markdown_html_and_pdf():
    resp = client.post(
        "/doc/run",
        headers=AUTH_HEADERS,
        json={"document_type": "INCIDENT_REPORT", "persist_files": False},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "success"
    assert body["pdf_size_bytes"] > 500


def test_end_to_end_investigation_pipeline_escalates_real_attack():
    resp = client.post(
        "/pipeline/investigate",
        headers=AUTH_HEADERS,
        json={"persist_reports": False},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["pipeline_status"] == "escalated"
    assert data["alerts_detected"] == 1
    assert data["triage_results"][0]["priority"] == "P1_CRITICAL"
    assert len(data["hunts_executed"]) == 1
    assert len(data["incident_reports"]) == 1
