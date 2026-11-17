# AI SOC Autonomous Agents

[![CI/CD Pipeline](https://github.com/lawaleladipo/ai-soc-autonomous-agents/actions/workflows/ci.yaml/badge.svg)](https://github.com/lawaleladipo/ai-soc-autonomous-agents/actions)
![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-Microservice-009688)
![License](https://img.shields.io/badge/License-MIT-green)

**AI SOC Autonomous Agents** is an API-key-protected **FastAPI SecOps microservice** that replaces the brittle "single mega-prompt chatbot" pattern with **five narrow, single-responsibility security agents** surrounded by deterministic guardrails, maintenance-window false-positive suppression, asset-inventory risk matrices, and offline fallback scorers.

---

## Architecture

```text
                       +-----------------------------------+
                       |   FastAPI Gateway (app.py)        |
                       |   Constant-Time Key Auth + Sanit. |
                       +-----------------+-----------------+
                                         |
       +----------------+----------------+----------------+----------------+
       |                |                |                |                |
       v                v                v                v                v
+-------------+  +-------------+  +-------------+  +-------------+  +-------------+
| /triage/run |  | /threat/run |  |  /hunt/run  |  |  /cve/run   |  |  /doc/run   |
| AlertTriage |  |   Threat    |  |   Threat    |  |  CVE + KEV  |  |  Incident   |
|    Agent    |  |  Detection  |  |   Hunting   |  |  Inventory  |  |  MD/HTML/   |
|             |  |    Agent    |  |    Agent    |  |    Agent    |  |  PDF Agent  |
+------+------+  +------+------+  +------+------+  +------+------+  +------+------+
       |                |                |                |                |
       +----------------+----------------+----------------+----------------+
                                         |
                                         v
             +-------------------------------------------------------+
             | /pipeline/investigate (Restraint-Gated Orchestrator)  |
             | Logs -> Threat Detection -> Triage (Window + Matrix)  |
             | -> [Only if P1/P2 & FP <= 0.7] MITRE Hunt -> PDF/MD   |
             +-------------------------------------------------------+
```

---

## Bounded Specialist Agents

1. **Threat Detection Agent (`POST /threat/run`):** Combines deterministic regex rules (Base64 PowerShell `-enc`, `curl | sh`, reverse shells, SSH brute-force, archive staging), untrusted CIDR checks, and IoC lookups—boosting confidence only when deterministic indicators corroborate the LLM.
2. **Alert Triage Agent (`POST /triage/run`):** Evaluates cross-midnight backup/maintenance windows (`23:00–01:00`, `02:00–04:00`), allowlisted scanners, `(technical_severity × business_impact)` `P1–P5` priority matrices, SLA clocks (`1h` to `168h`), and specialization + queue-capacity analyst routing.
3. **Threat Hunting Agent (`POST /hunt/run`):** Executes structured MITRE ATT&CK hypotheses (`T1021.002` SMB fan-out, `T1134` token manipulation, `T1053.005` scheduled tasks, `T1071.004` DNS tunneling, `T1003` LSASS credential dumping) with MD5 event deduplication and pivot correlation.
4. **CVE & CISA KEV Prioritization Agent (`POST /cve/run`):** Cross-references live **NVD v2.0** + **CISA Known Exploited Vulnerabilities (KEV)** feeds against actual `system_inventory` so an actively exploited flaw on software you run outranks a theoretical `CVSS 9.8` on software you don't.
5. **Incident Documentation Agent (`POST /doc/run`):** Renders audience-separated `EXECUTIVE_SUMMARY`, `TECHNICAL_ANALYSIS`, `FORENSIC_SUMMARY`, and `INCIDENT_REPORT` packages into **Markdown, HTML, JSON, and styled A4 PDF** (`ReportLab`).
6. **End-to-End Restraint Pipeline (`POST /pipeline/investigate`):** Chains Detection → Triage → conditional Threat Hunting → Incident Report generation, automatically halting before hunting when Triage classifies an event as benign maintenance/scanner activity.

---

## Quick Start

```bash
git clone https://github.com/lawaleladipo/ai-soc-autonomous-agents.git
cd ai-soc-autonomous-agents
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env
```

> **Works Offline Out of the Box:** Set `GROQ_API_KEY` in `.env` to enable live `llama-3.3-70b-versatile` (`temperature=0.1`) JSON reasoning, or run immediately without an API key using each agent's built-in deterministic fallback engine.

### Start the API Server

```bash
export API_KEY="dev-local-soc-key"
.venv/bin/uvicorn app:app --reload --port 8000
```

### Example API Calls

```bash
# 1. Health & capability check
curl -s http://127.0.0.1:8000/health | jq

# 2. Run End-to-End Coordinated Investigation Pipeline
curl -s -X POST http://127.0.0.1:8000/pipeline/investigate \
  -H "X-API-Key: dev-local-soc-key" \
  -H "Content-Type: application/json" \
  -d '{}' | jq

# 3. Prioritize CVEs (pass {"fetch_live": true} to query NVD v2.0 + CISA KEV live)
curl -s -X POST http://127.0.0.1:8000/cve/run \
  -H "X-API-Key: dev-local-soc-key" \
  -H "Content-Type: application/json" \
  -d '{"fetch_live": false}' | jq
```

---

## Running Tests & Linter

```bash
.venv/bin/pytest -q
.venv/bin/flake8 app.py agents config utils tests --max-line-length=127
```

## Author & License

Built by **Olawale Oladipo** ([GitHub](https://github.com/lawaleladipo) · [Medium](https://medium.com/@lawaleladipo) · [LinkedIn](https://www.linkedin.com/in/olawale-oladipo-cybersecurity/)).  
Released under the [MIT License](LICENSE).
