# app.py
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from agents import cve_agent, threat_agent, triage_agent, hunt_agent, doc_agent
import os
from dotenv import load_dotenv
import logging

# Load .env
load_dotenv()

API_KEY = os.getenv("API_KEY", "supersecret1")

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AI-SOC")

# FastAPI app
app = FastAPI(title="AI SOC Autonomous Agents")

# Allow all origins (optional, for dashboard testing)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Helper: API key check
def verify_api_key(api_key: str):
    if api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")


# ======================
# CVE Agent Endpoint
# ======================
@app.post("/cve/run")
def run_cve_agent(api_key: str = Header(...)):
    verify_api_key(api_key)
    agent = cve_agent.CVEAgent()
    result = agent.run()
    return result


# ======================
# Threat Agent Endpoint
# ======================
@app.post("/threat/run")
def run_threat_agent(api_key: str = Header(...)):
    verify_api_key(api_key)
    agent = threat_agent.ThreatAgent()
    result = agent.run()
    return result


# ======================
# Triage Agent Endpoint
# ======================
@app.post("/triage/run")
def run_triage_agent(api_key: str = Header(...)):
    verify_api_key(api_key)
    agent = triage_agent.TriageAgent()
    result = agent.run()
    return result


# ======================
# Hunt Agent Endpoint
# ======================
@app.post("/hunt/run")
def run_hunt_agent(api_key: str = Header(...)):
    verify_api_key(api_key)
    agent = hunt_agent.HuntAgent()
    result = agent.run()
    return result


# ======================
# Documentation Agent Endpoint
# ======================
@app.post("/doc/run")
def run_doc_agent(api_key: str = Header(...)):
    verify_api_key(api_key)
    agent = doc_agent.DocAgent()
    result = agent.run()
    return result


# ======================
# Health Check
# ======================
@app.get("/health")
def health_check():
    return {"status": "ok", "message": "AI SOC API is running"}
