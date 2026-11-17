#!/usr/bin/env python3
"""
Documentation Agent — Multi-Audience Incident Reporting (Markdown, HTML, JSON & A4 PDF).
Generates tailored Executive, Technical, Forensic, and Full Incident Post-Mortem packages.
"""

import asyncio
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
from io import BytesIO
import json
from typing import Any, Dict, List, Optional

from jinja2 import Template
import markdown
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from config.settings import Settings
from utils.llm_helper import call_groq_json
from utils.logger import get_logger

logger = get_logger(__name__)
settings = Settings()


class DocumentType(Enum):
    INCIDENT_REPORT = "INCIDENT_REPORT"
    EXECUTIVE_SUMMARY = "EXECUTIVE_SUMMARY"
    TECHNICAL_ANALYSIS = "TECHNICAL_ANALYSIS"
    FORENSIC_SUMMARY = "FORENSIC_SUMMARY"


@dataclass
class IncidentData:
    incident_id: str
    title: str
    description: str
    severity: str
    status: str
    detection_time: str
    containment_time: Optional[str]
    resolution_time: Optional[str]
    affected_systems: List[str]
    attack_vectors: List[str]
    mitre_techniques: List[str]
    iocs: List[str]
    timeline: List[Dict[str, Any]]
    evidence: List[Dict[str, Any]]
    impact_assessment: Dict[str, Any]
    response_actions: List[str]
    lessons_learned: List[str]
    recommendations: List[str]


@dataclass
class DocumentMetadata:
    document_id: str
    document_type: str
    title: str
    author: str
    created_date: str
    version: str
    classification: str


MITRE_DESCRIPTIONS: Dict[str, str] = {
    "T1190": "Exploit Public-Facing Application",
    "T1110": "Brute Force",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1134": "Access Token Manipulation",
    "T1003": "OS Credential Dumping",
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1071.004": "Application Layer Protocol: DNS",
    "T1048": "Exfiltration Over Alternative Protocol",
}

INCIDENT_MARKDOWN_TEMPLATE = """# {{ metadata.title }}

- **Incident ID:** `{{ incident.incident_id }}`
- **Classification:** `{{ metadata.classification }}`
- **Severity / Status:** `{{ incident.severity }}` / `{{ incident.status }}`
- **Generated:** `{{ metadata.created_date }}`

## Executive Summary
{{ ai_analysis.executive_summary }}

## Technical Analysis
{{ ai_analysis.technical_details }}

## Affected Systems
{% for sys in incident.affected_systems %}- `{{ sys }}`
{% endfor %}

## MITRE ATT&CK Coverage
{% for tech in incident.mitre_techniques %}- **{{ tech }}** — {{ mitre_descriptions.get(tech, "Mapped Technique") }}
{% endfor %}

## Indicators of Compromise (IoCs)
{% for ioc in incident.iocs %}- `{{ ioc }}`
{% endfor %}

## Chronological Timeline
{% for ev in incident.timeline %}- **{{ ev.timestamp }}** — {{ ev.description }}
{% endfor %}

## Containment & Remediation Actions
{% for act in incident.response_actions %}- {{ act }}
{% endfor %}

## Engineering Recommendations
{% for rec in incident.recommendations %}- {{ rec }}
{% endfor %}
"""


def default_sample_incident() -> IncidentData:
    now = datetime.now().isoformat()
    return IncidentData(
        incident_id="INC-2025-0814",
        title="Encoded PowerShell Execution & Credential Dumping Attempt on Payment Gateway",
        description="High-confidence encoded PowerShell followed by LSASS dump attempt contained prior to exfiltration.",
        severity="CRITICAL",
        status="CONTAINED",
        detection_time=now,
        containment_time=now,
        resolution_time=None,
        affected_systems=["payment-gateway"],
        attack_vectors=["Compromised administrative SSH/WinRM session"],
        mitre_techniques=["T1059.001", "T1003.001", "T1021.002"],
        iocs=["ip:185.220.101.45", "process:powershell.exe", "process:procdump.exe"],
        timeline=[
            {"timestamp": "2025-08-14T10:30:00", "description": "Repeated SSH authentication failures from 185.220.101.45"},
            {"timestamp": "2025-08-14T11:15:22", "description": "Encoded PowerShell (-enc) executed on payment-gateway"},
            {"timestamp": "2025-08-14T11:17:00", "description": "LSASS memory dump attempt blocked and host isolated"},
        ],
        evidence=[{"type": "edr_process_tree", "source": "edr.log"}],
        impact_assessment={
            "business_impact": "HIGH — PCI-DSS scoped host isolated; zero confirmed cardholder exfiltration",
            "data_compromise": "None confirmed",
        },
        response_actions=[
            "Isolated payment-gateway from east-west SMB segments",
            "Revoked active administrative tokens and rotated credentials",
        ],
        lessons_learned=["Enforce hardware-backed MFA on all jump-host administrative paths"],
        recommendations=[
            "Deploy ASR / Custom IOA rule blocking procdump/rundll32 access to lsass.exe",
            "Restrict east-west TCP/445 between payment-gateway and peer subnets",
        ],
    )


class DocumentationAgent:
    """Generates structured Markdown, HTML, JSON, and A4 PDF incident documentation."""

    def __init__(self):
        self.styles = self._init_pdf_styles()

    def _init_pdf_styles(self):
        styles = getSampleStyleSheet()
        styles.add(
            ParagraphStyle(
                "IncidentTitle",
                parent=styles["Title"],
                fontSize=16,
                alignment=TA_CENTER,
                textColor=colors.HexColor("#1B365D"),
                spaceAfter=18,
            )
        )
        return styles

    async def _generate_ai_narrative(
        self, incident: IncidentData, doc_type: DocumentType
    ) -> Dict[str, Any]:
        prompt = (
            f"Generate a {doc_type.value} narrative in JSON for incident {incident.incident_id}:\n"
            f"Title: {incident.title}\nSeverity: {incident.severity}\n"
            f"Affected Systems: {incident.affected_systems}\n"
            f"MITRE: {incident.mitre_techniques}\nIoCs: {incident.iocs}\n"
            "Return JSON keys: executive_summary (string), technical_details (string)."
        )
        ai = call_groq_json(
            "You are a principal incident response technical writer. Be factual, concise, and audit-ready.",
            prompt,
            max_tokens=1000,
        )
        if ai and ai.get("executive_summary"):
            return ai

        return {
            "executive_summary": (
                f"Incident {incident.incident_id} ({incident.severity}) affected "
                f"{len(incident.affected_systems)} system(s) ({', '.join(incident.affected_systems)}). "
                f"Current status is {incident.status}. {incident.description}"
            ),
            "technical_details": (
                f"Observed tradecraft mapped to {', '.join(incident.mitre_techniques) or 'N/A'} "
                f"across {len(incident.timeline)} timeline event(s) and {len(incident.iocs)} IoC(s)."
            ),
        }

    def _render_markdown(
        self, incident: IncidentData, metadata: DocumentMetadata, ai_analysis: Dict[str, Any]
    ) -> str:
        tmpl = Template(INCIDENT_MARKDOWN_TEMPLATE)
        return tmpl.render(
            incident=incident,
            metadata=metadata,
            ai_analysis=ai_analysis,
            mitre_descriptions=MITRE_DESCRIPTIONS,
        )

    def _render_html(self, md_text: str, metadata: DocumentMetadata) -> str:
        body = markdown.markdown(md_text, extensions=["tables"])
        return (
            "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
            f"<title>{metadata.title}</title>"
            "<style>body{font-family:system-ui,sans-serif;max-width:860px;margin:32px auto;line-height:1.55;}"
            "code{background:#f3f4f6;padding:2px 5px;border-radius:4px;}</style>"
            f"</head><body>{body}</body></html>"
        )

    def _render_pdf_bytes(
        self, incident: IncidentData, metadata: DocumentMetadata, ai_analysis: Dict[str, Any]
    ) -> bytes:
        buf = BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=54, rightMargin=54, topMargin=54, bottomMargin=54)
        story: List[Any] = [
            Paragraph(metadata.title, self.styles["IncidentTitle"]),
            Spacer(1, 0.15 * inch),
        ]

        rows = [
            ["Incident ID", incident.incident_id],
            ["Severity / Status", f"{incident.severity} / {incident.status}"],
            ["Classification", metadata.classification],
            ["Affected Systems", ", ".join(incident.affected_systems) or "N/A"],
            ["MITRE ATT&CK", ", ".join(incident.mitre_techniques) or "N/A"],
        ]
        table = Table(rows, colWidths=[1.8 * inch, 4.4 * inch])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E5E7EB")),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#9CA3AF")),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("PADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        story.extend([table, Spacer(1, 0.2 * inch)])
        story.append(Paragraph("Executive Summary", self.styles["Heading2"]))
        story.append(Paragraph(str(ai_analysis.get("executive_summary", "")), self.styles["Normal"]))
        story.append(Spacer(1, 0.15 * inch))
        story.append(Paragraph("Technical Analysis", self.styles["Heading2"]))
        story.append(Paragraph(str(ai_analysis.get("technical_details", "")), self.styles["Normal"]))
        doc.build(story)
        return buf.getvalue()

    async def generate_incident_report(
        self,
        incident_data: IncidentData,
        document_type: DocumentType = DocumentType.INCIDENT_REPORT,
        persist_files: bool = True,
    ) -> Dict[str, Any]:
        now_str = datetime.now().strftime("%Y%m%d-%H%M%S")
        metadata = DocumentMetadata(
            document_id=f"DOC-{incident_data.incident_id}-{now_str}",
            document_type=document_type.value,
            title=f"{document_type.value.replace('_', ' ').title()}: {incident_data.title}",
            author="AI Documentation Agent",
            created_date=datetime.now().isoformat(),
            version="1.0",
            classification="CONFIDENTIAL",
        )
        ai_analysis = await self._generate_ai_narrative(incident_data, document_type)
        md_content = self._render_markdown(incident_data, metadata, ai_analysis)
        html_content = self._render_html(md_content, metadata)
        pdf_bytes = self._render_pdf_bytes(incident_data, metadata, ai_analysis)

        saved_files: List[str] = []
        if persist_files:
            out_dir = settings.DATA_DIR / "reports"
            out_dir.mkdir(parents=True, exist_ok=True)
            base = out_dir / metadata.document_id
            md_path = f"{base}.md"
            html_path = f"{base}.html"
            pdf_path = f"{base}.pdf"
            json_path = f"{base}.json"

            with open(md_path, "w", encoding="utf-8") as f:
                f.write(md_content)
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            with open(pdf_path, "wb") as f:
                f.write(pdf_bytes)
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "metadata": asdict(metadata),
                        "incident": asdict(incident_data),
                        "ai_analysis": ai_analysis,
                    },
                    f,
                    indent=2,
                )
            saved_files = [md_path, html_path, pdf_path, json_path]

        return {
            "status": "success",
            "document_id": metadata.document_id,
            "document_type": document_type.value,
            "pdf_size_bytes": len(pdf_bytes),
            "files_generated": saved_files,
            "executive_summary": ai_analysis["executive_summary"],
            "markdown_preview": md_content[:1200],
        }

    async def run(
        self,
        incident: Optional[Dict[str, Any]] = None,
        document_type: str = "INCIDENT_REPORT",
        persist_files: bool = True,
    ) -> Dict[str, Any]:
        if incident:
            base = asdict(default_sample_incident())
            base.update(incident)
            inc_obj = IncidentData(**base)
        else:
            inc_obj = default_sample_incident()

        dtype = (
            DocumentType[document_type.upper()]
            if document_type.upper() in DocumentType.__members__
            else DocumentType.INCIDENT_REPORT
        )
        return await self.generate_incident_report(
            inc_obj, document_type=dtype, persist_files=persist_files
        )


DocAgent = DocumentationAgent

if __name__ == "__main__":
    print(json.dumps(asyncio.run(DocumentationAgent().run()), indent=2))
