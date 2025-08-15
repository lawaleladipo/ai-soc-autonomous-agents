last_modified=datetime.now().isoformat(),
                version="1.0",
                classification="CONFIDENTIAL",
                distribution="INTERNAL",
                retention_period="7 years"
            )
            
            # Generate different document formats
            documents = {}
            
            # Generate Markdown document
            markdown_doc = await self._generate_markdown_document(incident_data, metadata, ai_analysis, document_type)
            documents['markdown'] = markdown_doc
            
            # Generate PDF document
            pdf_doc = await self._generate_pdf_document(incident_data, metadata, ai_analysis, document_type)
            documents['pdf'] = pdf_doc
            
            # Generate JSON structured data
            json_doc = await self._generate_json_document(incident_data, metadata, ai_analysis, document_type)
            documents['json'] = json_doc
            
            # Generate HTML document
            html_doc = await self._generate_html_document(incident_data, metadata, ai_analysis, document_type)
            documents['html'] = html_doc
            
            # Save documents
            saved_files = await self._save_documents(documents, metadata)
            
            result = {
                "status": "success",
                "document_id": metadata.document_id,
                "document_type": document_type.value,
                "files_generated": saved_files,
                "metadata": asdict(metadata),
                "ai_analysis_summary": ai_analysis.get('executive_summary', 'Analysis completed'),
                "generation_time": datetime.now().isoformat()
            }
            
            logger.info(f"Document generation completed: {metadata.document_id}")
            return result
            
        except Exception as e:
            logger.error(f"Document generation failed: {e}")
            return {
                "status": "error",
                "error": str(e),
                "incident_id": incident_data.incident_id
            }
    
    async def _generate_ai_analysis(self, incident_data: IncidentData, document_type: DocumentType) -> Dict[str, Any]:
        """
        Generate AI-powered analysis for the incident
        """
        try:
            # Prepare incident context for AI
            incident_context = {
                "incident_id": incident_data.incident_id,
                "title": incident_data.title,
                "severity": incident_data.severity,
                "affected_systems": incident_data.affected_systems,
                "attack_vectors": incident_data.attack_vectors,
                "mitre_techniques": incident_data.mitre_techniques,
                "timeline_events": len(incident_data.timeline),
                "iocs_count": len(incident_data.iocs),
                "evidence_pieces": len(incident_data.evidence)
            }
            
            # Create analysis prompt based on document type
            if document_type == DocumentType.EXECUTIVE_SUMMARY:
                prompt = self._create_executive_analysis_prompt(incident_data, incident_context)
            elif document_type == DocumentType.TECHNICAL_ANALYSIS:
                prompt = self._create_technical_analysis_prompt(incident_data, incident_context)
            elif document_type == DocumentType.FORENSIC_SUMMARY:
                prompt = self._create_forensic_analysis_prompt(incident_data, incident_context)
            else:
                prompt = self._create_comprehensive_analysis_prompt(incident_data, incident_context)
            
            response = self.groq_client.chat.completions.create(
                model="mixtral-8x7b-32768",
                messages=[
                    {"role": "system", "content": "You are an expert cybersecurity analyst and technical writer specializing in incident documentation and analysis."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=2000
            )
            
            analysis = json.loads(response.choices[0].message.content)
            logger.info(f"AI analysis generated for {document_type.value}")
            return analysis
            
        except Exception as e:
            logger.error(f"AI analysis generation failed: {e}")
            return {
                "executive_summary": "AI analysis unavailable - manual review required",
                "technical_details": "Technical analysis could not be generated automatically",
                "error": str(e)
            }
    
    def _create_comprehensive_analysis_prompt(self, incident_data: IncidentData, context: Dict) -> str:
        """Create comprehensive analysis prompt"""
        return f"""
        Analyze this security incident and provide comprehensive documentation analysis:
        
        Incident Details:
        {json.dumps(context, indent=2)}
        
        Timeline Summary:
        {json.dumps(incident_data.timeline[:5], indent=2, default=str)}
        
        Evidence Summary:  
        {json.dumps([e.get('type', 'unknown') for e in incident_data.evidence], indent=2)}
        
        IOCs:
        {incident_data.iocs[:10]}
        
        MITRE Techniques:
        {incident_data.mitre_techniques}
        
        Provide comprehensive JSON analysis with:
        1. executive_summary (2-3 paragraphs for leadership)
        2. technical_details (detailed technical analysis)
        3. attack_chain (step-by-step attack progression)
        4. threat_actor_profile (likely threat actor characteristics)
        5. business_impact (business impact assessment)
        6. current_status (current incident status)
        7. next_steps (prioritized next actions)
        8. resource_requirements (resources needed)
        9. timeline_analysis (analysis of attack timeline)
        10. evidence_assessment (quality and completeness of evidence)
        11. containment_effectiveness (assessment of containment actions)
        12. recovery_recommendations (recovery and restoration steps)
        13. prevention_measures (future prevention recommendations)
        14. compliance_implications (regulatory/compliance considerations)
        15. communication_points (key points for stakeholder communication)
        """
    
    def _create_executive_analysis_prompt(self, incident_data: IncidentData, context: Dict) -> str:
        """Create executive summary analysis prompt"""
        return f"""
        Create an executive-level analysis of this security incident:
        
        Incident: {incident_data.title}
        Severity: {incident_data.severity}
        Systems Affected: {len(incident_data.affected_systems)}
        Attack Vectors: {incident_data.attack_vectors}
        
        Provide executive-focused JSON analysis with:
        1. key_points (3-5 critical bullet points)
        2. business_impact (business impact in executive terms)
        3. current_status (current situation and response status)
        4. next_steps (key next actions for leadership awareness)
        5. resource_requirements (resource needs and budget implications)
        6. risk_assessment (ongoing risk to the organization)
        7. stakeholder_communication (communication strategy)
        8. timeline_for_resolution (expected resolution timeline)
        9. lessons_learned_preview (initial lessons learned)
        10. executive_decision_points (decisions needed from leadership)
        """
    
    def _create_technical_analysis_prompt(self, incident_data: IncidentData, context: Dict) -> str:
        """Create technical analysis prompt"""
        return f"""
        Provide deep technical analysis of this security incident:
        
        Technical Context:
        - MITRE Techniques: {incident_data.mitre_techniques}
        - IOCs: {len(incident_data.iocs)} indicators
        - Evidence: {len(incident_data.evidence)} pieces
        - Timeline Events: {len(incident_data.timeline)}
        
        Sample Timeline Events:
        {json.dumps(incident_data.timeline[:3], indent=2, default=str)}
        
        Sample Evidence:
        {json.dumps(incident_data.evidence[:3], indent=2, default=str)}
        
        Provide technical JSON analysis with:
        1. attack_chain (detailed attack progression)
        2. threat_actor_profile (TTP analysis and attribution)
        3. vulnerabilities_exploited (technical vulnerability analysis)
        4. lateral_movement (lateral movement techniques and paths)
        5. data_exfiltration (data exfiltration analysis)
        6. persistence_mechanisms (persistence techniques identified)
        7. evasion_techniques (defense evasion methods used)
        8. tools_and_malware (tools and malware analysis)
        9. network_indicators (network-based IOCs and patterns)
        10. host_indicators (host-based IOCs and artifacts)
        11. forensic_artifacts (key forensic evidence)
        12. technical_recommendations (technical remediation steps)
        """
    
    def _create_forensic_analysis_prompt(self, incident_data: IncidentData, context: Dict) -> str:
        """Create forensic analysis prompt"""
        return f"""
        Provide forensic analysis of this security incident:
        
        Forensic Context:
        - Evidence Pieces: {len(incident_data.evidence)}
        - Timeline Precision: {len(incident_data.timeline)} events
        - Affected Systems: {incident_data.affected_systems}
        
        Evidence Types Available:
        {json.dumps([e.get('type', 'unknown') for e in incident_data.evidence])}
        
        Provide forensic JSON analysis with:
        1. evidence_timeline (chronological evidence analysis)
        2. artifact_analysis (key artifacts and their significance)
        3. chain_of_custody (evidence handling assessment)
        4. forensic_gaps (gaps in evidence collection)
        5. attribution_evidence (evidence supporting attribution)
        6. reconstruction_confidence (confidence in event reconstruction)
        7. additional_evidence_needed (recommended additional evidence)
        8. forensic_methodology (methodology used in analysis)
        9. legal_considerations (legal and evidentiary considerations)
        10. expert_testimony_readiness (readiness for legal proceedings)
        """
    
    async def _generate_markdown_document(self, incident_data: IncidentData, metadata: DocumentMetadata, ai_analysis: Dict, document_type: DocumentType) -> str:
        """Generate Markdown document"""
        try:
            template_name = document_type.value.lower()
            if template_name not in self.templates:
                template_name = "incident_report"
            
            template = Template(self.templates[template_name])
            
            # Prepare template context
            context = {
                'incident': incident_data,
                'metadata': metadata,
                'ai_analysis': ai_analysis,
                'mitre_descriptions': self.mitre_mappings,
                'evidence_summary': self._generate_evidence_summary(incident_data.evidence),
                'supporting_docs': self._generate_supporting_docs_section(incident_data)
            }
            
            markdown_content = template.render(**context)
            return markdown_content
            
        except Exception as e:
            logger.error(f"Markdown generation failed: {e}")
            return f"# Document Generation Error\n\nError generating markdown: {str(e)}"
    
    async def _generate_pdf_document(self, incident_data: IncidentData, metadata: DocumentMetadata, ai_analysis: Dict, document_type: DocumentType) -> bytes:
        """Generate PDF document"""
        try:
            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
            
            # Build PDF content
            story = []
            
            # Title page
            story.extend(self._build_title_page(incident_data, metadata, ai_analysis))
            story.append(PageBreak())
            
            # Executive summary
            if ai_analysis.get('executive_summary'):
                story.extend(self._build_executive_summary_section(ai_analysis))
                story.append(PageBreak())
            
            # Main content sections
            story.extend(self._build_incident_overview_section(incident_data))
            story.extend(self._build_timeline_section(incident_data))
            story.extend(self._build_technical_analysis_section(incident_data, ai_analysis))
            story.extend(self._build_impact_assessment_section(incident_data))
            story.extend(self._build_response_actions_section(incident_data))
            story.extend(self._build_recommendations_section(incident_data))
            
            # Appendices
            story.append(PageBreak())
            story.extend(self._build_appendices(incident_data, ai_analysis))
            
            # Build PDF
            doc.build(story)
            pdf_content = buffer.getvalue()
            buffer.close()
            
            return pdf_content
            
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            return b"PDF generation failed"
    
    def _build_title_page(self, incident_data: IncidentData, metadata: DocumentMetadata, ai_analysis: Dict) -> List:
        """Build PDF title page"""
        story = []
        
        # Title
        title = Paragraph(metadata.title, self.styles['CustomTitle'])
        story.append(title)
        story.append(Spacer(1, 0.5*inch))
        
        # Incident details table
        incident_details = [
            ['Incident ID:', incident_data.incident_id],
            ['Classification:', metadata.classification],
            ['Severity:', incident_data.severity],
            ['Status:', incident_data.status],
            ['Generated:', metadata.created_date],
            ['Author:', metadata.author]
        ]
        
        details_table = Table(incident_details, colWidths=[2*inch, 4*inch])
        details_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(details_table)
        story.append(Spacer(1, 1*inch))
        
        # Critical alert if high severity
        if incident_data.severity in ['CRITICAL', 'HIGH']:
            alert_text = f"⚠️ {incident_data.severity} SEVERITY INCIDENT - IMMEDIATE ATTENTION REQUIRED"
            alert = Paragraph(alert_text, self.styles['CriticalAlert'])
            story.append(alert)
            story.append(Spacer(1, 0.5*inch))
        
        return story
    
    def _build_executive_summary_section(self, ai_analysis: Dict) -> List:
        """Build executive summary section"""
        story = []
        
        heading = Paragraph("Executive Summary", self.styles['CustomHeading1'])
        story.append(heading)
        story.append(Spacer(1, 0.2*inch))
        
        summary_text = ai_analysis.get('executive_summary', 'Executive summary not available')
        summary = Paragraph(summary_text, self.styles['Normal'])
        story.append(summary)
        story.append(Spacer(1, 0.3*inch))
        
        return story
    
    def _build_incident_overview_section(self, incident_data: IncidentData) -> List:
        """Build incident overview section"""
        story = []
        
        heading = Paragraph("Incident Overview", self.styles['CustomHeading1'])
        story.append(heading)
        story.append(Spacer(1, 0.2*inch))
        
        # Overview table
        overview_data = [
            ['Incident ID:', incident_data.incident_id],
            ['Title:', incident_data.title],
            ['Severity:', incident_data.severity],
            ['Status:', incident_data.status],
            ['Detection Time:', incident_data.detection_time],
            ['Containment Time:', incident_data.containment_time or 'Ongoing'],
            ['Resolution Time:', incident_data.resolution_time or 'Ongoing'],
            ['Affected Systems:', f"{len(incident_data.affected_systems)} systems"],
            ['IOCs Identified:', f"{len(incident_data.iocs)} indicators"]
        ]
        
        overview_table = Table(overview_data, colWidths=[2*inch, 4*inch])
        overview_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(overview_table)
        story.append(Spacer(1, 0.3*inch))
        
        return story
    
    def _build_timeline_section(self, incident_data: IncidentData) -> List:
        """Build timeline section"""
        story = []
        
        heading = Paragraph("Timeline of Events", self.styles['CustomHeading1'])
        story.append(heading)
        story.append(Spacer(1, 0.2*inch))
        
        if incident_data.timeline:
            timeline_data = [['Timestamp', 'Event Description', 'Source']]
            
            for event in incident_data.timeline[:20]:  # Limit to first 20 events
                timeline_data.append([
                    event.get('timestamp', 'Unknown'),
                    event.get('description', 'No description'),
                    event.get('source', 'Unknown')
                ])
            
            timeline_table = Table(timeline_data, colWidths=[1.5*inch, 3*inch, 1.5*inch])
            timeline_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))
            
            story.append(timeline_table)
        else:
            no_timeline = Paragraph("No timeline data available", self.styles['Normal'])
            story.append(no_timeline)
        
        story.append(Spacer(1, 0.3*inch))
        return story
    
    def _build_technical_analysis_section(self, incident_data: IncidentData, ai_analysis: Dict) -> List:
        """Build technical analysis section"""
        story = []
        
        heading = Paragraph("Technical Analysis", self.styles['CustomHeading1'])
        story.append(heading)
        story.append(Spacer(1, 0.2*inch))
        
        # Technical details
        technical_details = ai_analysis.get('technical_details', 'Technical analysis not available')
        details = Paragraph(technical_details, self.styles['Normal'])
        story.append(details)
        story.append(Spacer(1, 0.2*inch))
        
        # MITRE ATT&CK techniques
        if incident_data.mitre_techniques:
            mitre_heading = Paragraph("MITRE ATT&CK Techniques", self.styles['CustomHeading2'])
            story.append(mitre_heading)
            
            mitre_data = [['Technique ID', 'Technique Name']]
            for technique in incident_data.mitre_techniques:
                technique_name = self.mitre_mappings.get(technique, 'Unknown technique')
                mitre_data.append([technique, technique_name])
            
            mitre_table = Table(mitre_data, colWidths=[1.5*inch, 4.5*inch])
            mitre_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(mitre_table)
            story.append(Spacer(1, 0.2*inch))
        
        # IOCs
        if incident_data.iocs:
            ioc_heading = Paragraph("Indicators of Compromise", self.styles['CustomHeading2'])
            story.append(ioc_heading)
            
            ioc_text = "<br/>".join([f"• {ioc}" for ioc in incident_data.iocs[:20]])  # Limit to 20
            ioc_para = Paragraph(ioc_text, self.styles['Normal'])
            story.append(ioc_para)
            story.append(Spacer(1, 0.2*inch))
        
        return story
    
    def _build_impact_assessment_section(self, incident_data: IncidentData) -> List:
        """Build impact assessment section"""
        story = []
        
        heading = Paragraph("Impact Assessment", self.styles['CustomHeading1'])
        story.append(heading)
        story.append(Spacer(1, 0.2*inch))
        
        impact = incident_data.impact_assessment
        
        impact_data = [
            ['Business Impact:', impact.get('business_impact', 'Under assessment')],
            ['Systems Affected:', f"{len(incident_data.affected_systems)} systems"],
            ['Data Compromise:', impact.get('data_compromise', 'Under investigation')],
            ['Financial Impact:', impact.get('financial_impact', 'Under assessment')],
            ['Regulatory Impact:', impact.get('regulatory_impact', 'Under assessment')]
        ]
        
        impact_table = Table(impact_data, colWidths=[2*inch, 4*inch])
        impact_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(impact_table)
        story.append(Spacer(1, 0.3*inch))
        
        return story
    
    def _build_response_actions_section(self, incident_data: IncidentData) -> List:
        """Build response actions section"""
        story = []
        
        heading = Paragraph("Response Actions Taken", self.styles['CustomHeading1'])
        story.append(heading)
        story.append(Spacer(1, 0.2*inch))
        
        if incident_data.response_actions:
            actions_text = "<br/>".join([f"• {action}" for action in incident_data.response_actions])
            actions_para = Paragraph(actions_text, self.styles['Normal'])
            story.append(actions_para)
        else:
            no_actions = Paragraph("No response actions documented", self.styles['Normal'])
            story.append(no_actions)
        
        story.append(Spacer(1, 0.3*inch))
        return story
    
    def _build_recommendations_section(self, incident_data: IncidentData) -> List:
        """Build recommendations section"""
        story = []
        
        heading = Paragraph("Recommendations", self.styles['CustomHeading1'])
        story.append(heading)
        story.append(Spacer(1, 0.2*inch))
        
        if incident_data.recommendations:
            recs_text = "<br/>".join([f"• {rec}" for rec in incident_data.recommendations])
            recs_para = Paragraph(recs_text, self.styles['Normal'])
            story.append(recs_para)
        else:
            no_recs = Paragraph("No recommendations available", self.styles['Normal'])
            story.append(no_recs)
        
        story.append(Spacer(1, 0.3*inch))
        return story
    
    def _build_appendices(self, incident_data: IncidentData, ai_analysis: Dict) -> List:
        """Build appendices section"""
        story = []
        
        heading = Paragraph("Appendices", self.styles['CustomHeading1'])
        story.append(heading)
        story.append(Spacer(1, 0.2*inch))
        
        # Appendix A: Evidence Summary
        appendix_a = Paragraph("Appendix A: Evidence Summary", self.styles['CustomHeading2'])
        story.append(appendix_a)
        
        evidence_summary = self._generate_evidence_summary(incident_data.evidence)
        evidence_para = Paragraph(evidence_summary, self.styles['Normal'])
        story.append(evidence_para)
        story.append(Spacer(1, 0.2*inch))
        
        # Appendix B: Detailed Timeline
        if len(incident_data.timeline) > 20:
            appendix_b = Paragraph("Appendix B: Complete Timeline", self.styles['CustomHeading2'])
            story.append(appendix_b)
            
            timeline_text = "<br/>".join([
                f"{event.get('timestamp', 'Unknown')}: {event.get('description', 'No description')}"
                for event in incident_data.timeline[20:]  # Events not shown in main timeline
            ])
            timeline_para = Paragraph(timeline_text, self.styles['Normal'])
            story.append(timeline_para)
        
        return story
    
    def _generate_evidence_summary(self, evidence: List[Dict]) -> str:
        """Generate evidence summary text"""
        if not evidence:
            return "No evidence documented for this incident."
        
        evidence_types = {}
        for item in evidence:
            evidence_type = item.get('type', 'unknown')
            evidence_types[evidence_type] = evidence_types.get(evidence_type, 0) + 1
        
        summary_parts = [f"Total evidence items: {len(evidence)}"]
        for evidence_type, count in evidence_types.items():
            summary_parts.append(f"• {evidence_type}: {count} items")
        
        return "<br/>".join(summary_parts)
    
    def _generate_supporting_docs_section(self, incident_data: IncidentData) -> str:
        """Generate supporting documentation section"""
        docs = []
        
        if incident_data.external_references:
            docs.append("External References:")
            for ref in incident_data.external_references:
                docs.append(f"• {ref}")
        
        if incident_data.analyst_notes:
            docs.append("<br/>Analyst Notes:")
            for note in incident_data.analyst_notes:
                docs.append(f"• {note}")
        
        return "<br/>".join(docs) if docs else "No supporting documentation available."
    
    async def _generate_json_document(self, incident_data: IncidentData, metadata: DocumentMetadata, ai_analysis: Dict, document_type: DocumentType) -> str:
        """Generate structured JSON document"""
        try:
            json_doc = {
                "metadata": asdict(metadata),
                "incident_data": asdict(incident_data),
                "ai_analysis": ai_analysis,
                "document_type": document_type.value,
                "generation_timestamp": datetime.now().isoformat(),
                "schema_version": "1.0"
            }
            
            return json.dumps(json_doc, indent=2, default=str)
            
        except Exception as e:
            logger.error(f"JSON generation failed: {e}")
            return json.dumps({"error": str(e)}, indent=2)
    
    async def _generate_html_document(self, incident_data: IncidentData, metadata: DocumentMetadata, ai_analysis: Dict, document_type: DocumentType) -> str:
        """Generate HTML document"""
        try:
            # Generate markdown first
            markdown_content = await self._generate_markdown_document(incident_data, metadata, ai_analysis, document_type)
            
            # Convert markdown to HTML
            html_content = markdown.markdown(markdown_content, extensions=['tables', 'toc'])
            
            # Wrap in full HTML document
            full_html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{metadata.title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 40px; }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; }}
        h2 {{ color: #34495e; border-bottom: 1px solid #bdc3c7; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .critical {{ background-color: #ffebee; border-left: 5px solid #f44336; padding: 10px; }}
        .high {{ background-color: #fff3e0; border-left: 5px solid #ff9800; padding: 10px; }}
        .code {{ background-color: #f5f5f5; padding: 10px; border-radius: 4px; font-family: monospace; }}
    </style>
</head>
<body>
    {html_content}
    <hr>
    <footer>
        <p><em>Generated automatically by Cybersecurity AI Documentation System on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</em></p>
    </footer>
</body>
</html>
"""
            return full_html
            
        except Exception as e:
            logger.error(f"HTML generation failed: {e}")
            return f"<html><body><h1>HTML Generation Error</h1><p>{str(e)}</p></body></html>"
    
    async def _save_documents(self, documents: Dict[str, Any], metadata: DocumentMetadata) -> List[str]:
        """Save generated documents to files"""
        saved_files = []
        base_filename = f"{metadata.document_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        try:
            # Save Markdown
            if 'markdown' in documents:
                md_filename = f"data/reports/{base_filename}.md"
                with open(md_filename, 'w', encoding='utf-8') as f:
                    f.write(documents['markdown'])
                saved_files.append(md_filename)
            
            # Save PDF
            if 'pdf' in documents and isinstance(documents['pdf'], bytes):
                pdf_filename = f"data/reports/{base_filename}.pdf"
                with open(pdf_filename, 'wb') as f#!/usr/bin/env python3
"""
Documentation Agent - Autonomous Incident Documentation and Reporting
Automatically generates comprehensive incident reports and documentation.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
import base64
from io import BytesIO

import pandas as pd
from groq import Groq
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from jinja2 import Template
import markdown

from utils.logger import get_logger
from utils.security import sanitize_input
from config.settings import Settings

# Initialize components
logger = get_logger(__name__)
settings = Settings()

class DocumentType(Enum):
    """Document types"""
    INCIDENT_REPORT = "INCIDENT_REPORT"
    THREAT_ANALYSIS = "THREAT_ANALYSIS"
    FORENSIC_SUMMARY = "FORENSIC_SUMMARY"
    EXECUTIVE_SUMMARY = "EXECUTIVE_SUMMARY"
    TECHNICAL_ANALYSIS = "TECHNICAL_ANALYSIS"
    REMEDIATION_PLAN = "REMEDIATION_PLAN"
    LESSONS_LEARNED = "LESSONS_LEARNED"
    IOC_REPORT = "IOC_REPORT"

class IncidentSeverity(Enum):
    """Incident severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class IncidentData:
    """Incident data structure for documentation"""
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
    analyst_notes: List[str]
    external_references: List[str]

@dataclass
class DocumentMetadata:
    """Document metadata"""
    document_id: str
    document_type: str
    title: str
    author: str
    created_date: str
    last_modified: str
    version: str
    classification: str
    distribution: str
    retention_period: str

class DocumentationAgent:
    """
    Autonomous incident documentation and reporting agent
    """
    
    def __init__(self):
        self.groq_client = Groq(api_key=settings.GROQ_API_KEY)
        self.templates = self._load_document_templates()
        self.styles = self._initialize_document_styles()
        self.mitre_mappings = self._load_mitre_mappings()
        
    def _load_document_templates(self) -> Dict[str, str]:
        """Load document templates"""
        return {
            "incident_report": """
# Incident Report: {{ incident.title }}

**Incident ID:** {{ incident.incident_id }}  
**Classification:** {{ metadata.classification }}  
**Date Created:** {{ metadata.created_date }}  
**Report Author:** {{ metadata.author }}

## Executive Summary

{{ ai_analysis.executive_summary }}

## Incident Overview

- **Severity:** {{ incident.severity }}
- **Status:** {{ incident.status }}
- **Detection Time:** {{ incident.detection_time }}
- **Containment Time:** {{ incident.containment_time or "Ongoing" }}
- **Resolution Time:** {{ incident.resolution_time or "Ongoing" }}

## Timeline of Events

{% for event in incident.timeline %}
**{{ event.timestamp }}** - {{ event.description }}
{% endfor %}

## Technical Analysis

{{ ai_analysis.technical_details }}

### MITRE ATT&CK Mapping

{% for technique in incident.mitre_techniques %}
- {{ technique }}: {{ mitre_descriptions.get(technique, "Description not available") }}
{% endfor %}

### Indicators of Compromise (IOCs)

{% for ioc in incident.iocs %}
- {{ ioc }}
{% endfor %}

## Impact Assessment

- **Business Impact:** {{ incident.impact_assessment.business_impact }}
- **Systems Affected:** {{ incident.affected_systems|length }} systems
- **Data Compromise:** {{ incident.impact_assessment.data_compromise }}
- **Financial Impact:** {{ incident.impact_assessment.financial_impact }}

## Response Actions Taken

{% for action in incident.response_actions %}
- {{ action }}
{% endfor %}

## Recommendations

{% for recommendation in incident.recommendations %}
- {{ recommendation }}
{% endfor %}

## Lessons Learned

{% for lesson in incident.lessons_learned %}
- {{ lesson }}
{% endfor %}

## Appendices

### A. Evidence Summary
{{ evidence_summary }}

### B. Supporting Documentation
{{ supporting_docs }}

---
*This report was generated automatically by the Cybersecurity AI Documentation System*
""",
            
            "executive_summary": """
# Executive Summary - Security Incident {{ incident.incident_id }}

**Incident:** {{ incident.title }}  
**Severity:** {{ incident.severity }}  
**Status:** {{ incident.status }}  
**Date:** {{ incident.detection_time }}

## Key Points

{{ ai_analysis.key_points }}

## Business Impact

{{ ai_analysis.business_impact }}

## Current Status

{{ ai_analysis.current_status }}

## Next Steps

{{ ai_analysis.next_steps }}

## Resource Requirements

{{ ai_analysis.resource_requirements }}
""",
            
            "technical_analysis": """
# Technical Analysis - {{ incident.title }}

## Attack Chain Analysis

{{ ai_analysis.attack_chain }}

## Threat Actor Assessment

{{ ai_analysis.threat_actor_profile }}

## Vulnerability Exploitation

{{ ai_analysis.vulnerabilities_exploited }}

## Lateral Movement Analysis

{{ ai_analysis.lateral_movement }}

## Data Exfiltration Assessment

{{ ai_analysis.data_exfiltration }}

## Persistence Mechanisms

{{ ai_analysis.persistence_mechanisms }}
"""
        }
    
    def _initialize_document_styles(self) -> Dict:
        """Initialize document styles for PDF generation"""
        styles = getSampleStyleSheet()
        
        custom_styles = {
            'CustomTitle': ParagraphStyle(
                'CustomTitle',
                parent=styles['Title'],
                fontSize=18,
                spaceAfter=30,
                alignment=TA_CENTER,
                textColor=colors.darkblue
            ),
            'CustomHeading1': ParagraphStyle(
                'CustomHeading1',
                parent=styles['Heading1'],
                fontSize=14,
                spaceAfter=12,
                textColor=colors.darkblue,
                borderWidth=1,
                borderColor=colors.darkblue,
                borderPadding=5
            ),
            'CustomHeading2': ParagraphStyle(
                'CustomHeading2',
                parent=styles['Heading2'],
                fontSize=12,
                spaceAfter=10,
                textColor=colors.darkred
            ),
            'CriticalAlert': ParagraphStyle(
                'CriticalAlert',
                parent=styles['Normal'],
                fontSize=11,
                textColor=colors.red,
                backColor=colors.lightgrey,
                borderWidth=1,
                borderColor=colors.red,
                borderPadding=8
            ),
            'CodeStyle': ParagraphStyle(
                'CodeStyle',
                parent=styles['Code'],
                fontSize=9,
                fontName='Courier',
                backColor=colors.lightgrey,
                borderWidth=1,
                borderColor=colors.grey,
                borderPadding=5
            )
        }
        
        styles.add(custom_styles['CustomTitle'])
        styles.add(custom_styles['CustomHeading1'])
        styles.add(custom_styles['CustomHeading2'])
        styles.add(custom_styles['CriticalAlert'])
        styles.add(custom_styles['CodeStyle'])
        
        return styles
    
    def _load_mitre_mappings(self) -> Dict[str, str]:
        """Load MITRE ATT&CK technique descriptions"""
        return {
            "T1190": "Exploit Public-Facing Application",
            "T1021.002": "Remote Services: SMB/Windows Admin Shares",
            "T1134": "Access Token Manipulation",
            "T1003": "OS Credential Dumping",
            "T1053.005": "Scheduled Task/Job: Scheduled Task",
            "T1071.004": "Application Layer Protocol: DNS",
            "T1055": "Process Injection",
            "T1059.001": "Command and Scripting Interpreter: PowerShell",
            "T1068": "Exploitation for Privilege Escalation",
            "T1078": "Valid Accounts",
            "T1135": "Network Share Discovery",
            "T1083": "File and Directory Discovery",
            "T1572": "Protocol Tunneling"
        }
    
    async def generate_incident_report(self, incident_data: IncidentData, document_type: DocumentType = DocumentType.INCIDENT_REPORT) -> Dict[str, Any]:
        """
        Generate comprehensive incident documentation
        """
        logger.info(f"Generating {document_type.value} for incident {incident_data.incident_id}")
        
        try:
            # Generate AI analysis
            ai_analysis = await self._generate_ai_analysis(incident_data, document_type)
            
            # Create document metadata
            metadata = DocumentMetadata(
                document_id=f"DOC-{incident_data.incident_id}-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                document_type=document_type.value,
                title=f"{document_type.value.replace('_', ' ').title()} - {incident_data.title}",
                author="AI Documentation Agent",
                created_date=datetime.now().isoformat(),
                last_modified=datetime.