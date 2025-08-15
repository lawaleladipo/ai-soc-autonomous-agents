#!/usr/bin/env python3
"""
Alert Triage Agent - AI-Powered Alert Analysis and Prioritization
Reduces alert fatigue by intelligently triaging security alerts.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib

import pandas as pd
from groq import Groq
from utils.logger import get_logger
from utils.security import sanitize_input
from config.settings import Settings

# Initialize components
logger = get_logger(__name__)
settings = Settings()

class AlertStatus(Enum):
    """Alert status types"""
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"
    FALSE_POSITIVE = "FALSE_POSITIVE"

class TriagePriority(Enum):
    """Triage priority levels"""
    P1_CRITICAL = "P1_CRITICAL"    # Immediate response required
    P2_HIGH = "P2_HIGH"            # Response within 2 hours
    P3_MEDIUM = "P3_MEDIUM"        # Response within 8 hours
    P4_LOW = "P4_LOW"              # Response within 24 hours
    P5_INFO = "P5_INFO"            # Informational only

@dataclass
class TriageResult:
    """Triage analysis result"""
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

class AlertTriageAgent:
    """
    AI-powered alert triage and prioritization agent
    """
    
    def __init__(self):
        self.groq_client = Groq(api_key=settings.GROQ_API_KEY)
        self.alert_history = self._load_alert_history()
        self.false_positive_patterns = self._load_fp_patterns()
        self.business_context = self._load_business_context()
        self.analyst_workload = self._load_analyst_workload()
        
    def _load_alert_history(self) -> pd.DataFrame:
        """Load historical alert data for pattern analysis"""
        try:
            # In production, load from database
            # For demo, create sample data
            sample_data = [
                {
                    "alert_id": "ALERT-001",
                    "alert_type": "brute_force",
                    "severity": "HIGH",
                    "resolution": "true_positive",
                    "resolution_time_hours": 2.5,
                    "analyst": "alice"
                },
                {
                    "alert_id": "ALERT-002", 
                    "alert_type": "malware_detection",
                    "severity": "CRITICAL",
                    "resolution": "false_positive",
                    "resolution_time_hours": 0.5,
                    "analyst": "bob"
                }
            ]
            return pd.DataFrame(sample_data)
        except Exception as e:
            logger.error(f"Failed to load alert history: {e}")
            return pd.DataFrame()
    
    def _load_fp_patterns(self) -> Dict:
        """Load known false positive patterns"""
        return {
            "common_patterns": [
                "automated_backup_process",
                "scheduled_maintenance",
                "legitimate_admin_activity",
                "antivirus_update",
                "patch_management"
            ],
            "time_based_fps": {
                "maintenance_window": {"start": "02:00", "end": "04:00"},
                "backup_window": {"start": "23:00", "end": "01:00"}
            },
            "source_based_fps": {
                "trusted_internal_tools": ["backup-server", "monitoring-system"],
                "known_scanners": ["vulnerability-scanner", "compliance-check"]
            }
        }
    
    def _load_business_context(self) -> Dict:
        """Load business context for impact assessment"""
        return {
            "critical_systems": [
                "payment-gateway", "customer-db", "web-frontend",
                "api-gateway", "auth-service"
            ],
            "business_hours": {"start": 9, "end": 17},
            "high_value_assets": [
                "financial-data", "customer-pii", "intellectual-property"
            ],
            "compliance_requirements": [
                "PCI-DSS", "GDPR", "SOX", "HIPAA"
            ]
        }
    
    def _load_analyst_workload(self) -> Dict:
        """Load current analyst workload information"""
        return {
            "analysts": {
                "alice": {"current_alerts": 3, "skill_level": "senior", "specialization": "malware"},
                "bob": {"current_alerts": 5, "skill_level": "intermediate", "specialization": "network"},
                "charlie": {"current_alerts": 2, "skill_level": "senior", "specialization": "forensics"}
            },
            "team_capacity": {"max_alerts_per_analyst": 8, "escalation_threshold": 6}
        }
    
    async def triage_alert(self, alert_data: Dict[str, Any]) -> TriageResult:
        """
        Perform comprehensive alert triage analysis
        """
        logger.info(f"Triaging alert: {alert_data.get('alert_id', 'UNKNOWN')}")
        
        try:
            # Sanitize input data
            alert_data = self._sanitize_alert_data(alert_data)
            
            # AI-powered analysis
            ai_analysis = await self._ai_triage_analysis(alert_data)
            
            # Historical pattern matching
            pattern_analysis = self._analyze_historical_patterns(alert_data)
            
            # False positive assessment
            fp_assessment = self._assess_false_positive_likelihood(alert_data)
            
            # Business impact analysis
            business_impact = self._analyze_business_impact(alert_data)
            
            # Technical severity assessment
            tech_severity = self._assess_technical_severity(alert_data, ai_analysis)
            
            # Priority calculation
            priority = self._calculate_priority(ai_analysis, business_impact, tech_severity)
            
            # Generate recommendations
            recommendations = await self._generate_recommendations(alert_data, ai_analysis)
            
            # Find similar alerts
            similar_alerts = self._find_similar_alerts(alert_data)
            
            # Determine escalation need
            escalation_required = self._should_escalate(priority, fp_assessment, business_impact)
            
            # Estimate effort
            effort_estimate = self._estimate_effort(alert_data, ai_analysis, pattern_analysis)
            
            # Calculate SLA deadline
            sla_deadline = self._calculate_sla_deadline(priority)
            
            # Assign analyst
            assigned_analyst = self._suggest_analyst(alert_data, priority)
            
            # Create triage result
            triage_result = TriageResult(
                alert_id=alert_data.get('alert_id', f"TRIAGE-{datetime.now().strftime('%Y%m%d-%H%M%S')}"),
                original_alert=alert_data,
                triage_timestamp=datetime.now().isoformat(),
                priority=priority,
                confidence_score=ai_analysis.get('confidence_score', 0.7),
                false_positive_probability=fp_assessment['probability'],
                business_impact=business_impact['level'],
                technical_severity=tech_severity,
                recommended_actions=recommendations,
                escalation_required=escalation_required,
                estimated_effort_hours=effort_estimate,
                similar_alerts=similar_alerts,
                contextual_analysis={
                    'ai_analysis': ai_analysis,
                    'pattern_analysis': pattern_analysis,
                    'fp_assessment': fp_assessment,
                    'business_context': business_impact
                },
                ai_summary=ai_analysis.get('summary', 'No AI summary available'),
                next_steps=ai_analysis.get('next_steps', []),
                sla_deadline=sla_deadline,
                assigned_analyst=assigned_analyst
            )
            
            # Save triage result
            self._save_triage_result(triage_result)
            
            logger.info(f"Alert {alert_data.get('alert_id')} triaged as {priority}")
            return triage_result
            
        except Exception as e:
            logger.error(f"Error triaging alert: {e}")
            # Return minimal triage result
            return self._create_fallback_triage_result(alert_data, str(e))
    
    def _sanitize_alert_data(self, alert_data: Dict) -> Dict:
        """Sanitize alert data for processing"""
        sanitized = {}
        for key, value in alert_data.items():
            if isinstance(value, str):
                sanitized[key] = sanitize_input(value)
            else:
                sanitized[key] = value
        return sanitized
    
    async def _ai_triage_analysis(self, alert_data: Dict) -> Dict:
        """
        Use Groq AI for comprehensive alert analysis
        """
        try:
            prompt = f"""
            Perform comprehensive triage analysis on this security alert:
            
            Alert Details:
            {json.dumps(alert_data, indent=2)}
            
            Business Context:
            - Critical Systems: {self.business_context['critical_systems']}
            - High Value Assets: {self.business_context['high_value_assets']}
            - Compliance Requirements: {self.business_context['compliance_requirements']}
            
            Current Time: {datetime.now().isoformat()}
            Business Hours: {self.business_context['business_hours']['start']}:00 - {self.business_context['business_hours']['end']}:00
            
            Provide a comprehensive JSON response with:
            1. summary (brief 2-3 sentence analysis)
            2. confidence_score (0.0-1.0)
            3. threat_assessment (detailed threat analysis)
            4. business_impact_score (0-100)
            5. technical_severity_score (0-100)
            6. urgency_factors (list of factors increasing urgency)
            7. mitigating_factors (list of factors reducing urgency)
            8. false_positive_indicators (list)
            9. true_positive_indicators (list)
            10. recommended_priority (P1_CRITICAL/P2_HIGH/P3_MEDIUM/P4_LOW/P5_INFO)
            11. immediate_actions (list of immediate steps)
            12. investigation_steps (list of investigation actions)
            13. containment_recommendations (list)
            14. evidence_preservation_needed (boolean)
            15. external_communication_required (boolean)
            16. estimated_investigation_time_hours (float)
            17. skills_required (list)
            18. tools_needed (list)
            19. next_steps (ordered list of next actions)
            20. escalation_triggers (conditions requiring escalation)
            """
            
            response = self.groq_client.chat.completions.create(
                model="mixtral-8x7b-32768",
                messages=[
                    {"role": "system", "content": "You are a senior cybersecurity analyst specializing in alert triage and incident response. Provide thorough, actionable analysis."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=1500
            )
            
            analysis = json.loads(response.choices[0].message.content)
            logger.info(f"AI triage analysis completed with confidence: {analysis.get('confidence_score', 0)}")
            return analysis
            
        except Exception as e:
            logger.error(f"AI triage analysis failed: {e}")
            return {
                "summary": "AI analysis unavailable",
                "confidence_score": 0.5,
                "recommended_priority": "P3_MEDIUM"
            }
    
    def _analyze_historical_patterns(self, alert_data: Dict) -> Dict:
        """
        Analyze alert against historical patterns
        """
        if self.alert_history.empty:
            return {"pattern_match": False, "confidence": 0.0}
        
        # Look for similar alerts
        alert_type = alert_data.get('alert_type', '').lower()
        source_ip = alert_data.get('source_ip', '')
        
        similar_alerts = self.alert_history[
            (self.alert_history['alert_type'].str.lower() == alert_type) |
            (self.alert_history.get('source_ip', '') == source_ip)
        ]
        
        if not similar_alerts.empty:
            # Calculate false positive rate for similar alerts
            fp_rate = len(similar_alerts[similar_alerts['resolution'] == 'false_positive']) / len(similar_alerts)
            avg_resolution_time = similar_alerts['resolution_time_hours'].mean()
            
            return {
                "pattern_match": True,
                "similar_count": len(similar_alerts),
                "false_positive_rate": fp_rate,
                "avg_resolution_time": avg_resolution_time,
                "confidence": 0.8 if len(similar_alerts) >= 3 else 0.5
            }
        
        return {"pattern_match": False, "confidence": 0.0}
    
    def _assess_false_positive_likelihood(self, alert_data: Dict) -> Dict:
        """
        Assess likelihood that alert is a false positive
        """
        fp_score = 0.0
        indicators = []
        
        # Check common FP patterns
        alert_description = alert_data.get('description', '').lower()
        message = alert_data.get('message', '').lower()
        
        for pattern in self.false_positive_patterns['common_patterns']:
            if pattern.replace('_', ' ') in alert_description or pattern.replace('_', ' ') in message:
                fp_score += 0.3
                indicators.append(f"Contains common FP pattern: {pattern}")
        
        # Check time-based patterns
        current_time = datetime.now().time()
        for window_name, window in self.false_positive_patterns['time_based_fps'].items():
            start_time = datetime.strptime(window['start'], '%H:%M').time()
            end_time = datetime.strptime(window['end'], '%H:%M').time()
            
            if start_time <= current_time <= end_time:
                fp_score += 0.2
                indicators.append(f"Occurred during {window_name}")
        
        # Check source-based patterns
        source_system = alert_data.get('source_system', '').lower()
        for category, systems in self.false_positive_patterns['source_based_fps'].items():
            if any(system in source_system for system in systems):
                fp_score += 0.4
                indicators.append(f"Source matches {category}")
        
        # Cap the score
        fp_probability = min(fp_score, 0.9)
        
        return {
            "probability": fp_probability,
            "indicators": indicators,
            "confidence": 0.7 if indicators else 0.3
        }
    
    def _analyze_business_impact(self, alert_data: Dict) -> Dict:
        """
        Analyze potential business impact of the alert
        """
        impact_score = 0
        factors = []
        
        # Check if critical systems are affected
        affected_systems = alert_data.get('affected_systems', [])
        for system in affected_systems:
            if any(critical in system.lower() for critical in self.business_context['critical_systems']):
                impact_score += 30
                factors.append(f"Critical system affected: {system}")
        
        # Check for high-value assets
        alert_description = alert_data.get('description', '').lower()
        for asset in self.business_context['high_value_assets']:
            if asset.replace('-', ' ') in alert_description:
                impact_score += 25
                factors.append(f"High-value asset involved: {asset}")
        
        # Check compliance implications
        for requirement in self.business_context['compliance_requirements']:
            if requirement.lower() in alert_description:
                impact_score += 20
                factors.append(f"Compliance requirement affected: {requirement}")
        
        # Time sensitivity
        current_hour = datetime.now().hour
        business_hours = self.business_context['business_hours']
        if business_hours['start'] <= current_hour <= business_hours['end']:
            impact_score += 15
            factors.append("Occurred during business hours")
        
        # Determine impact level
        if impact_score >= 70:
            level = "CRITICAL"
        elif impact_score >= 50:
            level = "HIGH"
        elif impact_score >= 30:
            level = "MEDIUM"
        else:
            level = "LOW"
        
        return {
            "score": impact_score,
            "level": level,
            "factors": factors
        }
    
    def _assess_technical_severity(self, alert_data: Dict, ai_analysis: Dict) -> str:
        """
        Assess technical severity of the alert
        """
        # Start with original severity if available
        base_severity = alert_data.get('severity', 'MEDIUM').upper()
        
        # Factor in AI assessment
        ai_severity_score = ai_analysis.get('technical_severity_score', 50)
        
        # Consider CVSS score if available
        cvss_score = alert_data.get('cvss_score', 0.0)
        
        # Calculate combined severity
        severity_score = 0
        
        if base_severity == "CRITICAL":
            severity_score += 40
        elif base_severity == "HIGH":
            severity_score += 30
        elif base_severity == "MEDIUM":
            severity_score += 20
        elif base_severity == "LOW":
            severity_score += 10
        
        severity_score += (ai_severity_score * 0.4)  # 40% weight to AI
        severity_score += (cvss_score * 6)  # CVSS 0-10 scale to 0-60
        
        # Determine final severity
        if severity_score >= 80:
            return "CRITICAL"
        elif severity_score >= 60:
            return "HIGH"
        elif severity_score >= 40:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _calculate_priority(self, ai_analysis: Dict, business_impact: Dict, tech_severity: str) -> str:
        """
        Calculate overall alert priority
        """
        # Start with AI recommendation
        ai_priority = ai_analysis.get('recommended_priority', 'P3_MEDIUM')
        
        # Factor in business impact
        business_level = business_impact.get('level', 'LOW')
        
        # Create priority matrix
        priority_matrix = {
            ('CRITICAL', 'CRITICAL'): 'P1_CRITICAL',
            ('CRITICAL', 'HIGH'): 'P1_CRITICAL',
            ('HIGH', 'CRITICAL'): 'P1_CRITICAL',
            ('HIGH', 'HIGH'): 'P2_HIGH',
            ('MEDIUM', 'HIGH'): 'P2_HIGH',
            ('HIGH', 'MEDIUM'): 'P2_HIGH',
            ('MEDIUM', 'MEDIUM'): 'P3_MEDIUM',
            ('LOW', 'HIGH'): 'P3_MEDIUM',
            ('HIGH', 'LOW'): 'P3_MEDIUM',
            ('MEDIUM', 'LOW'): 'P4_LOW',
            ('LOW', 'MEDIUM'): 'P4_LOW',
            ('LOW', 'LOW'): 'P5_INFO'
        }
        
        calculated_priority = priority_matrix.get((tech_severity, business_level), 'P3_MEDIUM')
        
        # Use the higher priority between AI and calculated
        priority_values = {
            'P1_CRITICAL': 5,
            'P2_HIGH': 4,
            'P3_MEDIUM': 3,
            'P4_LOW': 2,
            'P5_INFO': 1
        }
        
        if priority_values.get(ai_priority, 3) >= priority_values.get(calculated_priority, 3):
            return ai_priority
        else:
            return calculated_priority
    
    async def _generate_recommendations(self, alert_data: Dict, ai_analysis: Dict) -> List[str]:
        """
        Generate actionable recommendations
        """
        recommendations = []
        
        # Add AI recommendations
        recommendations.extend(ai_analysis.get('immediate_actions', []))
        recommendations.extend(ai_analysis.get('investigation_steps', []))
        
        # Add rule-based recommendations
        alert_type = alert_data.get('alert_type', '').lower()
        
        if 'brute_force' in alert_type:
            recommendations.extend([
                "Block source IP address",
                "Review account lockout policies",
                "Check for successful logins from same source"
            ])
        elif 'malware' in alert_type:
            recommendations.extend([
                "Isolate affected systems",
                "Run full antimalware scan",
                "Check for lateral movement"
            ])
        elif 'phishing' in alert_type:
            recommendations.extend([
                "Block malicious URLs/domains",
                "Notify affected users",
                "Check email logs for similar attempts"
            ])
        
        return list(set(recommendations))  # Remove duplicates
    
    def _find_similar_alerts(self, alert_data: Dict) -> List[str]:
        """
        Find similar alerts in recent history
        """
        similar = []
        
        if not self.alert_history.empty:
            alert_type = alert_data.get('alert_type', '')
            source_ip = alert_data.get('source_ip', '')
            
            # Look for alerts with same type or source
            similar_mask = (
                (self.alert_history['alert_type'] == alert_type) |
                (self.alert_history.get('source_ip', '') == source_ip)
            )
            
            similar_alerts = self.alert_history[similar_mask]
            similar = similar_alerts['alert_id'].tolist()[:5]  # Limit to 5
        
        return similar
    
    def _should_escalate(self, priority: str, fp_assessment: Dict, business_impact: Dict) -> bool:
        """
        Determine if alert should be escalated
        """
        # Always escalate P1 alerts
        if priority == 'P1_CRITICAL':
            return True
        
        # Escalate high business impact
        if business_impact.get('level') == 'CRITICAL':
            return True
        
        # Don't escalate likely false positives
        if fp_assessment.get('probability', 0) > 0.7:
            return False
        
        # Escalate P2 during business hours
        if priority == 'P2_HIGH':
            current_hour = datetime.now().hour
            business_hours = self.business_context['business_hours']
            if business_hours['start'] <= current_hour <= business_hours['end']:
                return True
        
        return False
    
    def _estimate_effort(self, alert_data: Dict, ai_analysis: Dict, pattern_analysis: Dict) -> float:
        """
        Estimate effort required in hours
        """
        base_effort = {
            'P1_CRITICAL': 4.0,
            'P2_HIGH': 2.0,
            'P3_MEDIUM': 1.0,
            'P4_LOW': 0.5,
            'P5_INFO': 0.25
        }
        
        # Get base effort from AI analysis
        effort = ai_analysis.get('estimated_investigation_time_hours', 1.0)
        
        # Adjust based on historical patterns
        if pattern_analysis.get('pattern_match', False):
            avg_time = pattern_analysis.get('avg_resolution_time', effort)
            effort = (effort + avg_time) / 2  # Average with historical data
        
        # Adjust for complexity indicators
        complexity_indicators = [
            'multiple_systems', 'encryption', 'persistence', 
            'lateral_movement', 'privilege_escalation'
        ]
        
        alert_text = str(alert_data.get('description', '')).lower()
        complexity_count = sum(1 for indicator in complexity_indicators if indicator in alert_text)
        
        effort += complexity_count * 0.5  # Add 30 minutes per complexity factor
        
        return round(effort, 2)
    
    def _calculate_sla_deadline(self, priority: str) -> str:
        """
        Calculate SLA deadline based on priority
        """
        sla_hours = {
            'P1_CRITICAL': 1,    # 1 hour
            'P2_HIGH': 4,        # 4 hours  
            'P3_MEDIUM': 24,     # 1 day
            'P4_LOW': 72,        # 3 days
            'P5_INFO': 168       # 1 week
        }
        
        hours = sla_hours.get(priority, 24)
        deadline = datetime.now() + timedelta(hours=hours)
        return deadline.isoformat()
    
    def _suggest_analyst(self, alert_data: Dict, priority: str) -> Optional[str]:
        """
        Suggest best analyst for the alert
        """
        analysts = self.analyst_workload['analysts']
        
        # Filter analysts by availability
        available_analysts = {
            name: info for name, info in analysts.items()
            if info['current_alerts'] < self.analyst_workload['team_capacity']['max_alerts_per_analyst']
        }
        
        if not available_analysts:
            return None  # All analysts at capacity
        
        # Match by specialization
        alert_type = alert_data.get('alert_type', '').lower()
        for name, info in available_analysts.items():
            specialization = info.get('specialization', '').lower()
            if specialization in alert_type:
                return name
        
        # Assign to analyst with lowest workload
        return min(available_analysts.keys(), 
                  key=lambda x: available_analysts[x]['current_alerts'])
    
    def _create_fallback_triage_result(self, alert_data: Dict, error_msg: str) -> TriageResult:
        """
        Create minimal triage result when processing fails
        """
        return TriageResult(
            alert_id=alert_data.get('alert_id', f"TRIAGE-ERROR-{datetime.now().strftime('%Y%m%d-%H%M%S')}"),
            original_alert=alert_data,
            triage_timestamp=datetime.now().isoformat(),
            priority="P3_MEDIUM",
            confidence_score=0.1,
            false_positive_probability=0.5,
            business_impact="UNKNOWN",
            technical_severity="UNKNOWN", 
            recommended_actions=[f"Manual review required - {error_msg}"],
            escalation_required=True,
            estimated_effort_hours=1.0,
            similar_alerts=[],
            contextual_analysis={"error": error_msg},
            ai_summary=f"Triage failed: {error_msg}",
            next_steps=["Manual analyst review required"],
            sla_deadline=(datetime.now() + timedelta(hours=4)).isoformat()
        )
    
    def _save_triage_result(self, result: TriageResult):
        """Save triage result to storage"""
        try:
            filename = f"data/reports/triage_{result.alert_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(asdict(result), f, indent=2, default=str)
            logger.info(f"Triage result saved: {filename}")
        except Exception as e:
            logger.error(f"Failed to save triage result: {e}")
    
    async def batch_triage(self, alerts: List[Dict]) -> List[TriageResult]:
        """
        Triage multiple alerts efficiently
        """
        logger.info(f"Starting batch triage for {len(alerts)} alerts")
        
        # Process alerts in parallel
        tasks = [self.triage_alert(alert) for alert in alerts]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and log errors
        triage_results = []
        for i, result in enumerate(results):
            if isinstance(result, TriageResult):
                triage_results.append(result)
            elif isinstance(result, Exception):
                logger.error(f"Error triaging alert {i}: {result}")
                # Create fallback result
                fallback = self._create_fallback_triage_result(
                    alerts[i], f"Batch processing error: {result}"
                )
                triage_results.append(fallback)
        
        # Sort results by priority
        priority_order = {'P1_CRITICAL': 5, 'P2_HIGH': 4, 'P3_MEDIUM': 3, 'P4_LOW': 2, 'P5_INFO': 1}
        triage_results.sort(key=lambda x: priority_order.get(x.priority, 0), reverse=True)
        
        logger.info(f"Batch triage completed: {len(triage_results)} results")
        return triage_results
    
    def generate_triage_report(self, triage_results: List[TriageResult]) -> Dict:
        """
        Generate comprehensive triage report
        """
        if not triage_results:
            return {"error": "No triage results provided"}
        
        # Calculate statistics
        priorities = [r.priority for r in triage_results]
        priority_counts = {p: priorities.count(p) for p in set(priorities)}
        
        avg_confidence = sum(r.confidence_score for r in triage_results) / len(triage_results)
        avg_fp_prob = sum(r.false_positive_probability for r in triage_results) / len(triage_results)
        
        escalation_count = sum(1 for r in triage_results if r.escalation_required)
        
        report = {
            "report_id": f"TRIAGE-REPORT-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_alerts": len(triage_results),
                "priority_breakdown": priority_counts,
                "escalation_required": escalation_count,
                "avg_confidence_score": round(avg_confidence, 2),
                "avg_false_positive_probability": round(avg_fp_prob, 2),
                "estimated_total_effort_hours": sum(r.estimated_effort_hours for r in triage_results)
            },
            "high_priority_alerts": [
                asdict(r) for r in triage_results 
                if r.priority in ['P1_CRITICAL', 'P2_HIGH']
            ][:10],  # Top 10 high priority
            "recommendations": self._generate_batch_recommendations(triage_results),
            "workload_distribution": self._analyze_workload_distribution(triage_results)
        }
        
        return report
    
    def _generate_batch_recommendations(self, triage_results: List[TriageResult]) -> List[str]:
        """Generate recommendations for the batch"""
        recommendations = []
        
        critical_count = sum(1 for r in triage_results if r.priority == 'P1_CRITICAL')
        if critical_count > 0:
            recommendations.append(f"URGENT: {critical_count} critical alerts require immediate attention")
        
        high_fp_alerts = [r for r in triage_results if r.false_positive_probability > 0.7]
        if len(high_fp_alerts) > 5:
            recommendations.append(f"Consider tuning detection rules - {len(high_fp_alerts)} likely false positives")
        
        return recommendations
    
    def _analyze_workload_distribution(self, triage_results: List[TriageResult]) -> Dict:
        """Analyze workload distribution among analysts"""
        workload = {}
        
        for result in triage_results:
            if result.assigned_analyst:
                analyst = result.assigned_analyst
                if analyst not in workload:
                    workload[analyst] = {
                        'alert_count': 0,
                        'total_effort_hours': 0,
                        'priorities': []
                    }
                
                workload[analyst]['alert_count'] += 1
                workload[analyst]['total_effort_hours'] += result.estimated_effort_hours
                workload[analyst]['priorities'].append(result.priority)
        
        return workload

# Main execution for testing
if __name__ == "__main__":
    async def main():
        agent = AlertTriageAgent()
        
        # Test with sample alerts
        test_alerts = [
            {
                "alert_id": "ALERT-TEST-001",
                "alert_type": "brute_force_attempt",
                "severity": "HIGH",
                "source_ip": "192.168.1.100",
                "description": "Multiple failed login attempts detected",
                "affected_systems": ["web-server-1"],
                "timestamp": datetime.now().isoformat()
            },
            {
                "alert_id": "ALERT-TEST-002", 
                "alert_type": "malware_detection",
                "severity": "CRITICAL",
                "description": "Malicious file detected on payment gateway",
                "affected_systems": ["payment-gateway"],
                "timestamp": datetime.now().isoformat()
            }
        ]
        
        # Batch triage
        results = await agent.batch_triage(test_alerts)
        
        # Generate report
        report = agent.generate_triage_report(results)
        
        print(f"Triage Report: {json.dumps(report, indent=2, default=str)}")
        
        # Individual triage example
        individual_result = await agent.triage_alert(test_alerts[0])
        print(f"\nIndividual Triage Result:")
        print(f"Priority: {individual_result.priority}")
        print(f"Confidence: {individual_result.confidence_score}")
        print(f"FP Probability: {individual_result.false_positive_probability}")
        print(f"Assigned to: {individual_result.assigned_analyst}")
        print(f"Actions: {individual_result.recommended_actions[:3]}")
    
    asyncio.run(main())