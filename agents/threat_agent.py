#!/usr/bin/env python3
"""
Threat Detection Agent - Autonomous Threat Detection and Analysis
Monitors logs, network traffic, and system behavior for suspicious patterns.
"""

import asyncio
import json
import logging
import re
import hashlib
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum

import requests
import pandas as pd
from groq import Groq
from utils.logger import get_logger
from utils.security import sanitize_input, validate_ip_address
from utils.threat_intel import ThreatIntelligence
from config.settings import Settings

# Initialize components
logger = get_logger(__name__)
settings = Settings()

class ThreatType(Enum):
    """Threat classification types"""
    MALWARE = "MALWARE"
    PHISHING = "PHISHING"
    BRUTE_FORCE = "BRUTE_FORCE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    ANOMALOUS_BEHAVIOR = "ANOMALOUS_BEHAVIOR"
    NETWORK_INTRUSION = "NETWORK_INTRUSION"
    INSIDER_THREAT = "INSIDER_THREAT"

class ThreatSeverity(Enum):
    """Threat severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class ThreatAlert:
    """Threat Alert data model"""
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

class ThreatDetectionAgent:
    """
    Autonomous Threat Detection Agent using multiple detection methods
    """
    
    def __init__(self):
        self.groq_client = Groq(api_key=settings.GROQ_API_KEY)
        self.threat_intel = ThreatIntelligence()
        self.detection_rules = self._load_detection_rules()
        self.ml_models = self._initialize_ml_models()
        self.baseline_behavior = self._load_baseline_behavior()
        
    def _load_detection_rules(self) -> Dict:
        """Load signature-based detection rules"""
        return {
            "brute_force": {
                "pattern": r"Failed (password|login|authentication).*from\s+(\d+\.\d+\.\d+\.\d+)",
                "threshold": 5,
                "time_window": 300,  # 5 minutes
                "severity": "HIGH"
            },
            "privilege_escalation": {
                "pattern": r"(sudo|su|runas).*root|administrator",
                "keywords": ["privilege", "escalation", "elevation"],
                "severity": "HIGH"
            },
            "malicious_commands": {
                "patterns": [
                    r"powershell.*-enc\s+[A-Za-z0-9+/=]{20,}",  # Encoded PowerShell
                    r"cmd\.exe.*\/c\s+.*&",  # Command chaining
                    r"wget|curl.*\|.*sh",  # Download and execute
                    r"nc.*-e.*\/bin\/(bash|sh)",  # Netcat reverse shell
                ],
                "severity": "CRITICAL"
            },
            "data_exfiltration": {
                "patterns": [
                    r"scp.*-r.*\/.*",  # Recursive file copy
                    r"tar.*-czf.*\/tmp\/.*",  # Archive creation
                    r"(ftp|sftp).*put.*",  # File uploads
                ],
                "data_volume_threshold": 100 * 1024 * 1024,  # 100MB
                "severity": "HIGH"
            },
            "network_anomalies": {
                "unusual_ports": [4444, 5555, 6666, 7777, 8888, 9999],
                "suspicious_domains": [".tk", ".ml", ".ga", ".cf"],
                "severity": "MEDIUM"
            }
        }
    
    def _initialize_ml_models(self) -> Dict:
        """Initialize ML models for behavioral analysis"""
        # In production, load pre-trained models
        # For demo, return model placeholders
        return {
            "anomaly_detector": None,  # Would be trained anomaly detection model
            "classification_model": None,  # Would be threat classification model
            "behavioral_model": None  # Would be user/system behavior model
        }
    
    def _load_baseline_behavior(self) -> Dict:
        """Load baseline behavior patterns"""
        return {
            "normal_login_hours": {"start": 8, "end": 18},
            "typical_data_transfer": {"max_mb_per_hour": 50},
            "common_processes": ["chrome.exe", "firefox.exe", "outlook.exe"],
            "trusted_ips": ["192.168.1.0/24", "10.0.0.0/8"],
            "admin_users": ["admin", "administrator", "root"]
        }
    
    async def analyze_log_entry(self, log_entry: str, log_source: str) -> Optional[ThreatAlert]:
        """
        Analyze a single log entry for threats
        """
        try:
            # Sanitize input
            log_entry = sanitize_input(log_entry)
            
            # Rule-based detection
            rule_matches = self._apply_detection_rules(log_entry, log_source)
            
            # AI-powered analysis
            ai_analysis = await self._ai_threat_analysis(log_entry, log_source)
            
            # Behavioral analysis
            behavioral_anomaly = self._detect_behavioral_anomaly(log_entry, log_source)
            
            # Threat intelligence lookup
            intel_matches = await self._check_threat_intelligence(log_entry)
            
            # Combine all detection methods
            threat_indicators = rule_matches + behavioral_anomaly + intel_matches
            
            if threat_indicators or ai_analysis.get('threat_detected', False):
                return await self._create_threat_alert(
                    log_entry, log_source, threat_indicators, ai_analysis
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Error analyzing log entry: {e}")
            return None
    
    def _apply_detection_rules(self, log_entry: str, log_source: str) -> List[Dict]:
        """
        Apply signature-based detection rules
        """
        matches = []
        
        # Check brute force attempts
        if re.search(self.detection_rules["brute_force"]["pattern"], log_entry, re.IGNORECASE):
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", log_entry)
            if ip_match:
                matches.append({
                    "rule": "brute_force",
                    "severity": "HIGH",
                    "indicator": ip_match.group(1),
                    "description": "Brute force login attempt detected"
                })
        
        # Check privilege escalation
        if re.search(self.detection_rules["privilege_escalation"]["pattern"], log_entry, re.IGNORECASE):
            matches.append({
                "rule": "privilege_escalation",
                "severity": "HIGH",
                "description": "Privilege escalation attempt detected"
            })
        
        # Check malicious commands
        for pattern in self.detection_rules["malicious_commands"]["patterns"]:
            if re.search(pattern, log_entry, re.IGNORECASE):
                matches.append({
                    "rule": "malicious_command",
                    "severity": "CRITICAL",
                    "pattern": pattern,
                    "description": "Malicious command execution detected"
                })
        
        # Check data exfiltration patterns
        for pattern in self.detection_rules["data_exfiltration"]["patterns"]:
            if re.search(pattern, log_entry, re.IGNORECASE):
                matches.append({
                    "rule": "data_exfiltration",
                    "severity": "HIGH",
                    "pattern": pattern,
                    "description": "Potential data exfiltration detected"
                })
        
        return matches
    
    async def _ai_threat_analysis(self, log_entry: str, log_source: str) -> Dict:
        """
        Use Groq AI for advanced threat analysis
        """
        try:
            prompt = f"""
            Analyze this log entry for potential security threats:
            
            Log Source: {log_source}
            Log Entry: {log_entry}
            
            Current Time: {datetime.now().isoformat()}
            
            Provide a JSON response with:
            1. threat_detected (boolean)
            2. threat_type (MALWARE/PHISHING/BRUTE_FORCE/etc.)
            3. confidence_score (0.0-1.0)
            4. severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)
            5. indicators (list of IoCs found)
            6. mitre_techniques (list of MITRE ATT&CK techniques)
            7. analysis_summary (brief explanation)
            8. false_positive_likelihood (0.0-1.0)
            9. recommended_actions (list)
            10. affected_systems (list)
            """
            
            response = self.groq_client.chat.completions.create(
                model="mixtral-8x7b-32768",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in threat detection and log analysis. Provide accurate, actionable threat intelligence."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=800
            )
            
            analysis = json.loads(response.choices[0].message.content)
            logger.info(f"AI threat analysis completed with confidence: {analysis.get('confidence_score', 0)}")
            return analysis
            
        except Exception as e:
            logger.error(f"AI threat analysis failed: {e}")
            return {
                "threat_detected": False,
                "confidence_score": 0.0,
                "analysis_summary": "AI analysis unavailable"
            }
    
    def _detect_behavioral_anomaly(self, log_entry: str, log_source: str) -> List[Dict]:
        """
        Detect behavioral anomalies based on baseline
        """
        anomalies = []
        
        # Check login time anomalies
        if "login" in log_entry.lower() or "logon" in log_entry.lower():
            current_hour = datetime.now().hour
            baseline = self.baseline_behavior["normal_login_hours"]
            
            if current_hour < baseline["start"] or current_hour > baseline["end"]:
                anomalies.append({
                    "type": "temporal_anomaly",
                    "severity": "MEDIUM",
                    "description": f"Login attempt outside normal hours: {current_hour}:00"
                })
        
        # Check for admin activity
        admin_keywords = ["administrator", "admin", "root", "sudo"]
        if any(keyword in log_entry.lower() for keyword in admin_keywords):
            anomalies.append({
                "type": "privileged_activity",
                "severity": "MEDIUM",
                "description": "Administrative activity detected"
            })
        
        # Check for unusual network connections
        ip_pattern = r"(\d+\.\d+\.\d+\.\d+)"
        ip_matches = re.findall(ip_pattern, log_entry)
        
        for ip in ip_matches:
            try:
                ip_obj = ipaddress.ip_address(ip)
                is_trusted = any(
                    ip_obj in ipaddress.ip_network(trusted_net) 
                    for trusted_net in self.baseline_behavior["trusted_ips"]
                )
                
                if not is_trusted and not ip_obj.is_private:
                    anomalies.append({
                        "type": "untrusted_network",
                        "severity": "MEDIUM",
                        "indicator": ip,
                        "description": f"Connection to untrusted external IP: {ip}"
                    })
            except ValueError:
                continue
        
        return anomalies
    
    async def _check_threat_intelligence(self, log_entry: str) -> List[Dict]:
        """
        Check log entry against threat intelligence feeds
        """
        matches = []
        
        try:
            # Extract potential IoCs
            ip_pattern = r"(\d+\.\d+\.\d+\.\d+)"
            domain_pattern = r"([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}"
            hash_pattern = r"\b[a-fA-F0-9]{32,64}\b"
            
            ips = re.findall(ip_pattern, log_entry)
            domains = re.findall(domain_pattern, log_entry)
            hashes = re.findall(hash_pattern, log_entry)
            
            # Check IPs against threat intel
            for ip in ips:
                if validate_ip_address(ip):
                    intel_result = await self.threat_intel.check_ip(ip)
                    if intel_result.get("malicious", False):
                        matches.append({
                            "type": "malicious_ip",
                            "severity": "HIGH",
                            "indicator": ip,
                            "description": f"Known malicious IP detected: {ip}",
                            "threat_intel": intel_result
                        })
            
            # Check domains against threat intel
            for domain in domains:
                intel_result = await self.threat_intel.check_domain(domain)
                if intel_result.get("malicious", False):
                    matches.append({
                        "type": "malicious_domain",
                        "severity": "HIGH",
                        "indicator": domain,
                        "description": f"Known malicious domain detected: {domain}",
                        "threat_intel": intel_result
                    })
            
            # Check file hashes
            for file_hash in hashes:
                intel_result = await self.threat_intel.check_hash(file_hash)
                if intel_result.get("malicious", False):
                    matches.append({
                        "type": "malicious_file",
                        "severity": "CRITICAL",
                        "indicator": file_hash,
                        "description": f"Known malicious file hash detected: {file_hash}",
                        "threat_intel": intel_result
                    })
            
        except Exception as e:
            logger.error(f"Threat intelligence lookup failed: {e}")
        
        return matches
    
    async def _create_threat_alert(
        self, 
        log_entry: str, 
        log_source: str, 
        indicators: List[Dict], 
        ai_analysis: Dict
    ) -> ThreatAlert:
        """
        Create a comprehensive threat alert
        """
        alert_id = f"THREAT-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{hashlib.md5(log_entry.encode()).hexdigest()[:8]}"
        
        # Determine overall severity
        severity_scores = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        max_severity = "INFO"
        
        for indicator in indicators:
            if severity_scores.get(indicator.get("severity", "INFO"), 0) > severity_scores[max_severity]:
                max_severity = indicator["severity"]
        
        ai_severity = ai_analysis.get("severity", "INFO")
        if severity_scores.get(ai_severity, 0) > severity_scores[max_severity]:
            max_severity = ai_severity
        
        # Extract affected systems
        affected_systems = ai_analysis.get("affected_systems", [])
        if not affected_systems:
            # Try to extract from log
            hostname_pattern = r"([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*)"
            potential_hosts = re.findall(hostname_pattern, log_entry)
            affected_systems = potential_hosts[:3]  # Limit to first 3
        
        # Compile all indicators
        all_indicators = []
        for indicator in indicators:
            if "indicator" in indicator:
                all_indicators.append(indicator["indicator"])
        all_indicators.extend(ai_analysis.get("indicators", []))
        
        # Generate remediation steps
        remediation_steps = ai_analysis.get("recommended_actions", [])
        if not remediation_steps:
            remediation_steps = self._generate_default_remediation(max_severity, indicators)
        
        # Calculate confidence and false positive probability
        confidence = ai_analysis.get("confidence_score", 0.7)
        if indicators:
            # Boost confidence if rule-based detection also triggered
            confidence = min(confidence + 0.2, 1.0)
        
        false_positive_prob = ai_analysis.get("false_positive_likelihood", 0.3)
        
        alert = ThreatAlert(
            alert_id=alert_id,
            timestamp=datetime.now().isoformat(),
            threat_type=ai_analysis.get("threat_type", "ANOMALOUS_BEHAVIOR"),
            severity=max_severity,
            confidence=confidence,
            source_ip=self._extract_source_ip(log_entry),
            destination_ip=self._extract_destination_ip(log_entry),
            affected_systems=affected_systems,
            indicators=list(set(all_indicators)),  # Remove duplicates
            mitre_techniques=ai_analysis.get("mitre_techniques", []),
            raw_logs=[log_entry],
            analysis={
                "rule_matches": indicators,
                "ai_analysis": ai_analysis,
                "log_source": log_source
            },
            remediation_steps=remediation_steps,
            false_positive_probability=false_positive_prob
        )
        
        logger.info(f"Threat alert created: {alert_id} - {max_severity}")
        return alert
    
    def _extract_source_ip(self, log_entry: str) -> Optional[str]:
        """Extract source IP from log entry"""
        patterns = [
            r"from\s+(\d+\.\d+\.\d+\.\d+)",
            r"src[_=](\d+\.\d+\.\d+\.\d+)",
            r"source[_=](\d+\.\d+\.\d+\.\d+)"
        ]
        
        for pattern in patterns:
            match = re.search(pattern, log_entry, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
    
    def _extract_destination_ip(self, log_entry: str) -> Optional[str]:
        """Extract destination IP from log entry"""
        patterns = [
            r"to\s+(\d+\.\d+\.\d+\.\d+)",
            r"dst[_=](\d+\.\d+\.\d+\.\d+)",
            r"destination[_=](\d+\.\d+\.\d+\.\d+)"
        ]
        
        for pattern in patterns:
            match = re.search(pattern, log_entry, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
    
    def _generate_default_remediation(self, severity: str, indicators: List[Dict]) -> List[str]:
        """Generate default remediation steps"""
        steps = []
        
        if severity == "CRITICAL":
            steps.extend([
                "Immediate isolation of affected systems",
                "Contact incident response team",
                "Preserve evidence for forensic analysis"
            ])
        elif severity == "HIGH":
            steps.extend([
                "Monitor affected systems closely",
                "Review user access and permissions",
                "Consider temporary access restrictions"
            ])
        
        # Add specific steps based on threat type
        for indicator in indicators:
            rule = indicator.get("rule", "")
            if rule == "brute_force":
                steps.append("Block source IP address")
                steps.append("Implement account lockout policies")
            elif rule == "malicious_command":
                steps.append("Kill suspicious processes")
                steps.append("Scan system for malware")
            elif rule == "data_exfiltration":
                steps.append("Review data access logs")
                steps.append("Check network traffic for unusual data transfers")
        
        return list(set(steps))  # Remove duplicates
    
    async def process_log_batch(self, log_entries: List[Dict]) -> List[ThreatAlert]:
        """
        Process multiple log entries efficiently
        """
        logger.info(f"Processing batch of {len(log_entries)} log entries")
        threats = []
        
        # Process in parallel for better performance
        tasks = []
        for log_data in log_entries:
            log_entry = log_data.get("message", "")
            log_source = log_data.get("source", "unknown")
            tasks.append(self.analyze_log_entry(log_entry, log_source))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, ThreatAlert):
                threats.append(result)
            elif isinstance(result, Exception):
                logger.error(f"Error processing log entry: {result}")
        
        logger.info(f"Detected {len(threats)} threats from batch")
        return threats
    
    async def continuous_monitoring(self, log_stream_callback):
        """
        Continuous threat monitoring mode
        """
        logger.info("Starting continuous threat monitoring")
        
        while True:
            try:
                # Get new log entries from callback
                log_entries = await log_stream_callback()
                
                if log_entries:
                    threats = await self.process_log_batch(log_entries)
                    
                    # Handle detected threats
                    for threat in threats:
                        await self._handle_threat_alert(threat)
                
                # Wait before next poll
                await asyncio.sleep(settings.MONITORING_INTERVAL)
                
            except Exception as e:
                logger.error(f"Error in continuous monitoring: {e}")
                await asyncio.sleep(60)  # Wait 1 minute before retrying
    
    async def _handle_threat_alert(self, threat: ThreatAlert):
        """
        Handle a detected threat alert
        """
        logger.warning(f"THREAT DETECTED: {threat.alert_id} - {threat.severity}")
        
        # Save to database/file
        self._save_threat_alert(threat)
        
        # Send notifications based on severity
        if threat.severity in ["CRITICAL", "HIGH"]:
            await self._send_urgent_notification(threat)
        
        # Auto-response for certain threat types
        if threat.severity == "CRITICAL" and threat.confidence > 0.8:
            await self._initiate_auto_response(threat)
    
    def _save_threat_alert(self, threat: ThreatAlert):
        """Save threat alert to storage"""
        try:
            filename = f"data/logs/threat_{threat.alert_id}.json"
            with open(filename, 'w') as f:
                json.dump(asdict(threat), f, indent=2, default=str)
            logger.info(f"Threat alert saved: {filename}")
        except Exception as e:
            logger.error(f"Failed to save threat alert: {e}")
    
    async def _send_urgent_notification(self, threat: ThreatAlert):
        """Send urgent notification for high-severity threats"""
        # Implementation would integrate with Slack, email, SMS, etc.
        logger.critical(f"URGENT THREAT NOTIFICATION: {threat.alert_id}")
    
    async def _initiate_auto_response(self, threat: ThreatAlert):
        """Initiate automated response for critical threats"""
        logger.critical(f"INITIATING AUTO-RESPONSE for {threat.alert_id}")
        # Implementation would include automated containment actions

# Main execution for testing
if __name__ == "__main__":
    async def main():
        agent = ThreatDetectionAgent()
        
        # Test with sample log entries
        test_logs = [
            {
                "message": "Aug 14 10:30:00 server1 sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
                "source": "auth.log"
            },
            {
                "message": "2024-08-14 11:15:22 [INFO] User admin executed: powershell.exe -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwA=",
                "source": "system.log"
            }
        ]
        
        threats = await agent.process_log_batch(test_logs)
        
        print(f"Threats detected: {len(threats)}")
        for threat in threats:
            print(f"- {threat.alert_id}: {threat.threat_type} ({threat.severity})")
    
    asyncio.run(main())