#!/usr/bin/env python3
"""
Threat Hunting Agent - Proactive Threat Discovery and Analysis
Autonomously hunts for advanced threats and indicators of compromise.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
import ipaddress

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

class HuntStatus(Enum):
    """Threat hunt status"""
    SCHEDULED = "SCHEDULED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

class ThreatCategory(Enum):
    """Threat hunting categories"""
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    PERSISTENCE = "PERSISTENCE"
    COMMAND_CONTROL = "COMMAND_CONTROL"
    EXFILTRATION = "EXFILTRATION"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    DEFENSE_EVASION = "DEFENSE_EVASION"
    DISCOVERY = "DISCOVERY"
    COLLECTION = "COLLECTION"
    IMPACT = "IMPACT"

@dataclass
class HuntHypothesis:
    """Threat hunting hypothesis"""
    hypothesis_id: str
    name: str
    description: str
    mitre_techniques: List[str]
    threat_category: str
    priority: int
    data_sources: List[str]
    search_queries: List[str]
    expected_indicators: List[str]
    confidence_threshold: float
    created_date: str
    last_updated: str

@dataclass
class HuntResult:
    """Threat hunt execution result"""
    hunt_id: str
    hypothesis: HuntHypothesis
    execution_timestamp: str
    status: str
    findings: List[Dict[str, Any]]
    iocs_discovered: List[str]
    affected_systems: List[str]
    confidence_score: float
    false_positive_likelihood: float
    mitre_mappings: List[str]
    recommendations: List[str]
    evidence: List[Dict[str, Any]]
    timeline: List[Dict[str, Any]]
    ai_analysis: Dict[str, Any]
    execution_time_seconds: float
    next_hunt_suggestions: List[str]

class ThreatHuntingAgent:
    """
    Autonomous threat hunting agent for proactive threat discovery
    """
    
    def __init__(self):
        self.groq_client = Groq(api_key=settings.GROQ_API_KEY)
        self.threat_intel = ThreatIntelligence()
        self.hunt_hypotheses = self._load_hunt_hypotheses()
        self.hunt_history = self._load_hunt_history()
        self.data_sources = self._initialize_data_sources()
        self.active_hunts = {}
        
    def _load_hunt_hypotheses(self) -> Dict[str, HuntHypothesis]:
        """Load predefined threat hunting hypotheses"""
        hypotheses = {
            "lateral_movement_smb": HuntHypothesis(
                hypothesis_id="HUNT-001",
                name="Lateral Movement via SMB",
                description="Detect lateral movement using SMB connections to multiple hosts",
                mitre_techniques=["T1021.002", "T1135", "T1083"],
                threat_category="LATERAL_MOVEMENT",
                priority=8,
                data_sources=["network_logs", "windows_events", "smb_logs"],
                search_queries=[
                    "EventID:5156 AND DestPort:445",
                    "smb_connection AND multiple_hosts",
                    "net_use OR net_view"
                ],
                expected_indicators=["multiple_smb_connections", "admin_shares", "rapid_succession"],
                confidence_threshold=0.7,
                created_date=datetime.now().isoformat(),
                last_updated=datetime.now().isoformat()
            ),
            "privilege_escalation_tokens": HuntHypothesis(
                hypothesis_id="HUNT-002", 
                name="Token Manipulation for Privilege Escalation",
                description="Hunt for token manipulation techniques used for privilege escalation",
                mitre_techniques=["T1134", "T1134.001", "T1134.002"],
                threat_category="PRIVILEGE_ESCALATION",
                priority=9,
                data_sources=["windows_events", "process_logs", "security_logs"],
                search_queries=[
                    "EventID:4648 OR EventID:4624",
                    "SeDebugPrivilege OR SeImpersonatePrivilege",
                    "CreateProcessWithTokenW OR ImpersonateLoggedOnUser"
                ],
                expected_indicators=["token_creation", "impersonation", "privilege_changes"],
                confidence_threshold=0.8,
                created_date=datetime.now().isoformat(),
                last_updated=datetime.now().isoformat()
            ),
            "persistence_scheduled_tasks": HuntHypothesis(
                hypothesis_id="HUNT-003",
                name="Persistence via Scheduled Tasks",
                description="Detect malicious scheduled tasks used for persistence",
                mitre_techniques=["T1053.005", "T1053"],
                threat_category="PERSISTENCE",
                priority=7,
                data_sources=["windows_events", "task_scheduler_logs"],
                search_queries=[
                    "EventID:4698 OR EventID:4702",
                    "schtasks /create OR Register-ScheduledTask",
                    "TaskScheduler/Operational"
                ],
                expected_indicators=["suspicious_task_creation", "unusual_execution_time", "hidden_tasks"],
                confidence_threshold=0.6,
                created_date=datetime.now().isoformat(),
                last_updated=datetime.now().isoformat()
            ),
            "c2_dns_tunneling": HuntHypothesis(
                hypothesis_id="HUNT-004",
                name="Command & Control via DNS Tunneling",
                description="Identify DNS tunneling for command and control communications",
                mitre_techniques=["T1071.004", "T1572"],
                threat_category="COMMAND_CONTROL",
                priority=8,
                data_sources=["dns_logs", "network_traffic"],
                search_queries=[
                    "dns_query_type:TXT AND response_length:>100",
                    "dns_subdomain_count:>5",
                    "base64_encoded_dns_queries"
                ],
                expected_indicators=["long_dns_queries", "frequent_dns_requests", "encoded_data"],
                confidence_threshold=0.7,
                created_date=datetime.now().isoformat(),
                last_updated=datetime.now().isoformat()
            ),
            "credential_dumping": HuntHypothesis(
                hypothesis_id="HUNT-005",
                name="Credential Dumping Activities",
                description="Hunt for credential dumping tools and techniques",
                mitre_techniques=["T1003", "T1003.001", "T1003.002", "T1003.003"],
                threat_category="CREDENTIAL_ACCESS",
                priority=9,
                data_sources=["process_logs", "memory_dumps", "security_events"],
                search_queries=[
                    "lsass.exe AND (procdump OR mimikatz OR sekurlsa)",
                    "EventID:4656 AND ObjectName:SAM",
                    "vssadmin create shadow OR ntdsutil"
                ],
                expected_indicators=["lsass_access", "sam_access", "shadow_copy_creation"],
                confidence_threshold=0.8,
                created_date=datetime.now().isoformat(),
                last_updated=datetime.now().isoformat()
            )
        }
        
        logger.info(f"Loaded {len(hypotheses)} hunting hypotheses")
        return hypotheses
    
    def _load_hunt_history(self) -> pd.DataFrame:
        """Load historical hunt results for pattern analysis"""
        try:
            # In production, load from database
            # For demo, create sample data
            sample_data = [
                {
                    "hunt_id": "HUNT-RUN-001",
                    "hypothesis_id": "HUNT-001",
                    "execution_date": "2024-08-13",
                    "findings_count": 3,
                    "true_positives": 1,
                    "false_positives": 2,
                    "execution_time": 45.2
                }
            ]
            return pd.DataFrame(sample_data)
        except Exception as e:
            logger.error(f"Failed to load hunt history: {e}")
            return pd.DataFrame()
    
    def _initialize_data_sources(self) -> Dict:
        """Initialize data source connections and configurations"""
        return {
            "elasticsearch": {
                "enabled": True,
                "host": "localhost:9200",
                "indices": ["winlogbeat-*", "packetbeat-*", "filebeat-*"]
            },
            "splunk": {
                "enabled": False,
                "host": "localhost:8089",
                "indexes": ["windows", "network", "security"]
            },
            "syslog": {
                "enabled": True,
                "host": "localhost:514",
                "facilities": ["auth", "daemon", "kern"]
            },
            "windows_events": {
                "enabled": True,
                "channels": ["Security", "System", "Application"]
            },
            "network_logs": {
                "enabled": True,
                "sources": ["firewall", "ids", "proxy"]
            }
        }
    
    async def execute_hunt(self, hypothesis_id: str, time_range_hours: int = 24) -> HuntResult:
        """
        Execute a specific threat hunt
        """
        logger.info(f"Executing hunt: {hypothesis_id}")
        
        if hypothesis_id not in self.hunt_hypotheses:
            raise ValueError(f"Unknown hypothesis: {hypothesis_id}")
        
        hypothesis = self.hunt_hypotheses[hypothesis_id]
        hunt_id = f"HUNT-RUN-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{hypothesis_id}"
        
        start_time = datetime.now()
        self.active_hunts[hunt_id] = {"status": HuntStatus.RUNNING, "start_time": start_time}
        
        try:
            # Collect data from sources
            data_collection = await self._collect_hunt_data(hypothesis, time_range_hours)
            
            # Execute search queries
            search_results = await self._execute_search_queries(hypothesis, data_collection)
            
            # Analyze findings with AI
            ai_analysis = await self._ai_hunt_analysis(hypothesis, search_results)
            
            # Extract IOCs and evidence
            iocs_discovered = self._extract_iocs(search_results)
            evidence = self._compile_evidence(search_results, ai_analysis)
            
            # Build timeline
            timeline = self._build_timeline(search_results)
            
            # Generate recommendations
            recommendations = await self._generate_hunt_recommendations(hypothesis, ai_analysis, search_results)
            
            # Calculate metrics
            confidence_score = self._calculate_hunt_confidence(ai_analysis, search_results, hypothesis)
            false_positive_likelihood = self._assess_fp_likelihood(search_results, hypothesis)
            
            # Create result
            hunt_result = HuntResult(
                hunt_id=hunt_id,
                hypothesis=hypothesis,
                execution_timestamp=start_time.isoformat(),
                status=HuntStatus.COMPLETED.value,
                findings=search_results.get('findings', []),
                iocs_discovered=iocs_discovered,
                affected_systems=self._extract_affected_systems(search_results),
                confidence_score=confidence_score,
                false_positive_likelihood=false_positive_likelihood,
                mitre_mappings=hypothesis.mitre_techniques,
                recommendations=recommendations,
                evidence=evidence,
                timeline=timeline,
                ai_analysis=ai_analysis,
                execution_time_seconds=(datetime.now() - start_time).total_seconds(),
                next_hunt_suggestions=ai_analysis.get('suggested_follow_up_hunts', [])
            )
            
            # Save result
            self._save_hunt_result(hunt_result)
            
            # Update hunt status
            self.active_hunts[hunt_id]["status"] = HuntStatus.COMPLETED
            
            logger.info(f"Hunt {hunt_id} completed with {len(hunt_result.findings)} findings")
            return hunt_result
            
        except Exception as e:
            logger.error(f"Hunt {hunt_id} failed: {e}")
            self.active_hunts[hunt_id]["status"] = HuntStatus.FAILED
            
            # Return failed result
            return HuntResult(
                hunt_id=hunt_id,
                hypothesis=hypothesis,
                execution_timestamp=start_time.isoformat(),
                status=HuntStatus.FAILED.value,
                findings=[],
                iocs_discovered=[],
                affected_systems=[],
                confidence_score=0.0,
                false_positive_likelihood=1.0,
                mitre_mappings=hypothesis.mitre_techniques,
                recommendations=[f"Hunt failed: {str(e)}"],
                evidence=[],
                timeline=[],
                ai_analysis={"error": str(e)},
                execution_time_seconds=(datetime.now() - start_time).total_seconds(),
                next_hunt_suggestions=[]
            )
    
    async def _collect_hunt_data(self, hypothesis: HuntHypothesis, time_range_hours: int) -> Dict:
        """
        Collect data from configured sources
        """
        logger.info(f"Collecting data for hunt: {hypothesis.name}")
        
        data_collection = {
            "time_range": {
                "start": (datetime.now() - timedelta(hours=time_range_hours)).isoformat(),
                "end": datetime.now().isoformat()
            },
            "sources_queried": [],
            "total_events": 0,
            "data_quality": "GOOD"
        }
        
        # Query each required data source
        for source in hypothesis.data_sources:
            try:
                if source in self.data_sources and self.data_sources[source].get("enabled", False):
                    source_data = await self._query_data_source(source, hypothesis, time_range_hours)
                    data_collection[source] = source_data
                    data_collection["sources_queried"].append(source)
                    data_collection["total_events"] += source_data.get("event_count", 0)
                else:
                    logger.warning(f"Data source {source} not available or disabled")
            except Exception as e:
                logger.error(f"Error querying {source}: {e}")
                data_collection[source] = {"error": str(e), "event_count": 0}
        
        logger.info(f"Data collection completed: {data_collection['total_events']} events from {len(data_collection['sources_queried'])} sources")
        return data_collection
    
    async def _query_data_source(self, source: str, hypothesis: HuntHypothesis, time_range_hours: int) -> Dict:
        """
        Query a specific data source
        """
        # In production, this would connect to actual data sources
        # For demo, simulate data retrieval
        
        if source == "windows_events":
            return await self._query_windows_events(hypothesis, time_range_hours)
        elif source == "network_logs":
            return await self._query_network_logs(hypothesis, time_range_hours)
        elif source == "process_logs":
            return await self._query_process_logs(hypothesis, time_range_hours)
        else:
            # Generic data source simulation
            return {
                "source_type": source,
                "event_count": 150,
                "sample_events": [
                    {"timestamp": datetime.now().isoformat(), "event": f"Sample {source} event 1"},
                    {"timestamp": datetime.now().isoformat(), "event": f"Sample {source} event 2"}
                ]
            }
    
    async def _query_windows_events(self, hypothesis: HuntHypothesis, time_range_hours: int) -> Dict:
        """Query Windows Event Logs"""
        # Simulate Windows event log queries
        sample_events = []
        
        if "T1021.002" in hypothesis.mitre_techniques:  # SMB lateral movement
            sample_events.extend([
                {
                    "timestamp": datetime.now().isoformat(),
                    "event_id": 5156,
                    "source_ip": "192.168.1.50",
                    "dest_ip": "192.168.1.100",
                    "dest_port": 445,
                    "process": "explorer.exe",
                    "user": "admin"
                },
                {
                    "timestamp": datetime.now().isoformat(),
                    "event_id": 5156,
                    "source_ip": "192.168.1.50", 
                    "dest_ip": "192.168.1.101",
                    "dest_port": 445,
                    "process": "explorer.exe",
                    "user": "admin"
                }
            ])
        
        if "T1134" in hypothesis.mitre_techniques:  # Token manipulation
            sample_events.extend([
                {
                    "timestamp": datetime.now().isoformat(),
                    "event_id": 4648,
                    "user": "admin",
                    "target_user": "SYSTEM",
                    "process": "suspicious.exe",
                    "privileges": "SeDebugPrivilege"
                }
            ])
        
        return {
            "source_type": "windows_events",
            "event_count": len(sample_events),
            "events": sample_events
        }
    
    async def _query_network_logs(self, hypothesis: HuntHypothesis, time_range_hours: int) -> Dict:
        """Query network logs"""
        sample_events = []
        
        if "T1071.004" in hypothesis.mitre_techniques:  # DNS tunneling
            sample_events.extend([
                {
                    "timestamp": datetime.now().isoformat(),
                    "query_type": "TXT",
                    "domain": "suspicious-domain.com",
                    "query": "ZGF0YWV4ZmlsdHJhdGlvbi1iYXNlNjQ=.suspicious-domain.com",
                    "response_length": 255,
                    "source_ip": "192.168.1.50"
                }
            ])
        
        return {
            "source_type": "network_logs",
            "event_count": len(sample_events),
            "events": sample_events
        }
    
    async def _query_process_logs(self, hypothesis: HuntHypothesis, time_range_hours: int) -> Dict:
        """Query process execution logs"""
        sample_events = []
        
        if "T1003" in hypothesis.mitre_techniques:  # Credential dumping
            sample_events.extend([
                {
                    "timestamp": datetime.now().isoformat(),
                    "process": "mimikatz.exe",
                    "command_line": "sekurlsa::logonpasswords",
                    "parent_process": "cmd.exe",
                    "user": "admin",
                    "pid": 1234
                }
            ])
        
        return {
            "source_type": "process_logs", 
            "event_count": len(sample_events),
            "events": sample_events
        }
    
    async def _execute_search_queries(self, hypothesis: HuntHypothesis, data_collection: Dict) -> Dict:
        """
        Execute search queries against collected data
        """
        logger.info(f"Executing search queries for {hypothesis.name}")
        
        findings = []
        query_results = {}
        
        for i, query in enumerate(hypothesis.search_queries):
            try:
                # Execute query against relevant data sources
                query_matches = await self._execute_single_query(query, data_collection, hypothesis)
                query_results[f"query_{i+1}"] = {
                    "query": query,
                    "matches": query_matches,
                    "match_count": len(query_matches)
                }
                findings.extend(query_matches)
                
            except Exception as e:
                logger.error(f"Error executing query '{query}': {e}")
                query_results[f"query_{i+1}"] = {
                    "query": query,
                    "error": str(e),
                    "matches": [],
                    "match_count": 0
                }
        
        # Remove duplicates and correlate findings
        unique_findings = self._deduplicate_findings(findings)
        correlated_findings = self._correlate_findings(unique_findings, hypothesis)
        
        return {
            "query_results": query_results,
            "findings": correlated_findings,
            "total_matches": len(unique_findings),
            "correlated_matches": len(correlated_findings)
        }
    
    async def _execute_single_query(self, query: str, data_collection: Dict, hypothesis: HuntHypothesis) -> List[Dict]:
        """Execute a single search query"""
        matches = []
        
        # Parse query and determine applicable data sources
        applicable_sources = self._determine_applicable_sources(query, hypothesis.data_sources)
        
        for source in applicable_sources:
            if source in data_collection and "events" in data_collection[source]:
                source_matches = self._search_events(query, data_collection[source]["events"])
                for match in source_matches:
                    match["data_source"] = source
                    match["query_matched"] = query
                matches.extend(source_matches)
        
        return matches
    
    def _determine_applicable_sources(self, query: str, available_sources: List[str]) -> List[str]:
        """Determine which data sources are applicable for a query"""
        applicable = []
        
        query_lower = query.lower()
        
        # Map query patterns to data sources
        source_patterns = {
            "windows_events": ["eventid", "event_id", "logon", "token", "privilege"],
            "network_logs": ["dns", "ip", "port", "domain", "connection"],
            "process_logs": ["process", "command", "exe", "pid", "parent"],
            "smb_logs": ["smb", "445", "share", "net_use"],
            "security_logs": ["authentication", "authorization", "access"]
        }
        
        for source in available_sources:
            if source in source_patterns:
                if any(pattern in query_lower for pattern in source_patterns[source]):
                    applicable.append(source)
            else:
                # Default: include all available sources if no specific mapping
                applicable.append(source)
        
        return applicable if applicable else available_sources
    
    def _search_events(self, query: str, events: List[Dict]) -> List[Dict]:
        """Search events based on query criteria"""
        matches = []
        query_lower = query.lower()
        
        for event in events:
            # Simple pattern matching for demo
            event_str = json.dumps(event, default=str).lower()
            
            # Handle different query formats
            if "and" in query_lower:
                # AND logic
                terms = [term.strip() for term in query_lower.split(" and ")]
                if all(self._match_term(term, event, event_str) for term in terms):
                    matches.append(event)
            elif "or" in query_lower:
                # OR logic
                terms = [term.strip() for term in query_lower.split(" or ")]
                if any(self._match_term(term, event, event_str) for term in terms):
                    matches.append(event)
            else:
                # Single term
                if self._match_term(query_lower, event, event_str):
                    matches.append(event)
        
        return matches
    
    def _match_term(self, term: str, event: Dict, event_str: str) -> bool:
        """Match a search term against an event"""
        # Handle specific field matches
        if ":" in term:
            field, value = term.split(":", 1)
            field = field.strip()
            value = value.strip()
            
            # Handle numeric comparisons
            if value.startswith(">"):
                try:
                    threshold = float(value[1:])
                    event_value = event.get(field, 0)
                    return float(event_value) > threshold
                except:
                    return False
            else:
                # Exact or substring match
                return value in str(event.get(field, "")).lower()
        else:
            # General substring match
            return term in event_str
    
    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """Remove duplicate findings"""
        unique_findings = []
        seen_hashes = set()
        
        for finding in findings:
            # Create hash of key fields to identify duplicates
            key_fields = ["timestamp", "source_ip", "process", "event_id"]
            hash_data = {k: finding.get(k, "") for k in key_fields if k in finding}
            finding_hash = hashlib.md5(json.dumps(hash_data, sort_keys=True).encode()).hexdigest()
            
            if finding_hash not in seen_hashes:
                unique_findings.append(finding)
                seen_hashes.add(finding_hash)
        
        return unique_findings
    
    def _correlate_findings(self, findings: List[Dict], hypothesis: HuntHypothesis) -> List[Dict]:
        """Correlate findings to identify related events"""
        if len(findings) <= 1:
            return findings
        
        # Group findings by common attributes
        correlation_groups = {}
        
        for finding in findings:
            # Correlation keys based on hypothesis type
            if hypothesis.threat_category == "LATERAL_MOVEMENT":
                key = finding.get("source_ip", "unknown")
            elif hypothesis.threat_category == "CREDENTIAL_ACCESS":
                key = finding.get("user", "unknown")
            else:
                key = finding.get("process", finding.get("user", "unknown"))
            
            if key not in correlation_groups:
                correlation_groups[key] = []
            correlation_groups[key].append(finding)
        
        # Only return groups with multiple related events
        correlated_findings = []
        for key, group in correlation_groups.items():
            if len(group) >= 2:  # At least 2 related events
                # Add correlation metadata
                for finding in group:
                    finding["correlation_key"] = key
                    finding["related_events_count"] = len(group)
                correlated_findings.extend(group)
            elif len(group) == 1:
                # Single events might still be significant
                group[0]["correlation_key"] = key
                group[0]["related_events_count"] = 1
                correlated_findings.extend(group)
        
        return correlated_findings
    
    async def _ai_hunt_analysis(self, hypothesis: HuntHypothesis, search_results: Dict) -> Dict:
        """
        Use Groq AI to analyze hunt results
        """
        try:
            findings_summary = {
                "total_findings": len(search_results.get("findings", [])),
                "query_results": search_results.get("query_results", {}),
                "sample_findings": search_results.get("findings", [])[:5]  # First 5 findings
            }
            
            prompt = f"""
            Analyze these threat hunting results:
            
            Hunt Hypothesis: {hypothesis.name}
            Description: {hypothesis.description}
            MITRE Techniques: {hypothesis.mitre_techniques}
            Threat Category: {hypothesis.threat_category}
            
            Search Results Summary:
            {json.dumps(findings_summary, indent=2, default=str)}
            
            Expected Indicators: {hypothesis.expected_indicators}
            
            Provide a comprehensive JSON analysis with:
            1. threat_detected (boolean)
            2. confidence_score (0.0-1.0)
            3. severity_assessment (CRITICAL/HIGH/MEDIUM/LOW)
            4. true_positive_likelihood (0.0-1.0)
            5. attack_progression_stage (Initial Access/Execution/Persistence/etc.)
            6. threat_actor_characteristics (list)
            7. indicators_matched (list of matched expected indicators)
            8. additional_indicators_found (list)
            9. attack_timeline_analysis (chronological analysis)
            10. affected_systems_analysis
            11. recommended_containment_actions (list)
            12. recommended_investigation_steps (list)
            13. suggested_follow_up_hunts (list)
            14. mitre_technique_confidence (dict mapping techniques to confidence)
            15. evidence_quality_assessment (HIGH/MEDIUM/LOW)
            16. business_impact_potential (description)
            17. analyst_recommendations (list)
            """
            
            response = self.groq_client.chat.completions.create(
                model="mixtral-8x7b-32768",
                messages=[
                    {"role": "system", "content": "You are an expert threat hunter and incident response analyst. Provide thorough, accurate analysis of hunting results."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=1500
            )
            
            analysis = json.loads(response.choices[0].message.content)
            logger.info(f"AI hunt analysis completed with confidence: {analysis.get('confidence_score', 0)}")
            return analysis
            
        except Exception as e:
            logger.error(f"AI hunt analysis failed: {e}")
            return {
                "threat_detected": len(search_results.get("findings", [])) > 0,
                "confidence_score": 0.5,
                "severity_assessment": "MEDIUM",
                "analysis_error": str(e)
            }
    
    def _extract_iocs(self, search_results: Dict) -> List[str]:
        """Extract Indicators of Compromise from findings"""
        iocs = set()
        
        findings = search_results.get("findings", [])
        
        for finding in findings:
            # Extract IP addresses
            if "source_ip" in finding:
                iocs.add(f"ip:{finding['source_ip']}")
            if "dest_ip" in finding:
                iocs.add(f"ip:{finding['dest_ip']}")
            
            # Extract domains
            if "domain" in finding:
                iocs.add(f"domain:{finding['domain']}")
            
            # Extract file hashes
            if "hash" in finding:
                iocs.add(f"hash:{finding['hash']}")
            
            # Extract processes
            if "process" in finding:
                iocs.add(f"process:{finding['process']}")
            
            # Extract command lines
            if "command_line" in finding:
                iocs.add(f"cmdline:{finding['command_line'][:100]}")  # Truncate long commands
        
        return list(iocs)
    
    def _compile_evidence(self, search_results: Dict, ai_analysis: Dict) -> List[Dict]:
        """Compile evidence packages from hunt results"""
        evidence = []
        
        findings = search_results.get("findings", [])
        
        for i, finding in enumerate(findings):
            evidence_item = {
                "evidence_id": f"EVIDENCE-{i+1}",
                "type": "log_event",
                "source": finding.get("data_source", "unknown"),
                "timestamp": finding.get("timestamp"),
                "content": finding,
                "relevance_score": 0.8 if finding.get("related_events_count", 0) > 1 else 0.6,
                "mitre_mapping": self._map_finding_to_mitre(finding, ai_analysis)
            }
            evidence.append(evidence_item)
        
        return evidence
    
    def _map_finding_to_mitre(self, finding: Dict, ai_analysis: Dict) -> List[str]:
        """Map individual finding to MITRE techniques"""
        # Use AI analysis technique confidence if available
        technique_confidence = ai_analysis.get("mitre_technique_confidence", {})
        
        mapped_techniques = []
        for technique, confidence in technique_confidence.items():
            if confidence > 0.5:  # Only include high-confidence mappings
                mapped_techniques.append(technique)
        
        return mapped_techniques
    
    def _build_timeline(self, search_results: Dict) -> List[Dict]:
        """Build chronological timeline of events"""
        findings = search_results.get("findings", [])
        
        # Sort findings by timestamp
        timestamped_findings = [f for f in findings if f.get("timestamp")]
        timestamped_findings.sort(key=lambda x: x.get("timestamp", ""))