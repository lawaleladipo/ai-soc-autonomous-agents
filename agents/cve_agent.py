#!/usr/bin/env python3
"""
CVE Agent - Autonomous CVE Ingestion and Prioritization
Monitors CVE feeds, assesses risk, and prioritizes vulnerabilities.
"""

import asyncio
import json
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

import requests
from groq import Groq
import pandas as pd
from utils.logger import get_logger
from utils.security import sanitize_input, validate_cve_format
from config.settings import Settings

# Initialize logger and settings
logger = get_logger(__name__)
settings = Settings()

class CVESeverity(Enum):
    """CVE Severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class CVEEntry:
    """CVE Entry data model"""
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    published_date: str
    modified_date: str
    affected_systems: List[str]
    exploitability: str
    remediation_priority: int
    mitre_techniques: List[str]
    threat_intelligence: Dict
    risk_score: float

class CVEAgent:
    """
    Autonomous CVE Agent for vulnerability management
    """
    
    def __init__(self):
        self.groq_client = Groq(api_key=settings.GROQ_API_KEY)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CybersecAgent/1.0',
            'Accept': 'application/json'
        })
        self.cve_cache = {}
        self.system_inventory = self._load_system_inventory()
        
    def _load_system_inventory(self) -> Dict:
        """Load system inventory for vulnerability mapping"""
        try:
            # In production, this would connect to CMDB/asset management
            return {
                "web-servers": ["nginx/1.20.1", "apache/2.4.41"],
                "databases": ["mysql/8.0.28", "postgresql/13.7"],
                "os": ["ubuntu/20.04", "centos/7.9", "windows/server2019"],
                "applications": ["docker/20.10.17", "kubernetes/1.24.3"]
            }
        except Exception as e:
            logger.error(f"Failed to load system inventory: {e}")
            return {}
    
    async def ingest_cve_feeds(self) -> List[Dict]:
        """
        Ingest CVE data from multiple sources
        """
        logger.info("Starting CVE feed ingestion")
        
        sources = [
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "https://cve.mitre.org/data/downloads/allitems-cvrf.xml"
        ]
        
        all_cves = []
        
        for source in sources:
            try:
                cves = await self._fetch_cve_data(source)
                all_cves.extend(cves)
                logger.info(f"Ingested {len(cves)} CVEs from {source}")
            except Exception as e:
                logger.error(f"Failed to ingest from {source}: {e}")
                continue
                
        # Remove duplicates and sort by severity
        unique_cves = self._deduplicate_cves(all_cves)
        logger.info(f"Total unique CVEs processed: {len(unique_cves)}")
        
        return unique_cves
    
    async def _fetch_cve_data(self, source_url: str) -> List[Dict]:
        """
        Fetch CVE data from a specific source
        """
        try:
            # Simulate CVE feed data (in production, fetch from actual feeds)
            sample_cves = [
                {
                    "cve_id": "CVE-2024-12345",
                    "description": "Critical buffer overflow in web server component",
                    "cvss_score": 9.8,
                    "severity": "CRITICAL",
                    "published_date": "2024-08-14T10:00:00Z",
                    "affected_products": ["nginx", "apache"],
                    "exploitability": "HIGH"
                },
                {
                    "cve_id": "CVE-2024-12346",
                    "description": "SQL injection vulnerability in database connector",
                    "cvss_score": 7.5,
                    "severity": "HIGH",
                    "published_date": "2024-08-13T15:30:00Z",
                    "affected_products": ["mysql", "postgresql"],
                    "exploitability": "MEDIUM"
                }
            ]
            return sample_cves
            
        except Exception as e:
            logger.error(f"Error fetching CVE data: {e}")
            return []
    
    def _deduplicate_cves(self, cves: List[Dict]) -> List[Dict]:
        """
        Remove duplicate CVEs and keep the most recent version
        """
        seen_cves = {}
        for cve in cves:
            cve_id = cve.get('cve_id')
            if cve_id not in seen_cves:
                seen_cves[cve_id] = cve
            else:
                # Keep the more recent version
                if cve.get('modified_date', '') > seen_cves[cve_id].get('modified_date', ''):
                    seen_cves[cve_id] = cve
                    
        return list(seen_cves.values())
    
    async def assess_risk_with_ai(self, cve_data: Dict) -> Tuple[float, Dict]:
        """
        Use Groq AI to assess CVE risk and provide detailed analysis
        """
        try:
            prompt = f"""
            Analyze this CVE and provide a comprehensive risk assessment:
            
            CVE ID: {cve_data.get('cve_id')}
            Description: {cve_data.get('description')}
            CVSS Score: {cve_data.get('cvss_score')}
            Affected Products: {cve_data.get('affected_products', [])}
            Exploitability: {cve_data.get('exploitability')}
            
            System Inventory: {json.dumps(self.system_inventory, indent=2)}
            
            Provide a JSON response with:
            1. risk_score (0-100)
            2. business_impact (LOW/MEDIUM/HIGH/CRITICAL)
            3. exploitability_assessment
            4. affected_systems_in_inventory
            5. remediation_priority (1-5, where 1 is highest)
            6. mitre_attack_techniques (list)
            7. threat_intelligence_summary
            8. recommended_actions (list)
            """
            
            response = self.groq_client.chat.completions.create(
                model="mixtral-8x7b-32768",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in vulnerability assessment. Provide accurate, actionable risk analysis."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=1000
            )
            
            analysis = json.loads(response.choices[0].message.content)
            risk_score = analysis.get('risk_score', 50.0)
            
            logger.info(f"AI risk assessment completed for {cve_data.get('cve_id')}: {risk_score}/100")
            return risk_score, analysis
            
        except Exception as e:
            logger.error(f"AI risk assessment failed: {e}")
            # Fallback to rule-based scoring
            return self._fallback_risk_scoring(cve_data), {}
    
    def _fallback_risk_scoring(self, cve_data: Dict) -> float:
        """
        Fallback rule-based risk scoring when AI fails
        """
        base_score = cve_data.get('cvss_score', 0.0) * 10
        
        # Adjust based on exploitability
        exploitability = cve_data.get('exploitability', '').upper()
        if exploitability == 'HIGH':
            base_score += 15
        elif exploitability == 'MEDIUM':
            base_score += 10
        elif exploitability == 'LOW':
            base_score += 5
            
        # Check if affects systems in inventory
        affected_products = cve_data.get('affected_products', [])
        inventory_match = any(
            product.lower() in str(self.system_inventory).lower() 
            for product in affected_products
        )
        
        if inventory_match:
            base_score += 20
            
        return min(base_score, 100.0)
    
    def map_to_mitre_attack(self, cve_data: Dict, ai_analysis: Dict) -> List[str]:
        """
        Map CVE to MITRE ATT&CK techniques
        """
        techniques = ai_analysis.get('mitre_attack_techniques', [])
        
        if not techniques:
            # Rule-based mapping fallback
            description = cve_data.get('description', '').lower()
            
            technique_keywords = {
                'T1190': ['remote', 'exploit', 'service'],
                'T1068': ['privilege', 'escalation', 'elevation'],
                'T1059': ['code execution', 'command', 'script'],
                'T1055': ['injection', 'process'],
                'T1003': ['credential', 'password', 'hash'],
                'T1078': ['account', 'login', 'authentication']
            }
            
            for technique, keywords in technique_keywords.items():
                if any(keyword in description for keyword in keywords):
                    techniques.append(technique)
        
        return techniques
    
    async def prioritize_vulnerabilities(self, cves: List[Dict]) -> List[CVEEntry]:
        """
        Prioritize vulnerabilities based on risk assessment
        """
        logger.info("Prioritizing vulnerabilities")
        prioritized_cves = []
        
        for cve in cves:
            try:
                # AI-powered risk assessment
                risk_score, ai_analysis = await self.assess_risk_with_ai(cve)
                
                # Map to MITRE ATT&CK
                mitre_techniques = self.map_to_mitre_attack(cve, ai_analysis)
                
                # Determine affected systems
                affected_systems = self._identify_affected_systems(cve)
                
                # Create CVE entry
                cve_entry = CVEEntry(
                    cve_id=cve.get('cve_id'),
                    description=cve.get('description'),
                    severity=cve.get('severity'),
                    cvss_score=cve.get('cvss_score', 0.0),
                    published_date=cve.get('published_date'),
                    modified_date=cve.get('modified_date', ''),
                    affected_systems=affected_systems,
                    exploitability=cve.get('exploitability', 'UNKNOWN'),
                    remediation_priority=ai_analysis.get('remediation_priority', 3),
                    mitre_techniques=mitre_techniques,
                    threat_intelligence=ai_analysis.get('threat_intelligence_summary', {}),
                    risk_score=risk_score
                )
                
                prioritized_cves.append(cve_entry)
                
            except Exception as e:
                logger.error(f"Error processing CVE {cve.get('cve_id')}: {e}")
                continue
        
        # Sort by risk score (highest first)
        prioritized_cves.sort(key=lambda x: x.risk_score, reverse=True)
        
        logger.info(f"Prioritized {len(prioritized_cves)} vulnerabilities")
        return prioritized_cves
    
    def _identify_affected_systems(self, cve_data: Dict) -> List[str]:
        """
        Identify which systems in our inventory are affected
        """
        affected_systems = []
        affected_products = cve_data.get('affected_products', [])
        
        for category, products in self.system_inventory.items():
            for product in products:
                for affected in affected_products:
                    if affected.lower() in product.lower():
                        affected_systems.append(f"{category}:{product}")
        
        return affected_systems
    
    def generate_cve_report(self, prioritized_cves: List[CVEEntry]) -> Dict:
        """
        Generate comprehensive CVE report
        """
        report = {
            "report_id": f"CVE-REPORT-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_cves": len(prioritized_cves),
                "critical_count": sum(1 for cve in prioritized_cves if cve.severity == "CRITICAL"),
                "high_count": sum(1 for cve in prioritized_cves if cve.severity == "HIGH"),
                "medium_count": sum(1 for cve in prioritized_cves if cve.severity == "MEDIUM"),
                "low_count": sum(1 for cve in prioritized_cves if cve.severity == "LOW"),
                "avg_risk_score": sum(cve.risk_score for cve in prioritized_cves) / len(prioritized_cves) if prioritized_cves else 0
            },
            "top_10_critical": [asdict(cve) for cve in prioritized_cves[:10]],
            "mitre_techniques": self._analyze_mitre_coverage(prioritized_cves),
            "affected_systems_summary": self._analyze_system_impact(prioritized_cves),
            "recommendations": self._generate_recommendations(prioritized_cves)
        }
        
        return report
    
    def _analyze_mitre_coverage(self, cves: List[CVEEntry]) -> Dict:
        """
        Analyze MITRE ATT&CK technique coverage
        """
        technique_counts = {}
        for cve in cves:
            for technique in cve.mitre_techniques:
                technique_counts[technique] = technique_counts.get(technique, 0) + 1
        
        return sorted(technique_counts.items(), key=lambda x: x[1], reverse=True)
    
    def _analyze_system_impact(self, cves: List[CVEEntry]) -> Dict:
        """
        Analyze impact on different system categories
        """
        system_impact = {}
        for cve in cves:
            for system in cve.affected_systems:
                category = system.split(':')[0] if ':' in system else system
                if category not in system_impact:
                    system_impact[category] = {
                        'count': 0,
                        'max_risk_score': 0,
                        'avg_risk_score': 0,
                        'cve_ids': []
                    }
                
                system_impact[category]['count'] += 1
                system_impact[category]['max_risk_score'] = max(
                    system_impact[category]['max_risk_score'], 
                    cve.risk_score
                )
                system_impact[category]['cve_ids'].append(cve.cve_id)
        
        # Calculate averages
        for category in system_impact:
            category_cves = [cve for cve in cves if any(system.startswith(category) for system in cve.affected_systems)]
            if category_cves:
                system_impact[category]['avg_risk_score'] = sum(cve.risk_score for cve in category_cves) / len(category_cves)
        
        return system_impact
    
    def _generate_recommendations(self, cves: List[CVEEntry]) -> List[str]:
        """
        Generate actionable recommendations
        """
        recommendations = []
        
        critical_cves = [cve for cve in cves if cve.severity == "CRITICAL"]
        if critical_cves:
            recommendations.append(f"URGENT: {len(critical_cves)} critical vulnerabilities require immediate patching")
        
        high_risk_cves = [cve for cve in cves if cve.risk_score >= 80]
        if high_risk_cves:
            recommendations.append(f"Prioritize patching {len(high_risk_cves)} high-risk vulnerabilities within 24-48 hours")
        
        # System-specific recommendations
        system_impact = self._analyze_system_impact(cves)
        for system, impact in system_impact.items():
            if impact['max_risk_score'] >= 90:
                recommendations.append(f"Emergency patching required for {system} systems (risk score: {impact['max_risk_score']:.1f})")
        
        return recommendations
    
    async def run_autonomous_scan(self) -> Dict:
        """
        Run autonomous CVE scanning and prioritization
        """
        logger.info("Starting autonomous CVE scan")
        
        try:
            # Ingest CVE feeds
            cves = await self.ingest_cve_feeds()
            
            if not cves:
                logger.warning("No CVEs retrieved from feeds")
                return {"status": "warning", "message": "No CVEs found"}
            
            # Prioritize vulnerabilities
            prioritized_cves = await self.prioritize_vulnerabilities(cves)
            
            # Generate report
            report = self.generate_cve_report(prioritized_cves)
            
            # Save report
            report_path = f"data/reports/cve_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2)
            
            logger.info(f"CVE scan completed. Report saved to {report_path}")
            
            return {
                "status": "success",
                "report_path": report_path,
                "summary": report["summary"],
                "top_vulnerabilities": [cve.cve_id for cve in prioritized_cves[:5]]
            }
            
        except Exception as e:
            logger.error(f"CVE scan failed: {e}")
            return {"status": "error", "message": str(e)}

# Main execution for testing
if __name__ == "__main__":
    async def main():
        agent = CVEAgent()
        result = await agent.run_autonomous_scan()
        print(f"CVE Agent Result: {json.dumps(result, indent=2)}")
    
    asyncio.run(main())