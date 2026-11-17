from typing import Any, Dict, Set


class ThreatIntelligence:
    """
    Lightweight Threat Intelligence enrichment adapter with curated offline IoCs
    and clean extension hooks for external feeds (AbuseIPDB, VirusTotal, URLhaus).
    """

    KNOWN_MALICIOUS_IPS: Set[str] = {
        "185.220.101.45",
        "45.155.205.233",
        "198.51.100.99",
        "203.0.113.66",
    }

    KNOWN_MALICIOUS_DOMAINS: Set[str] = {
        "c2-beacon-sync.tk",
        "suspicious-domain.com",
        "auth-reverify-portal.ml",
        "payload-dropper.ga",
    }

    KNOWN_MALICIOUS_HASHES: Set[str] = {
        "44d88612fea8a8f36de82e1278abb02f",
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    }

    async def check_ip(self, ip: str) -> Dict[str, Any]:
        clean = ip.strip()
        is_bad = clean in self.KNOWN_MALICIOUS_IPS
        return {
            "indicator": clean,
            "malicious": is_bad,
            "source": "curated-threat-feed" if is_bad else "none",
            "confidence": 0.92 if is_bad else 0.0,
        }

    async def check_domain(self, domain: str) -> Dict[str, Any]:
        clean = domain.strip().lower().rstrip(".")
        is_bad = clean in self.KNOWN_MALICIOUS_DOMAINS or clean.endswith(
            (".tk", ".ml", ".ga", ".cf")
        )
        return {
            "indicator": clean,
            "malicious": is_bad,
            "source": "curated-domain-intel" if is_bad else "none",
            "confidence": 0.85 if is_bad else 0.0,
        }

    async def check_hash(self, file_hash: str) -> Dict[str, Any]:
        clean = file_hash.strip().lower()
        is_bad = clean in self.KNOWN_MALICIOUS_HASHES
        return {
            "indicator": clean,
            "malicious": is_bad,
            "source": "curated-malware-hashes" if is_bad else "none",
            "confidence": 0.98 if is_bad else 0.0,
        }
