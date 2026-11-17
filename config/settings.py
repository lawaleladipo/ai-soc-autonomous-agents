import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


class Settings:
    """Centralized runtime settings loaded from environment variables."""

    def __init__(self):
        self.BASE_DIR: Path = BASE_DIR
        self.API_KEY: str = os.getenv("API_KEY", "dev-local-soc-key")
        self.GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "").strip()
        self.GROQ_MODEL: str = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
        self.MONITORING_INTERVAL: int = int(os.getenv("MONITORING_INTERVAL", "60"))
        self.NVD_API_URL: str = os.getenv(
            "NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0"
        )
        self.CISA_KEV_URL: str = os.getenv(
            "CISA_KEV_URL",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        )
        self.DATA_DIR: Path = BASE_DIR / "data"
        (self.DATA_DIR / "logs").mkdir(parents=True, exist_ok=True)
        (self.DATA_DIR / "reports").mkdir(parents=True, exist_ok=True)
