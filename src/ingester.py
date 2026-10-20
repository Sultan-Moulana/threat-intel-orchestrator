import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any
import requests
from src.config import Config

logger = logging.getLogger(__name__)

class OTXIngester:
    def __init__(self):
        self.api_key = Config.OTX_API_KEY
        self.base_url = Config.OTX_BASE_URL
        self.mock_mode = Config.MOCK_MODE or not bool(self.api_key)

    def fetch_pulses(self) -> List[Dict[str, Any]]:
        if self.mock_mode:
            logger.info("Running in MOCK_MODE. Generating simulated CTI pulses...")
            return self._get_mock_pulses()

        since_time = (
            datetime.now(timezone.utc) - timedelta(hours=Config.LOOKBACK_HOURS)
        ).isoformat()

        headers = {"X-OTX-API-KEY": self.api_key}
        params = {"modified_since": since_time, "limit": 20}

        try:
            logger.info(f"Fetching pulses from AlienVault OTX modified since {since_time}...")
            response = requests.get(
                self.base_url, headers=headers, params=params, timeout=15
            )
            response.raise_for_status()
            data = response.json()
            pulses = data.get("results", [])
            logger.info(f"Successfully ingested {len(pulses)} threat pulses.")
            return pulses
        except requests.RequestException as exc:
            logger.error(f"Failed to fetch pulses from OTX API: {exc}")
            return []

    @staticmethod
    def _get_mock_pulses() -> List[Dict[str, Any]]:
        """Provides realistic threat pulses for local testing and CI verification."""
        return [
            {
                "id": "pulse-apt-001",
                "name": "CobaltStrike C2 Infrastructure Campaign",
                "author_name": "AlienVault_Research",
                "tlp": "amber",
                "tags": ["c2", "cobaltstrike", "apt", "ransomware"],
                "indicators": [
                    {"type": "IPv4", "indicator": "185.220.101.45", "description": "Primary C2 Node"},
                    {"type": "IPv4", "indicator": "45.155.205.233", "description": "Secondary Beacon"},
                    {"type": "domain", "indicator": "auth-login-microsoft-update.com", "description": "Phishing & C2 Domain"},
                    {"type": "FileHash-SHA256", "indicator": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "description": "Dropper payload"}
                ]
            },
            {
                "id": "pulse-scan-002",
                "name": "Low-Confidence SSH Brute Force Scanners",
                "author_name": "Community_Feed",
                "tlp": "white",
                "tags": ["scanner", "ssh"],
                "indicators": [
                    {"type": "IPv4", "indicator": "198.51.100.22", "description": "Port 22 scanner"},
                    {"type": "IPv4", "indicator": "127.0.0.1", "description": "False positive localhost test"}
                ]
            }
        ]