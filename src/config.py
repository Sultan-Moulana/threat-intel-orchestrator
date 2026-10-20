import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    OTX_API_KEY: str = os.getenv("OTX_API_KEY", "")
    OTX_BASE_URL: str = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    SLACK_WEBHOOK_URL: str = os.getenv("SLACK_WEBHOOK_URL", "")
    MOCK_MODE: bool = os.getenv("MOCK_MODE", "false").lower() == "true"
    LOOKBACK_HOURS: int = int(os.getenv("LOOKBACK_HOURS", "24"))
    OUTPUT_DIR: str = os.getenv("OUTPUT_DIR", "output")

    # High-priority tags that elevate an IoC's confidence score
    HIGH_RISK_TAGS = {
        "ransomware", "apt", "c2", "cobaltstrike", "botnet", 
        "zero-day", "exploit", "phishing", "LockBit", "lazarus"
    }