import ipaddress
import logging
from typing import List, Dict, Any
from pydantic import BaseModel, Field
from src.config import Config

logger = logging.getLogger(__name__)

class NormalizedIoC(BaseModel):
    value: str
    ioc_type: str  # ip, domain, sha256, md5
    source_pulse: str
    confidence_score: int = Field(ge=0, le=100)
    severity: str  # HIGH, MEDIUM, LOW
    tags: List[str]
    description: str

class CTINormalizer:
    TYPE_MAPPING = {
        "IPv4": "ip",
        "domain": "domain",
        "hostname": "domain",
        "FileHash-SHA256": "sha256",
        "FileHash-MD5": "md5",
    }

    @classmethod
    def normalize_pulses(cls, pulses: List[Dict[str, Any]]) -> List[NormalizedIoC]:
        normalized_map: Dict[str, NormalizedIoC] = {}

        for pulse in pulses:
            pulse_name = pulse.get("name", "Unknown Pulse")
            raw_tags = [t.lower() for t in pulse.get("tags", [])]
            tlp = pulse.get("tlp", "white").lower()
            score, severity = cls._calculate_risk(raw_tags, tlp)

            for raw_ioc in pulse.get("indicators", []):
                raw_type = raw_ioc.get("type", "")
                value = raw_ioc.get("indicator", "").strip()

                if raw_type not in cls.TYPE_MAPPING or not value:
                    continue

                mapped_type = cls.TYPE_MAPPING[raw_type]

                # Validate IPv4 and prevent blocking private/loopback addresses
                if mapped_type == "ip" and not cls._is_valid_public_ip(value):
                    logger.warning(f"Filtered invalid or private IP indicator: {value}")
                    continue

                # Deduplicate: keep the entry with the highest confidence score
                if value in normalized_map and normalized_map[value].confidence_score >= score:
                    continue

                normalized_map[value] = NormalizedIoC(
                    value=value,
                    ioc_type=mapped_type,
                    source_pulse=pulse_name,
                    confidence_score=score,
                    severity=severity,
                    tags=raw_tags,
                    description=raw_ioc.get("description") or "No description provided",
                )

        results = list(normalized_map.values())
        logger.info(f"Normalized and deduplicated {len(results)} valid IoCs.")
        return results

    @staticmethod
    def _is_valid_public_ip(ip_str: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return ip_obj.is_global and not (
                ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
            )
        except ValueError:
            return False

    @staticmethod
    def _calculate_risk(tags: List[str], tlp: str) -> tuple[int, str]:
        base_score = 50
        matched_tags = set(tags).intersection({t.lower() for t in Config.HIGH_RISK_TAGS})
        base_score += len(matched_tags) * 15

        if tlp in {"amber", "red"}:
            base_score += 10

        final_score = min(base_score, 100)
        if final_score >= 80:
            severity = "HIGH"
        elif final_score >= 60:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return final_score, severity