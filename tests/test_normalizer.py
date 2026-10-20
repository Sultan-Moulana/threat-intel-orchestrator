from src.normalizer import CTINormalizer

def test_private_and_loopback_ips_are_filtered():
    mock_pulse = [
        {
            "name": "Poisoned Feed Test",
            "tlp": "amber",
            "tags": ["c2", "ransomware"],
            "indicators": [
                {"type": "IPv4", "indicator": "127.0.0.1", "description": "Loopback"},
                {"type": "IPv4", "indicator": "192.168.1.1", "description": "Local Gateway"},
                {"type": "IPv4", "indicator": "185.220.101.45", "description": "Valid Malicious IP"},
            ],
        }
    ]
    results = CTINormalizer.normalize_pulses(mock_pulse)
    assert len(results) == 1
    assert results[0].value == "185.220.101.45"
    assert results[0].severity == "HIGH"
    assert results[0].confidence_score >= 80