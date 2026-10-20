import logging
import sys
from src.ingester import OTXIngester
from src.normalizer import CTINormalizer
from src.distributor import CTIDistributor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("CTI-Orchestrator")

def run_pipeline() -> None:
    logger.info("Starting Automated Threat Intelligence Orchestrator pipeline...")

    ingester = OTXIngester()
    raw_pulses = ingester.fetch_pulses()

    if not raw_pulses:
        logger.warning("No pulses retrieved. Exiting pipeline cleanly.")
        return

    normalized_iocs = CTINormalizer.normalize_pulses(raw_pulses)
    if not normalized_iocs:
        logger.warning("No valid public IoCs remained after normalization.")
        return

    distributor = CTIDistributor()
    distributor.export_json_feed(normalized_iocs)
    distributor.update_firewall_rules(normalized_iocs)
    distributor.send_slack_alert(normalized_iocs)

    logger.info("CTI Orchestration run completed successfully.")

if __name__ == "__main__":
    run_pipeline()