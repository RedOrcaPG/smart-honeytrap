# ==========================================================
# Import Standard Library
# ==========================================================

import time

# ==========================================================
# Import Third Party Library
# ==========================================================

from netfilterqueue import NetfilterQueue

# ==========================================================
# Import Local Module
# ==========================================================

from config import DETECTION_CONFIG
from config import NFQUEUE_CONFIG

from detector.packet_parser import PacketParser
from detector.flow_tracker import FlowTracker
from detector.feature_extractor import FeatureExtractor
from detector.ddos_detector import DDoSDetector

from logger.logger import Logger


# ==========================================================
# Smart Honeytrap
# ==========================================================

class SmartHoneyTrap:

    def __init__(self):
        # Configuration
        self.config = DETECTION_CONFIG
        self.nfqueue_config = NFQUEUE_CONFIG

        # Detection Pipline
        self.parser = PacketParser()
        self.tracker = FlowTracker()
        self.extractor = FeatureExtractor()
        self.detector = DDoSDetector()

        #Logging
        self.logger = Logger()

    def process_packet(
            self,
            raw_packet: bytes
    ) -> None:
        
        packet = self.parser.parse(raw_packet)
        self.tracker.add_packet(packet)
        self.analyze_completed_flows(packet.timestamp)

    def analyze_completed_flows(
        self,
        current_time: float
    ) -> None:

        completed_flows = self.tracker.get_completed_flows(current_time)

        for flow in completed_flows:
            feature = self.extractor.extract(flow)
            result = self.detector.detect(feature)
            self.logger.save_detection(flow, result)

    def packet_callback(
        self,
        packet
    ) -> None:

        try:
            self.process_packet(
                packet.get_payload()
            )
        
        finally:
            packet.accept()
    
    def start(self) -> None:

        queue = NetfilterQueue()

        queue.bind(
            self.nfqueue_config["queue_number"],
            self.packet_callback
        )

        try:
            print(f"Smart Honeytrap started " f"(Queue {self.nfqueue_config['queue_number']})...")
            queue.run()

        except KeyboardInterrupt:
            print("\nStopping Smart Honeytrap...")

        finally:
            queue.unbind()
            self.shutdown()

    def shutdown(self) -> None:
        self.logger.close()

if __name__ == "__main__":
    honeytrap = SmartHoneyTrap()
    honeytrap.start()