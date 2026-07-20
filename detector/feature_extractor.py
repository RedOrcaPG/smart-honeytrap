# ==========================================================
# Import Standard Library
# ==========================================================

from dataclasses import dataclass

# ==========================================================
# Import Local Module
# ==========================================================

from detector.flow_tracker import Flow
from config import DETECTION_CONFIG

# ==========================================================
# Constants
# ==========================================================



# ==========================================================
# Feature Model
# ==========================================================

@dataclass(frozen=True)
class Feature:

    duration: float

    packet_rate: float

    byte_rate: float

    average_packet_size: float

    syn_count: int

    http_request_count: int


# ==========================================================
# Feature Extractor
# ==========================================================

class FeatureExtractor:

    @staticmethod
    def extract(flow: Flow) -> Feature:
        
        config = DETECTION_CONFIG
        # --------------------------------------------------
        # Flow Duration
        # --------------------------------------------------

        duration = flow.last_seen - flow.first_seen

        duration = max(
            duration,
            config["minimum_flow_duration"]
        )

        # --------------------------------------------------
        # Flow Statistics
        # --------------------------------------------------

        packet_count = flow.packet_count

        byte_count = flow.byte_count

        packet_rate = packet_count / duration

        byte_rate = byte_count / duration

        average_packet_size = (

            byte_count / packet_count

            if packet_count > 0

            else 0.0

        )       

        # --------------------------------------------------
        # Packet Statistics
        # --------------------------------------------------

        syn_count = 0

        http_request_count = 0

        for packet in flow.packets:

            if packet.protocol == "TCP" and "S" in packet.tcp_flags:

                syn_count += 1

            if packet.http_method:

                http_request_count += 1

        # --------------------------------------------------
        # Return Immutable Feature
        # --------------------------------------------------

        return Feature(
            duration=duration,
            packet_rate=packet_rate,
            byte_rate=byte_rate,
            average_packet_size=average_packet_size,
            syn_count=syn_count,
            http_request_count=http_request_count
        )