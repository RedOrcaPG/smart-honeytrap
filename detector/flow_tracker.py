# ==========================================================
# Import Standard Library
# ==========================================================

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

# ==========================================================
# Import Local Module
# ==========================================================

from detector.models import PacketInfo


# ==========================================================
# Flow Model
# ==========================================================

@dataclass
class Flow:

    # Flow Timestamp
    first_seen: float
    last_seen: float

    # Flow Statistics
    packet_count: int = 0
    byte_count: int = 0

    # Packet Collection
    packets: List[PacketInfo] = field(default_factory=list)


# ==========================================================
# Flow Tracker
# ==========================================================

class FlowTracker:

    def __init__(self):

        self.flows: Dict[
            Tuple[str, str, int, int, str],
            Flow
        ] = {}

    # ------------------------------------------------------
    # Flow Key Generator
    # ------------------------------------------------------

    @staticmethod
    def create_flow_key(packet: PacketInfo) -> Tuple[str, str, int, int, str]:

        return (

            packet.src_ip,
            packet.dst_ip,
            packet.src_port,
            packet.dst_port,
            packet.protocol

        )

    # ------------------------------------------------------
    # Add Packet Into Flow
    # ------------------------------------------------------

    def add_packet(self, packet: PacketInfo):

        flow_key = self.create_flow_key(packet)

        if flow_key not in self.flows:

            self.flows[flow_key] = Flow(

                first_seen=packet.timestamp,
                last_seen=packet.timestamp

            )

        flow = self.flows[flow_key]

        flow.last_seen = packet.timestamp

        flow.packet_count += 1

        flow.byte_count += packet.packet_length

        flow.packets.append(packet)

    # ------------------------------------------------------
    # Get Single Flow
    # ------------------------------------------------------

    def get_flow(self, flow_key):

        return self.flows.get(flow_key)

    # ------------------------------------------------------
    # Get All Flows
    # ------------------------------------------------------

    def get_all_flows(self):

        return self.flows.copy()

    # ------------------------------------------------------
    # Remove Flow
    # ------------------------------------------------------

    def remove_flow(self, flow_key):

        self.flows.pop(flow_key, None)

    # ------------------------------------------------------
    # Clear All Flows
    # ------------------------------------------------------

    def clear(self):

        self.flows.clear()