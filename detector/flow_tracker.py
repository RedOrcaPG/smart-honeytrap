# ==========================================================
# Import Standard Library
# ==========================================================

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

# ==========================================================
# Import Local Module
# ==========================================================

from detector.models import PacketInfo, Flow
from config import DETECTION_CONFIG


FlowKey = Tuple[
    str, 
    str, 
    int, 
    int, 
    str
]

# ==========================================================
# Flow Tracker
# ==========================================================

class FlowTracker:

    def __init__(self):

        self.flows: Dict[
            Tuple[str, str, int, int, str],
            Flow
        ] = {}

        self.idle_timeout = DETECTION_CONFIG["time_window"]

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
    # Private Helper For Add Packet 
    # ------------------------------------------------------

    def _create_flow(
        self,
        packet: PacketInfo
    ) -> Flow:

        # Membuat Flow Baru Berdasarkan Paket Pertama
        return Flow(
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            protocol=packet.protocol,
            start_time=packet.timestamp,
            last_update=packet.timestamp
        )
    
    # ------------------------------------------------------
    # Add Packet Into Flow
    # ------------------------------------------------------

    def add_packet(
        self, 
        packet: PacketInfo
    ) -> None:

        flow_key = self.create_flow_key(packet)
        flow = self.flows.get(flow_key)

        if flow is None:
            flow = self._create_flow(packet)
            self.flows[flow_key] = flow

        flow.add_packet(packet)

    # ------------------------------------------------------
    # Get Single Flow
    # ------------------------------------------------------
    
    def get_flow(
        self,
        flow_key: FlowKey
    ) -> Flow | None:
        return self.flows.get(flow_key)

    # ------------------------------------------------------
    # Get All Flows
    # ------------------------------------------------------

    def get_all_flows(self):
        return self.flows.copy()

    # ------------------------------------------------------
    # Get Completed Flows
    # ------------------------------------------------------

    def get_completed_flows(
        self,
        current_time: float
    ) -> List[Flow]:

        completed_flows: List[Flow] = []
        expired_keys: List[
            Tuple[str, str, int, int, str]
        ] = []

        for flow_key, flow in self.flows.items():

            if flow.is_idle(
                current_time, 
                self.idle_timeout
            ):
                completed_flows.append(flow)
                expired_keys.append(flow_key)

        for flow_key in expired_keys:
            self.remove_flow(flow_key)
        return completed_flows

    # ------------------------------------------------------
    # Remove Flow
    # ------------------------------------------------------

    def remove_flow(
        self,
        flow_key: FlowKey
    ) -> None:
        self.flows.pop(flow_key, None)

    # ------------------------------------------------------
    # Flush All Flows
    # ------------------------------------------------------

    # def flush_all(self) -> List[Flow]:

    #     remaining_flows = sorted(
    #         self.flows.values(),
    #         key=lambda flow: flow.start_time
    #     )

    #     self.flows.clear()

    #     return remaining_flows

    # ------------------------------------------------------
    # Clear All Flows
    # ------------------------------------------------------

    def clear(self):
        self.flows.clear()