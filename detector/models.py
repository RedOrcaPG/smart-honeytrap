# ==========================================================
# Import Standard Library
# ==========================================================

from dataclasses import dataclass, field
import time
from typing import List

# ==========================================================
# Packet Information Model
# ==========================================================

@dataclass(slots=True)
class PacketInfo:

    # Packet Timestamp
    timestamp: float = field(default_factory=time.time)

    # Network Layer
    src_ip: str = ""
    dst_ip: str = ""

    # Transport Layer
    src_port: int = 0
    dst_port: int = 0

    protocol: str = ""

    # Packet Information
    packet_length: int = 0

    tcp_flags: str = ""

    # HTTP Information
    http_method: str = ""
    http_path: str = ""

    # Payload Size
    payload_size: int = 0

# ==========================================================
# Flow Packet
# ==========================================================

@dataclass(slots=True)
class Flow:

    # Flow Identity
    src_ip: str
    dst_ip: str

    src_port: int
    dst_port: int

    protocol: str

    # Flow Time 
    start_time: float
    last_update: float

    # Flow Statics
    packet_count: int = 0
    byte_count: int = 0
    http_request_count: int = 0
    syn_count: int = 0

    # Packet Collection
    packets: List[PacketInfo] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return self.last_update - self.start_time

    @property
    def first_packet(self) -> PacketInfo:

        if not self.packets:
            raise ValueError(
                "Flow does not contain any packets."
            )
        return self.packets[0]

    def add_packet(
        self, 
        packet: PacketInfo
    ) -> None:

        self.last_update = packet.timestamp
        self.packet_count += 1
        self.byte_count += packet.packet_length
        self.packets.append(packet)

        if packet.http_method:
            self.http_request_count += 1

        if "S" in packet.tcp_flags:
            self.syn_count += 1

    def is_idle(
        self,
        current_time: float,
        idle_timeout: float
    ) -> bool:
        return (current_time - self.last_update) >= idle_timeout

    def clear_packets(self) -> None:
        self.packets.clear()

    
# ==========================================================
# Source Activity
# ==========================================================

@dataclass(slots=True)
class SourceActivity:

    representative_flow: Flow

    # Source Identitiy
    src_ip: str

    # Windows Information
    start_time: float
    last_update: float
    window: float

    # Source Statistics
    flow_count: int = 0
    packet_count: int = 0 
    http_request_count: int = 0
    syn_count: int = 0 
    
    @property
    def duration(self) -> float:
        return self.last_update - self.start_time

    @property
    def flow_rate(self) -> float:
        # Return Completed flow rate (flow/second)
        if self.duration <= 0:
            return 0.0
        return self.flow_count / self.duration

    @property
    def packet_rate(self) -> float:
        # Return packet rate (packet/second)
        if self.duration <= 0:
            return 0.0
        return self.packet_count / self.duration

    @property
    def request_rate(self) -> float:
        # Return HTTP request rate (request/second)
        if self.duration <= 0:
            return 0.0
        return self.http_request_count / self.duration

    def add_flow(
        self, 
        flow:Flow
    ) -> None :

        self.flow_count += 1
        self.packet_count += flow.packet_count
        self.http_request_count += flow.http_request_count
        self.last_update = flow.last_update

    def is_expired(
        self,
        current_time: float,
        window: float
    ) -> bool:
        return (current_time - self.start_time) >= window