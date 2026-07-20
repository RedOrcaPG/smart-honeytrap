# ==========================================================
# Import Standard Library
# ==========================================================

from dataclasses import dataclass, field
import time


# ==========================================================
# Packet Information Model
# ==========================================================

@dataclass
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