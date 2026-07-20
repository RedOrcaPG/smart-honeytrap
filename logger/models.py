# ==========================================================
# Import Standard Library
# ==========================================================

from dataclasses import dataclass, field
from datetime import datetime


# ==========================================================
# Log Entry Model
# ==========================================================

@dataclass
class LogEntry:

    # Timestamp
    timestamp: datetime = field(default_factory=datetime.now)

    # Network Information
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""

    # HTTP Information
    method: str = ""
    url: str = ""
    status_code: int = 0
    request_size: int = 0
    user_agent: str = ""

    # Traffic Statistics
    packet_rate: float = 0.0
    byte_rate: float = 0.0

    # Detection Result
    detection_score: int = 0
    decision: str = "NORMAL"
    redirected: bool = False

    # Analysis
    attack_type: str = ""
    reason: str = ""