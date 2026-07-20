# ==========================================================
# Import Local Module
# ==========================================================

from database.connection import DatabaseConnection
from logger.models import LogEntry
from detector.flow_tracker import Flow
from detector.detection_result import DetectionResult
from datetime import datetime

# ==========================================================
# Import Third Party Library
# ==========================================================

import json

# ==========================================================
# Logger Class
# ==========================================================

class Logger:

    def __init__(self):

        self.db = DatabaseConnection()
        self.db.connect()


    def save_http(self, log_entry: LogEntry):
        query = """
            INSERT INTO logs
            (
                timestamp,
                src_ip,
                dst_ip,
                protocol,
                method,
                url,
                packet_rate,
                byte_rate,
                detection_score,
                decision,
                redirected,
                user_agent
            )
            VALUES
            (
                %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s
            )
        """
        values = (

            log_entry.timestamp,
            log_entry.src_ip,
            log_entry.dst_ip,
            log_entry.protocol,
            log_entry.method,
            log_entry.url,
            log_entry.packet_rate,
            log_entry.byte_rate,
            log_entry.detection_score,
            log_entry.decision,
            log_entry.redirected,
            log_entry.user_agent
        )
        self._execute(query, values)

    def save_detection(self, flow: Flow, result: DetectionResult):
        if not flow.packets:
            return

        packet = flow.packets[0]
        query = """
            INSERT INTO detection_logs
            (
                timestamp,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol,
                duration,
                packet_count,
                byte_count,
                packet_rate,
                byte_rate,
                average_packet_size,
                syn_count,
                http_request_count,
                score,
                decision,
                triggered_rules
            )   
            VALUES
            (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s
            )
        """
        values = (
            datetime.now(),
            packet.src_ip,
            packet.dst_ip,
            packet.src_port,
            packet.dst_port,
            packet.protocol,
            result.feature.duration,
            flow.packet_count,
            flow.byte_count,
            result.feature.packet_rate,
            result.feature.byte_rate,
            result.feature.average_packet_size,
            result.feature.syn_count,
            result.feature.http_request_count,
            result.score,
            result.decision,
            json.dumps(result.triggered_rules, ensure_ascii=False)
        )
        self._execute(query, values)

    def _execute(self, query, values):
        cursor = self.db.cursor()
        cursor.execute(query, values)
        self.db.commit()

        
    def close(self):
        self.db.close()