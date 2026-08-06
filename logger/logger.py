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

import mariadb
import json

# ==========================================================
# Logger Class
# ==========================================================

class Logger:

    def __init__(self):
        pass


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

    def save_detection(
        self,  
        result: DetectionResult
        ):

        flow = result.activity.representative_flow

        try:
            packet = flow.first_packet
        except ValueError:
            return
        
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
                flow_count,
                packet_count,
                http_request_count,
                syn_count,
                flow_rate,
                packet_rate,
                request_rate,
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
            result.activity.duration,
            result.activity.flow_count,
            result.activity.packet_count,
            result.activity.http_request_count,
            result.activity.syn_count,
            result.activity.flow_rate,
            result.activity.packet_rate,
            result.activity.request_rate,
            result.score,
            result.decision,
            json.dumps(result.triggered_rules, ensure_ascii=False)
        )
        self._execute(query, values)

    def _execute(self, query, values):
        connection = DatabaseConnection()
        cursor = None

        try:
            connection.connect()

            cursor = connection.cursor()
            cursor.execute(query, values)

            connection.commit()

        except mariadb.Error:
            connection.rollback()
            raise

        finally:
            if cursor is not None:
                cursor.close()

            connection.close()