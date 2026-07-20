# ==========================================================
# Import Third Party Library
# ==========================================================

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTPRequest
from scapy.packet import Raw

# ==========================================================
# Import Local Module
# ==========================================================

from detector.models import PacketInfo


# ==========================================================
# Packet Parser
# ==========================================================

class PacketParser:

    def parse(self, raw_packet: bytes) -> PacketInfo:

        packet_info = PacketInfo()

        try:

            packet = IP(raw_packet)

            # --------------------------------------------------
            # Packet Information
            # --------------------------------------------------

            packet_info.packet_length = len(raw_packet)

            # --------------------------------------------------
            # Network Layer
            # --------------------------------------------------

            if packet.haslayer(IP):

                ip = packet[IP]

                packet_info.src_ip = ip.src
                packet_info.dst_ip = ip.dst

            # --------------------------------------------------
            # TCP Layer
            # --------------------------------------------------

            if packet.haslayer(TCP):

                tcp = packet[TCP]

                packet_info.protocol = "TCP"

                packet_info.src_port = tcp.sport
                packet_info.dst_port = tcp.dport

                packet_info.tcp_flags = str(tcp.flags)

            # --------------------------------------------------
            # UDP Layer
            # --------------------------------------------------

            elif packet.haslayer(UDP):

                udp = packet[UDP]

                packet_info.protocol = "UDP"

                packet_info.src_port = udp.sport
                packet_info.dst_port = udp.dport

            # --------------------------------------------------
            # Other IP Protocol
            # --------------------------------------------------

            elif packet.haslayer(IP):

                packet_info.protocol = "IP"

            # --------------------------------------------------
            # HTTP Layer
            # --------------------------------------------------

            if packet.haslayer(HTTPRequest):

                http = packet[HTTPRequest]

                packet_info.http_method = http.Method.decode(
                    errors="ignore"
                )

                packet_info.http_path = http.Path.decode(
                    errors="ignore"
                )

            # --------------------------------------------------
            # Payload
            # --------------------------------------------------

            if packet.haslayer(Raw):

                packet_info.payload_size = len(packet[Raw].load)

        except (IndexError, AttributeError, ValueError, TypeError):

            # Mengembalikan PacketInfo kosong agar pipeline
            # tetap berjalan walaupun ada paket yang gagal diparse.
            return packet_info

        return packet_info