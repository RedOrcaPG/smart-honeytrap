"""
==========================================================
Smart Honeytrap
Configuration File

Author  : RedOrcaPG
Version : 1.0.0
==========================================================
"""
# =============================
# Fake Database Configuration
# =============================
DB_CONFIG = {
    "host": "localhost",
    "port": 3306,
    "user": "user_baru",
    "password": "123",
    "database": "portal_fk"
}

# ==========================
# Fake Server Configuration
# ==========================
SERVER_CONFIG = {
    "host": "0.0.0.0",
    "port": 8080,
    "debug": True
}


# ==========================
# NFQUEUE Configuration
# ==========================

NFQUEUE_CONFIG = {
    "queue_number": 1
}



# ==========================================================
# Detection Configuration
# ==========================================================

DETECTION_CONFIG = {

    # ------------------------------------------------------
    # Flow Configuration
    # ------------------------------------------------------

    # Flow Window (Second)
    "time_window": 2,

    # Minimum Flow Duration (Second)
    "minimum_flow_duration": 0.001,

    # ------------------------------------------------------
    # Feature Threshold
    # ------------------------------------------------------

    # Packet Rate Threshold (packet/sec)
    "packet_threshold": 300,

    # Byte Rate Threshold (byte/sec)
    "byte_threshold": 3000000,

    # SYN Packet Threshold (packet)
    "syn_threshold": 100,

    # HTTP Request Threshold (request)
    "http_threshold": 200,

    # ------------------------------------------------------
    # Feature Weight
    # ------------------------------------------------------

    "packet_weight": 25,

    "byte_weight": 20,

    "syn_weight": 30,

    "http_weight": 25,

    # ------------------------------------------------------
    # Decision Threshold
    # ------------------------------------------------------

    "suspicious_score": 30,

    "ddos_score": 70,

    # ------------------------------------------------------
    # Decision Label
    # ------------------------------------------------------

    "normal_label": "NORMAL",

    "suspicious_label": "SUSPICIOUS",

    "ddos_label": "DDOS",
}


# ==========================================================
# Redirect Configuration
# ==========================================================

REDIRECT_CONFIG = {

    # Real Website
    "real_server_ip": "127.0.0.1",
    "real_server_port": 80,
    # Fake Website
    "fake_server_ip": "127.0.0.1",
    "fake_server_port": 8080,
}


# ==========================================================
# Logger Configuration
# ==========================================================

LOGGER_CONFIG = {
    # Console Logger
    "console": True,
    # Save to MariaDB
    "database": True,
    # Save to CSV (Future Development)
    "csv": False,
    # Save to Log File (Future Development)
    "file": False,
    #path yg tidak masuk ke log
    "ignore_paths": (
        "/static/",
        "/favicon.ico",
    )
}

