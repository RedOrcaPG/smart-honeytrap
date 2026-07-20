# ==========================================================
# Import Standard Library
# ==========================================================

from typing import NamedTuple

# ==========================================================
# Import Local Module
# ==========================================================

from config import DETECTION_CONFIG

from detector.feature_extractor import Feature
from detector.detection_result import DetectionResult


# ==========================================================
# Detection Rule Model
# ==========================================================

class DetectionRule(NamedTuple):

    feature: str

    threshold: str

    weight: str


# ==========================================================
# DDoS Detector
# ==========================================================

class DDoSDetector:

    # ------------------------------------------------------
    # Detection Rule Table
    # ------------------------------------------------------

    RULES = (

        DetectionRule(

            feature="packet_rate",

            threshold="packet_threshold",

            weight="packet_weight"

        ),

        DetectionRule(

            feature="byte_rate",

            threshold="byte_threshold",

            weight="byte_weight"

        ),

        DetectionRule(

            feature="syn_count",

            threshold="syn_threshold",

            weight="syn_weight"

        ),

        DetectionRule(

            feature="http_request_count",

            threshold="http_threshold",

            weight="http_weight"

        )

    )

    def __init__(self):

        self.config = DETECTION_CONFIG

    # ------------------------------------------------------
    # Public Detection API
    # ------------------------------------------------------

    def detect(
        self,
        feature: Feature
    ) -> DetectionResult:

        score, triggered_rules = self._calculate_score(feature)

        decision = self._make_decision(score)

        return DetectionResult(

            score=score,

            decision=decision,

            triggered_rules=tuple(sorted(triggered_rules)),

            feature=feature

        )

    # ------------------------------------------------------
    # Calculate Weighted Score
    # ------------------------------------------------------

    def _calculate_score(
        self,
        feature: Feature
    ) -> tuple[int, set[str]]:

        score = 0

        triggered_rules = set()

        config = self.config

        for rule in self.RULES:

            value = getattr(feature, rule.feature)

            if value >= config[rule.threshold]:

                score += config[rule.weight]

                triggered_rules.add(rule.feature)

        return score, triggered_rules

    # ------------------------------------------------------
    # Decision Engine
    # ------------------------------------------------------

    def _make_decision(
        self,
        score: int
    ) -> str:

        config = self.config

        if score >= config["ddos_score"]:

            return config["ddos_label"]

        if score >= config["suspicious_score"]:

            return config["suspicious_label"]

        return config["normal_label"]