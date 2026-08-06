# ==========================================================
# Import Standard Library
# ==========================================================

from typing import NamedTuple

# ==========================================================
# Import Local Module
# ==========================================================

from config import DETECTION_CONFIG

from detector.models import SourceActivity
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
        feature="flow_count",
        threshold="flow_count_threshold",
        weight="flow_count_weight"
    ),

    DetectionRule(
        feature="packet_count",
        threshold="packet_count_threshold",
        weight="packet_count_weight"
    ),

    DetectionRule(
        feature="http_request_count",
        threshold="http_request_threshold",
        weight="http_request_weight"
    ),

    DetectionRule(
        feature="syn_count",
        threshold="syn_threshold",
        weight="syn_weight"
    )
)

    def __init__(self):

        self.config = DETECTION_CONFIG

    # ------------------------------------------------------
    # Public Detection API
    # ------------------------------------------------------

    def detect(
        self,
        activity: SourceActivity
    ) -> DetectionResult:

        score, triggered_rules = self._calculate_score(activity)

        decision = self._make_decision(score)

        return DetectionResult(

            score=score,

            decision=decision,

            triggered_rules=tuple(sorted(triggered_rules)),

            activity=activity

        )

    # ------------------------------------------------------
    # Calculate Weighted Score
    # ------------------------------------------------------

    def _calculate_score(
        self,
        activity: SourceActivity
    ) -> tuple[int, set[str]]:

        score = 0

        triggered_rules = set()

        config = self.config

        for rule in self.RULES:

            value = getattr(activity, rule.feature)

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