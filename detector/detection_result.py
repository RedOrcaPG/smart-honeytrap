# ==========================================================
# Import Standard Library
# ==========================================================

from dataclasses import dataclass
from typing import Tuple


# ==========================================================
# Import Local Module
# ==========================================================

from detector.feature_extractor import Feature


# ==========================================================
# Detection Result Model
# ==========================================================

@dataclass(frozen=True)
class DetectionResult:

    # Detection Score
    score: int

    # Detection Decision
    decision: str

    # Triggered Detection Rules
    triggered_rules: Tuple[str, ...]

    # Evaluated Feature
    feature: Feature