# ==========================================================
# Import Standard Library
# ==========================================================

from typing import Dict, List

# ==========================================================
# Import Local Module
# ==========================================================

from detector.models import Flow, SourceActivity
from config import DETECTION_CONFIG


# ==========================================================
# Source Activity Tracker
# ==========================================================

class SourceActivityTracker:

    def __init__(self):

        self.activities: Dict[
            str,
            SourceActivity
        ] = {}

        self.window = DETECTION_CONFIG["time_window"]

    # ------------------------------------------------------
    # Private Helper For Add Flow
    # ------------------------------------------------------

    def _create_activity(
        self,
        flow: Flow
    ) -> SourceActivity:

        return SourceActivity(
            src_ip=flow.src_ip,
            representative_flow=flow,
            start_time=flow.start_time,
            last_update=flow.last_update,
            window=self.window,
            
        )

    # ------------------------------------------------------
    # Private Helper for update activity
    # ------------------------------------------------------

    def _start_new_activity(
        self,
        flow: Flow
    ) -> SourceActivity:
        activity = self._create_activity(flow)
        activity.add_flow(flow)
        self.activities[flow.src_ip] = activity
        return activity
    
    # ------------------------------------------------------
    # Get Update Source Activities
    # ------------------------------------------------------

    def update_activity(
        self,
        flow: Flow
    ) -> SourceActivity | None:

        activity = self.activities.get(flow.src_ip)

        #
        # First activity from this source
        #
        if activity is None:

            self._start_new_activity(flow)

            return None

        current_time = flow.start_time

        #
        # Observation window expired
        #
        if activity.is_expired(
            current_time,
            self.window
        ):

            completed_activity = activity

            self._start_new_activity(flow)

            return completed_activity

        #
        # Observation window still active
        #
        activity.add_flow(flow)

        return None
    
    # ------------------------------------------------------
    # flush flow Source Activities
    # ------------------------------------------------------

    def flush_expired_activities(
        self,
        current_time: float
    ) -> List[SourceActivity]:

        completed_activities: List[SourceActivity] = []
        expired_sources: List[str] = []

        for src_ip, activity in self.activities.items():

            if activity.is_expired(
                current_time,
                self.window
            ):
                completed_activities.append(activity)
                expired_sources.append(src_ip)

        for src_ip in expired_sources:
            self.remove_activity(src_ip)

        return completed_activities

    # ------------------------------------------------------
    # Final Flush Activity
    # ------------------------------------------------------

    # def flush_all(self) -> List[SourceActivity]:

    #     remaining_activities = list(self.activities.values())

    #     self.activities.clear()

    #     return remaining_activities
    # ------------------------------------------------------
    # Remove Source Activity
    # ------------------------------------------------------

    def remove_activity(
        self,
        src_ip: str
    ) -> None:

        self.activities.pop(src_ip, None)

    # ------------------------------------------------------
    # Clear All Source Activities
    # ------------------------------------------------------

    def clear(self) -> None:

        self.activities.clear()