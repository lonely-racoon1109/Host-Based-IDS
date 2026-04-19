from datetime import datetime, timedelta
from collections import defaultdict


class LogAggregator:
    def __init__(self, window_minutes=1):
        self.window_minutes = window_minutes
        self.window_start = None
        self.window_end = None
        self.current_window = []

    # --------------------------------------------------
    # EVENT INGESTION
    # --------------------------------------------------

    def add_event(self, event):
        event_time = self._to_datetime(event["timestamp"])
        if event_time is None:
            return None

        # Initialize window
        if self.window_start is None:
            self._start_new_window(event_time)

        # If event belongs to current window
        if self.window_start <= event_time < self.window_end:
            self.current_window.append(event)
            return None

        # If event is beyond window → flush ALL missed windows
        summaries = []

        while event_time >= self.window_end:
            summary = self._flush_current_window()
            if summary:
                summaries.append(summary)
            self._start_new_window(self.window_end)

        # add event to new window
        self.current_window.append(event)

        return summaries  # may contain multiple flushed windows

    # --------------------------------------------------
    # WINDOW MANAGEMENT
    # --------------------------------------------------

    def _start_new_window(self, start_time):
        self.window_start = start_time
        self.window_end = start_time + timedelta(minutes=self.window_minutes)
        self.current_window = []

    def _flush_current_window(self):
        if not self.current_window:
            return None

        summary = self._aggregate(
            self.current_window,
            self.window_start,
            self.window_end
        )

        self.current_window = []
        return summary

    def flush(self):
        """Force flush remaining data"""
        return self._flush_current_window()

    # --------------------------------------------------
    # AGGREGATION
    # --------------------------------------------------

    def _aggregate(self, events, window_start, window_end):
        counts = defaultdict(int)
        users_failed = set()
        users_all = set()
        ips = []
        service_counts = defaultdict(int)

        for ev in events:
            et = ev.get("event_type")
            counts[et] += 1

            user = ev.get("user")
            ip = ev.get("ip")
            service = ev.get("service", "unknown")

            if user:
                users_all.add(user)
                if et == "AUTH_FAILED":
                    users_failed.add(user)

            if ip:
                ips.append("local" if ip == "::1" else ip)

            if service:
                service_counts[service] += 1

        failed = counts["AUTH_FAILED"]
        success = counts["AUTH_SUCCESS"]
        total_auth = failed + success

        failed_seen = False
        sequence_flag = 0

        for ev in events:
            if ev["event_type"] == "AUTH_FAILED":
                failed_seen = True
            elif ev["event_type"] == "AUTH_SUCCESS" and failed_seen:
                sequence_flag = 1

        return {
            "window_start": window_start,
            "window_end": window_end,

            "failed_logins": failed,
            "successful_logins": success,
            "priv_escalations": counts["PRIV_ESCALATION"],
            "file_access_events": counts["FILE_ACCESS"],
            "kernel_alerts": counts["KERNEL_ALERT"],

            "total_events": len(events),

            "unique_ips": len(set(ips)),
            "ip_list": ips,

            "users_targeted": list(users_all),

            "auth_ratio": round(failed / total_auth, 4) if total_auth > 0 else -1,

            "multiple_failed_users_flag": int(len(users_failed) > 1),
            "priv_after_failure_flag": int(counts["PRIV_ESCALATION"] > 0 and failed > 0),

            "failed_to_success_sequence": sequence_flag,

            "service_counts": dict(service_counts),
            "failed_burst": failed / max(1, len(events)),
        }

    # --------------------------------------------------
    # HELPERS
    # --------------------------------------------------

    @staticmethod
    def _to_datetime(value):
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            try:
                return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return None
        return None