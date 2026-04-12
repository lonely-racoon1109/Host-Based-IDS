from datetime import datetime, timedelta


class LogAggregator:
    def __init__(self, window_minutes=1):
        self.window_minutes = window_minutes
        self.current_window = []
        self.window_start = None
        self.reset()

    
    def reset(self):
        self.summary = {
            "AUTH_FAILED": 0,
            "AUTH_SUCCESS": 0,
            "PRIV_ESCALATION": 0,
            "FILE_ACCESS": 0,
            "users": set(),
            "ips": set()
        }

    def _parse_time(self, timestamp):
        return datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")

    def add_log(self, log):
        log_time = self._parse_time(log["timestamp"])

        if self.window_start is None:
            self.window_start = log_time

        # Check if log belongs to current window
        if log_time < self.window_start + timedelta(minutes=self.window_minutes):
            self.current_window.append(log)
            return None  # still collecting

        # Window expired → aggregate
        summary = self._aggregate(self.current_window)

        # Reset for next window
        self.current_window = [log]
        self.window_start = log_time

        return summary

    def flush(self):
        """Call at end to process remaining logs"""
        if self.current_window:
            return self._aggregate(self.current_window)
        return None

    def _aggregate(self, logs):
        self.reset()
        failed_users = set()
        for log in logs:
            et = log["event_type"]

            if et == "AUTH_FAILED":
                failed_users.add(log["user"])

            if et in self.summary:
                self.summary[et]+=1

            if log.get("user"):
                self.summary["users"].add(log["user"])

            if log.get("ip"):
                self.summary["ips"].add(log["ip"])
                     
        start_time = logs[0]["timestamp"]
        end_time = logs[-1]["timestamp"]

        return {
            "start-time": start_time,
            "end-time": end_time,
            "time_period": f"{start_time}–{end_time}",
            "service": list(set(log.get("service", "unknown") for log in logs)),
            "failed_logins": self.summary["AUTH_FAILED"],
            "successful_logins": self.summary["AUTH_SUCCESS"],
            "priv_escalations": self.summary["PRIV_ESCALATION"],
            "file_access_events": self.summary["FILE_ACCESS"],
            "unique_ips": len(self.summary["ips"]),
            "users_targeted": list(self.summary["users"]),
            "multiple_failed_users_flag": 1 if len(failed_users) > 1 else 0
                }