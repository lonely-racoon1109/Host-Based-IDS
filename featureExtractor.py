from datetime import datetime
import math
from collections import Counter

# Ordered list of feature names — single source of truth.
# The vector returned by extract() always matches this order.
FEATURE_COLUMNS = [
    "failed_logins",
    "successful_logins",
    "priv_escalations",
    "file_access_events",
    "kernel_alerts",
    "auth_ratio",
    "unique_ips",
    "failed_per_ip",
    "users_count",
    "privileged_user_targeted",
    "multiple_failed_users_flag",
    "priv_after_failure_flag",
    "svc_sshd",
    "svc_sudo",
    "svc_kernel",
    "hour",
    "day_of_week",
    "is_night",
    "is_weekend",
    "sensitive_file_access",
    "suspicious_command_flag",
    "weird_behavior_flag",
    "ip_entropy",
    "failed_to_success_sequence",
    "failed_burst",
    "failed_density",
]

# Accounts considered privileged for targeting detection.
# Expand this list as needed.
PRIVILEGED_ACCOUNTS = frozenset({
    "root", "www-data", "postgres", "mysql", "daemon",
    "nobody", "bin", "sys", "mail", "ftp", "admin",
})


class FeatureExtractor:
    def __init__(self, privileged_accounts=None):
        self.privileged_accounts = privileged_accounts or PRIVILEGED_ACCOUNTS

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def extract(self, summary):
        """
        Convert an aggregator summary dict into a named feature dict
        and a plain ordered list (the vector for sklearn).

        Returns:
            feature_dict   : {column_name: value, ...}  — for inspection/logging
            feature_vector : [float, ...]               — for model.predict()
        """
        dt = self._get_datetime(summary)
        service_counts = summary.get("service_counts", {})
        users = set(summary.get("users_targeted", []))

        failed   = summary.get("failed_logins", 0)
        success  = summary.get("successful_logins", 0)
        unique_ips = summary.get("unique_ips", 0)

        # auth_ratio: use pre-computed value from aggregator (-1 = quiet window)
        auth_ratio = summary.get("auth_ratio", -1)

        # You will need aggregator to pass these (safe defaults for now)
        sensitive_files = summary.get("sensitive_files_accessed", 0)
        commands        = summary.get("commands", [])

        # 1. Sensitive file access
        sensitive_file_access = int(sensitive_files > 0)

        # 2. Suspicious command detection
        SUSPICIOUS_COMMANDS = ["nmap", "netstat", "hydra", "cat /etc/shadow", "sudo su", "chmod 777"]
        suspicious_command_flag = int(any(cmd in str(commands) for cmd in SUSPICIOUS_COMMANDS))

        # 3. Weird behavior pattern
        weird_behavior_flag = int(
            (dt.hour < 6 or dt.hour >= 22) and summary.get("priv_escalations", 0) > 0
            or (failed > 5 and len(users) > 3)
        )

        ips = summary.get("ip_list", [])

        if len(ips) <= 1:
            ip_entropy = 0.0
        else:
            counts = Counter(ips)
            total = len(ips)
            ip_entropy = -sum(
                (c/total) * math.log2(c/total)
                for c in counts.values()
            )
        

        # failed_per_ip: only meaningful when IPs were actually extracted
        failed_per_ip = round(failed / unique_ips, 4) if unique_ips > 0 else 0

        feature_dict = {
            "failed_logins":              failed,
            "successful_logins":          success,
            "priv_escalations":           summary.get("priv_escalations", 0),
            "file_access_events":         summary.get("file_access_events", 0),
            "kernel_alerts":              summary.get("kernel_alerts", 0),
            "auth_ratio":                 auth_ratio,
            "unique_ips":                 unique_ips,
            "failed_per_ip":              failed_per_ip,
            "users_count":                len(users),
            "privileged_user_targeted":   int(bool(users & self.privileged_accounts)),
            "multiple_failed_users_flag": summary.get("multiple_failed_users_flag", 0),
            "priv_after_failure_flag":    summary.get("priv_after_failure_flag", 0),
            # Per-service binary flags (replaces single service_id)
            "svc_sshd":   int(bool(service_counts.get("sshd", 0) or
                                   service_counts.get("sshd-session", 0))),
            "svc_sudo":   int(bool(service_counts.get("sudo", 0))),
            "svc_kernel": int(bool(service_counts.get("kernel", 0))),
            # Time features
            "hour":        dt.hour,
            "day_of_week": dt.weekday(),
            "is_night":    int(dt.hour < 6 or dt.hour >= 22),
            "is_weekend":  int(dt.weekday() >= 5),
            "sensitive_file_access": sensitive_file_access,
            "suspicious_command_flag": suspicious_command_flag,
            "weird_behavior_flag": weird_behavior_flag,
            "ip_entropy": ip_entropy,
            "failed_to_success_sequence": summary.get("failed_to_success_sequence", 0),
            "failed_burst": summary.get("failed_burst", 0),
            "failed_density": failed / max(1, summary.get("total_events", 1)),
        }

        # Build vector in guaranteed column order
        feature_vector = [feature_dict[col] for col in FEATURE_COLUMNS]

        return feature_dict, feature_vector

    def get_feature_names(self):
        """Return column names — pass to model trainer for feature importance."""
        return list(FEATURE_COLUMNS)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_datetime(self, summary):
        """
        Accept window_start as datetime object or ISO string.
        Falls back to current time if missing (shouldn't happen in production).
        """
        ws = summary.get("window_start")
        if isinstance(ws, datetime):
            return ws
        if isinstance(ws, str):
            try:
                return datetime.strptime(ws, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                pass
        # Fallback — log a warning in production
        return datetime.now()