from datetime import datetime

class FeatureExtractor:
    def __init__(self):
         self.service_map = {
            "sshd": 1,
            "sshd-session": 1,
            "sudo": 2,
            "kernel": 3
        }

    def extract(self, log):
        # service
        dt = datetime.strptime(log["start-time"], "%Y-%m-%d %H:%M:%S")

        hour = dt.hour                   
        day_of_week = dt.weekday()  

        is_night = 1 if hour < 6 or hour > 22 else 0

        services = log.get("services", [])
        service_id = max([self.service_map.get(s, 0) for s in services], default=0)

        # login info
        failed = log.get("failed_logins", 0)
        success = log.get("successful_logins", 0)
        priv_esc = log.get("priv_escalations", 0)
        file_access = log.get("file_access_events", 0)

        ratio = failed / (success + 1)
        unique_ips = log.get("unique_ips", 0)
        failed_per_ip = failed / (unique_ips+1)

        # users
        users = log.get("users_targeted", [])
        users_count = len(users)
        privileged_flag = 1 if "root" in users else 0

        multiple_failed_users_flag = log.get("multiple_failed_users_flag", 0)

        feature_vector = [
            service_id,
            failed,
            success,
            priv_esc,
            file_access,
            ratio,
            unique_ips,
            failed_per_ip,
            users_count,
            multiple_failed_users_flag,
            privileged_flag,
            hour,
            day_of_week,
            is_night
        ]
        return feature_vector, log