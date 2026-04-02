def aggregate_logs(log_list):
    summary = {
        "failed_logins": 0,
        "users_targeted": set(), # Sets only store unique names
        "unique_ips": set()
    }
    
    for log in log_list:
        if "Failed" in log['event']:
            summary["failed_logins"] += 1
        summary["users_targeted"].add(log['user'])
        summary["unique_ips"].add(log['ip'])
    
    # Convert sets back to lists for the AI model later
    summary["users_targeted"] = list(summary["users_targeted"])
    summary["unique_ips"] = len(summary["unique_ips"])
    
    return summary

# Example use:
# If you pass a list of 4 parsed logs here, it will return 1 summary.