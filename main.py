import re
from datetime import datetime
import json

# --- MODULE 3: THE PARSER ---
log_pattern = r'(?P<date>\w{3}\s+\d+\s\d+:\d+:\d+)\s(?P<service>\w+).*:\s(?P<event>.*?)\sfor\s(?P<user>\w+)\sfrom\s(?P<ip>\d+\.\d+\.\d+\.\d+)'

def parse_line(line):
    match = re.search(log_pattern, line)
    if match:
        data = match.groupdict()
        # Date Formatting to YYYY-DD-MM
        current_year = 2026 
        raw_date = f"{data['date']} {current_year}"
        date_obj = datetime.strptime(raw_date, "%b %d %H:%M:%S %Y")
        data['date'] = date_obj.strftime("%Y-%d-%m %H:%M:%S")
        return data
    return None

# --- MODULE 4: THE AGGREGATOR ---
def aggregate_logs(log_buffer):
    summary = {
        "failed_logins": 0,
        "successful_logins": 0,
        "services": set(),
        "users_targeted": set(),
        "unique_ips": set()
    }
    
    for log in log_buffer:
        if "Accepted" in log['event']:
            summary["successful_logins"] += 1
        elif "Failed" in log['event']:
            summary["failed_logins"] += 1
            
        summary["services"].add(log['service'])
        summary["users_targeted"].add(log['user'])
        summary["unique_ips"].add(log['ip'])
    
    return {
        "window_start": log_buffer[0]['date'],
        "failed": summary["failed_logins"],
        "success": summary["successful_logins"],
        "services": list(summary["services"]),
        "unique_ips": len(summary["unique_ips"]),
        "users": list(summary["users_targeted"])
    }

# --- THE BATCH PROCESSOR ---
all_parsed_logs = []

# 1. Read and parse everything first
with open("access.log", "r") as file:
    for line in file:
        parsed = parse_line(line)
        if parsed:
            all_parsed_logs.append(parsed)

# 2. Group into batches of 5
batch_size = 5
final_summaries = []



for i in range(0, len(all_parsed_logs), batch_size):
    # Take a "slice" of 5 logs
    current_batch = all_parsed_logs[i : i + batch_size]
    
    # Summarize this specific batch
    summary = aggregate_logs(current_batch)
    final_summaries.append(summary)

# 3. Print the results
print(f"Processed {len(all_parsed_logs)} logs into {len(final_summaries)} summaries.\n")

for idx, s in enumerate(final_summaries, 1):
    print(f"--- Summary Row {idx} ---")
    print(json.dumps(s, indent=4))
    print("-" * 30)