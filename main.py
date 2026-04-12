from module1 import FileSource, JournalSource, LogSourceManager
from module2 import LogWatcher
from module5 import FeatureExtractor
from module3 import LogParser
from module4 import LogAggregator
from module7 import AnomalyDetector
from email_module import send_alert_email

import json
import re
from datetime import datetime
import time

dataset = "dummy.json"
file1 = FileSource("synthetic_logs.txt")  #log file
journal = JournalSource()

manager = LogSourceManager([journal])

manager.initialize_sources()

print("-----------------------------------------------")
print("Sources initialized.\n")
for source in manager.sources:
    print(source)
print("-----------------------------------------------")

# for source in manager.sources:
#     print(source.get_name(), end="\n\n")
#     print(f"Handle: {source.get_handle()}")
#     print("-----------------------------------------------")

# print("Rotation check in background....")
# while True:
#     try:
#         manager.check_sources()
#         time.sleep(2)  
#     except KeyboardInterrupt:
#         print("Stopping rotation")
#         break

    
parser = LogParser()
aggregator = LogAggregator(window_minutes=1)
extractor = FeatureExtractor()
detector = AnomalyDetector()

watcher = LogWatcher(manager.sources)
watcher.initialize_offsets()

print("IDS has started running....")

while True:
    try:
        manager.check_sources() 
        new_lines = watcher.watch()
        print("RAW:", new_lines)

        for line in new_lines:
            parsed = parser.parse_line(line)

            print("PARSED:", parsed)

            if parsed is None:
                continue

            summary = aggregator.add_log(parsed)


# with open("synthetic_logs.txt", "r") as f:
#     lines = f.readlines()

# lines.sort(key=parser.extract_time)


            if summary:
                features, raw = extractor.extract(summary)
                result = detector.predict(features)

                print("\n=== IDS OUTPUT ===")
                print("Summary:", raw)
                print("Features:", features)
                print("Prediction:", result)

                if result == "ANOMALY":
                    print("🚨 ALERT: Suspicious activity detected!")
                    send_alert_email(raw, features, result)
                print("-" * 50)
        
        time.sleep(1)

    except KeyboardInterrupt:
        print("\nStopping IDS...")
        break

# flush remaining
final = aggregator.flush()
if final:
    features, raw = extractor.extract(final)
    result = detector.predict(features)

    print("\nFINAL WINDOW")
    print("Prediction:", result)

# features_only = [entry["features"] for entry in dataset]

# with open("features_only.json", "w") as f:
#     json.dump(features_only, f, indent=4)

# with open("features.json", "w") as f:
#     json.dump(dataset, f, separators=(",", ":"))