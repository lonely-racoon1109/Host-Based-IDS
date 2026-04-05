from module1 import FileSource, JournalSource, LogSourceManager
from module2 import LogWatcher
from module5 import FeatureExtractor
from module3 import LogParser
from module4 import LogAggregator
from utils import extract_time

import json
import re
from datetime import datetime

dataset = "dummy.json"
file1 = FileSource("/home/shubhashree/Projects/python/offline-sync/uploads/.sync/log.json")
# journal = JournalSource()

# manager = LogSourceManager([file1])

# manager.initialize_sources()

# print("-----------------------------------------------")
# print("Sources initialized.\n")
# print(manager.sources[0])
# # print(manager.sources[1])
# print("-----------------------------------------------")

# for source in manager.sources:
#     print(source.get_name(), end="\n\n")
#     print(f"Handle: {source.get_handle()}")
#     print("-----------------------------------------------")

# print("Rotation check....")
# while True:
#     try:
#         manager.check_sources()
#         time.sleep(2)  
#     except KeyboardInterrupt:
#         print("Stopping rotation")
#         break

# watcher = LogWatcher(manager.sources)
# watcher.initialize_offsets()

# watcher.watch()
    
parser = LogParser()
aggregator = LogAggregator(window_minutes=5)
extractor = FeatureExtractor()

with open("logs.txt", "r") as f:
    lines = f.readlines()

# sort by timestamp

lines.sort(key=extract_time)
dataset = []

for line in lines:
    parsed = parser.parse_line(line)

    if parsed is None:
        continue

    summary = aggregator.add_log(parsed)

    if summary:
        features, raw = extractor.extract(summary)
        dataset.append({
            "features": features,
            "summary": raw
        })

# flush remaining logs
final = aggregator.flush()
if final:
    features, raw = extractor.extract(final)
    dataset.append({
        "features": features,
        "summary": raw
    })

with open("features.json", "w") as f:
    json.dump(dataset, f, separators=(",", ":"))