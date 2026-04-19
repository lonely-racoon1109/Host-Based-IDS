from datetime import datetime, timedelta
import time
import numpy as np

from logSources import FileSource, JournalSource, LogSourceManager
from logWatcher import LogWatcher
from logParser import LogParser, _SYSLOG_TS_RE
from logAggregator import LogAggregator
from featureExtractor import FeatureExtractor, FEATURE_COLUMNS
from anomalyDetector import AnomalyDetector, ShapExplainer
from email_module import send_alert_email

import joblib
import json
import csv
import os


LOG_FILE = os.path.join(os.path.dirname(__file__), "ids_log.csv")

# for u in root admin test user guest; do
#   ssh $u@localhost
# done

# --------------------------------------------------
# 1. Load model
# --------------------------------------------------

model = joblib.load("models/isolation_forest.joblib")
scaler = joblib.load("models/scaler.joblib")

with open("models/model_config.json") as f:
    config = json.load(f)

FEATURE_COLS = FEATURE_COLUMNS[:24]
THRESHOLD = config["threshold"]

print("[INFO] Model loaded")


file_exists = os.path.isfile("ids_log.csv")
# --------------------------------------------------
# 2. Setup pipeline
# --------------------------------------------------
filesource = FileSource("/var/log/sudo.log")
journal = JournalSource(
    units=["sshd", "sudo", "su", "polkit", "systemd-logind"]
)

manager = LogSourceManager([filesource, journal])
manager.initialize_sources()

watcher = LogWatcher(manager)
watcher.initialize_offsets()

parser = LogParser()
aggregator = LogAggregator(window_minutes=1)
extractor = FeatureExtractor()
detector = AnomalyDetector()
explainer = ShapExplainer(model)

print("\n[INFO] IDS running...\n")


# --------------------------------------------------
# 3. Prediction
# --------------------------------------------------
def override(features, label, score):
    if features["failed_logins"] >= 10:
        return "ANOMALY", score + 0.4

    if features["users_count"] >= 4:
        return "ANOMALY", score + 0.4

    if features["failed_burst"] > 0.6:
        return "ANOMALY", score + 0.5

    return label, score

def predict(features_dict):
    # 🔥 FORCE EXACT 24 FEATURES (MATCH TRAINED MODEL)
    aligned = [features_dict.get(c, 0) for c in FEATURE_COLS]

    # trim extra features
    aligned = aligned[:24]

    x = np.array(aligned).reshape(1, -1)

    print("X shape:", x.shape)  # should be (1, 24)

    x_scaled = scaler.transform(x)

    score = -model.decision_function(x_scaled)[0]
    label = "ANOMALY" if score >= THRESHOLD else "NORMAL"

    return label, score

# --------------------------------------------------
# 4. MAIN LOOP (FIXED)
# --------------------------------------------------

while True:
    try:
        manager.check_sources()
        new_lines = watcher.collect()

        for _, line in new_lines:
            print("[RAW]", line)

            parsed = parser.parse_line(line)

            if not parsed:
                continue

            print(f"[EVENT][{parsed['timestamp']}] {parsed['event_type']} {parsed['service']}")

            parsed["service"] = (
                "sshd" if "sshd" in parsed.get("service", "")
                else "sudo" if "sudo" in parsed.get("service", "")
                else "kernel" if "kernel" in parsed.get("service", "")
                else "polkit" if "polkit" in parsed.get("service", "")
                else parsed.get("service")
            )
            result = aggregator.add_event(parsed)

            if result:
                # result can be list OR single dict
                if isinstance(result, list):
                    summaries = result
                else:
                    summaries = [result]

                for summary in summaries:
                    features, raw = extractor.extract(summary)

                    prediction, score = predict(features)
                    prediction, score = override(features, prediction, score)

                    with open(LOG_FILE, "a", newline="") as f:
                        writer = csv.DictWriter(f, fieldnames=[
                            "timestamp", "score", "label", "service", "user", "ip"
                        ])

                        if f.tell() == 0:
                            writer.writeheader()

                        writer.writerow({
                            "timestamp": summary["window_start"].isoformat(),
                            "score": float(score),
                            "label": prediction,
                            "service": summary.get("dominant_service", "unknown"),
                            "user": ",".join(summary.get("users_targeted", [])),
                            "ip": ",".join(summary.get("ip_list", [])),
                        })

                    print("\n=== IDS OUTPUT ===")
                    print("Prediction:", prediction)
                    print("Score:", round(score, 4))

                    if prediction == "ANOMALY":
                        top_features = explainer.explain(features, FEATURE_COLS)

                        send_alert_email(
                            summary=summary,
                            features=features,
                            prediction=prediction,
                            score=score,
                            shap_features=top_features
                        )

        time.sleep(1)

    except KeyboardInterrupt:
        break