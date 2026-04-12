# from sklearn.ensemble import IsolationForest
# import json
# import joblib


# class AnomalyDetector:
#     def __init__(self):
#         self.model = IsolationForest(
#             n_estimators=100,
#             contamination=0.1,
#             random_state=42
#         )

#     def train(self, feature_file):
#         with open(feature_file, "r") as f:
#             data = json.load(f)

#         X = [entry["features"] if isinstance(entry, dict) else entry for entry in data]

#         self.model.fit(X)
#         print(f"[INFO] Model trained on {len(X)} samples")

#     def predict(self, features):
#         score = self.model.decision_function([features])[0]
#         label = self.model.predict([features])[0]  # -1 anomaly, 1 normal
#         return score, label

#     def save(self, path="model.pkl"):
#         joblib.dump(self.model, path)

#     def load(self, path="model.pkl"):
#         self.model = joblib.load(path)

import joblib
import pickle

model = joblib.load("ids_model.pkl")

prediction = model.predict(
    [
    # brute force attack
    [1, 20, 0, 0, 0, 20.0, 1, 20.0, 1, 0, 0, 2, 6, 1],

    # distributed brute force
    [1, 25, 1, 0, 0, 25.0, 5, 5.0, 6, 1, 0, 3, 5, 1],

    # privilege escalation attack
    [2, 2, 1, 10, 0, 2.0, 2, 1.0, 3, 0, 1, 23, 6, 1],

    # sensitive file access spike
    [3, 1, 0, 0, 12, 1.0, 2, 0.5, 2, 0, 1, 1, 0, 1],

    # combined attack (realistic)
    [1, 15, 2, 5, 3, 7.5, 4, 3.75, 5, 1, 1, 2, 6, 1]
] )

if prediction[0] == -1:
    print("⚠️ ALERT: Possible intrusion detected")
else:
    print("Normal activity")