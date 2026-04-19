import joblib
import json
import numpy as np

import shap
import numpy as np

class ShapExplainer:
    def __init__(self, model):
        self.model = model
        self.explainer = shap.Explainer(model)

    def explain(self, feature_dict, feature_order):
        x = np.array([[feature_dict[f] for f in feature_order]])

        shap_values = self.explainer(x)

        contributions = {}
        for i, f in enumerate(feature_order):
            contributions[f] = float(shap_values.values[0][i])

        # sort by importance
        top = sorted(contributions.items(), key=lambda x: abs(x[1]), reverse=True)[:5]

        return top

class AnomalyDetector:
    def __init__(self):
        self.model = joblib.load("models/isolation_forest.joblib")
        self.scaler = joblib.load("models/scaler.joblib")

        with open("models/model_config.json") as f:
            config = json.load(f)

        self.threshold = config["threshold"]
        self.feature_order = config["features"]

    def predict(self, feature_dict):
        x = np.array([features[c] for c in FEATURE_COLS]).reshape(1, -1)
        x_scaled = scaler.transform(x)

        score = -model.decision_function(x_scaled)[0]
        prediction = "ANOMALY" if score >= THRESHOLD else "NORMAL"

        # ✅ APPLY OVERRIDE HERE
        prediction, score = override(features, prediction, score)