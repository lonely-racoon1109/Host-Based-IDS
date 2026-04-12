import joblib
import numpy as np

class AnomalyDetector:
    def __init__(self, model_path="ids_model.pkl"):
        self.model = joblib.load(model_path)

    def predict(self, feature_vector):
        X = np.array(feature_vector).reshape(1, -1)
        result = self.model.predict(X)[0]

        if result == -1:
            return "ANOMALY"
        return "NORMAL"