# file: model.py

import joblib
import os

# ✅ Set safe model path
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "phishing_model.pkl")

# ✅ Load model once
model = joblib.load(MODEL_PATH)

# ✅ Real prediction
def predict_from_features(feature_vector):
    proba = model.predict_proba([feature_vector])[0]
    pred = model.predict([feature_vector])[0]
    label = "phishing" if pred == 1 else "safe"
    confidence = round(max(proba), 2)
    return {
        "label": label,
        "confidence": confidence
    }

