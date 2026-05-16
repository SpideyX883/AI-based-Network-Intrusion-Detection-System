import joblib
import json
from pathlib import Path
from models.config import *
from models.feature_extractor import FeatureExtractor  # Use your updated extractor

# Load trained model and feature extractor
model = joblib.load(BASE_DIR / "best_model.joblib")
fe = FeatureExtractor()

def predict_bin(file_path: Path):
    try:
        data = file_path.read_bytes()
        features = fe.extract(data)

        # Ensure consistent order of features
        feature_vector = [features[k] for k in sorted(features.keys())]

        proba = model.predict_proba([feature_vector])[0][1]
        return {
            "file": file_path.name,
            "prediction": "MALICIOUS" if proba > 0.7 else "BENIGN",
            "confidence": round(float(proba), 4),
            "top_features": features  # renamed for clarity
        }
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 predict.py <binary_file>")
    else:
        result = predict_bin(Path(sys.argv[1]))
        print(json.dumps(result, indent=2))
