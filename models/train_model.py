import numpy as np
import pandas as pd
import joblib
from pathlib import Path
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from sklearn.metrics import classification_report
from feature_extrcation import FeatureExtractor  # Fixed import
from config import *

def load_features():
    """Load features with proper error handling"""
    features, labels = [], []
    extractor = FeatureExtractor()
    
    # Load benign samples
    try:
        meta = pd.read_csv(PROCESSED_DIR / "benign_metadata.csv")
        for _, row in meta.iterrows():
            try:
                bin_file = RAW_BENIGN / row["filename"]
                data = bin_file.read_bytes()
                feats = extractor.extract(data, row["protocol"])
                features.append(list(feats.values()))
                labels.append(0)
            except Exception as e:
                print(f"Skipped {row['filename']}: {str(e)}")
    except FileNotFoundError:
        print("Error: Missing benign_metadata.csv. Run 01_process_metadata.py first")
        exit(1)
    
    # Load malicious samples
    for bin_file in RAW_MALICIOUS.rglob("*.bin"):
        try:
            data = bin_file.read_bytes()
            feats = extractor.extract(data, "malicious")
            features.append(list(feats.values()))
            labels.append(1)
        except Exception as e:
            print(f"Skipped {bin_file}: {str(e)}")
    
    return np.array(features), np.array(labels)

def train():
    print("Loading features...")
    X, y = load_features()
    
    # 75/15/10 split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, stratify=y, random_state=42
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train, y_train, test_size=VAL_SIZE/(1-TEST_SIZE), stratify=y_train, random_state=42
    )
    
    print(f"\nDataset sizes:\n"
          f"- Train: {len(X_train)}\n"
          f"- Val:   {len(X_val)}\n"
          f"- Test:  {len(X_test)}")
    
    # Train XGBoost
    print("\nTraining model...")
    model = XGBClassifier(
        scale_pos_weight=sum(y == 0)/sum(y == 1),
        eval_metric="logloss",
        early_stopping_rounds=10,
        random_state=42
    )
    assert np.issubdtype(X_train.dtype, np.number), "Feature matrix must be numeric"
    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        verbose=10
    )
    
    # Evaluate
    print("\nValidation Report:")
    print(classification_report(y_val, model.predict(X_val)))
    print("\nTest Report:")
    print(classification_report(y_test, model.predict(X_test)))
    
    # Save model
    MODEL_DIR.mkdir(exist_ok=True)
    model_path = MODEL_DIR / "best_model.joblib"
    joblib.dump(model, model_path)
    print(f"\nModel saved to {model_path}")

if __name__ == "__main__":
    train()
