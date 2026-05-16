from pathlib import Path

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
RAW_BENIGN = BASE_DIR / "raw" / "benign"
RAW_MALICIOUS = BASE_DIR / "raw" / "malicious"
PROCESSED_DIR = BASE_DIR / "processed"
MODEL_DIR = BASE_DIR

# Model config
MODEL_NAME = "xgboost"
TEST_SIZE = 0.1
VAL_SIZE = 0.15

# Features
NGRAM_RANGE = (2, 4)
TOP_NGRAMS = 50
