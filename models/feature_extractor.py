# Fixed `feature_extrcation.py` (remove protocol field entirely)
from capstone import *
import numpy as np
from scipy.stats import entropy
import joblib
from pathlib import Path
from models.config import *

class FeatureExtractor:
    def __init__(self):
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.ngrams = self._load_ngrams()

    def _load_ngrams(self):
        ngram_file = PROCESSED_DIR / "top_ngrams.joblib"
        return joblib.load(ngram_file) if ngram_file.exists() else {}

    def _calc_entropy(self, data):
        if not data:
            return 0.0
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        prob = counts / counts.sum()
        return float(entropy(prob, base=2))

    def extract(self, payload, protocol=None):  # protocol ignored
        features = {
            "size": len(payload),
            "entropy": self._calc_entropy(payload),
            **{f"ngram_{k}": payload.count(v) for k, v in self.ngrams.items()}
        }

        try:
            instructions = [i.mnemonic for i in self.md.disasm(payload, 0x1000)]
            features.update({
                "mov": instructions.count("mov"),
                "call": instructions.count("call"),
                "jmp": instructions.count("jmp")
            })
        except:
            features.update({"mov": 0, "call": 0, "jmp": 0})

        return features

def build_ngram_database():
    from collections import Counter
    ngrams = Counter()
    for path in [RAW_BENIGN, RAW_MALICIOUS]:
        for bin_file in path.rglob("*.bin"):
            try:
                data = bin_file.read_bytes()
                for n in range(NGRAM_RANGE[0], NGRAM_RANGE[1] + 1):
                    ngrams.update([data[i:i+n] for i in range(len(data)-n+1)])
            except Exception as e:
                print(f"Skipped {bin_file}: {str(e)}")

    top_ngrams = {f"ng_{i}": k for i, (k, _) in enumerate(ngrams.most_common(TOP_NGRAMS))}
    joblib.dump(top_ngrams, PROCESSED_DIR / "top_ngrams.joblib")

if __name__ == "__main__":
    build_ngram_database()
