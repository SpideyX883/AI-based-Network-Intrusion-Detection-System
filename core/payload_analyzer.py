import multiprocessing as mp
import logging
import base64
import re
import tempfile
import os
import urllib.parse
from pathlib import Path
from plugins import get_plugins
from models.predict import predict_bin
import json


class PayloadAnalyzer:
    def __init__(self, controller):
        self.controller = controller
        self.logger = logging.getLogger('Analyzer')
        self.keywords = self.load_keywords()
        self.plugins = get_plugins('analyzer')
        self.model = self._load_model()

    def load_keywords(self):
        """Safe keyword loading with validation"""
        try:
            with open(Path(__file__).parent / "../config/keywords.json") as f:
                raw_keywords = json.load(f)

            # Validate structure
            required_sections = ['linux', 'windows_cmd', 'powershell', 'malicious_patterns']
            if not all(section in raw_keywords for section in required_sections):
                raise ValueError("Missing required keyword sections")

            # Compile regex patterns
            compiled = {
                section: [re.compile(re.escape(kw), re.IGNORECASE) for kw in raw_keywords[section]]
                for section in raw_keywords
            }
            return compiled

        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON: {e}")
            return self.get_default_keywords()
        except Exception as e:
            logging.error(f"Keyword loading failed: {e}")
            return self.get_default_keywords()

    def get_default_keywords(self):
        """Fallback keyword dictionary with regex patterns"""
        defaults = {
            'linux': ['sudo', 'rm -rf', 'chmod'],
            'windows_cmd': ['net user', 'reg add'],
            'powershell': ['Invoke-Expression'],
            'malicious_patterns': ['base64_decode', 'eval(']
        }
        return {
            category: [re.compile(re.escape(kw), re.IGNORECASE) for kw in kws]
            for category, kws in defaults.items()
        }

    def _load_model(self):
        """Load ML model for binary analysis"""
        try:
            model_path = Path('models/malware_model.joblib')
            if model_path.exists():
                import joblib
                return joblib.load(model_path)
            return None
        except Exception as e:
            self.logger.error(f"Model loading failed: {e}")
            return None

    def analyze_payload(self, src_ip, dst_ip, payload, timestamp):
        """Full payload analysis pipeline"""
        try:
            results = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'timestamp': timestamp,
                'malicious': False,
                'reason': '',
                'confidence': 0
            }

            # Skip empty payloads
            if not payload or len(payload) < 10:
                return results

            # Step 1: Keyword matching
            decoded = self._decode_payload(payload)
            keyword_result = self._check_keywords(decoded)
            if keyword_result['malicious']:
                keyword_result.update(results)
                return keyword_result

            # Step 2: Binary analysis (for larger payloads)
            if len(payload) > 100 and self.model:
                binary_result = self._analyze_binary(payload)
                if binary_result['malicious']:
                    binary_result.update(results)
                    return binary_result

            # Step 3: Plugin analysis
            for plugin in self.plugins:
                try:
                    plugin_result = plugin().analyze(payload)
                    if plugin_result['malicious']:
                        plugin_result.update(results)
                        return plugin_result
                except Exception as e:
                    self.logger.error(f"Plugin failed: {e}")

            return results
        except Exception as e:
            self.logger.error(f"Payload analysis failed: {e}")
            return {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'timestamp': timestamp,
                'malicious': False,
                'reason': 'analysis_failed',
                'confidence': 0
            }

    def _decode_payload(self, payload):
        """Multi-layer payload decoding"""
        try:
            decoded = payload.decode('utf-8', errors='ignore').lower()

            # URL decoding
            decoded += " " + urllib.parse.unquote(decoded)

            # Base64 decoding
            for b64 in re.findall(r'[A-Za-z0-9+/=]{20,}', decoded):
                try:
                    decoded += " " + base64.b64decode(b64).decode('utf-8', errors='ignore')
                except Exception:
                    continue

            return decoded
        except Exception:
            return ""

    def _check_keywords(self, decoded_payload):
        """Check for malicious keywords/patterns"""
        for category, patterns in self.keywords.items():
            for pattern in patterns:
                if pattern.search(decoded_payload):
                    return {
                        'malicious': True,
                        'reason': f"{category}_keyword:{pattern.pattern}",
                        'confidence': 0.9
                    }
        return {'malicious': False}

    def _analyze_binary(self, payload):
        """Analyze binary payload using ML"""
        try:
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp.write(payload)
                tmp_path = tmp.name

            features = self._extract_features(tmp_path)
            result = self.model.predict_proba([features])[0]
            os.unlink(tmp_path)

            if result[1] > 0.7:  # Malicious threshold
                return {
                    'malicious': True,
                    'reason': f"malicious_binary:{result[1]:.2f}",
                    'confidence': result[1]
                }
            return {'malicious': False}
        except Exception as e:
            self.logger.error(f"Binary analysis failed: {e}")
            return {'malicious': False}

    def _extract_features(self, file_path):
        """Extract features for ML model"""
        # Dummy implementation — replace with actual feature extraction logic
        return [0.0] * 100  # Replace with real features


def start_analyzer(input_queue, output_queue, controller):
    """Initialize analyzer process"""
    analyzer = PayloadAnalyzer(controller)

    def worker():
        while True:
            try:
                src_ip, dst_ip, payload, timestamp = input_queue.get()
                result = analyzer.analyze_payload(src_ip, dst_ip, payload, timestamp)
                if result['malicious']:
                    output_queue.put(result)
            except Exception as e:
                logging.error(f"Analyzer worker failed: {e}")

    process = mp.Process(target=worker)
    process.daemon = True
    process.start()
    return process
