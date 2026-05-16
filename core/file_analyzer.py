# core/file_analyzer.py
from models.malware_detector.scanner import MalwareScanner
import logging

class FileAnalyzer:
    def __init__(self):
        self.scanner = MalwareScanner()
        self.logger = logging.getLogger('FileAnalyzer')

    def analyze(self, file_path):
        """Analyze files with multiple detection methods"""
        try:
            # First check if it's a PE file
            if not self._is_pe_file(file_path):
                return {'malicious': False, 'reason': 'not_pe_file'}
            
            # Perform malware scan
            result = self.scanner.scan(file_path)
            
            if result['malicious']:
                self.logger.warning(
                    f"Malicious file detected: {file_path} "
                    f"(Confidence: {result['confidence']:.2%})"
                )
            
            return result
            
        except Exception as e:
            self.logger.error(f"File analysis failed: {e}")
            return {'malicious': True, 'reason': 'analysis_error'}

    def _is_pe_file(self, file_path):
        """Check if file is a Windows PE executable"""
        try:
            with open(file_path, 'rb') as f:
                return f.read(2) == b'MZ'
        except Exception as e:
            self.logger.error(f"PE check failed: {e}")
            return False
