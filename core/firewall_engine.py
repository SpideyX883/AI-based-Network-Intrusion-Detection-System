import json
import time
import subprocess
import logging
from pathlib import Path
from collections import defaultdict
from scapy.all import IP, TCP, UDP, ICMP, Raw

class FirewallEngine:
    def __init__(self, controller):
        self.BASE_DIR = Path(__file__).parent
        self.RULES_FILE = self.BASE_DIR / "../config/rules.json"
        self.controller = controller
        self.logger = logging.getLogger('Firewall')
        self.rules = []
        self.temp_blocks = {}
        self.threat_intel = defaultdict(int)
        self.load_rules()

    def load_rules(self):
        """Load and validate firewall rules"""
        try:
            with open(self.RULES_FILE) as f:
                config = json.load(f)
                self.rules = config.get('rules', [])
                self.logger.info(f"Loaded {len(self.rules)} firewall rules")
                
                # Validate rule structure
                for rule in self.rules:
                    if not all(k in rule for k in ['name', 'protocol', 'action']):
                        raise ValueError(f"Invalid rule structure: {rule}")
        except Exception as e:
            self.logger.critical(f"Rule loading failed: {e}")
            raise

    def analyze(self, packet):
        """Process packet through all firewall rules"""
        try:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Check temporary blocks
            if src_ip in self.temp_blocks:
                if time.time() < self.temp_blocks[src_ip]['expires']:
                    return "block"
                del self.temp_blocks[src_ip]

            # Check threat intelligence
            if self.threat_intel[src_ip] > 3:  # Threshold for automatic block
                self.controller.block_ip(src_ip, "Threat intelligence threshold")
                return "block"

            # Protocol-specific analysis
            protocol = None
            if TCP in packet:
                protocol = 'tcp'
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                flags = packet[TCP].flags
            elif UDP in packet:
                protocol = 'udp'
                dport = packet[UDP].dport
            elif ICMP in packet:
                protocol = 'icmp'

            # Rule matching
            for rule in self.rules:
                if self._match_rule(packet, rule, protocol):
                    self.logger.debug(f"Rule '{rule['name']}' matched for {src_ip}")
                    return rule['action']
            
            return "allow"
        except Exception as e:
            self.logger.error(f"Firewall analysis failed: {e}")
            return "allow"

    def _match_rule(self, packet, rule, protocol):
        """Check if packet matches specific rule"""
        try:
            # Protocol check
            if rule['protocol'] != protocol:
                return False

            # Port check
            if 'destination_port' in rule:
                if TCP in packet and packet[TCP].dport != rule['destination_port']:
                    return False
                if UDP in packet and packet[UDP].dport != rule['destination_port']:
                    return False

            # Additional conditions can be added here
            return True
        except Exception as e:
            self.logger.warning(f"Rule matching error: {e}")
            return False

    def add_temp_block(self, ip, duration):
        """Temporarily block an IP address"""
        self.temp_blocks[ip] = {
            'timestamp': time.time(),
            'expires': time.time() + duration
        }
        self.logger.info(f"Temporarily blocked {ip} for {duration} seconds")

    def update_threat_intelligence(self, ip):
        """Update threat reputation for an IP"""
        self.threat_intel[ip] += 1
        if self.threat_intel[ip] == 3:  # Only log when threshold is reached
            self.logger.warning(f"Threat score increased for {ip} (score: {self.threat_intel[ip]})")
