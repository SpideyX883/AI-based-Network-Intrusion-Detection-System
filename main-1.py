#!/usr/bin/env python3
import os
import sys
import signal
import time
import logging
import multiprocessing as mp
import subprocess
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from scapy.all import IP, TCP, UDP, ICMP, Raw, Ether
from netfilterqueue import NetfilterQueue
import json
# Constants
CONFIG_DIR = "config"
RULES_FILE = os.path.join(CONFIG_DIR, "rules.json")
WHITELIST_FILE = os.path.join(CONFIG_DIR, "whitelist.txt")
LOG_DIR = "logs"
ALERT_LOG = os.path.join(LOG_DIR, "alerts.log")
TRAFFIC_LOG = os.path.join(LOG_DIR, "traffic.log")

class NIPSController:
    def __init__(self):
        self.RULES_FILE = Path(__file__).parent / "config/rules.json"
        self.setup_directories()
        self.setup_logging()
        self.load_configurations()
        
        # Component initialization
        from core.firewall_engine import FirewallEngine
        from core.dos_protector import DOSProtector
        from core.payload_analyzer import start_analyzer
        #from file_monitor import start_file_monitor
        
        self.firewall = FirewallEngine(self)
        self.dos_protector = DOSProtector(self)
        
        # IPC Communication
        self.payload_queue = mp.Queue(maxsize=1000)
        self.result_queue = mp.Queue()
        self.analyzer = start_analyzer(self.payload_queue, self.result_queue, self)
       # self.file_monitor = start_file_monitor(self)
        
        # State tracking
        self.traffic_stats = defaultdict(lambda: defaultdict(int))
        self.blocked_ips = {}
        self.start_time = datetime.now()

    def setup_directories(self):
        """Ensure required directories exist"""
        os.makedirs(CONFIG_DIR, exist_ok=True)
        os.makedirs(LOG_DIR, exist_ok=True)
        if not os.path.exists(WHITELIST_FILE):
            open(WHITELIST_FILE, 'w').close()

    def setup_logging(self):
        """Configure comprehensive logging system"""
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            handlers=[
                logging.FileHandler(ALERT_LOG),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger('NIPS')
        
        # Traffic-specific logger
        traffic_handler = logging.FileHandler(TRAFFIC_LOG)
        traffic_handler.setFormatter(logging.Formatter('%(message)s'))
        self.traffic_logger = logging.getLogger('TRAFFIC')
        self.traffic_logger.addHandler(traffic_handler)
        self.traffic_logger.propagate = False

    def load_configurations(self):
        """Load all configuration files with validation"""
        try:
            # Whitelist loading
            with open(WHITELIST_FILE) as f:
                self.whitelist = {line.strip() for line in f if line.strip()}
            
            # Rules loading
            if not os.path.exists(RULES_FILE):
                self.logger.error(f"Rules file not found at {RULES_FILE}")
                self.generate_default_rules()
            with open(RULES_FILE) as f:
                self.rules = json.load(f)
                
        except json.JSONDecodeError as e:
            self.logger.critical(f"Invalid JSON in rules file: {e}")
            sys.exit(1)
        except Exception as e:
            self.logger.critical(f"Configuration error: {e}")
            sys.exit(1)

    def generate_default_rules(self):
        """Create default rules if none exist"""
        default_rules = {
            "rules": [
                {
                    "name": "block_ssh_bruteforce",
                    "protocol": "tcp",
                    "destination_port": 22,
                    "action": "block",
                    "threshold": {
                        "count": 5,
                        "period": 60
                    }
                }
            ],
            "thresholds": {
                "syn_flood": 100,
                "udp_flood": 500,
                "icmp_flood": 200
            }
        }
        with open(RULES_FILE, 'w') as f:
            json.dump(default_rules, f, indent=2)
        self.logger.warning(f"Generated default rules at {RULES_FILE}")

    def initialize_network(self):
        """Configure iptables and network settings"""
        try:
            subprocess.run(["iptables", "-F"], check=True)
            subprocess.run(["iptables", "-X"], check=True)
            subprocess.run([
                "iptables", "-A", "INPUT",
                "-j", "NFQUEUE", "--queue-num", "1"
            ], check=True)
            subprocess.run([
                "iptables", "-A", "OUTPUT",
                "-j", "NFQUEUE", "--queue-num", "1"
            ], check=True)
            self.logger.info("Network rules initialized")
        except subprocess.CalledProcessError as e:
            self.logger.critical(f"Failed to configure iptables: {e}")
            sys.exit(1)

    def packet_handler(self, packet):
        """Complete packet processing pipeline"""
        try:
            # Decode packet
            scapy_pkt = IP(packet.get_payload())
            if not scapy_pkt:
                raise ValueError("Invalid packet structure")
            
            src_ip = scapy_pkt.src
            dst_ip = scapy_pkt.dst
            
            # Log basic traffic
            self.log_traffic(scapy_pkt)
            
            # Whitelist check
            if src_ip in self.whitelist:
                packet.accept()
                return

            # DOS protection
            dos_action = self.dos_protector.analyze(scapy_pkt)
            if dos_action == "block":
                self.block_ip(src_ip, "DOS detected")
                packet.drop()
                return

            # Firewall rules
            fw_action = self.firewall.analyze(scapy_pkt)
            if fw_action != "allow":
                self.log_alert(
                    f"Firewall blocked {src_ip} -> {dst_ip}",
                    "firewall",
                    src_ip
                )
                packet.drop()
                return

            # Payload analysis (async)
            if Raw in scapy_pkt:
                self.payload_queue.put((
                    src_ip,
                    dst_ip,
                    bytes(scapy_pkt[Raw].load),
                    time.time()
                ))
                try:
                    result = self.result_queue.get(timeout=0.2)
                    if result["malicious"]:
                        self.handle_malicious_payload(result)
                        packet.drop()
                        return
                except mp.queues.Empty:
                    pass

            packet.accept()
            
        except Exception as e:
            self.logger.error(f"Packet processing failed: {e}", exc_info=True)
            packet.accept()

    def handle_malicious_payload(self, result):
        """Take action on malicious content"""
        ip = result["src_ip"]
        reason = result["reason"]
        
        self.log_alert(
            f"Malicious payload from {ip}: {reason}",
            "payload_analysis",
            ip
        )
        
        # Update threat intelligence
        self.firewall.update_threat_intelligence(ip)
        
        # Block based on severity
        if "critical" in reason.lower():
            self.block_ip(ip, f"Critical threat: {reason}")
        else:
            self.firewall.add_temp_block(ip, 300)  # 5 minute block

    def block_ip(self, ip, reason=""):
        """Permanently block an IP address"""
        try:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True
            )
            self.blocked_ips[ip] = time.time()
            self.log_alert(f"Blocked IP {ip}: {reason}", "block", ip)
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to block {ip}: {e}")

    def log_traffic(self, packet):
        """Record traffic statistics and logs"""
        protocol = "other"
        if TCP in packet:
            protocol = "tcp"
        elif UDP in packet:
            protocol = "udp"
        elif ICMP in packet:
            protocol = "icmp"
            
        self.traffic_stats[protocol]["total"] += 1
        self.traffic_logger.info(
            f"{time.time()},{packet.src},{packet.dst},{protocol},"
            f"{len(packet)},{packet.getlayer(Raw) is not None}"
        )

    def log_alert(self, message, alert_type, ip=None):
        """Standardized alert logging"""
        alert = {
            "timestamp": datetime.now().isoformat(),
            "type": alert_type,
            "message": message,
            "ip": ip
        }
        self.logger.warning(json.dumps(alert))
        
        # Additional actions (email, SIEM integration, etc.)
        if alert_type == "critical":
            self.notify_admin(alert)

    def run(self):
        """Main execution loop"""
        self.initialize_network()
        
        nfqueue = NetfilterQueue()
        try:
            nfqueue.bind(1, self.packet_handler)
            
            # Signal handling
            signal.signal(signal.SIGINT, self.shutdown)
            signal.signal(signal.SIGTERM, self.shutdown)
            
            self.logger.info(f"NIPS started at {self.start_time}")
            print("[*] NIPS is running. Press Ctrl+C to stop.")
            
            # Main loop
            nfqueue.run()
            
        except Exception as e:
            self.logger.critical(f"Fatal error: {e}", exc_info=True)
            self.shutdown()

    def shutdown(self, signum=None, frame=None):
        """Graceful shutdown procedure"""
        self.logger.info("Initiating shutdown...")
        
        # Stop components
        self.analyzer.terminate()
       # self.file_monitor.stop()
        
        # Cleanup iptables
        try:
            subprocess.run(["iptables", "-F"], check=True)
            subprocess.run(["iptables", "-X"], check=True)
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to clean iptables: {e}")
        
        # Final stats
        runtime = datetime.now() - self.start_time
        self.logger.info(
            f"Shutdown complete. Runtime: {runtime}. "
            f"Packets processed: {sum(stats['total'] for stats in self.traffic_stats.values())}"
        )
        sys.exit(0)

if __name__ == "__main__":
    nips = NIPSController()
    nips.run()
