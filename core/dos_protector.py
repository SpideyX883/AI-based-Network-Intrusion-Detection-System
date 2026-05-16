import time
import logging
import json
from collections import defaultdict, deque
from scapy.all import IP, TCP, UDP, ICMP
from scapy.packet import Packet
from typing import Union

class DOSProtector:
    def __init__(self, controller):
        self.controller = controller
        self.logger = logging.getLogger('DOS')
        self.rates = defaultdict(lambda: defaultdict(lambda: deque(maxlen=1000)))
        self.syn_cache = {}
        self.load_thresholds()
        self.logger.info("DOSProtector initialized")

    def load_thresholds(self):
        """Load DOS protection thresholds from config"""
        try:
            with open(self.controller.RULES_FILE) as f:
                config = json.load(f)
                self.thresholds = {
                    'syn_flood': config.get('thresholds', {}).get('syn_flood', 100),
                    'udp_flood': config.get('thresholds', {}).get('udp_flood', 500),
                    'icmp_flood': config.get('thresholds', {}).get('icmp_flood', 200),
                    'connection_rate': config.get('thresholds', {}).get('connection_rate', 50)
                }
            self.logger.info(f"Loaded DOS thresholds: {self.thresholds}")
        except Exception as e:
            self.logger.error(f"Threshold loading failed: {e}")
            self.thresholds = {
                'syn_flood': 100,
                'udp_flood': 500,
                'icmp_flood': 200,
                'connection_rate': 50
            }

    def analyze(self, packet: Union[Packet, bytes]) -> str:
        """
        Analyze network packet for DOS patterns
        Args:
            packet: Either a Scapy packet or raw bytes from NetfilterQueue
        Returns:
            str: 'block' if attack detected, 'allow' otherwise
        """
        try:
            # Convert to Scapy packet if needed
            scapy_pkt = self._ensure_scapy_packet(packet)
            if not scapy_pkt or not scapy_pkt.haslayer(IP):
                return "allow"

            src_ip = scapy_pkt[IP].src
            now = time.time()

            # Protocol-specific analysis
            if scapy_pkt.haslayer(TCP):
                return self._analyze_tcp(scapy_pkt, src_ip, now)
            elif scapy_pkt.haslayer(UDP):
                return self._analyze_udp(scapy_pkt, src_ip, now)
            elif scapy_pkt.haslayer(ICMP):
                return self._analyze_icmp(scapy_pkt, src_ip, now)

            return "allow"
        except Exception as e:
            self.logger.error(f"DOS analysis failed: {str(e)}", exc_info=True)
            return "allow"

    def _ensure_scapy_packet(self, packet: Union[Packet, bytes]) -> Packet:
        """Convert raw packets to Scapy format"""
        if isinstance(packet, bytes):
            return IP(packet)
        elif hasattr(packet, 'get_payload'):  # NetfilterQueue packet
            return IP(packet.get_payload())
        return packet

    def _analyze_tcp(self, pkt: Packet, src_ip: str, timestamp: float) -> str:
        """Analyze TCP packets for SYN floods"""
        tcp = pkt[TCP]
        
        # SYN packet analysis
        if 'S' in str(tcp.flags) and not ('A' in str(tcp.flags)):
            self.rates[src_ip]['syn'].append(timestamp)
            if len(self.rates[src_ip]['syn']) > self.thresholds['syn_flood']:
                self.controller.log_alert(
                    f"SYN flood detected from {src_ip} ({len(self.rates[src_ip]['syn'])} packets)",
                    "syn_flood",
                    src_ip
                )
                return "block"
            
            # Track SYN packets for handshake verification
            self.syn_cache[(src_ip, tcp.sport)] = timestamp

        # ACK packet verification
        elif 'A' in str(tcp.flags):
            key = (pkt[IP].dst, tcp.dport)
            if key in self.syn_cache:
                del self.syn_cache[key]

        return "allow"

    def _analyze_udp(self, pkt: Packet, src_ip: str, timestamp: float) -> str:
        """Analyze UDP packets for floods"""
        self.rates[src_ip]['udp'].append(timestamp)
        if len(self.rates[src_ip]['udp']) > self.thresholds['udp_flood']:
            self.controller.log_alert(
                f"UDP flood detected from {src_ip} ({len(self.rates[src_ip]['udp'])} packets)",
                "udp_flood",
                src_ip
            )
            return "block"
        return "allow"

    def _analyze_icmp(self, pkt: Packet, src_ip: str, timestamp: float) -> str:
        """Analyze ICMP packets for floods"""
        self.rates[src_ip]['icmp'].append(timestamp)
        if len(self.rates[src_ip]['icmp']) > self.thresholds['icmp_flood']:
            self.controller.log_alert(
                f"ICMP flood detected from {src_ip} ({len(self.rates[src_ip]['icmp'])} packets)",
                "icmp_flood",
                src_ip
            )
            return "block"
        return "allow"

    def _cleanup_old_entries(self, current_time: float):
        """Remove stale entries from tracking"""
        timeout = 60  # 1 minute window
        for ip in list(self.rates.keys()):
            for proto in list(self.rates[ip].keys()):
                while (self.rates[ip][proto] and 
                       current_time - self.rates[ip][proto][0] > timeout):
                    self.rates[ip][proto].popleft()
                if not self.rates[ip][proto]:
                    del self.rates[ip][proto]
