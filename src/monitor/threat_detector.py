"""
Threat Detector Module - Detects suspicious network activity
Identifies port scans, brute-force attempts, and anomalies
"""

from collections import defaultdict
from datetime import datetime, timedelta
from src.utils.logger import log_threat, log_port_scan, threat_logger


class ThreatDetector:
    """Detect and classify suspicious network activity"""
    
    # Configuration thresholds
    PORT_SCAN_THRESHOLD = 10  # More than 10 different ports in 60 seconds
    BRUTE_FORCE_THRESHOLD = 5  # More than 5 connection attempts in 30 seconds
    SLOW_SCAN_THRESHOLD = 30  # More than 30 different ports in 10 minutes
    RESET_THRESHOLD = 20  # More than 20 RST packets indicates scanning
    
    def __init__(self):
        """Initialize threat detector"""
        self.connection_history = defaultdict(list)  # IP -> list of connections
        self.threat_log = []  # List of detected threats
        self.blocked_ips = set()  # IPs already identified as threats
        
    def analyze_connection(self, remote_ip, remote_port, protocol='TCP'):
        """
        Analyze a single connection for threats
        
        Args:
            remote_ip: Remote IP address
            remote_port: Remote port number
            protocol: Connection protocol (TCP/UDP)
            
        Returns:
            Threat level: 'LOW', 'MEDIUM', 'HIGH', or None
        """
        # Record the connection
        connection = {
            'port': remote_port,
            'timestamp': datetime.now(),
            'protocol': protocol
        }
        
        self.connection_history[remote_ip].append(connection)
        
        # Clean old connections (older than 10 minutes)
        cutoff_time = datetime.now() - timedelta(minutes=10)
        self.connection_history[remote_ip] = [
            c for c in self.connection_history[remote_ip]
            if c['timestamp'] > cutoff_time
        ]
        
        # Analyze for threats
        threat_level = self._detect_threats(remote_ip)
        
        return threat_level
    
    def _detect_threats(self, ip_address):
        """
        Detect various types of threats from an IP
        
        Returns:
            Threat level or None
        """
        connections = self.connection_history[ip_address]
        
        if not connections:
            return None
        
        # Detect port scanning
        port_scan_threat = self._detect_port_scan(ip_address, connections)
        if port_scan_threat:
            return port_scan_threat
        
        # Detect brute-force attempts
        brute_force_threat = self._detect_brute_force(ip_address, connections)
        if brute_force_threat:
            return brute_force_threat
        
        # Detect suspicious service targeting
        suspicious_threat = self._detect_suspicious_patterns(ip_address, connections)
        if suspicious_threat:
            return suspicious_threat
        
        return None
    
    def _detect_port_scan(self, ip_address, connections):
        """
        Detect port scanning attempts
        
        Fast scan: Many different ports in short time
        Slow scan: Many ports over longer period
        
        Returns:
            'HIGH' if port scan detected, None otherwise
        """
        if len(connections) < self.PORT_SCAN_THRESHOLD:
            return None
        
        # Get unique ports accessed
        ports_accessed = set(c['port'] for c in connections)
        
        if len(ports_accessed) >= self.PORT_SCAN_THRESHOLD:
            # Fast port scan detection
            recent_conns = [
                c for c in connections
                if c['timestamp'] > datetime.now() - timedelta(minutes=1)
            ]
            
            if len(set(c['port'] for c in recent_conns)) >= 10:
                threat_msg = f"FAST PORT SCAN: {len(ports_accessed)} unique ports in short timeframe"
                log_port_scan(ip_address, len(ports_accessed), threat_msg)
                self._log_threat(ip_address, 'PORT_SCAN', threat_msg)
                return 'HIGH'
        
        # Slow scan detection
        if len(ports_accessed) >= self.SLOW_SCAN_THRESHOLD:
            threat_msg = f"SLOW PORT SCAN: {len(ports_accessed)} unique ports over time"
            log_port_scan(ip_address, len(ports_accessed), threat_msg)
            self._log_threat(ip_address, 'PORT_SCAN', threat_msg)
            return 'MEDIUM'
        
        return None
    
    def _detect_brute_force(self, ip_address, connections):
        """
        Detect brute-force attack attempts
        
        Checks for rapid repeated connection attempts to same ports
        
        Returns:
            'HIGH' if brute-force detected, None otherwise
        """
        # Count connections in last 30 seconds
        recent_time = datetime.now() - timedelta(seconds=30)
        recent_conns = [c for c in connections if c['timestamp'] > recent_time]
        
        if len(recent_conns) >= self.BRUTE_FORCE_THRESHOLD:
            # Common brute-force target ports
            brute_force_ports = {22, 3389, 445, 21, 23}
            
            ports_accessed = [c['port'] for c in recent_conns]
            
            # Check if targeting common brute-force ports
            if any(port in ports_accessed for port in brute_force_ports):
                threat_msg = f"BRUTE-FORCE ATTEMPT: {len(recent_conns)} rapid connections detected"
                self._log_threat(ip_address, 'BRUTE_FORCE', threat_msg)
                log_threat(ip_address, 'BRUTE_FORCE', threat_msg)
                return 'HIGH'
        
        return None
    
    def _detect_suspicious_patterns(self, ip_address, connections):
        """
        Detect other suspicious patterns
        
        - Targeting multiple high-risk ports
        - Sequential port access pattern
        
        Returns:
            'MEDIUM' if suspicious pattern detected, None otherwise
        """
        high_risk_ports = {
            22,    # SSH
            3389,  # RDP
            445,   # SMB
            139,   # NetBIOS
            25,    # SMTP
            23,    # Telnet
            21,    # FTP
            1433,  # MSSQL
            3306,  # MySQL
        }
        
        ports_accessed = [c['port'] for c in connections]
        high_risk_accessed = sum(1 for p in ports_accessed if p in high_risk_ports)
        
        if high_risk_accessed >= 3:
            threat_msg = f"SUSPICIOUS PATTERN: {high_risk_accessed} high-risk ports accessed"
            self._log_threat(ip_address, 'SUSPICIOUS', threat_msg)
            return 'MEDIUM'
        
        # Check for sequential port access (indicates automation)
        if len(ports_accessed) >= 5:
            sorted_ports = sorted(ports_accessed)
            sequential_count = 0
            
            for i in range(len(sorted_ports) - 1):
                if sorted_ports[i+1] - sorted_ports[i] <= 100:
                    sequential_count += 1
            
            if sequential_count >= 4:
                threat_msg = f"AUTOMATED SCANNING: Sequential port access pattern detected"
                self._log_threat(ip_address, 'AUTOMATED_SCAN', threat_msg)
                return 'MEDIUM'
        
        return None
    
    def _log_threat(self, ip_address, threat_type, details):
        """Log a detected threat"""
        threat = {
            'ip': ip_address,
            'type': threat_type,
            'details': details,
            'timestamp': datetime.now(),
            'action_taken': 'NONE'
        }
        
        self.threat_log.append(threat)
        threat_logger.warning(f"Threat detected from {ip_address}: {threat_type} - {details}")
    
    def get_threats_from_ip(self, ip_address):
        """Get all detected threats from an IP"""
        return [t for t in self.threat_log if t['ip'] == ip_address]
    
    def get_recent_threats(self, minutes=60):
        """Get threats detected in last N minutes"""
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        return [t for t in self.threat_log if t['timestamp'] > cutoff_time]
    
    def get_threat_summary(self):
        """Get summary of all detected threats"""
        recent_threats = self.get_recent_threats(minutes=60)
        
        by_type = defaultdict(int)
        for threat in recent_threats:
            by_type[threat['type']] += 1
        
        threatened_ips = set(t['ip'] for t in recent_threats)
        
        return {
            'total_threats': len(recent_threats),
            'threatened_ips': len(threatened_ips),
            'threats_by_type': dict(by_type),
            'threatened_ips_list': list(threatened_ips),
            'timestamp': datetime.now()
        }
    
    def mark_ip_as_threat(self, ip_address):
        """Mark an IP as a known threat"""
        self.blocked_ips.add(ip_address)
        threat_logger.warning(f"IP marked for blocking: {ip_address}")
    
    def is_ip_threat(self, ip_address):
        """Check if IP is already marked as threat"""
        return ip_address in self.blocked_ips
    
    def get_blocked_ips(self):
        """Get list of all blocked IPs"""
        return list(self.blocked_ips)
    
    def clear_ip(self, ip_address):
        """Remove IP from threat list (unblock)"""
        self.blocked_ips.discard(ip_address)
        threat_logger.info(f"IP removed from threat list: {ip_address}")
