"""
Port Scanner Module - Scans and analyzes open ports on the system
Identifies which ports are listening and vulnerable services
"""

import socket
import subprocess
import os
from datetime import datetime
from src.utils.logger import activity_logger


class PortScanner:
    """Scan and analyze open ports"""
    
    # Common port to service mappings
    COMMON_PORTS = {
        20: 'FTP-DATA',
        21: 'FTP',
        22: 'SSH',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        8080: 'HTTP-ALT',
        8443: 'HTTPS-ALT',
    }
    
    def __init__(self):
        """Initialize port scanner"""
        self.scan_results = {}
        self.last_scan_time = None
        
    def scan_port(self, host, port, timeout=1):
        """
        Scan a single port on a host
        
        Args:
            host: IP address or hostname to scan
            port: Port number to scan
            timeout: Timeout for connection attempt
            
        Returns:
            True if port is open, False if closed
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception as e:
            activity_logger.debug(f"Error scanning port {port}: {str(e)}")
            return False
    
    def get_service_name(self, port):
        """
        Get service name for a port
        
        Args:
            port: Port number
            
        Returns:
            Service name or 'Unknown'
        """
        # First check common ports dict
        if port in self.COMMON_PORTS:
            return self.COMMON_PORTS[port]
        
        # Then try system services
        try:
            return socket.getservbyport(port)
        except:
            return 'Unknown'
    
    def scan_host_ports(self, host, ports=None, timeout=1):
        """
        Scan multiple ports on a host
        
        Args:
            host: IP address or hostname to scan
            ports: List of ports to scan (default: common ports)
            timeout: Connection timeout per port
            
        Returns:
            List of open ports with service info
        """
        if ports is None:
            ports = list(self.COMMON_PORTS.keys())
        
        open_ports = []
        
        activity_logger.info(f"Scanning {host} for {len(ports)} ports...")
        
        for port in ports:
            if self.scan_port(host, port, timeout):
                service = self.get_service_name(port)
                port_info = {
                    'port': port,
                    'service': service,
                    'state': 'OPEN',
                    'timestamp': datetime.now()
                }
                open_ports.append(port_info)
                activity_logger.info(f"Open port found: {port} ({service})")
        
        self.scan_results[host] = open_ports
        self.last_scan_time = datetime.now()
        
        return open_ports
    
    def scan_localhost(self, ports=None, timeout=1):
        """
        Scan localhost for open ports
        
        Args:
            ports: List of ports to scan
            timeout: Connection timeout
            
        Returns:
            List of open ports on localhost
        """
        return self.scan_host_ports('127.0.0.1', ports, timeout)
    
    def scan_port_range(self, host, start_port, end_port, timeout=1):
        """
        Scan a range of ports
        
        Args:
            host: IP address to scan
            start_port: Starting port number
            end_port: Ending port number
            timeout: Connection timeout
            
        Returns:
            List of open ports in range
        """
        ports = list(range(start_port, end_port + 1))
        return self.scan_host_ports(host, ports, timeout)
    
    def get_listening_ports_advanced(self):
        """
        Get listening ports using system commands (more reliable)
        macOS: netstat or ss command
        
        Returns:
            List of listening ports
        """
        try:
            listening_ports = []
            
            # Try using netstat (macOS)
            result = subprocess.run(
                ['netstat', '-an'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            for line in result.stdout.split('\n'):
                if 'LISTEN' in line:
                    parts = line.split()
                    if len(parts) > 3:
                        # Extract port from address
                        try:
                            addr = parts[3]
                            if '.' in addr:  # IPv4
                                port = int(addr.split('.')[-1])
                            elif ':' in addr:  # IPv6 or IPv4:port
                                port = int(addr.split(':')[-1])
                            else:
                                continue
                            
                            service = self.get_service_name(port)
                            listening_ports.append({
                                'port': port,
                                'service': service,
                                'state': 'LISTEN',
                                'timestamp': datetime.now()
                            })
                        except (ValueError, IndexError):
                            continue
            
            # Remove duplicates
            unique_ports = {}
            for port_info in listening_ports:
                unique_ports[port_info['port']] = port_info
            
            activity_logger.info(f"Found {len(unique_ports)} listening ports")
            return list(unique_ports.values())
            
        except Exception as e:
            activity_logger.error(f"Error scanning listening ports: {str(e)}")
            return []
    
    def detect_port_change(self, previous_ports, current_ports):
        """
        Detect changes in port state (new open/closed ports)
        
        Args:
            previous_ports: Previous scan results
            current_ports: Current scan results
            
        Returns:
            Dictionary with new_open and newly_closed ports
        """
        prev_port_nums = {p['port'] for p in previous_ports}
        curr_port_nums = {p['port'] for p in current_ports}
        
        new_open = curr_port_nums - prev_port_nums
        newly_closed = prev_port_nums - curr_port_nums
        
        return {
            'new_open': new_open,
            'newly_closed': newly_closed,
            'timestamp': datetime.now()
        }
    
    def get_scan_summary(self):
        """Get summary of all scans performed"""
        return {
            'scan_results': self.scan_results,
            'last_scan_time': self.last_scan_time,
            'total_hosts_scanned': len(self.scan_results),
            'total_open_ports': sum(len(ports) for ports in self.scan_results.values())
        }
