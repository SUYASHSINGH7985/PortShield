"""
Connection Monitor Module - Tracks active network connections and ports
Monitors incoming/outgoing connections in real-time
"""

import psutil
import socket
from collections import defaultdict
from datetime import datetime, timedelta
from src.utils.logger import log_connection, activity_logger


class ConnectionMonitor:
    """Monitor and track network connections"""
    
    def __init__(self):
        """Initialize the monitor"""
        self.connections = []
        self.port_activity = defaultdict(list)  # Track connections per port
        self.ip_activity = defaultdict(list)    # Track connections per IP
        self.connection_history = defaultdict(int)  # Count connections per IP
        
    def get_active_connections(self):
        """
        Get all active network connections
        
        Returns:
            List of connection dictionaries with IP, port, protocol, and state
        """
        try:
            active_conns = []
            
            # Get all network connections using psutil
            # Arguments: kind='inet' (IPv4), 'inet6' (IPv6), 'all'
            for conn in psutil.net_connections(kind='inet'):
                # Skip connections without remote address
                if not conn.raddr:
                    continue
                
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                protocol = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
                state = conn.status if hasattr(conn, 'status') else 'UNKNOWN'
                
                connection_info = {
                    'remote_ip': remote_ip,
                    'remote_port': remote_port,
                    'local_port': conn.laddr.port if conn.laddr else 0,
                    'protocol': protocol,
                    'state': state,
                    'timestamp': datetime.now(),
                    'pid': conn.pid
                }
                
                active_conns.append(connection_info)
                
                # Update tracking dictionaries
                self.port_activity[remote_port].append(connection_info)
                self.ip_activity[remote_ip].append(connection_info)
                self.connection_history[remote_ip] += 1
                
            self.connections = active_conns
            activity_logger.info(f"Monitoring: Found {len(active_conns)} active connections")
            return active_conns
            
        except Exception as e:
            activity_logger.error(f"Error getting active connections: {str(e)}")
            return []
    
    def get_listening_ports(self):
        """
        Get all ports the system is listening on
        
        Returns:
            List of listening ports with protocol info
        """
        try:
            listening_ports = []
            
            for conn in psutil.net_connections(kind='inet'):
                # Filter for LISTEN state only
                if conn.status == psutil.CONN_LISTEN:
                    protocol = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
                    
                    port_info = {
                        'port': conn.laddr.port,
                        'protocol': protocol,
                        'address': conn.laddr.ip,
                        'timestamp': datetime.now()
                    }
                    
                    listening_ports.append(port_info)
            
            activity_logger.info(f"Listening ports: {len(listening_ports)} ports detected")
            return listening_ports
            
        except Exception as e:
            activity_logger.error(f"Error getting listening ports: {str(e)}")
            return []
    
    def get_connections_from_ip(self, ip_address):
        """
        Get all connections from a specific IP
        
        Args:
            ip_address: IP to filter by
            
        Returns:
            List of connections from that IP
        """
        return self.ip_activity.get(ip_address, [])
    
    def get_connections_to_port(self, port):
        """
        Get all connections to a specific port
        
        Args:
            port: Port number to filter by
            
        Returns:
            List of connections to that port
        """
        return self.port_activity.get(port, [])
    
    def get_ip_connection_count(self, ip_address):
        """Get number of connections from an IP"""
        return self.connection_history.get(ip_address, 0)
    
    def get_connection_summary(self):
        """
        Get summary statistics about connections
        
        Returns:
            Dictionary with connection statistics
        """
        self.get_active_connections()  # Update data
        
        unique_ips = len(self.ip_activity)
        unique_ports = len(self.port_activity)
        total_connections = len(self.connections)
        
        # Find top IPs by connection count
        top_ips = sorted(
            self.connection_history.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        # Find top ports
        top_ports = sorted(
            [(port, len(conns)) for port, conns in self.port_activity.items()],
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        return {
            'total_connections': total_connections,
            'unique_ips': unique_ips,
            'unique_ports': unique_ports,
            'top_ips': top_ips,
            'top_ports': top_ports,
            'timestamp': datetime.now()
        }
    
    def clear_old_activity(self, hours=24):
        """
        Clear activity data older than specified hours
        
        Args:
            hours: Hours of history to keep
        """
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        # Clear old port activity
        for port in self.port_activity:
            self.port_activity[port] = [
                conn for conn in self.port_activity[port]
                if conn['timestamp'] > cutoff_time
            ]
        
        # Clear old IP activity
        for ip in self.ip_activity:
            self.ip_activity[ip] = [
                conn for conn in self.ip_activity[ip]
                if conn['timestamp'] > cutoff_time
            ]
        
        activity_logger.info(f"Cleared activity older than {hours} hours")
