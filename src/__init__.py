"""
PortShield - Intelligent Port Monitoring Firewall
Main package initialization
"""

__version__ = "1.0.0"
__author__ = "PortShield Team"
__description__ = "Real-time port monitoring and intelligent firewall for small business networks"

from src.utils.logger import threat_logger, firewall_logger, activity_logger
from src.monitor.threat_detector import ThreatDetector
from src.monitor.connection_monitor import ConnectionMonitor
from src.monitor.port_scanner import PortScanner
from src.firewall.firewall_manager import FirewallManager

__all__ = [
    'ThreatDetector',
    'ConnectionMonitor',
    'PortScanner',
    'FirewallManager',
    'threat_logger',
    'firewall_logger',
    'activity_logger'
]
