"""
Logger Module - Centralized logging for PortShield
Handles all logging operations for monitoring, threats, and debugging
"""

import logging
import os
from datetime import datetime

# Create logs directory if it doesn't exist
LOG_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'logs')
os.makedirs(LOG_DIR, exist_ok=True)

# Log file paths
THREAT_LOG = os.path.join(LOG_DIR, 'threats.log')
FIREWALL_LOG = os.path.join(LOG_DIR, 'firewall.log')
ACTIVITY_LOG = os.path.join(LOG_DIR, 'activity.log')


def setup_logger(name, log_file, level=logging.INFO):
    """
    Setup a logger with file and console handlers
    
    Args:
        name: Logger name
        log_file: Path to log file
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # File handler - logs to file
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(level)
    
    # Console handler - logs to console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    
    # Formatter - defines log message format
    # Format: [TIMESTAMP] LEVEL - MESSAGE
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger


# Initialize different loggers for different purposes
threat_logger = setup_logger('ThreatDetector', THREAT_LOG)
firewall_logger = setup_logger('Firewall', FIREWALL_LOG)
activity_logger = setup_logger('Activity', ACTIVITY_LOG)


def log_threat(ip, threat_type, details):
    """Log a detected threat"""
    threat_logger.warning(
        f"THREAT DETECTED - IP: {ip} | Type: {threat_type} | Details: {details}"
    )


def log_firewall_action(action, ip, details):
    """Log firewall actions (blocking, unblocking)"""
    firewall_logger.info(
        f"FIREWALL ACTION - Action: {action} | IP: {ip} | Details: {details}"
    )


def log_connection(source_ip, destination_port, protocol, details):
    """Log network connections"""
    activity_logger.info(
        f"CONNECTION - Source: {source_ip} | Port: {destination_port} | Protocol: {protocol} | Details: {details}"
    )


def log_port_scan(ip, ports_scanned, details):
    """Log detected port scans"""
    threat_logger.warning(
        f"PORT SCAN DETECTED - IP: {ip} | Ports Scanned: {ports_scanned} | Details: {details}"
    )
