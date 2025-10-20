"""
Firewall Manager Module - Manages PF firewall rules and IP blocking
Adds/removes firewall rules to block malicious IPs
"""

import subprocess
import os
from datetime import datetime
from src.utils.logger import log_firewall_action, firewall_logger


class FirewallManager:
    """Manage PF firewall rules and blocking"""
    
    BLOCKLIST_FILE = os.path.join(
        os.path.dirname(__file__),
        'blocklist.txt'
    )
    
    PF_CONF_FILE = os.path.join(
        os.path.dirname(__file__),
        'pf.conf'
    )
    
    def __init__(self):
        """Initialize firewall manager"""
        self.blocked_ips = self._load_blocklist()
        self.rules_loaded = False
        
    def _load_blocklist(self):
        """Load blocked IPs from file"""
        blocked_ips = set()
        
        try:
            if os.path.exists(self.BLOCKLIST_FILE):
                with open(self.BLOCKLIST_FILE, 'r') as f:
                    for line in f:
                        ip = line.strip()
                        # Skip comments and empty lines
                        if ip and not ip.startswith('#'):
                            blocked_ips.add(ip)
        except Exception as e:
            firewall_logger.error(f"Error loading blocklist: {str(e)}")
        
        return blocked_ips
    
    def _save_blocklist(self):
        """Save blocked IPs to file"""
        try:
            with open(self.BLOCKLIST_FILE, 'w') as f:
                # Write header
                f.write('# PortShield Blocklist\n')
                f.write(f'# Updated: {datetime.now()}\n')
                f.write('# Format: one IP per line\n\n')
                
                # Write IPs
                for ip in sorted(self.blocked_ips):
                    f.write(f'{ip}\n')
            
            firewall_logger.info(f"Blocklist saved with {len(self.blocked_ips)} IPs")
        except Exception as e:
            firewall_logger.error(f"Error saving blocklist: {str(e)}")
    
    def block_ip(self, ip_address, reason='Manual block', persist=True):
        """
        Block an IP address
        
        Args:
            ip_address: IP to block
            reason: Reason for blocking
            persist: Whether to save to blocklist file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Add to in-memory blocklist
            self.blocked_ips.add(ip_address)
            
            # Save to file if persist=True
            if persist:
                self._save_blocklist()
            
            # Try to add PF rule (requires sudo)
            self._add_pf_rule(ip_address)
            
            log_firewall_action('BLOCK', ip_address, reason)
            firewall_logger.info(f"IP blocked: {ip_address} - {reason}")
            
            return True
            
        except Exception as e:
            firewall_logger.error(f"Error blocking IP {ip_address}: {str(e)}")
            return False
    
    def unblock_ip(self, ip_address, persist=True):
        """
        Unblock an IP address
        
        Args:
            ip_address: IP to unblock
            persist: Whether to save to file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Remove from in-memory blocklist
            self.blocked_ips.discard(ip_address)
            
            # Save to file
            if persist:
                self._save_blocklist()
            
            # Try to remove PF rule
            self._remove_pf_rule(ip_address)
            
            log_firewall_action('UNBLOCK', ip_address, 'Manual unblock')
            firewall_logger.info(f"IP unblocked: {ip_address}")
            
            return True
            
        except Exception as e:
            firewall_logger.error(f"Error unblocking IP {ip_address}: {str(e)}")
            return False
    
    def is_ip_blocked(self, ip_address):
        """Check if IP is blocked"""
        return ip_address in self.blocked_ips
    
    def get_blocked_ips(self):
        """Get list of all blocked IPs"""
        return sorted(list(self.blocked_ips))
    
    def get_blocked_ips_count(self):
        """Get count of blocked IPs"""
        return len(self.blocked_ips)
    
    def clear_all_blocks(self, confirm=False):
        """
        Clear all blocked IPs (dangerous operation)
        
        Args:
            confirm: Must be True to proceed
            
        Returns:
            True if successful
        """
        if not confirm:
            firewall_logger.warning("clear_all_blocks called without confirmation")
            return False
        
        try:
            self.blocked_ips.clear()
            self._save_blocklist()
            firewall_logger.warning("All IP blocks cleared")
            return True
        except Exception as e:
            firewall_logger.error(f"Error clearing blocks: {str(e)}")
            return False
    
    def _add_pf_rule(self, ip_address):
        """
        Add PF firewall rule to block IP (macOS)
        
        Requires: sudo privileges and PF configuration
        """
        try:
            # Command to add rule using pfctl
            # This requires the rule table to exist in pf.conf
            cmd = ['sudo', 'pfctl', '-t', 'blocked_ips', '-T', 'add', ip_address]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                firewall_logger.info(f"PF rule added for {ip_address}")
            else:
                firewall_logger.warning(f"PF rule add failed for {ip_address}: {result.stderr}")
        
        except Exception as e:
            firewall_logger.debug(f"Could not add PF rule: {str(e)}")
            # This is non-critical, so we don't fail the whole operation
    
    def _remove_pf_rule(self, ip_address):
        """
        Remove PF firewall rule (macOS)
        """
        try:
            cmd = ['sudo', 'pfctl', '-t', 'blocked_ips', '-T', 'delete', ip_address]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                firewall_logger.info(f"PF rule removed for {ip_address}")
        
        except Exception as e:
            firewall_logger.debug(f"Could not remove PF rule: {str(e)}")
    
    def load_pf_rules(self):
        """
        Load PF configuration rules
        
        Requires: sudo privileges
        """
        try:
            cmd = ['sudo', 'pfctl', '-f', self.PF_CONF_FILE]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                self.rules_loaded = True
                firewall_logger.info("PF rules loaded successfully")
                return True
            else:
                firewall_logger.error(f"Error loading PF rules: {result.stderr}")
                return False
        
        except Exception as e:
            firewall_logger.error(f"Error loading PF rules: {str(e)}")
            return False
    
    def enable_firewall(self):
        """Enable PF firewall"""
        try:
            cmd = ['sudo', 'pfctl', '-e']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                firewall_logger.info("PF firewall enabled")
                return True
            else:
                firewall_logger.error(f"Error enabling firewall: {result.stderr}")
                return False
        
        except Exception as e:
            firewall_logger.error(f"Error enabling firewall: {str(e)}")
            return False
    
    def disable_firewall(self):
        """Disable PF firewall (dangerous)"""
        try:
            cmd = ['sudo', 'pfctl', '-d']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                firewall_logger.warning("PF firewall disabled")
                return True
            else:
                firewall_logger.error(f"Error disabling firewall: {result.stderr}")
                return False
        
        except Exception as e:
            firewall_logger.error(f"Error disabling firewall: {str(e)}")
            return False
    
    def get_pf_status(self):
        """Get current PF firewall status"""
        try:
            cmd = ['sudo', 'pfctl', '-s', 'info']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                return result.stdout
            else:
                return None
        
        except Exception as e:
            firewall_logger.debug(f"Error getting PF status: {str(e)}")
            return None
    
    def get_pf_rules(self):
        """Get current PF rules"""
        try:
            cmd = ['sudo', 'pfctl', '-s', 'rules']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                return result.stdout
            else:
                return None
        
        except Exception as e:
            firewall_logger.debug(f"Error getting PF rules: {str(e)}")
            return None
    
    def get_statistics(self):
        """Get firewall statistics"""
        return {
            'blocked_ips_count': self.get_blocked_ips_count(),
            'blocked_ips': self.get_blocked_ips(),
            'rules_loaded': self.rules_loaded,
            'timestamp': datetime.now()
        }
