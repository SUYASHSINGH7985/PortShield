"""
PortShield Dashboard - Flask web interface for firewall monitoring
Displays real-time network activity, threats, and blocking status
"""

from flask import Flask, render_template, jsonify, request
from datetime import datetime, timedelta
import json
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.monitor.connection_monitor import ConnectionMonitor
from src.monitor.port_scanner import PortScanner
from src.monitor.threat_detector import ThreatDetector
from src.firewall.firewall_manager import FirewallManager
from src.utils.logger import activity_logger

# Initialize Flask app
app = Flask(__name__, 
            template_folder=os.path.join(os.path.dirname(__file__), 'templates'),
            static_folder=os.path.join(os.path.dirname(__file__), 'static'))

# Initialize security modules
conn_monitor = ConnectionMonitor()
port_scanner = PortScanner()
threat_detector = ThreatDetector()
firewall_manager = FirewallManager()

# Cache for performance
cache = {
    'last_update': datetime.now(),
    'connections': [],
    'threats': [],
    'stats': {}
}


@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html')


@app.route('/api/status', methods=['GET'])
def get_status():
    """Get overall system status"""
    try:
        # Update connection data
        connections = conn_monitor.get_active_connections()
        cache['connections'] = connections
        
        # Get threat summary
        threat_summary = threat_detector.get_threat_summary()
        
        # Get firewall stats
        firewall_stats = firewall_manager.get_statistics()
        
        # Get listening ports
        listening_ports = port_scanner.get_listening_ports_advanced()
        
        status = {
            'timestamp': datetime.now().isoformat(),
            'active_connections': len(connections),
            'listening_ports': len(listening_ports),
            'blocked_ips': firewall_stats['blocked_ips_count'],
            'recent_threats': threat_summary['total_threats'],
            'threatened_ips': threat_summary['threatened_ips'],
            'system_status': 'OPERATIONAL'
        }
        
        activity_logger.info(f"Dashboard status requested: {status}")
        return jsonify(status)
    
    except Exception as e:
        activity_logger.error(f"Error getting status: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/connections', methods=['GET'])
def get_connections():
    """Get active network connections"""
    try:
        limit = request.args.get('limit', 50, type=int)
        
        connections = conn_monitor.get_active_connections()[:limit]
        
        # Format for JSON
        formatted = []
        for conn in connections:
            formatted.append({
                'remote_ip': conn['remote_ip'],
                'remote_port': conn['remote_port'],
                'local_port': conn['local_port'],
                'protocol': conn['protocol'],
                'state': conn['state'],
                'timestamp': conn['timestamp'].isoformat(),
                'is_blocked': firewall_manager.is_ip_blocked(conn['remote_ip'])
            })
        
        return jsonify({
            'total': len(connections),
            'connections': formatted
        })
    
    except Exception as e:
        activity_logger.error(f"Error getting connections: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/threats', methods=['GET'])
def get_threats():
    """Get recent threats detected"""
    try:
        minutes = request.args.get('minutes', 60, type=int)
        
        threats = threat_detector.get_recent_threats(minutes=minutes)
        
        # Format for JSON
        formatted = []
        for threat in threats:
            formatted.append({
                'ip': threat['ip'],
                'type': threat['type'],
                'details': threat['details'],
                'timestamp': threat['timestamp'].isoformat(),
                'action_taken': threat['action_taken']
            })
        
        summary = threat_detector.get_threat_summary()
        
        return jsonify({
            'total_threats': summary['total_threats'],
            'threatened_ips': summary['threatened_ips'],
            'threats_by_type': summary['threats_by_type'],
            'recent_threats': formatted
        })
    
    except Exception as e:
        activity_logger.error(f"Error getting threats: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/blocked-ips', methods=['GET'])
def get_blocked_ips():
    """Get list of blocked IPs"""
    try:
        blocked_ips = firewall_manager.get_blocked_ips()
        
        return jsonify({
            'total_blocked': len(blocked_ips),
            'blocked_ips': blocked_ips
        })
    
    except Exception as e:
        activity_logger.error(f"Error getting blocked IPs: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/block-ip', methods=['POST'])
def block_ip():
    """Block an IP address"""
    try:
        data = request.get_json()
        ip_address = data.get('ip')
        reason = data.get('reason', 'Manual block via dashboard')
        
        if not ip_address:
            return jsonify({'error': 'IP address required'}), 400
        
        success = firewall_manager.block_ip(ip_address, reason)
        
        return jsonify({
            'success': success,
            'ip': ip_address,
            'message': f"IP {ip_address} blocked successfully" if success else "Failed to block IP"
        })
    
    except Exception as e:
        activity_logger.error(f"Error blocking IP: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/unblock-ip', methods=['POST'])
def unblock_ip():
    """Unblock an IP address"""
    try:
        data = request.get_json()
        ip_address = data.get('ip')
        
        if not ip_address:
            return jsonify({'error': 'IP address required'}), 400
        
        success = firewall_manager.unblock_ip(ip_address)
        
        return jsonify({
            'success': success,
            'ip': ip_address,
            'message': f"IP {ip_address} unblocked successfully" if success else "Failed to unblock IP"
        })
    
    except Exception as e:
        activity_logger.error(f"Error unblocking IP: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ports', methods=['GET'])
def get_ports():
    """Get listening ports"""
    try:
        ports = port_scanner.get_listening_ports_advanced()
        
        formatted = []
        for port in ports:
            formatted.append({
                'port': port['port'],
                'service': port['service'],
                'state': port['state'],
                'timestamp': port['timestamp'].isoformat()
            })
        
        return jsonify({
            'total_listening': len(ports),
            'ports': formatted
        })
    
    except Exception as e:
        activity_logger.error(f"Error getting ports: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan-ports', methods=['POST'])
def scan_ports():
    """Scan ports (manual trigger)"""
    try:
        data = request.get_json() if request.is_json else {}
        host = data.get('host', '127.0.0.1')
        
        ports = port_scanner.scan_host_ports(host)
        
        formatted = []
        for port in ports:
            formatted.append({
                'port': port['port'],
                'service': port['service'],
                'state': port['state']
            })
        
        return jsonify({
            'host': host,
            'open_ports': len(ports),
            'ports': formatted
        })
    
    except Exception as e:
        activity_logger.error(f"Error scanning ports: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/dashboard-data', methods=['GET'])
def get_dashboard_data():
    """Get all data needed for dashboard"""
    try:
        # Update all data
        connections = conn_monitor.get_active_connections()
        conn_summary = conn_monitor.get_connection_summary()
        threats = threat_detector.get_recent_threats(minutes=60)
        threat_summary = threat_detector.get_threat_summary()
        firewall_stats = firewall_manager.get_statistics()
        ports = port_scanner.get_listening_ports_advanced()
        
        # Format threats
        formatted_threats = []
        for threat in threats[-10:]:  # Last 10 threats
            formatted_threats.append({
                'ip': threat['ip'],
                'type': threat['type'],
                'timestamp': threat['timestamp'].isoformat()
            })
        
        # Format top connections
        top_ips = conn_summary['top_ips'][:5]
        
        dashboard_data = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_connections': conn_summary['total_connections'],
                'unique_ips': conn_summary['unique_ips'],
                'unique_ports': conn_summary['unique_ports'],
                'listening_ports': len(ports),
                'blocked_ips': firewall_stats['blocked_ips_count'],
                'threats_detected': threat_summary['total_threats'],
                'threatened_ips': threat_summary['threatened_ips']
            },
            'top_ips': [{'ip': ip, 'count': count} for ip, count in top_ips],
            'top_ports': [{'port': port, 'count': count} for port, count in conn_summary['top_ports'][:5]],
            'recent_threats': formatted_threats,
            'threat_types': threat_summary['threats_by_type']
        }
        
        return jsonify(dashboard_data)
    
    except Exception as e:
        activity_logger.error(f"Error getting dashboard data: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'operational', 'timestamp': datetime.now().isoformat()})


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def server_error(error):
    """Handle 500 errors"""
    activity_logger.error(f"Server error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    activity_logger.info("PortShield Dashboard starting...")
    
    # Start Flask development server
    # In production, use a proper WSGI server like Gunicorn
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        use_reloader=False  # Disable reloader when monitoring network
    )
