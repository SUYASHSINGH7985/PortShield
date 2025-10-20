## PortShield Setup Guide for macOS

### Complete Step-by-Step Installation and Configuration Guide

---

## **Phase 1: Prerequisites and Environment Setup**

### Step 1.1: Install Python and Dependencies

```bash
# Check Python version (requires 3.8+)
python3 --version

# Install required packages
pip3 install -r requirements.txt

# Verify installations
python3 -c "import flask, psutil, nmap; print('All packages installed!')"
```

### Step 1.2: Verify macOS PF Firewall is Available

```bash
# Check if PF is enabled on macOS
sudo pfctl -s info

# If not enabled, check if pf can be started
sudo pfctl -e  # Enable firewall (optional for testing)
```

---

## **Phase 2: Project Structure Understanding**

### Directory Layout:

```
PortShield/
├── src/
│   ├── dashboard/       # Flask web interface
│   │   ├── app.py      # Main Flask application
│   │   ├── templates/  # HTML templates
│   │   └── static/     # CSS, JavaScript
│   ├── firewall/       # Firewall management
│   │   ├── firewall_manager.py  # PF rule management
│   │   ├── pf.conf     # PF rules configuration
│   │   └── blocklist.txt # Blocked IPs list
│   ├── monitor/        # Network monitoring
│   │   ├── connection_monitor.py  # Track connections
│   │   ├── port_scanner.py        # Port scanning
│   │   └── threat_detector.py     # Threat detection
│   └── utils/
│       └── logger.py   # Centralized logging
├── tests/              # Unit tests
├── demo/               # Demo scripts
├── logs/               # Log files (auto-created)
└── requirements.txt    # Python dependencies
```

---

## **Phase 3: Module Explanation**

### **3.1 Logger Module** (`src/utils/logger.py`)

**What it does:** Centralized logging for all PortShield components

**Key Functions:**
- `log_threat()` - Log detected threats
- `log_firewall_action()` - Log firewall blocks/unblocks  
- `log_connection()` - Log network connections
- `log_port_scan()` - Log detected port scans

**How it works:**
1. Creates three log files: threats.log, firewall.log, activity.log
2. Logs to both file and console simultaneously
3. Includes timestamp, component name, severity level

**Example usage:**
```python
from src.utils.logger import log_threat
log_threat('192.168.1.100', 'PORT_SCAN', 'Detected 20 port scan attempts')
```

---

### **3.2 Connection Monitor** (`src/monitor/connection_monitor.py`)

**What it does:** Real-time tracking of network connections

**Key Methods:**
- `get_active_connections()` - Get all active TCP/UDP connections
- `get_listening_ports()` - Get ports system is listening on
- `get_connections_from_ip()` - Filter connections by source IP
- `get_ip_connection_count()` - Count connections from an IP

**How it works:**
1. Uses `psutil.net_connections()` to capture live network data
2. Organizes data by IP address and port number
3. Tracks connection history for pattern analysis
4. Maintains 24-hour history window

**Example usage:**
```python
from src.monitor.connection_monitor import ConnectionMonitor

monitor = ConnectionMonitor()
connections = monitor.get_active_connections()
for conn in connections:
    print(f"{conn['remote_ip']}:{conn['remote_port']} - {conn['protocol']}")
```

---

### **3.3 Port Scanner** (`src/monitor/port_scanner.py`)

**What it does:** Scans system and remote hosts for open ports

**Key Methods:**
- `scan_port()` - Test single port
- `scan_host_ports()` - Scan multiple ports on host
- `get_listening_ports_advanced()` - Use netstat to find listening ports
- `detect_port_change()` - Compare scan results over time

**How it works:**
1. Attempts TCP connection to each port
2. Times out quickly on closed ports (1 second default)
3. Maintains service name mappings (SSH=22, HTTP=80, etc.)
4. Uses both Python sockets and system commands

**Example usage:**
```python
from src.monitor.port_scanner import PortScanner

scanner = PortScanner()
open_ports = scanner.scan_localhost()
for port in open_ports:
    print(f"Port {port['port']}: {port['service']} is OPEN")
```

---

### **3.4 Threat Detector** (`src/monitor/threat_detector.py`)

**What it does:** Identifies malicious activity patterns

**Detects:**
- **Port Scans**: Fast scans (10+ ports in <1 minute)
- **Brute Force**: 5+ connection attempts to SSH/RDP/SMB in 30 seconds
- **Suspicious Patterns**: Multiple high-risk ports accessed
- **Automated Attacks**: Sequential port numbering

**Threat Levels:**
- `HIGH` - Immediate danger (block this IP)
- `MEDIUM` - Suspicious activity (monitor closely)
- `LOW` - Normal activity (no action)

**Key Methods:**
- `analyze_connection()` - Analyze single connection
- `get_threats_from_ip()` - Get all threats from an IP
- `get_recent_threats()` - Get threats in timeframe
- `mark_ip_as_threat()` - Escalate to firewall block

**Example usage:**
```python
from src.monitor.threat_detector import ThreatDetector

detector = ThreatDetector()
threat_level = detector.analyze_connection('203.0.113.50', 22, 'TCP')
if threat_level == 'HIGH':
    print("THREAT DETECTED - Should block this IP!")
```

---

### **3.5 Firewall Manager** (`src/firewall/firewall_manager.py`)

**What it does:** Manages IP blocks and PF firewall rules

**Key Methods:**
- `block_ip()` - Add IP to blocklist and PF rules
- `unblock_ip()` - Remove IP from blocklist
- `is_ip_blocked()` - Check if IP is blocked
- `get_blocked_ips()` - List all blocked IPs
- `enable_firewall()` / `disable_firewall()` - Control PF

**How it works:**
1. Maintains in-memory blocklist
2. Saves blocked IPs to `blocklist.txt` file
3. Uses `pfctl` command to add PF rules
4. Requires sudo privileges for PF operations

**Example usage:**
```python
from src.firewall.firewall_manager import FirewallManager

fw = FirewallManager()
fw.block_ip('192.168.1.100', 'Detected port scan')
blocked_list = fw.get_blocked_ips()
```

---

### **3.6 Flask Dashboard** (`src/dashboard/app.py`)

**What it does:** Web interface for monitoring and control

**API Endpoints:**
- `GET /` - Main dashboard page
- `GET /api/status` - System status summary
- `GET /api/connections` - Active connections
- `GET /api/threats` - Detected threats
- `GET /api/blocked-ips` - Blocked IP list
- `POST /api/block-ip` - Block an IP
- `POST /api/unblock-ip` - Unblock an IP
- `GET /api/ports` - Listening ports

**Frontend Features:**
- Real-time updates every 2 seconds
- Visual status cards with connection/threat counts
- Tables for IPs, ports, and threats
- Block/unblock IP interface
- Responsive Bootstrap design

---

## **Phase 4: Running PortShield**

### Step 4.1: Start the Dashboard

```bash
# Navigate to project directory
cd /path/to/PortShield

# Run Flask dashboard (development server)
python3 src/dashboard/app.py

# Output:
# * Running on http://0.0.0.0:5000
# * WARNING: This is a development server
```

### Step 4.2: Access the Dashboard

```
Open browser: http://localhost:5000
```

The dashboard will display:
- Active network connections
- Detected threats
- Currently blocked IPs
- Listening ports
- Real-time statistics

---

## **Phase 5: Testing the System**

### Step 5.1: Monitor Current Connections

```bash
# Open another terminal while dashboard is running
python3 -c "
from src.monitor.connection_monitor import ConnectionMonitor
monitor = ConnectionMonitor()
conns = monitor.get_active_connections()
print(f'Active connections: {len(conns)}')
for conn in conns[:5]:
    print(f'  {conn[\"remote_ip\"]}:{conn[\"remote_port\"]}')
"
```

### Step 5.2: Scan Local Ports

```bash
python3 -c "
from src.monitor.port_scanner import PortScanner
scanner = PortScanner()
ports = scanner.scan_localhost()
print(f'Open ports: {len(ports)}')
for port in ports:
    print(f'  Port {port[\"port\"]}: {port[\"service\"]}')
"
```

### Step 5.3: Test Threat Detection

```bash
python3 -c "
from src.monitor.threat_detector import ThreatDetector

detector = ThreatDetector()

# Simulate port scan activity
test_ips = ['203.0.113.50'] * 15  # Same IP, multiple ports
for i, ip in enumerate(test_ips):
    port = 1000 + i
    threat = detector.analyze_connection(ip, port, 'TCP')
    print(f'Connection from {ip}:{port} - Threat Level: {threat}')

# Check summary
summary = detector.get_threat_summary()
print(f'\nThreats detected: {summary[\"total_threats\"]}')
"
```

### Step 5.4: Test IP Blocking

```bash
python3 -c "
from src.firewall.firewall_manager import FirewallManager

fw = FirewallManager()

# Block an IP
fw.block_ip('203.0.113.50', 'Test blocking')
print('IP blocked')

# Check if blocked
is_blocked = fw.is_ip_blocked('203.0.113.50')
print(f'Is IP blocked: {is_blocked}')

# Get blocklist
blocked = fw.get_blocked_ips()
print(f'Blocked IPs: {blocked}')

# Unblock
fw.unblock_ip('203.0.113.50')
print('IP unblocked')
"
```

---

## **Phase 6: Advanced Usage**

### Step 6.1: Enable Firewall Rules (Requires Sudo)

```bash
# Load PF configuration
sudo pfctl -f src/firewall/pf.conf

# Enable firewall
sudo pfctl -e

# Check status
sudo pfctl -s info
```

### Step 6.2: View Firewall Logs

```bash
# Tail threat log
tail -f logs/threats.log

# Tail firewall log
tail -f logs/firewall.log

# Tail activity log
tail -f logs/activity.log
```

### Step 6.3: Manual IP Blocking via Command Line

```bash
python3 -c "
from src.firewall.firewall_manager import FirewallManager

fw = FirewallManager()
fw.block_ip('203.0.113.100', 'Malicious activity')
fw.block_ip('198.51.100.50', 'Port scanning')

print('Current blocklist:')
for ip in fw.get_blocked_ips():
    print(f'  - {ip}')
"
```

---

## **Phase 7: Customization**

### Edit Threat Detection Thresholds

In `src/monitor/threat_detector.py`, modify:

```python
class ThreatDetector:
    PORT_SCAN_THRESHOLD = 10      # Ports in 60 seconds
    BRUTE_FORCE_THRESHOLD = 5     # Attempts in 30 seconds
    SLOW_SCAN_THRESHOLD = 30      # Ports in 10 minutes
```

### Add Custom Firewall Rules

Edit `src/firewall/pf.conf`:

```bash
# Allow specific IP
pass in on en0 from 192.168.1.50 to any

# Block specific port
block in on en0 proto tcp to any port 23
```

### Add Dashboard Customizations

Edit `src/dashboard/static/css/style.css`:

```css
/* Change primary color */
:root {
    --primary-color: #your-color;
}
```

---

## **Phase 8: Troubleshooting**

### Issue: "Permission denied" for firewall operations

**Solution:** PF operations require sudo. Use:
```bash
sudo python3 src/dashboard/app.py
```

### Issue: Port already in use

**Solution:** Change Flask port in app.py:
```python
app.run(host='0.0.0.0', port=5001)  # Use different port
```

### Issue: No connections showing

**Solution:** Ensure there's active network traffic:
```bash
# Test with a network request
curl https://www.google.com

# Then check monitor
python3 -c "from src.monitor.connection_monitor import ConnectionMonitor; print(len(ConnectionMonitor().get_active_connections()))"
```

---

## **Summary of Components**

| Component | Purpose | Key Input | Output |
|-----------|---------|-----------|--------|
| **Logger** | Centralized logging | Events | Log files |
| **Connection Monitor** | Track connections | System data | Active connections |
| **Port Scanner** | Find open ports | Host/Port | Open port list |
| **Threat Detector** | Identify attacks | Connections | Threat level |
| **Firewall Manager** | Block/unblock IPs | IP address | PF rules, blocklist |
| **Dashboard** | Web interface | User input | Real-time display |

---

## **Security Best Practices**

1. **Keep logs archived** - Regularly backup logs
2. **Review alerts regularly** - Check recent_threats weekly
3. **Test whitelisting** - Add trusted IPs to exceptions
4. **Monitor resource usage** - Especially CPU/memory
5. **Run with minimal privileges** - Use dedicated user when possible
6. **Keep blacklist updated** - Merge with threat databases
7. **Use HTTPS in production** - Add SSL certificates
8. **Backup blocklist** - Version control blocklist.txt

