# PortShield – Intelligent Port Monitoring Firewall

## Overview

PortShield is a **production-ready, real-time port-monitoring firewall** designed to protect small business networks from unauthorized access, port scanning, and cyber attacks. It tracks incoming and outgoing network connections, detects sophisticated attack patterns, and automatically blocks malicious IPs.

**Perfect for:** Small business networks, development environments, and cybersecurity learning.

## ✨ Key Features

- ✅ **Real-time Port & Connection Monitoring** - Track all network activity instantly
- ✅ **Intelligent Threat Detection** - Identify port scans, brute-force attempts, and anomalies
- ✅ **Automatic IP Blocking** - Automatically block detected threats
- ✅ **Live Web Dashboard** - Beautiful real-time monitoring interface
- ✅ **Advanced Logging** - Comprehensive threat and activity logs
- ✅ **PF Firewall Integration** - Native macOS firewall management
- ✅ **RESTful API** - Full API for automation and integration
- ✅ **Educational & Demo-Ready** - Perfect for learning cybersecurity concepts

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Flask Dashboard                          │
│              (Web UI + REST API)                            │
└──────────────────┬──────────────────────────────────────────┘
                   │
         ┌─────────┴─────────┬────────────────────┐
         │                   │                    │
    ┌────▼────┐    ┌────────▼────┐    ┌─────────▼──────┐
    │Connection│    │    Port     │    │   Threat       │
    │ Monitor  │    │   Scanner   │    │   Detector     │
    └────┬────┘    └────────┬────┘    └────────┬───────┘
         │                  │                   │
         └──────────────────┼───────────────────┘
                            │
                   ┌────────▼────────┐
                   │  Firewall       │
                   │  Manager        │
                   │  (PF Rules)     │
                   └─────────────────┘
```

## 🔧 Tech Stack

- **Backend:** Python 3.8+, Flask 3.0
- **System Monitoring:** psutil (network connections)
- **Firewall:** macOS PF (Packet Filter)
- **Frontend:** HTML5, Bootstrap 5, Vanilla JavaScript
- **Logging:** Python logging module
- **Testing:** unittest framework

## 📋 System Requirements

- macOS 10.15+
- Python 3.8 or higher
- 50MB disk space
- Administrator access (for firewall operations)

## 🚀 Quick Start

### 1. Installation

```bash
# Clone repository
git clone https://github.com/suyashsingh7985/PortShield.git
cd PortShield

# Install dependencies
pip3 install -r requirements.txt

# Verify installation
python3 -c "import flask, psutil; print('✓ All dependencies installed')"
```

### 2. Start Dashboard

```bash
# Run the Flask server
python3 src/dashboard/app.py

# Open in browser
open http://localhost:5000
```

### 3. Monitor Network Activity

The dashboard will instantly show:
- Active network connections
- Listening ports
- Threat detection status
- Currently blocked IPs

## 📚 Component Guide

### Connection Monitor (`src/monitor/connection_monitor.py`)
Tracks all network connections in real-time:
- TCP and UDP connections
- Source and destination IPs/ports
- Connection state and protocol
- Per-IP connection history

### Port Scanner (`src/monitor/port_scanner.py`)
Analyzes open ports on system:
- Service identification (SSH, HTTP, MySQL, etc.)
- Port status monitoring
- Change detection
- Port range scanning

### Threat Detector (`src/monitor/threat_detector.py`)
Identifies attack patterns:
- **Port Scanning** (10+ different ports in short time)
- **Brute Force** (5+ rapid SSH/RDP connection attempts)
- **Suspicious Patterns** (multiple high-risk ports accessed)
- **Automated Attacks** (sequential port access)

### Firewall Manager (`src/firewall/firewall_manager.py`)
Controls IP blocking:
- Block/unblock IPs
- Manage PF firewall rules
- Persistent blocklist storage
- Firewall status monitoring

## 🎯 Usage Examples

### Example 1: Monitor Current Connections

```python
from src.monitor.connection_monitor import ConnectionMonitor

monitor = ConnectionMonitor()
conns = monitor.get_active_connections()

for conn in conns[:5]:
    print(f"{conn['remote_ip']}:{conn['remote_port']} - {conn['protocol']}")
```

### Example 2: Detect Threats

```python
from src.monitor.threat_detector import ThreatDetector

detector = ThreatDetector()

# Analyze connection
threat_level = detector.analyze_connection('203.0.113.50', 22, 'TCP')
print(f"Threat Level: {threat_level}")  # Could be: None, LOW, MEDIUM, HIGH
```

### Example 3: Block Malicious IP

```python
from src.firewall.firewall_manager import FirewallManager

fw = FirewallManager()
fw.block_ip('203.0.113.50', 'Detected port scanning')
print(f"Blocked IPs: {fw.get_blocked_ips()}")
```

## 🧪 Testing

Run comprehensive test suite:

```bash
# Run all tests
python3 tests/test_threat_detection.py

# Output:
# test_port_scan_detection ... ok
# test_brute_force_detection ... ok
# test_block_ip ... ok
# ========================
# Ran 20 tests in 0.450s
# OK
```

## 📊 Dashboard Features

### Real-Time Monitoring
- Active connections counter
- Threat detection alerts
- Blocked IP list
- Listening ports display

### Threat Management
- View recent threats with type and timestamp
- Automatic threat classification
- Threat history analysis

### IP Management
- Block IPs manually or automatically
- Unblock IPs on demand
- View complete blocklist
- Persistent storage

### Network Analytics
- Top communicating IPs
- Top ports by traffic
- Connection statistics
- Threat patterns

## 🔐 Security Configuration

### Enable macOS PF Firewall

```bash
# Load PF rules
sudo pfctl -f src/firewall/pf.conf

# Enable firewall
sudo pfctl -e

# Check status
sudo pfctl -s info
```

### Understanding PF Rules

Edit `src/firewall/pf.conf` to customize:
- Which ports to allow
- Which protocols to block
- Rate limiting rules
- Logging rules

## 📖 Complete Documentation

**For detailed setup and usage instructions, see:** [Setup Guide for macOS](docs/setup_guide_mac.md)

This comprehensive guide includes:
- Step-by-step installation
- Module-by-module explanation
- Running and testing the system
- Advanced customization
- Troubleshooting

**For demo and attack simulation**, see: [Attack Simulation Demo](demo/attack_demo.md)

This guide includes:
- 8 complete demo scenarios
- Port scanning simulation
- Brute-force attack simulation
- Real-time monitoring examples
- API testing examples

## 🎓 Learning Resources

### Understanding the Code

1. **Start with:** `src/utils/logger.py` - Simple logging setup
2. **Then:** `src/monitor/connection_monitor.py` - Network data collection
3. **Progress to:** `src/monitor/threat_detector.py` - Pattern recognition
4. **Firewall:** `src/firewall/firewall_manager.py` - System control
5. **UI:** `src/dashboard/app.py` - Flask API integration

### Key Concepts

- **Network Monitoring:** How to capture and analyze network packets
- **Threat Detection:** Pattern recognition for identifying attacks
- **Firewall Rules:** PF configuration for macOS
- **Real-time Dashboard:** WebSocket/API updates in Flask
- **Persistent Storage:** File-based blocklist management

## 🚀 Running Demos

### Demo 1: Simulate Port Scanning Attack
```bash
python3 << 'EOF'
from src.monitor.threat_detector import ThreatDetector
detector = ThreatDetector()
for port in range(1000, 1015):
    detector.analyze_connection("203.0.113.45", port, "TCP")
summary = detector.get_threat_summary()
print(f"Threats: {summary['total_threats']}")
EOF
```

### Demo 2: Monitor Real Connections
```bash
python3 << 'EOF'
from src.monitor.connection_monitor import ConnectionMonitor
monitor = ConnectionMonitor()
conns = monitor.get_active_connections()
print(f"Active connections: {len(conns)}")
EOF
```

### Demo 3: Block and Unblock IPs
```bash
python3 << 'EOF'
from src.firewall.firewall_manager import FirewallManager
fw = FirewallManager()
fw.block_ip("203.0.113.1", "Test")
print(f"Blocked: {fw.get_blocked_ips()}")
fw.unblock_ip("203.0.113.1")
print(f"After unblock: {fw.get_blocked_ips()}")
EOF
```

## 📁 Project Structure

```
PortShield/
├── src/
│   ├── dashboard/          # Flask web interface
│   │   ├── app.py         # Main Flask app with API endpoints
│   │   ├── templates/     # HTML templates
│   │   │   └── dashboard.html
│   │   └── static/        # CSS and JavaScript
│   │       ├── css/style.css
│   │       └── js/dashboard.js
│   ├── firewall/          # Firewall management
│   │   ├── firewall_manager.py
│   │   ├── pf.conf        # PF firewall rules
│   │   └── blocklist.txt  # IP blocklist
│   ├── monitor/           # Network monitoring
│   │   ├── connection_monitor.py
│   │   ├── port_scanner.py
│   │   └── threat_detector.py
│   └── utils/
│       └── logger.py      # Centralized logging
├── tests/
│   └── test_threat_detection.py  # Comprehensive unit tests
├── demo/
│   └── attack_demo.md     # Attack simulation examples
├── docs/
│   └── setup_guide_mac.md # Detailed setup guide
├── logs/                  # Auto-generated log files
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

## 🔍 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main dashboard page |
| `/api/status` | GET | System status summary |
| `/api/connections` | GET | Active network connections |
| `/api/threats` | GET | Recently detected threats |
| `/api/blocked-ips` | GET | List of blocked IPs |
| `/api/block-ip` | POST | Block an IP address |
| `/api/unblock-ip` | POST | Unblock an IP address |
| `/api/ports` | GET | Listening ports |
| `/api/scan-ports` | POST | Manually scan ports |
| `/api/dashboard-data` | GET | Complete dashboard data |

## 📈 Threat Detection Logic

### Port Scanning
- **Fast Scan:** 10+ unique ports in <1 minute → HIGH
- **Slow Scan:** 30+ unique ports over 10 minutes → MEDIUM

### Brute Force
- **Rapid SSH/RDP:** 5+ attempts in 30 seconds to port 22/3389 → HIGH

### Suspicious Patterns
- **Multi-port targeting:** 3+ high-risk ports accessed → MEDIUM
- **Sequential scanning:** Ports in numerical order pattern → MEDIUM

## 🛡️ Best Practices

1. **Monitor regularly** - Check logs weekly for patterns
2. **Update blocklist** - Merge with external threat intelligence
3. **Test firewall rules** - Verify rules work as expected
4. **Backup logs** - Archive logs for historical analysis
5. **Use HTTPS** - Deploy with SSL in production
6. **Rate limiting** - Adjust thresholds for your network
7. **Whitelist trusted IPs** - Add exceptions for known good sources
8. **Regular updates** - Keep threat detection rules current

## 🐛 Troubleshooting

### Issue: "Permission denied" error
**Solution:** Run with sudo for PF operations
```bash
sudo python3 src/dashboard/app.py
```

### Issue: No connections showing
**Solution:** Generate network traffic first
```bash
curl https://www.google.com
```

### Issue: Port 5000 already in use
**Solution:** Change port in app.py line ~370
```python
app.run(port=5001)
```

### Issue: Threat detection not working
**Solution:** Verify threat detector is analyzing connections
```bash
python3 -c "from src.monitor.threat_detector import ThreatDetector; print('Loaded')"
```

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

Contributions are welcome! Areas for improvement:
- Snort/Suricata integration
- Machine learning threat classification
- Advanced visualization
- Docker containerization
- REST API authentication

## 📧 Support

For issues and questions:
- Create a GitHub issue
- Check the troubleshooting section
- Review the setup guide

## 🌟 Credits

Created as an educational cybersecurity tool for learning network security concepts.

---

**Last Updated:** October 20, 2025
**Version:** 1.0.0
**Status:** Production Ready ✅
