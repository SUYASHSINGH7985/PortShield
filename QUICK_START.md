# PortShield - Quick Reference Guide

## 🚀 Start Here (2 minutes)

```bash
# 1. Install dependencies
pip3 install -r requirements.txt

# 2. Start dashboard
python3 src/dashboard/app.py

# 3. Open browser
open http://localhost:5000
```

---

## 📁 File Structure

```
src/
├── dashboard/
│   ├── app.py               ← Flask REST API
│   ├── templates/
│   │   └── dashboard.html   ← Web UI
│   └── static/
│       ├── css/style.css    ← Styling
│       └── js/dashboard.js  ← Real-time updates
├── monitor/
│   ├── connection_monitor.py ← Track connections
│   ├── port_scanner.py       ← Scan ports
│   └── threat_detector.py    ← Detect attacks
├── firewall/
│   ├── firewall_manager.py   ← Block IPs
│   ├── pf.conf               ← Firewall rules
│   └── blocklist.txt         ← Blocked IPs
└── utils/
    └── logger.py             ← Logging
```

---

## 💻 Common Commands

### Monitor Connections
```python
from src.monitor.connection_monitor import ConnectionMonitor
monitor = ConnectionMonitor()
conns = monitor.get_active_connections()
print(f"Connections: {len(conns)}")
```

### Detect Threats
```python
from src.monitor.threat_detector import ThreatDetector
detector = ThreatDetector()
for port in range(1000, 1020):
    detector.analyze_connection("203.0.113.50", port, "TCP")
print(detector.get_threat_summary())
```

### Block IPs
```python
from src.firewall.firewall_manager import FirewallManager
fw = FirewallManager()
fw.block_ip("203.0.113.50", "Port scanning")
print(fw.get_blocked_ips())
```

### Scan Ports
```python
from src.monitor.port_scanner import PortScanner
scanner = PortScanner()
ports = scanner.get_listening_ports_advanced()
for p in ports:
    print(f"Port {p['port']}: {p['service']}")
```

---

## 🧪 Run Tests

```bash
python3 tests/test_threat_detection.py
```

---

## 📊 API Endpoints

| Endpoint | Purpose |
|----------|---------|
| GET `/` | Dashboard page |
| GET `/api/status` | System status |
| GET `/api/connections` | Active connections |
| GET `/api/threats` | Recent threats |
| GET `/api/blocked-ips` | Blocked IPs |
| POST `/api/block-ip` | Block an IP |
| POST `/api/unblock-ip` | Unblock an IP |
| GET `/api/ports` | Listening ports |

---

## 🔥 Example: Simulate Attack & Auto-Block

```python
from src.monitor.threat_detector import ThreatDetector
from src.firewall.firewall_manager import FirewallManager

detector = ThreatDetector()
fw = FirewallManager()

# Simulate port scan
print("[*] Simulating port scan...")
for port in range(1000, 1020):
    detector.analyze_connection("203.0.113.50", port, "TCP")

# Check if threat detected
summary = detector.get_threat_summary()
print(f"[!] Threats: {summary['total_threats']}")

# Auto-block
if summary['total_threats'] > 0:
    fw.block_ip("203.0.113.50", "Auto-blocked")
    print(f"[+] Blocked: {fw.get_blocked_ips()}")
```

---

## 🔐 Enable Firewall (Optional)

```bash
sudo pfctl -f src/firewall/pf.conf
sudo pfctl -e
sudo pfctl -s info
```

---

## 📝 View Logs

```bash
tail -f logs/threats.log       # Threats
tail -f logs/firewall.log      # Firewall actions
tail -f logs/activity.log      # Network activity
```

---

## 🐛 Troubleshooting

| Problem | Solution |
|---------|----------|
| No connections | Run `curl https://google.com` first |
| Permission denied | Use `sudo python3 ...` |
| Port in use | Change port in app.py line ~370 |
| Import error | Run `pip3 install -r requirements.txt` |

---

## 📚 Learn More

- **Setup Guide:** `docs/setup_guide_mac.md`
- **Demos:** `demo/attack_demo.md`
- **Full Guide:** `IMPLEMENTATION_GUIDE.md`

---

## ⚡ Key Concepts

**Connection Monitor** → Sees what's happening
**Port Scanner** → Finds open services
**Threat Detector** → Recognizes patterns
**Firewall Manager** → Blocks threats
**Dashboard** → Shows everything
**Logger** → Records all actions

---

**Status: ✅ Ready to Use | All 11 Components Complete**
