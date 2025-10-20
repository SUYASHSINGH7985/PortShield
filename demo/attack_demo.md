## PortShield Demo: Attack Simulation and Testing

### Overview

This guide demonstrates how to test PortShield using simulated attacks and real-world scenarios.

---

## **Demo 1: Simulate Port Scanning Attack**

### Scenario: Detect a port scanner probing the network

```bash
# Start the dashboard first (Terminal 1)
python3 src/dashboard/app.py

# In Terminal 2, run the port scan simulation
python3 << 'EOF'
from src.monitor.threat_detector import ThreatDetector
from src.firewall.firewall_manager import FirewallManager
import time

detector = ThreatDetector()
fw = FirewallManager()

# Simulate rapid port scanning from attacker IP
attacker_ip = "203.0.113.45"
print(f"[*] Simulating port scan from {attacker_ip}")

# Scan 15 different ports rapidly (within 60 seconds)
for port in [80, 443, 22, 3389, 445, 139, 135, 445, 3306, 1433, 
             5432, 6379, 8080, 8443, 9200]:
    threat_level = detector.analyze_connection(attacker_ip, port, "TCP")
    print(f"[+] Port {port:5d} - Threat Level: {threat_level}")
    time.sleep(0.1)

# Check detected threats
summary = detector.get_threat_summary()
print(f"\n[!] THREAT SUMMARY:")
print(f"    Total threats detected: {summary['total_threats']}")
print(f"    Threatened IPs: {summary['threatened_ips']}")
print(f"    Threat types: {summary['threats_by_type']}")

# Mark for blocking
if threat_level == 'HIGH':
    detector.mark_ip_as_threat(attacker_ip)
    fw.block_ip(attacker_ip, "Automated: Port scan detected")
    print(f"\n[!] ACTION TAKEN: Blocked {attacker_ip}")
    print(f"    Currently blocked IPs: {len(fw.get_blocked_ips())}")

EOF
```

**Expected Output:**
```
[*] Simulating port scan from 203.0.113.45
[+] Port   80 - Threat Level: None
[+] Port  443 - Threat Level: None
[+] Port   22 - Threat Level: None
...
[+] Port 9200 - Threat Level: HIGH

[!] THREAT SUMMARY:
    Total threats detected: 1
    Threatened IPs: 1
    Threat types: {'PORT_SCAN': 1}

[!] ACTION TAKEN: Blocked 203.0.113.45
    Currently blocked IPs: 1
```

**What's Happening:**
1. Simulates 15 connection attempts from same IP to different ports
2. ThreatDetector recognizes pattern as port scan
3. Automatically marks threat as HIGH severity
4. IP is added to firewall blocklist
5. Check dashboard at http://localhost:5000 - you'll see the threat appear

---

## **Demo 2: Detect Brute-Force Attack**

### Scenario: SSH brute-force attempt

```bash
python3 << 'EOF'
from src.monitor.threat_detector import ThreatDetector
from src.firewall.firewall_manager import FirewallManager
import time

detector = ThreatDetector()
fw = FirewallManager()

attacker_ip = "198.51.100.77"
print(f"[*] Simulating brute-force attack on SSH from {attacker_ip}")

# Rapid connection attempts to SSH port (22)
print("[*] Connection attempts to port 22 (SSH):")
for attempt in range(8):
    threat_level = detector.analyze_connection(attacker_ip, 22, "TCP")
    print(f"[+] Attempt #{attempt+1} - Threat Level: {threat_level}")
    time.sleep(0.5)

# Check if blocked
summary = detector.get_threat_summary()
threats_from_ip = detector.get_threats_from_ip(attacker_ip)

print(f"\n[!] BRUTE-FORCE SUMMARY:")
print(f"    Threats from {attacker_ip}: {len(threats_from_ip)}")
for threat in threats_from_ip:
    print(f"    - {threat['type']}: {threat['details']}")

# Auto-block
if threats_from_ip:
    fw.block_ip(attacker_ip, "Automated: Brute-force attack detected")
    print(f"\n[!] ACTION: Blocked {attacker_ip}")

EOF
```

**What's Happening:**
1. Multiple rapid connections to SSH port (22) = brute-force indicator
2. Within 30 seconds, 8 attempts triggers BRUTE_FORCE detection
3. IP automatically flagged as HIGH threat
4. Firewall adds IP to block list
5. All future connections from this IP will be rejected

---

## **Demo 3: Monitor Real Network Traffic**

### Scenario: See actual connections on your system

```bash
python3 << 'EOF'
from src.monitor.connection_monitor import ConnectionMonitor
from src.monitor.port_scanner import PortScanner
import time

monitor = ConnectionMonitor()
scanner = PortScanner()

print("[*] PortShield Connection Monitor")
print("=" * 60)

# Get listening ports
print("\n[+] LISTENING PORTS:")
ports = scanner.get_listening_ports_advanced()
for port_info in ports:
    print(f"    Port {port_info['port']:5d} - {port_info['service']:15s} [{port_info['state']}]")

# Get active connections
print(f"\n[+] ACTIVE CONNECTIONS:")
print("=" * 60)

conns = monitor.get_active_connections()
print(f"Found {len(conns)} active connections\n")

# Group by protocol
tcp_conns = [c for c in conns if c['protocol'] == 'TCP']
udp_conns = [c for c in conns if c['protocol'] == 'UDP']

print(f"TCP: {len(tcp_conns)} | UDP: {len(udp_conns)}")
print("=" * 60)

# Show top connections
print("\nTOP CONNECTIONS:")
for i, conn in enumerate(conns[:10]):
    print(f"{i+1:2d}. {conn['remote_ip']:15s}:{conn['remote_port']:5d} [{conn['protocol']}] - {conn['state']}")

# Get summary
summary = monitor.get_connection_summary()
print(f"\nCONNECTION SUMMARY:")
print(f"  Total connections: {summary['total_connections']}")
print(f"  Unique IPs: {summary['unique_ips']}")
print(f"  Unique ports: {summary['unique_ports']}")

EOF
```

**What's Happening:**
1. Lists all listening ports on your system
2. Shows all active network connections in real-time
3. Groups connections by protocol (TCP/UDP)
4. Displays statistics about network activity
5. This data is continuously updated on the dashboard

---

## **Demo 4: Dashboard Real-Time Monitoring**

### Scenario: Watch threats appear in dashboard as they happen

```bash
# Terminal 1: Start dashboard
python3 src/dashboard/app.py

# Terminal 2: Open browser to http://localhost:5000

# Terminal 3: Generate traffic and threats
python3 << 'EOF'
from src.monitor.threat_detector import ThreatDetector
from src.monitor.connection_monitor import ConnectionMonitor
import time
import random

detector = ThreatDetector()
monitor = ConnectionMonitor()

print("[*] Generating simulated network events...")
print("[*] Watch the dashboard update in real-time!")
print("")

# Generate random traffic patterns
for iteration in range(5):
    print(f"\n[*] Iteration {iteration + 1}/5")
    
    # Normal traffic
    normal_ips = [f"192.168.1.{i}" for i in range(100, 110)]
    for ip in normal_ips:
        detector.analyze_connection(ip, random.choice([80, 443, 22]), "TCP")
    print(f"    Added {len(normal_ips)} normal connections")
    
    # Suspicious traffic
    suspicious_ip = "203.0.113.99"
    for port in range(1000, 1010):
        threat = detector.analyze_connection(suspicious_ip, port, "TCP")
    print(f"    Added suspicious port scan from {suspicious_ip}")
    
    # Get current stats
    summary = detector.get_threat_summary()
    print(f"    Total threats: {summary['total_threats']}")
    
    time.sleep(2)

print("\n[+] Demo complete! Check dashboard for results.")

EOF
```

**What's Happening:**
1. Generates network events continuously
2. Dashboard updates every 2 seconds
3. Watch threat counts rise as events are generated
4. See IP addresses appear in real-time
5. Observe pattern detection working

---

## **Demo 5: Test Blocking Functionality**

### Scenario: Block and unblock IPs through the system

```bash
python3 << 'EOF'
from src.firewall.firewall_manager import FirewallManager
import time

fw = FirewallManager()

# Test IPs
test_ips = [
    "203.0.113.1",
    "198.51.100.2", 
    "192.0.2.3",
]

print("[*] Testing IP Blocking Functionality")
print("=" * 60)

# BLOCK Phase
print("\n[+] BLOCKING PHASE:")
for ip in test_ips:
    success = fw.block_ip(ip, f"Test block for {ip}")
    print(f"    Block {ip}: {'SUCCESS' if success else 'FAILED'}")
    time.sleep(0.5)

# CHECK Phase
print("\n[+] VERIFICATION PHASE:")
blocked_ips = fw.get_blocked_ips()
print(f"    Total blocked IPs: {len(blocked_ips)}")
for ip in blocked_ips:
    is_blocked = fw.is_ip_blocked(ip)
    print(f"    {ip}: {'BLOCKED' if is_blocked else 'NOT BLOCKED'}")

# UNBLOCK Phase
print("\n[+] UNBLOCKING PHASE:")
for ip in test_ips[:2]:  # Unblock first 2
    success = fw.unblock_ip(ip)
    print(f"    Unblock {ip}: {'SUCCESS' if success else 'FAILED'}")
    time.sleep(0.5)

# FINAL CHECK
print("\n[+] FINAL STATE:")
final_blocked = fw.get_blocked_ips()
print(f"    Remaining blocked IPs: {len(final_blocked)}")
for ip in final_blocked:
    print(f"    - {ip}")

print("\n[+] Blocklist saved to: src/firewall/blocklist.txt")

EOF
```

**What's Happening:**
1. Demonstrates blocking multiple IPs
2. Verifies IPs are in blocklist
3. Tests unblocking functionality
4. Shows persistence (saved to file)
5. Proves firewall state management works

---

## **Demo 6: Analyze Threat Patterns**

### Scenario: Deep dive into detected threats

```bash
python3 << 'EOF'
from src.monitor.threat_detector import ThreatDetector
import time

detector = ThreatDetector()

print("[*] Analyzing Threat Detection Patterns")
print("=" * 60)

# Pattern 1: Port Scan
print("\n[+] PATTERN 1: Port Scan Detection")
scan_ip = "203.0.113.50"
for i in range(15):
    threat = detector.analyze_connection(scan_ip, 1000 + i, "TCP")
    if threat:
        print(f"    ALERT! Threat detected: {threat}")

threats = detector.get_threats_from_ip(scan_ip)
print(f"    Total threats from {scan_ip}: {len(threats)}")

# Pattern 2: Brute Force
print("\n[+] PATTERN 2: Brute-Force Detection")
brute_ip = "198.51.100.100"
ssh_ports = [22] * 6  # Rapid SSH attempts
for attempt in ssh_ports:
    threat = detector.analyze_connection(brute_ip, attempt, "TCP")
    if threat:
        print(f"    ALERT! Threat detected: {threat}")

threats = detector.get_threats_from_ip(brute_ip)
print(f"    Total threats from {brute_ip}: {len(threats)}")

# Pattern 3: Sequential Port Scanning
print("\n[+] PATTERN 3: Sequential Port Scan Detection")
auto_ip = "192.0.2.50"
for port in [80, 81, 82, 83, 84, 85, 86, 87]:  # Sequential ports
    threat = detector.analyze_connection(auto_ip, port, "TCP")

threats = detector.get_threats_from_ip(auto_ip)
print(f"    Total threats from {auto_ip}: {len(threats)}")

# Summary
print("\n[+] THREAT SUMMARY:")
summary = detector.get_threat_summary()
print(f"    Total threats detected: {summary['total_threats']}")
print(f"    Threatened IPs: {summary['threatened_ips']}")
print(f"    Breakdown by type:")
for threat_type, count in summary['threats_by_type'].items():
    print(f"      - {threat_type}: {count}")

EOF
```

**What's Happening:**
1. Demonstrates different threat patterns
2. Shows how detector identifies each type
3. Proves pattern recognition works
4. Generates summary of all detected threats

---

## **Demo 7: Performance and Scaling Test**

### Scenario: Test system with many connections

```bash
python3 << 'EOF'
from src.monitor.connection_monitor import ConnectionMonitor
from src.monitor.threat_detector import ThreatDetector
import time
import random

print("[*] Performance and Scaling Test")
print("=" * 60)

monitor = ConnectionMonitor()
detector = ThreatDetector()

# Generate large volume of connections
num_events = 1000
print(f"\n[+] Generating {num_events} network events...")

start_time = time.time()

for i in range(num_events):
    # Random IP (simulate different sources)
    random_ip = f"203.0.113.{random.randint(1, 255)}"
    random_port = random.randint(1000, 65535)
    
    # Analyze in detector
    detector.analyze_connection(random_ip, random_port, "TCP")
    
    if (i + 1) % 250 == 0:
        print(f"    [{i+1}/{num_events}] events processed...")

elapsed = time.time() - start_time

print(f"\n[+] Performance Results:")
print(f"    Events processed: {num_events}")
print(f"    Time elapsed: {elapsed:.2f} seconds")
print(f"    Events/second: {num_events/elapsed:.0f}")

summary = detector.get_threat_summary()
print(f"\n[+] Detection Results:")
print(f"    Threats detected: {summary['total_threats']}")
print(f"    Threatened IPs: {summary['threatened_ips']}")

EOF
```

---

## **Demo 8: API Testing**

### Scenario: Test dashboard API endpoints

```bash
# Start dashboard first
python3 src/dashboard/app.py

# In another terminal, test APIs
python3 << 'EOF'
import requests
import json

BASE_URL = "http://localhost:5000"

print("[*] Testing PortShield API Endpoints")
print("=" * 60)

# Test health check
print("\n[+] GET /api/health")
r = requests.get(f"{BASE_URL}/api/health")
print(f"    Status: {r.status_code}")
print(f"    Response: {r.json()}")

# Test status
print("\n[+] GET /api/status")
r = requests.get(f"{BASE_URL}/api/status")
print(f"    Status: {r.status_code}")
print(f"    Data: {json.dumps(r.json(), indent=2)}")

# Test blocked IPs
print("\n[+] GET /api/blocked-ips")
r = requests.get(f"{BASE_URL}/api/blocked-ips")
print(f"    Status: {r.status_code}")
print(f"    Blocked IPs: {r.json()['total_blocked']}")

# Test block IP
print("\n[+] POST /api/block-ip")
r = requests.post(
    f"{BASE_URL}/api/block-ip",
    json={"ip": "203.0.113.1", "reason": "API test"}
)
print(f"    Status: {r.status_code}")
print(f"    Response: {r.json()}")

# Test ports
print("\n[+] GET /api/ports")
r = requests.get(f"{BASE_URL}/api/ports")
print(f"    Status: {r.status_code}")
print(f"    Listening ports: {r.json()['total_listening']}")

EOF
```

---

## **Running All Demos Together**

Create a comprehensive test script:

```bash
#!/bin/bash

echo "[*] PortShield Complete Demo Suite"
echo "===================================="
echo ""
echo "[1/3] Starting Dashboard..."
python3 src/dashboard/app.py &
DASH_PID=$!
sleep 3

echo "[2/3] Running attack simulations..."
sleep 2

echo "[3/3] Opening browser..."
open http://localhost:5000

echo ""
echo "Dashboard running on http://localhost:5000"
echo "Press Ctrl+C to stop"
wait $DASH_PID
```

Save as `run_demo.sh` and execute:
```bash
chmod +x run_demo.sh
./run_demo.sh
```

