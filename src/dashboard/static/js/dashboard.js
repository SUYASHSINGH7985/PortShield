/**
 * PortShield Dashboard JavaScript
 * Handles real-time updates and API communication
 */

// Update interval in milliseconds
const UPDATE_INTERVAL = 2000; // 2 seconds

// Initialize dashboard on page load
document.addEventListener('DOMContentLoaded', function() {
    console.log('Dashboard initialized');
    updateDashboard();
    setInterval(updateDashboard, UPDATE_INTERVAL);
    updateClock();
    setInterval(updateClock, 1000);
});

/**
 * Update current time display
 */
function updateClock() {
    const now = new Date();
    const timeString = now.toLocaleTimeString();
    document.getElementById('current-time').textContent = timeString;
}

/**
 * Main dashboard update function
 */
async function updateDashboard() {
    try {
        // Fetch all dashboard data
        const response = await fetch('/api/dashboard-data');
        const data = await response.json();
        
        // Update summary cards
        document.getElementById('active-connections').textContent = data.summary.total_connections;
        document.getElementById('threats-count').textContent = data.summary.threats_detected;
        document.getElementById('blocked-ips-count').textContent = data.summary.blocked_ips;
        document.getElementById('listening-ports').textContent = data.summary.listening_ports;
        
        // Update tables
        updateTopIPsTable(data.top_ips);
        updateThreatsTable(data.recent_threats);
        updateBlockedIPsTable();
        updatePortsTable();
        
    } catch (error) {
        console.error('Error updating dashboard:', error);
    }
}

/**
 * Update top IPs table
 */
async function updateTopIPsTable(topIPs) {
    const tbody = document.getElementById('top-ips-body');
    
    if (!topIPs || topIPs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3" class="text-center">No connections</td></tr>';
        return;
    }
    
    let html = '';
    for (const item of topIPs) {
        const isBlocked = await checkIfBlocked(item.ip);
        const statusBadge = isBlocked ? 
            '<span class="badge badge-danger"><span class="status-indicator status-offline"></span>Blocked</span>' :
            '<span class="badge badge-success"><span class="status-indicator status-online"></span>Active</span>';
        
        html += `
            <tr>
                <td><strong>${item.ip}</strong></td>
                <td>${item.count}</td>
                <td>${statusBadge}</td>
            </tr>
        `;
    }
    
    tbody.innerHTML = html;
}

/**
 * Update threats table
 */
function updateThreatsTable(threats) {
    const tbody = document.getElementById('threats-body');
    
    if (!threats || threats.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3" class="text-center">No threats detected</td></tr>';
        return;
    }
    
    let html = '';
    for (const threat of threats) {
        const time = new Date(threat.timestamp).toLocaleTimeString();
        html += `
            <tr>
                <td><strong>${threat.ip}</strong></td>
                <td><span class="badge badge-warning">${threat.type}</span></td>
                <td>${time}</td>
            </tr>
        `;
    }
    
    tbody.innerHTML = html;
}

/**
 * Update blocked IPs table
 */
async function updateBlockedIPsTable() {
    try {
        const response = await fetch('/api/blocked-ips');
        const data = await response.json();
        const tbody = document.getElementById('blocked-ips-body');
        
        if (!data.blocked_ips || data.blocked_ips.length === 0) {
            tbody.innerHTML = '<tr><td colspan="2" class="text-center">No blocked IPs</td></tr>';
            return;
        }
        
        let html = '';
        for (const ip of data.blocked_ips) {
            html += `
                <tr>
                    <td><strong>${ip}</strong></td>
                    <td>
                        <button class="btn btn-sm btn-danger" onclick="unblockIP('${ip}')">
                            <i class="fas fa-unlock"></i> Unblock
                        </button>
                    </td>
                </tr>
            `;
        }
        
        tbody.innerHTML = html;
    } catch (error) {
        console.error('Error updating blocked IPs:', error);
    }
}

/**
 * Update listening ports table
 */
async function updatePortsTable() {
    try {
        const response = await fetch('/api/ports');
        const data = await response.json();
        const tbody = document.getElementById('ports-body');
        
        if (!data.ports || data.ports.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="text-center">No listening ports</td></tr>';
            return;
        }
        
        let html = '';
        for (const port of data.ports) {
            const protocol = port.service.includes('UDP') ? 'UDP' : 'TCP';
            html += `
                <tr>
                    <td><strong>${port.port}</strong></td>
                    <td>${port.service}</td>
                    <td>${protocol}</td>
                    <td><span class="badge bg-success">LISTEN</span></td>
                </tr>
            `;
        }
        
        tbody.innerHTML = html;
    } catch (error) {
        console.error('Error updating ports:', error);
    }
}

/**
 * Check if IP is blocked
 */
async function checkIfBlocked(ip) {
    try {
        const response = await fetch('/api/blocked-ips');
        const data = await response.json();
        return data.blocked_ips.includes(ip);
    } catch (error) {
        return false;
    }
}

/**
 * Block an IP address
 */
async function blockIP(ip = null) {
    // If no IP provided, get from input
    if (!ip) {
        ip = document.getElementById('block-ip-input').value.trim();
    }
    
    if (!ip) {
        alert('Please enter an IP address');
        return;
    }
    
    // Validate IP format
    if (!isValidIP(ip)) {
        alert('Please enter a valid IP address');
        return;
    }
    
    try {
        const response = await fetch('/api/block-ip', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                ip: ip,
                reason: 'Manual block via dashboard'
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showAlert(`IP ${ip} has been blocked`, 'success');
            document.getElementById('block-ip-input').value = '';
            updateDashboard();
        } else {
            showAlert(`Failed to block IP: ${data.message}`, 'danger');
        }
    } catch (error) {
        console.error('Error blocking IP:', error);
        showAlert('Error blocking IP', 'danger');
    }
}

/**
 * Unblock an IP address
 */
async function unblockIP(ip) {
    if (!confirm(`Are you sure you want to unblock ${ip}?`)) {
        return;
    }
    
    try {
        const response = await fetch('/api/unblock-ip', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ ip: ip })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showAlert(`IP ${ip} has been unblocked`, 'success');
            updateDashboard();
        } else {
            showAlert('Failed to unblock IP', 'danger');
        }
    } catch (error) {
        console.error('Error unblocking IP:', error);
        showAlert('Error unblocking IP', 'danger');
    }
}

/**
 * Validate IP address format
 */
function isValidIP(ip) {
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ip)) return false;
    
    const parts = ip.split('.');
    for (let part of parts) {
        const num = parseInt(part);
        if (num < 0 || num > 255) return false;
    }
    
    return true;
}

/**
 * Show alert message
 */
function showAlert(message, type = 'info') {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.role = 'alert';
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    // Add to top of page
    const container = document.querySelector('.container-fluid');
    container.insertBefore(alertDiv, container.firstChild);
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        alertDiv.remove();
    }, 5000);
}

/**
 * Scan ports (manual trigger)
 */
async function scanPorts(host = '127.0.0.1') {
    try {
        const response = await fetch('/api/scan-ports', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ host: host })
        });
        
        const data = await response.json();
        showAlert(`Scan complete: Found ${data.open_ports} open ports on ${host}`, 'info');
        updateDashboard();
    } catch (error) {
        console.error('Error scanning ports:', error);
        showAlert('Error scanning ports', 'danger');
    }
}

console.log('Dashboard JavaScript loaded');
