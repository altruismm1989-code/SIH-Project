"""
Flask Web Dashboard for CCTV Vulnerability Assessment
Run: python dashboard.py
Access: http://localhost:5000
"""

from flask import Flask, render_template, jsonify, request
import json
import os
from datetime import datetime
import folium
from geopy.geocoders import Nominatim
import socket

app = Flask(__name__)

class DashboardManager:
    def __init__(self):
        self.results_file = "cctv_scan_results.json"
        self.geolocator = Nominatim(user_agent="cctv_scanner")
    
    def load_results(self):
        """Load scan results"""
        if os.path.exists(self.results_file):
            with open(self.results_file, 'r') as f:
                return json.load(f)
        return {"devices": [], "vulnerabilities": []}
    
    def get_statistics(self):
        """Calculate dashboard statistics"""
        data = self.load_results()
        
        stats = {
            "total_devices": len(data.get("devices", [])),
            "total_vulnerabilities": len(data.get("vulnerabilities", [])),
            "critical_vulns": 0,
            "high_vulns": 0,
            "medium_vulns": 0,
            "low_vulns": 0,
            "vendors": {}
        }
        
        # Count vulnerabilities by severity
        for vuln in data.get("vulnerabilities", []):
            severity = vuln.get("severity", "UNKNOWN")
            if severity == "CRITICAL":
                stats["critical_vulns"] += 1
            elif severity == "HIGH":
                stats["high_vulns"] += 1
            elif severity == "MEDIUM":
                stats["medium_vulns"] += 1
            else:
                stats["low_vulns"] += 1
        
        # Count devices by vendor
        for device in data.get("devices", []):
            vendor = device.get("vendor", "Unknown")
            stats["vendors"][vendor] = stats["vendors"].get(vendor, 0) + 1
        
        return stats
    
    def get_device_locations(self):
        """Get approximate locations for devices"""
        data = self.load_results()
        locations = []
        
        for device in data.get("devices", []):
            ip = device.get("ip", "")
            try:
                # Get hostname
                hostname = socket.getfqdn(ip)
                
                # Simple location (in real scenario, use IP geolocation API)
                location = {
                    "ip": ip,
                    "vendor": device.get("vendor", "Unknown"),
                    "lat": 0.0,  # Replace with actual geolocation
                    "lon": 0.0,  # Replace with actual geolocation
                    "location_name": "Unknown",
                    "severity": self._get_device_severity(device, data.get("vulnerabilities", []))
                }
                locations.append(location)
            except:
                continue
        
        return locations
    
    def _get_device_severity(self, device, vulnerabilities):
        """Get highest severity for a device"""
        device_ip = device.get("ip")
        severities = []
        
        for vuln in vulnerabilities:
            if vuln.get("ip") == device_ip:
                severities.append(vuln.get("severity", "LOW"))
        
        if "CRITICAL" in severities:
            return "CRITICAL"
        elif "HIGH" in severities:
            return "HIGH"
        elif "MEDIUM" in severities:
            return "MEDIUM"
        return "LOW"
    
    def create_map(self):
        """Create interactive map"""
        m = folium.Map(location=[20.5937, 78.9629], zoom_start=5)  # India center
        
        locations = self.get_device_locations()
        
        for loc in locations:
            color = {
                "CRITICAL": "red",
                "HIGH": "orange",
                "MEDIUM": "yellow",
                "LOW": "green"
            }.get(loc["severity"], "blue")
            
            folium.Marker(
                [loc["lat"], loc["lon"]],
                popup=f"IP: {loc['ip']}<br>Vendor: {loc['vendor']}<br>Risk: {loc['severity']}",
                icon=folium.Icon(color=color)
            ).add_to(m)
        
        return m._repr_html_()

dashboard_mgr = DashboardManager()

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/statistics')
def api_statistics():
    """API endpoint for statistics"""
    return jsonify(dashboard_mgr.get_statistics())

@app.route('/api/devices')
def api_devices():
    """API endpoint for devices list"""
    data = dashboard_mgr.load_results()
    return jsonify(data.get("devices", []))

@app.route('/api/vulnerabilities')
def api_vulnerabilities():
    """API endpoint for vulnerabilities list"""
    data = dashboard_mgr.load_results()
    return jsonify(data.get("vulnerabilities", []))

@app.route('/api/locations')
def api_locations():
    """API endpoint for device locations"""
    return jsonify(dashboard_mgr.get_device_locations())

@app.route('/map')
def show_map():
    """Show interactive map"""
    return dashboard_mgr.create_map()

# HTML Template (save as templates/dashboard.html)
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CCTV Vulnerability Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.7.0/dist/chart.min.js"></script>
    <style>
        body { background-color: #f5f5f5; }
        .card { margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat-card { padding: 20px; text-align: center; }
        .stat-number { font-size: 2.5rem; font-weight: bold; }
        .critical { color: #dc3545; }
        .high { color: #fd7e14; }
        .medium { color: #ffc107; }
        .low { color: #28a745; }
        .navbar { background-color: #2c3e50; }
        .device-table { font-size: 0.9rem; }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark">
        <div class="container-fluid">
            <span class="navbar-brand mb-0 h1">
                <i class="fas fa-video"></i> CCTV Vulnerability Assessment Dashboard
            </span>
        </div>
    </nav>

    <div class="container-fluid mt-4">
        <div class="row">
            <!-- Statistics Cards -->
            <div class="col-md-3">
                <div class="card stat-card">
                    <div class="stat-number" id="total-devices">0</div>
                    <div class="text-muted">Total Devices</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card critical">
                    <div class="stat-number" id="critical-vulns">0</div>
                    <div class="text-muted">Critical Vulnerabilities</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card high">
                    <div class="stat-number" id="high-vulns">0</div>
                    <div class="text-muted">High Vulnerabilities</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card">
                    <div class="stat-number" id="total-vulns">0</div>
                    <div class="text-muted">Total Vulnerabilities</div>
                </div>
            </div>
        </div>

        <div class="row">
            <!-- Charts -->
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Vulnerabilities by Severity</h5>
                    </div>
                    <div class="card-body">
                        <canvas id="severity-chart"></canvas>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Devices by Vendor</h5>
                    </div>
                    <div class="card-body">
                        <canvas id="vendor-chart"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <!-- Devices Table -->
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header">
                        <h5>Discovered Devices</h5>
                    </div>
                    <div class="card-body">
                        <table class="table table-striped device-table" id="devices-table">
                            <thead>
                                <tr>
                                    <th>IP Address</th>
                                    <th>Vendor</th>
                                    <th>Model</th>
                                    <th>Firmware</th>
                                    <th>Open Ports</th>
                                    <th>Risk Level</th>
                                </tr>
                            </thead>
                            <tbody id="devices-tbody"></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <!-- Vulnerabilities Table -->
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header">
                        <h5>Identified Vulnerabilities</h5>
                    </div>
                    <div class="card-body">
                        <table class="table table-striped device-table" id="vulns-table">
                            <thead>
                                <tr>
                                    <th>IP Address</th>
                                    <th>CVE/ID</th>
                                    <th>Severity</th>
                                    <th>Description</th>
                                    <th>Vendor</th>
                                </tr>
                            </thead>
                            <tbody id="vulns-tbody"></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Fetch and display statistics
        async function loadStatistics() {
            const response = await fetch('/api/statistics');
            const stats = await response.json();
            
            document.getElementById('total-devices').textContent = stats.total_devices;
            document.getElementById('critical-vulns').textContent = stats.critical_vulns;
            document.getElementById('high-vulns').textContent = stats.high_vulns;
            document.getElementById('total-vulns').textContent = stats.total_vulnerabilities;
            
            // Create severity chart
            const severityCtx = document.getElementById('severity-chart').getContext('2d');
            new Chart(severityCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low'],
                    datasets: [{
                        data: [stats.critical_vulns, stats.high_vulns, stats.medium_vulns, stats.low_vulns],
                        backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745']
                    }]
                }
            });
            
            // Create vendor chart
            const vendorCtx = document.getElementById('vendor-chart').getContext('2d');
            new Chart(vendorCtx, {
                type: 'bar',
                data: {
                    labels: Object.keys(stats.vendors),
                    datasets: [{
                        label: 'Device Count',
                        data: Object.values(stats.vendors),
                        backgroundColor: '#3498db'
                    }]
                }
            });
        }
        
        // Load devices
        async function loadDevices() {
            const response = await fetch('/api/devices');
            const devices = await response.json();
            const tbody = document.getElementById('devices-tbody');
            
            tbody.innerHTML = '';
            devices.forEach(device => {
                const row = `
                    <tr>
                        <td>${device.ip}</td>
                        <td>${device.vendor}</td>
                        <td>${device.model}</td>
                        <td>${device.firmware}</td>
                        <td>${device.ports.join(', ')}</td>
                        <td><span class="badge bg-warning">Medium</span></td>
                    </tr>
                `;
                tbody.innerHTML += row;
            });
        }
        
        // Load vulnerabilities
        async function loadVulnerabilities() {
            const response = await fetch('/api/vulnerabilities');
            const vulns = await response.json();
            const tbody = document.getElementById('vulns-tbody');
            
            tbody.innerHTML = '';
            vulns.forEach(vuln => {
                const badgeClass = {
                    'CRITICAL': 'bg-danger',
                    'HIGH': 'bg-warning',
                    'MEDIUM': 'bg-info',
                    'LOW': 'bg-success'
                }[vuln.severity] || 'bg-secondary';
                
                const row = `
                    <tr>
                        <td>${vuln.ip}</td>
                        <td>${vuln.cve}</td>
                        <td><span class="badge ${badgeClass}">${vuln.severity}</span></td>
                        <td>${vuln.description}</td>
                        <td>${vuln.vendor}</td>
                    </tr>
                `;
                tbody.innerHTML += row;
            });
        }
        
        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', () => {
            loadStatistics();
            loadDevices();
            loadVulnerabilities();
            
            // Auto-refresh every 30 seconds
            setInterval(() => {
                loadStatistics();
                loadDevices();
                loadVulnerabilities();
            }, 30000);
        });
    </script>
</body>
</html>
"""

# Create templates directory and save HTML
if __name__ == "__main__":
    os.makedirs("templates", exist_ok=True)
    with open("templates/dashboard.html", "w") as f:
        f.write(DASHBOARD_HTML)
    
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║          CCTV Vulnerability Dashboard Starting          ║
    ╚══════════════════════════════════════════════════════════╝
    
    Dashboard URL: http://localhost:5000
    
    Press Ctrl+C to stop the server
    """)
    
    app.run(debug=True, host='0.0.0.0', port=5000)