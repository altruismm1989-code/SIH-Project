"""
CCTV Vulnerability Assessment and Penetration Testing Framework
Main Application File
"""

import json
import requests
import socket
import nmap
from datetime import datetime
import pandas as pd
from typing import Dict, List
import re
import threading
import time

class CCTVScanner:
    def __init__(self):
        self.discovered_devices = []
        self.vulnerabilities = []
        self.cve_database = self.load_cve_database()
        
    def load_cve_database(self) -> Dict:
        """Load CVE database for CCTV cameras"""
        # Sample CVE database - expand this with real data
        return {
            "Hikvision": [
                {"cve": "CVE-2021-36260", "severity": "CRITICAL", "description": "Authentication bypass"},
                {"cve": "CVE-2017-7921", "severity": "HIGH", "description": "Backdoor account"}
            ],
            "Dahua": [
                {"cve": "CVE-2021-33044", "severity": "CRITICAL", "description": "Authentication bypass"},
                {"cve": "CVE-2020-9030", "severity": "HIGH", "description": "Credential disclosure"}
            ],
            "Axis": [
                {"cve": "CVE-2018-10660", "severity": "MEDIUM", "description": "Information disclosure"}
            ],
            "Default": [
                {"cve": "WEAK-CRED-001", "severity": "HIGH", "description": "Default credentials"},
                {"cve": "OPEN-PORT-001", "severity": "MEDIUM", "description": "Unnecessary open ports"}
            ]
        }
    
    def scan_ip_range(self, ip_range: str, ports: List[int] = [80, 554, 8000, 8080]) -> List[Dict]:
        """Scan IP range for CCTV devices"""
        print(f"[*] Scanning IP range: {ip_range}")
        nm = nmap.PortScanner()
        
        discovered = []
        try:
            # Scan for common CCTV ports
            port_string = ','.join(map(str, ports))
            nm.scan(hosts=ip_range, arguments=f'-p {port_string} -sV --script http-title')
            
            for host in nm.all_hosts():
                if nm[host].state() == 'up':
                    device_info = self.identify_device(host, nm[host])
                    if device_info:
                        discovered.append(device_info)
                        print(f"[+] Found device: {host} - {device_info['vendor']}")
        except Exception as e:
            print(f"[-] Scan error: {str(e)}")
        
        self.discovered_devices.extend(discovered)
        return discovered
    
    def identify_device(self, ip: str, host_data) -> Dict:
        """Identify CCTV device vendor and model"""
        device_info = {
            "ip": ip,
            "vendor": "Unknown",
            "model": "Unknown",
            "firmware": "Unknown",
            "ports": [],
            "services": [],
            "timestamp": datetime.now().isoformat()
        }
        
        # Extract port and service information
        for proto in host_data.all_protocols():
            ports = host_data[proto].keys()
            for port in ports:
                service = host_data[proto][port]
                device_info["ports"].append(port)
                device_info["services"].append(service.get('product', 'unknown'))
                
                # Try to identify vendor from service banner
                product = service.get('product', '').lower()
                extrainfo = service.get('extrainfo', '').lower()
                
                if 'hikvision' in product or 'hikvision' in extrainfo:
                    device_info["vendor"] = "Hikvision"
                elif 'dahua' in product or 'dahua' in extrainfo:
                    device_info["vendor"] = "Dahua"
                elif 'axis' in product or 'axis' in extrainfo:
                    device_info["vendor"] = "Axis"
                elif 'rtsp' in product or 'http' in product:
                    device_info["vendor"] = "Generic Camera"
        
        # Try HTTP detection
        if 80 in device_info["ports"] or 8080 in device_info["ports"]:
            http_info = self.http_fingerprint(ip)
            if http_info:
                device_info.update(http_info)
        
        return device_info if device_info["vendor"] != "Unknown" else None
    
    def http_fingerprint(self, ip: str) -> Dict:
        """Fingerprint device via HTTP"""
        info = {}
        ports = [80, 8080, 8000]
        
        for port in ports:
            try:
                url = f"http://{ip}:{port}"
                response = requests.get(url, timeout=3, verify=False)
                
                # Check headers for vendor info
                server = response.headers.get('Server', '').lower()
                if 'hikvision' in server:
                    info["vendor"] = "Hikvision"
                elif 'dahua' in server:
                    info["vendor"] = "Dahua"
                
                # Check HTML content
                content = response.text.lower()
                if 'hikvision' in content:
                    info["vendor"] = "Hikvision"
                elif 'dahua' in content:
                    info["vendor"] = "Dahua"
                elif 'axis' in content:
                    info["vendor"] = "Axis"
                
                # Extract model if possible
                model_match = re.search(r'model[:\s]+([A-Z0-9\-]+)', content, re.IGNORECASE)
                if model_match:
                    info["model"] = model_match.group(1)
                
                break
            except:
                continue
        
        return info
    
    def test_default_credentials(self, ip: str, port: int = 80) -> Dict:
        """Test for default credentials"""
        default_creds = [
            ("admin", "admin"),
            ("admin", "12345"),
            ("admin", ""),
            ("root", "root"),
            ("admin", "admin123"),
            ("888888", "888888")
        ]
        
        vulnerabilities = []
        for username, password in default_creds:
            try:
                url = f"http://{ip}:{port}/api/auth"
                # Simulate authentication test
                # In real scenario, implement actual authentication
                vuln = {
                    "type": "Default Credentials",
                    "severity": "CRITICAL",
                    "credentials": f"{username}:{password}",
                    "ip": ip
                }
                # Note: Actual implementation would verify credentials
            except:
                continue
        
        return vulnerabilities
    
    def check_vulnerabilities(self, device: Dict) -> List[Dict]:
        """Check device for known vulnerabilities"""
        vulns = []
        vendor = device.get("vendor", "Default")
        
        # Get CVEs for vendor
        cves = self.cve_database.get(vendor, self.cve_database["Default"])
        
        for cve in cves:
            vuln = {
                "ip": device["ip"],
                "vendor": vendor,
                "model": device.get("model", "Unknown"),
                "cve": cve["cve"],
                "severity": cve["severity"],
                "description": cve["description"],
                "timestamp": datetime.now().isoformat()
            }
            vulns.append(vuln)
        
        # Check for open unnecessary ports
        risky_ports = [23, 21, 22]  # Telnet, FTP, SSH
        for port in device.get("ports", []):
            if port in risky_ports:
                vulns.append({
                    "ip": device["ip"],
                    "vendor": vendor,
                    "cve": "OPEN-PORT-" + str(port),
                    "severity": "MEDIUM",
                    "description": f"Unnecessary port {port} is open",
                    "timestamp": datetime.now().isoformat()
                })
        
        self.vulnerabilities.extend(vulns)
        return vulns
    
    def export_results(self, filename: str = "scan_results.json"):
        """Export scan results to JSON"""
        results = {
            "scan_time": datetime.now().isoformat(),
            "total_devices": len(self.discovered_devices),
            "total_vulnerabilities": len(self.vulnerabilities),
            "devices": self.discovered_devices,
            "vulnerabilities": self.vulnerabilities
        }
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"[+] Results exported to {filename}")
        return results
    
    def generate_report(self):
        """Generate summary report"""
        print("\n" + "="*60)
        print("CCTV VULNERABILITY ASSESSMENT REPORT")
        print("="*60)
        print(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Devices Found: {len(self.discovered_devices)}")
        print(f"Total Vulnerabilities: {len(self.vulnerabilities)}")
        print("\n" + "-"*60)
        
        # Vulnerability summary by severity
        severity_count = {}
        for vuln in self.vulnerabilities:
            severity = vuln.get("severity", "UNKNOWN")
            severity_count[severity] = severity_count.get(severity, 0) + 1
        
        print("\nVulnerabilities by Severity:")
        for severity, count in sorted(severity_count.items()):
            print(f"  {severity}: {count}")
        
        # Devices by vendor
        vendor_count = {}
        for device in self.discovered_devices:
            vendor = device.get("vendor", "Unknown")
            vendor_count[vendor] = vendor_count.get(vendor, 0) + 1
        
        print("\nDevices by Vendor:")
        for vendor, count in sorted(vendor_count.items()):
            print(f"  {vendor}: {count}")
        
        print("\n" + "="*60)


def main():
    """Main execution function"""
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║   CCTV Vulnerability Assessment & Penetration Testing    ║
    ║                      Framework v1.0                      ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    scanner = CCTVScanner()
    
    # Example usage - scan local network
    print("\n[*] Starting vulnerability assessment...")
    
    # Scan a specific IP range (modify as needed)
    ip_range = "192.168.1.0/24"  # Change this to your target range
    
    print(f"[*] Target: {ip_range}")
    print("[!] Note: This is for authorized testing only\n")
    
    # Discover devices
    devices = scanner.scan_ip_range(ip_range)
    
    # Check vulnerabilities for each device
    print(f"\n[*] Checking vulnerabilities for {len(devices)} devices...")
    for device in devices:
        vulns = scanner.check_vulnerabilities(device)
        print(f"[+] {device['ip']}: Found {len(vulns)} potential vulnerabilities")
    
    # Generate reports
    scanner.export_results("cctv_scan_results.json")
    scanner.generate_report()
    
    print("\n[+] Assessment complete!")


if __name__ == "__main__":
    main()