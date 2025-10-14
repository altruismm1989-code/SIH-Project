"""
Integrated CCTV Vulnerability Assessment and Penetration Testing Framework
Main Application with CLI Interface

Usage:
    python cctv_integrated_app.py --scan 192.168.1.0/24
    python cctv_integrated_app.py --analyze results.json
    python cctv_integrated_app.py --dashboard
"""

import argparse
import json
import sys
from datetime import datetime
from typing import Dict, List
import os

# Import components (ensure all modules are in same directory)
try:
    from cctv_scanner import CCTVScanner
    from cctv_ml_model import CCTVVulnerabilityML
except ImportError:
    print("[!] Required modules not found. Ensure all files are in the same directory.")
    print("[!] Required files: cctv_scanner.py, cctv_ml_model.py")
    sys.exit(1)


class IntegratedCCTVAssessment:
    """Main integrated application"""
    
    def __init__(self):
        self.scanner = CCTVScanner()
        self.ml_model = CCTVVulnerabilityML()
        self.results = {
            "scan_info": {},
            "devices": [],
            "vulnerabilities": [],
            "ml_predictions": [],
            "recommendations": []
        }
    
    def full_assessment(self, target: str, scan_ports: List[int] = None):
        """Perform complete vulnerability assessment"""
        print("\n" + "="*70)
        print("CCTV AUTOMATED VULNERABILITY ASSESSMENT & PENETRATION TESTING")
        print("="*70)
        print(f"\n[*] Target: {target}")
        print(f"[*] Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Store scan info
        self.results["scan_info"] = {
            "target": target,
            "start_time": datetime.now().isoformat(),
            "scan_type": "full_assessment"
        }
        
        # Phase 1: Device Discovery
        print("[Phase 1/4] Device Discovery and Fingerprinting")
        print("-" * 70)
        
        if scan_ports is None:
            scan_ports = [80, 554, 8000, 8080, 8888, 37777]
        
        devices = self.scanner.scan_ip_range(target, ports=scan_ports)
        self.results["devices"] = devices
        print(f"[+] Discovered {len(devices)} CCTV/DVR devices\n")
        
        if not devices:
            print("[!] No devices found. Assessment complete.")
            return
        
        # Phase 2: Vulnerability Detection
        print("[Phase 2/4] Vulnerability Detection")
        print("-" * 70)
        
        all_vulnerabilities = []
        for device in devices:
            print(f"[*] Scanning {device['ip']} ({device['vendor']})...")
            vulns = self.scanner.check_vulnerabilities(device)
            all_vulnerabilities.extend(vulns)
            print(f"    Found {len(vulns)} potential vulnerabilities")
        
        self.results["vulnerabilities"] = all_vulnerabilities
        print(f"\n[+] Total vulnerabilities identified: {len(all_vulnerabilities)}\n")
        
        # Phase 3: ML Analysis
        print("[Phase 3/4] Machine Learning Analysis")
        print("-" * 70)
        
        if not self.ml_model.trained:
            print("[*] Training ML model...")
            self.ml_model.train_model()
        
        ml_predictions = []
        for device in devices:
            print(f"[*] Analyzing {device['ip']}...")
            
            # Get vulnerabilities for this device
            device_vulns = [v for v in all_vulnerabilities if v.get('ip') == device['ip']]
            
            # Perform ML analysis
            analysis = self.ml_model.analyze_device(device, device_vulns)
            ml_predictions.append(analysis)
            
            print(f"    ML Prediction: {analysis['ml_prediction']['vulnerability_level']}")
            print(f"    Overall Risk Score: {analysis['overall_risk_score']}")
        
        self.results["ml_predictions"] = ml_predictions
        print(f"\n[+] ML analysis complete\n")
        
        # Phase 4: Generate Recommendations
        print("[Phase 4/4] Generating Security Recommendations")
        print("-" * 70)
        
        recommendations = self.generate_recommendations(devices, all_vulnerabilities, ml_predictions)
        self.results["recommendations"] = recommendations
        
        print(f"[+] Generated {len(recommendations)} security recommendations\n")
        
        # Complete
        self.results["scan_info"]["end_time"] = datetime.now().isoformat()
        self.results["scan_info"]["duration"] = "Assessment complete"
        
        # Generate reports
        self.generate_detailed_report()
        self.export_results()
        
        print("\n" + "="*70)
        print("[+] ASSESSMENT COMPLETE")
        print("="*70)
    
    def generate_recommendations(self, devices, vulnerabilities, ml_predictions) -> List[Dict]:
        """Generate security recommendations"""
        recommendations = []
        
        # Get unique CVEs
        unique_cves = set(v.get('cve', '') for v in vulnerabilities)
        
        for cve in unique_cves:
            mitigations = self.ml_model.get_mitigations(cve)
            
            # Count affected devices
            affected_ips = [v['ip'] for v in vulnerabilities if v.get('cve') == cve]
            
            recommendations.append({
                "cve": cve,
                "affected_devices": len(set(affected_ips)),
                "affected_ips": list(set(affected_ips)),
                "priority": self._get_priority(cve, vulnerabilities),
                "mitigations": mitigations
            })
        
        # Sort by priority
        recommendations.sort(key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x["priority"], 4))
        
        return recommendations
    
    def _get_priority(self, cve, vulnerabilities) -> str:
        """Determine priority of a CVE"""
        severities = [v.get('severity', 'LOW') for v in vulnerabilities if v.get('cve') == cve]
        
        if 'CRITICAL' in severities:
            return 'CRITICAL'
        elif 'HIGH' in severities:
            return 'HIGH'
        elif 'MEDIUM' in severities:
            return 'MEDIUM'
        return 'LOW'
    
    def generate_detailed_report(self):
        """Generate detailed assessment report"""
        print("\n" + "="*70)
        print("DETAILED ASSESSMENT REPORT")
        print("="*70)
        
        # Summary
        print(f"\nScan Date: {self.results['scan_info'].get('start_time', 'N/A')}")
        print(f"Target: {self.results['scan_info'].get('target', 'N/A')}")
        print(f"Total Devices: {len(self.results['devices'])}")
        print(f"Total Vulnerabilities: {len(self.results['vulnerabilities'])}")
        
        # Vulnerability breakdown
        severity_count = {}
        for vuln in self.results['vulnerabilities']:
            sev = vuln.get('severity', 'UNKNOWN')
            severity_count[sev] = severity_count.get(sev, 0) + 1
        
        print("\nVulnerability Severity Breakdown:")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = severity_count.get(severity, 0)
            print(f"  {severity}: {count}")
        
        # Device breakdown
        print("\nDevices by Vendor:")
        vendor_count = {}
        for device in self.results['devices']:
            vendor = device.get('vendor', 'Unknown')
            vendor_count[vendor] = vendor_count.get(vendor, 0) + 1
        
        for vendor, count in sorted(vendor_count.items()):
            print(f"  {vendor}: {count}")
        
        # Top vulnerabilities
        print("\nTop Critical Vulnerabilities:")
        critical_vulns = [v for v in self.results['vulnerabilities'] if v.get('severity') == 'CRITICAL']
        for i, vuln in enumerate(critical_vulns[:5], 1):
            print(f"  {i}. {vuln.get('cve')} - {vuln.get('description')} ({vuln.get('ip')})")
        
        # Recommendations summary
        print("\nTop Priority Recommendations:")
        for i, rec in enumerate(self.results['recommendations'][:5], 1):
            print(f"  {i}. {rec['cve']} - Priority: {rec['priority']}")
            print(f"     Affected Devices: {rec['affected_devices']}")
            print(f"     Key Mitigation: {rec['mitigations'][0]}")
        
        print("\n" + "="*70)
    
    def export_results(self, filename: str = None):
        """Export complete results"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"cctv_assessment_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n[+] Complete results exported to: {filename}")
        
        # Also save for dashboard
        with open("cctv_scan_results.json", 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # Generate CSV for devices
        self.export_devices_csv()
        
        # Generate CSV for vulnerabilities
        self.export_vulnerabilities_csv()
    
    def export_devices_csv(self):
        """Export devices to CSV"""
        import csv
        
        filename = "discovered_devices.csv"
        with open(filename, 'w', newline='') as f:
            if not self.results['devices']:
                return
            
            fieldnames = ['ip', 'vendor', 'model', 'firmware', 'ports', 'timestamp']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            
            writer.writeheader()
            for device in self.results['devices']:
                row = {
                    'ip': device.get('ip', ''),
                    'vendor': device.get('vendor', ''),
                    'model': device.get('model', ''),
                    'firmware': device.get('firmware', ''),
                    'ports': ','.join(map(str, device.get('ports', []))),
                    'timestamp': device.get('timestamp', '')
                }
                writer.writerow(row)
        
        print(f"[+] Devices exported to: {filename}")
    
    def export_vulnerabilities_csv(self):
        """Export vulnerabilities to CSV"""
        import csv
        
        filename = "identified_vulnerabilities.csv"
        with open(filename, 'w', newline='') as f:
            if not self.results['vulnerabilities']:
                return
            
            fieldnames = ['ip', 'vendor', 'cve', 'severity', 'description', 'timestamp']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            
            writer.writeheader()
            for vuln in self.results['vulnerabilities']:
                row = {
                    'ip': vuln.get('ip', ''),
                    'vendor': vuln.get('vendor', ''),
                    'cve': vuln.get('cve', ''),
                    'severity': vuln.get('severity', ''),
                    'description': vuln.get('description', ''),
                    'timestamp': vuln.get('timestamp', '')
                }
                writer.writerow(row)
        
        print(f"[+] Vulnerabilities exported to: {filename}")
    
    def analyze_existing_results(self, results_file: str):
        """Analyze existing scan results"""
        print(f"\n[*] Loading results from {results_file}...")
        
        try:
            with open(results_file, 'r') as f:
                self.results = json.load(f)
            
            print("[+] Results loaded successfully")
            self.generate_detailed_report()
        except Exception as e:
            print(f"[-] Error loading results: {str(e)}")


def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description='CCTV Vulnerability Assessment and Penetration Testing Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Scan local network:
    python cctv_integrated_app.py --scan 192.168.1.0/24
  
  Scan specific IP range with custom ports:
    python cctv_integrated_app.py --scan 10.0.0.1-10.0.0.50 --ports 80,554,8000
  
  Analyze existing results:
    python cctv_integrated_app.py --analyze cctv_assessment_20240101_120000.json
  
  Start web dashboard:
    python cctv_integrated_app.py --dashboard
        """
    )
    
    parser.add_argument('--scan', type=str, help='IP range to scan (e.g., 192.168.1.0/24)')
    parser.add_argument('--ports', type=str, help='Comma-separated ports to scan (default: 80,554,8000,8080)')
    parser.add_argument('--analyze', type=str, help='Analyze existing results file')
    parser.add_argument('--dashboard', action='store_true', help='Start web dashboard')
    parser.add_argument('--output', type=str, help='Output filename for results')
    
    args = parser.parse_args()
    
    # Banner
    print("""
    ╔══════════════════════════════════════════════════════════════════╗
    ║  CCTV Automated Vulnerability Assessment & Penetration Testing   ║
    ║                          Framework v1.0                          ║
    ║                                                                  ║
    ║  [!] For Authorized Security Testing Only                       ║
    ╚══════════════════════════════════════════════════════════════════╝
    """)
    
    app = IntegratedCCTVAssessment()
    
    if args.dashboard:
        print("[*] Starting web dashboard...")
        try:
            from cctv_dashboard import app as dashboard_app
            dashboard_app.run(debug=False, host='0.0.0.0', port=5000)
        except ImportError:
            print("[-] Dashboard module not found. Ensure cctv_dashboard.py is in the same directory.")
        return
    
    if args.analyze:
        app.analyze_existing_results(args.analyze)
        return
    
    if args.scan:
        # Parse ports
        ports = None
        if args.ports:
            ports = [int(p.strip()) for p in args.ports.split(',')]
        
        # Perform assessment
        app.full_assessment(args.scan, scan_ports=ports)
        
        # Export with custom filename if provided
        if args.output:
            app.export_results(args.output)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()