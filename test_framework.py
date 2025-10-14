"""
Test and Demo Script for CCTV Vulnerability Assessment Framework
This script demonstrates all features with simulated data
"""

import json
from datetime import datetime
import random

def create_sample_data():
    """Create sample scan data for demonstration"""
    
    sample_devices = [
        {
            "ip": "192.168.1.100",
            "vendor": "Hikvision",
            "model": "DS-2CD2042WD-I",
            "firmware": "5.4.0",
            "ports": [80, 554, 8000],
            "services": ["http", "rtsp", "web"],
            "timestamp": datetime.now().isoformat()
        },
        {
            "ip": "192.168.1.101",
            "vendor": "Dahua",
            "model": "IPC-HFW4431R-Z",
            "firmware": "2.800.0000000.18.R",
            "ports": [80, 554, 37777],
            "services": ["http", "rtsp", "custom"],
            "timestamp": datetime.now().isoformat()
        },
        {
            "ip": "192.168.1.102",
            "vendor": "Axis",
            "model": "M3046-V",
            "firmware": "9.80.1",
            "ports": [80, 443, 554],
            "services": ["http", "https", "rtsp"],
            "timestamp": datetime.now().isoformat()
        },
        {
            "ip": "192.168.1.103",
            "vendor": "Hikvision",
            "model": "DS-2CD2385G1-I",
            "firmware": "5.5.82",
            "ports": [80, 554],
            "services": ["http", "rtsp"],
            "timestamp": datetime.now().isoformat()
        }
    ]
    
    sample_vulnerabilities = [
        {
            "ip": "192.168.1.100",
            "vendor": "Hikvision",
            "model": "DS-2CD2042WD-I",
            "cve": "CVE-2021-36260",
            "severity": "CRITICAL",
            "description": "Authentication bypass vulnerability",
            "timestamp": datetime.now().isoformat()
        },
        {
            "ip": "192.168.1.100",
            "vendor": "Hikvision",
            "cve": "CVE-2017-7921",
            "severity": "HIGH",
            "description": "Backdoor account exists",
            "timestamp": datetime.now().isoformat()
        },
        {
            "ip": "192.168.1.100",
            "vendor": "Hikvision",
            "cve": "WEAK-CRED-001",
            "severity": "HIGH",
            "description": "Default credentials detected",
            "timestamp": datetime.now().isoformat()
        },
        {
            "ip": "192.168.1.101",
            "vendor": "Dahua",
            "cve": "CVE-2021-33044",
            "severity": "CRITICAL",
            "description": "Authentication bypass via crafted request",
            "timestamp": datetime.now().isoformat()
        },
        {
            "ip": "192.168.1.101",
            "vendor": "Dahua",
            "cve": "OPEN-PORT-37777",
            "severity": "MEDIUM",
            "description": "Proprietary protocol port exposed",
            "timestamp": datetime.now().isoformat()
        },
        {
            "ip": "192.168.1.102",
            "vendor": "Axis",
            "cve": "CVE-2018-10660",
            "severity": "MEDIUM",
            "description": "Information disclosure vulnerability",
            "timestamp": datetime.now().isoformat()
        },
        {
            "ip": "192.168.1.103",
            "vendor": "Hikvision",
            "cve": "WEAK-CRED-001",
            "severity": "HIGH",
            "description": "Default credentials detected",
            "timestamp": datetime.now().isoformat()
        }
    ]
    
    results = {
        "scan_time": datetime.now().isoformat(),
        "total_devices": len(sample_devices),
        "total_vulnerabilities": len(sample_vulnerabilities),
        "devices": sample_devices,
        "vulnerabilities": sample_vulnerabilities
    }
    
    return results


def test_scanner():
    """Test scanner module"""
    print("\n" + "="*70)
    print("TEST 1: Scanner Module")
    print("="*70)
    
    try:
        from cctv_scanner import CCTVScanner
        
        scanner = CCTVScanner()
        print("[+] Scanner initialized successfully")
        
        # Test CVE database
        print(f"[+] CVE database loaded: {len(scanner.cve_database)} vendors")
        
        # Test device identification
        test_device = {
            "ip": "192.168.1.100",
            "vendor": "Hikvision",
            "ports": [80, 554],
            "services": ["http", "rtsp"]
        }
        
        vulns = scanner.check_vulnerabilities(test_device)
        print(f"[+] Vulnerability check: Found {len(vulns)} vulnerabilities")
        
        print("[✓] Scanner module test PASSED")
        return True
        
    except Exception as e:
        print(f"[✗] Scanner module test FAILED: {str(e)}")
        return False


def test_ml_model():
    """Test ML model module"""
    print("\n" + "="*70)
    print("TEST 2: Machine Learning Module")
    print("="*70)
    
    try:
        from cctv_ml_model import CCTVVulnerabilityML
        
        ml_model = CCTVVulnerabilityML()
        print("[+] ML model initialized successfully")
        
        # Train model
        print("[*] Training ML model...")
        ml_model.train_model()
        print("[+] Model trained successfully")
        
        # Test prediction
        test_device = {
            "ip": "192.168.1.100",
            "vendor": "Hikvision",
            "firmware": "5.4.0",
            "ports": [80, 554, 8000, 23]
        }
        
        prediction = ml_model.predict_vulnerability(test_device)
        print(f"[+] Prediction: {prediction['vulnerability_level']}")
        print(f"[+] Confidence: {prediction['confidence']}")
        
        # Test exploitation steps
        steps = ml_model.get_exploitation_steps("CVE-2021-36260")
        print(f"[+] Exploitation steps: {len(steps)} steps loaded")
        
        # Test mitigations
        mitigations = ml_model.get_mitigations("CVE-2021-36260")
        print(f"[+] Mitigations: {len(mitigations)} recommendations loaded")
        
        print("[✓] ML model test PASSED")
        return True
        
    except Exception as e:
        print(f"[✗] ML model test FAILED: {str(e)}")
        return False


def test_data_export():
    """Test data export functionality"""
    print("\n" + "="*70)
    print("TEST 3: Data Export")
    print("="*70)
    
    try:
        # Create sample data
        data = create_sample_data()
        
        # Export to JSON
        with open("cctv_scan_results.json", 'w') as f:
            json.dump(data, f, indent=2)
        print("[+] JSON export successful: cctv_scan_results.json")
        
        # Export devices to CSV
        import csv
        with open("discovered_devices.csv", 'w', newline='') as f:
            fieldnames = ['ip', 'vendor', 'model', 'firmware', 'ports']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for device in data['devices']:
                writer.writerow({
                    'ip': device['ip'],
                    'vendor': device['vendor'],
                    'model': device['model'],
                    'firmware': device['firmware'],
                    'ports': ','.join(map(str, device['ports']))
                })
        print("[+] CSV export successful: discovered_devices.csv")
        
        print("[✓] Data export test PASSED")
        return True
        
    except Exception as e:
        print(f"[✗] Data export test FAILED: {str(e)}")
        return False


def test_dashboard_data():
    """Test dashboard can load data"""
    print("\n" + "="*70)
    print("TEST 4: Dashboard Data Loading")
    print("="*70)
    
    try:
        # Ensure data file exists
        data = create_sample_data()
        with open("cctv_scan_results.json", 'w') as f:
            json.dump(data, f, indent=2)
        
        # Try to import dashboard
        from cctv_dashboard import DashboardManager
        
        dashboard = DashboardManager()
        print("[+] Dashboard manager initialized")
        
        # Test loading results
        results = dashboard.load_results()
        print(f"[+] Loaded {results['total_devices']} devices")
        print(f"[+] Loaded {results['total_vulnerabilities']} vulnerabilities")
        
        # Test statistics
        stats = dashboard.get_statistics()
        print(f"[+] Statistics calculated: {stats['total_devices']} devices")
        
        print("[✓] Dashboard data loading test PASSED")
        return True
        
    except Exception as e:
        print(f"[✗] Dashboard test FAILED: {str(e)}")
        return False


def run_demo():
    """Run complete demo with sample data"""
    print("\n" + "="*70)
    print("DEMO: Complete Workflow Simulation")
    print("="*70)
    
    # Create sample data
    print("\n[*] Creating sample scan data...")
    data = create_sample_data()
    
    # Display summary
    print(f"\n[+] Sample Data Created:")
    print(f"    Total Devices: {data['total_devices']}")
    print(f"    Total Vulnerabilities: {data['total_vulnerabilities']}")
    
    # Breakdown by severity
    severity_count = {}
    for vuln in data['vulnerabilities']:
        sev = vuln['severity']
        severity_count[sev] = severity_count.get(sev, 0) + 1
    
    print(f"\n[+] Vulnerability Breakdown:")
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = severity_count.get(severity, 0)
        if count > 0:
            print(f"    {severity}: {count}")
    
    # Vendor breakdown
    vendor_count = {}
    for device in data['devices']:
        vendor = device['vendor']
        vendor_count[vendor] = vendor_count.get(vendor, 0) + 1
    
    print(f"\n[+] Device Vendor Breakdown:")
    for vendor, count in vendor_count.items():
        print(f"    {vendor}: {count}")
    
    # Show sample devices
    print(f"\n[+] Sample Devices:")
    for device in data['devices'][:3]:
        print(f"    {device['ip']} - {device['vendor']} {device['model']}")
    
    # Show critical vulnerabilities
    print(f"\n[+] Critical Vulnerabilities:")
    critical = [v for v in data['vulnerabilities'] if v['severity'] == 'CRITICAL']
    for vuln in critical:
        print(f"    {vuln['ip']} - {vuln['cve']}: {vuln['description']}")
    
    # Export data
    with open("cctv_scan_results.json", 'w') as f:
        json.dump(data, f, indent=2)
    print(f"\n[+] Data exported to: cctv_scan_results.json")
    
    # Generate recommendations
    print(f"\n[+] Security Recommendations:")
    print(f"    1. Update all Hikvision devices to latest firmware")
    print(f"    2. Change all default credentials immediately")
    print(f"    3. Implement network segmentation for cameras")
    print(f"    4. Close unnecessary ports (23, 21, 37777)")
    print(f"    5. Enable authentication logging and monitoring")
    
    print(f"\n[✓] Demo completed successfully!")


def main():
    """Main test runner"""
    print("""
    ╔══════════════════════════════════════════════════════════════════╗
    ║     CCTV Vulnerability Assessment Framework - Test Suite        ║
    ╚══════════════════════════════════════════════════════════════════╝
    """)
    
    print("\nStarting test suite...\n")
    
    results = []
    
    # Run tests
    results.append(("Scanner Module", test_scanner()))
    results.append(("ML Model Module", test_ml_model()))
    results.append(("Data Export", test_data_export()))
    results.append(("Dashboard Data", test_dashboard_data()))
    
    # Run demo
    run_demo()
    
    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASSED" if result else "✗ FAILED"
        print(f"{test_name}: {status}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n[✓] All tests PASSED! Framework is ready to use.")
        print("\nNext steps:")
        print("1. Run: python cctv_integrated_app.py --scan <target>")
        print("2. Or start dashboard: python cctv_integrated_app.py --dashboard")
    else:
        print("\n[!] Some tests FAILED. Please check error messages above.")
        print("Make sure all dependencies are installed: pip install -r requirements.txt")


if __name__ == "__main__":
    main()