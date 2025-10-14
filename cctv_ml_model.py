"""
Machine Learning Model for CCTV Vulnerability Classification
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
import joblib
import json
from typing import Dict, List

class CCTVVulnerabilityML:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.label_encoder = LabelEncoder()
        self.feature_encoders = {}
        self.trained = False
        
        # Vulnerability to exploitation steps mapping
        self.exploitation_steps = {
            "CVE-2021-36260": [
                "1. Identify Hikvision device version",
                "2. Send crafted HTTP request to bypass authentication",
                "3. Access admin panel without credentials",
                "4. Exploit configuration API endpoints"
            ],
            "CVE-2017-7921": [
                "1. Connect to device on port 80",
                "2. Use backdoor account credentials",
                "3. Access full system privileges",
                "4. Download configuration or video streams"
            ],
            "WEAK-CRED-001": [
                "1. Attempt common default credentials",
                "2. Try admin/admin, admin/12345, etc.",
                "3. Access device management interface",
                "4. Change settings or view camera feeds"
            ],
            "OPEN-PORT-001": [
                "1. Identify open unnecessary ports (Telnet, FTP)",
                "2. Attempt to connect via insecure protocols",
                "3. Exploit weak authentication on these services",
                "4. Gain shell access or file system access"
            ]
        }
        
        # Mitigation recommendations
        self.mitigations = {
            "CVE-2021-36260": [
                "Update firmware to latest version immediately",
                "Implement network segmentation for cameras",
                "Enable firewall rules to restrict access",
                "Monitor authentication logs for anomalies"
            ],
            "CVE-2017-7921": [
                "Update firmware to patched version",
                "Change all default credentials",
                "Disable unused accounts",
                "Implement strong password policy"
            ],
            "WEAK-CRED-001": [
                "Change all default credentials immediately",
                "Implement strong password requirements (12+ chars, complexity)",
                "Enable account lockout after failed attempts",
                "Use multi-factor authentication if available"
            ],
            "OPEN-PORT-001": [
                "Close unnecessary ports (Telnet, FTP)",
                "Use secure alternatives (SSH instead of Telnet)",
                "Implement port-based firewall rules",
                "Regular port scanning and auditing"
            ],
            "DEFAULT": [
                "Regular firmware updates and patch management",
                "Network isolation and VLAN segmentation",
                "Strong authentication mechanisms",
                "Regular security audits and monitoring",
                "Disable unused services and ports"
            ]
        }
    
    def create_training_data(self):
        """Create synthetic training data for the model"""
        data = []
        
        # Generate training samples
        vendors = ["Hikvision", "Dahua", "Axis", "Generic Camera"]
        firmware_ages = ["old", "medium", "recent", "latest"]
        port_configs = ["minimal", "standard", "excessive"]
        auth_types = ["weak", "default", "strong", "mfa"]
        
        for vendor in vendors:
            for fw in firmware_ages:
                for ports in port_configs:
                    for auth in auth_types:
                        # Calculate risk score based on factors
                        risk = 0
                        if vendor in ["Hikvision", "Dahua"]: risk += 2
                        if fw == "old": risk += 3
                        elif fw == "medium": risk += 2
                        if ports == "excessive": risk += 2
                        elif ports == "standard": risk += 1
                        if auth == "weak": risk += 3
                        elif auth == "default": risk += 2
                        
                        # Determine vulnerability class
                        if risk >= 7:
                            vuln_class = "CRITICAL"
                        elif risk >= 5:
                            vuln_class = "HIGH"
                        elif risk >= 3:
                            vuln_class = "MEDIUM"
                        else:
                            vuln_class = "LOW"
                        
                        data.append({
                            "vendor": vendor,
                            "firmware_age": fw,
                            "port_config": ports,
                            "auth_strength": auth,
                            "vulnerability": vuln_class
                        })
        
        return pd.DataFrame(data)
    
    def train_model(self):
        """Train the ML model"""
        print("[*] Generating training data...")
        df = self.create_training_data()
        
        print("[*] Encoding features...")
        # Encode categorical features
        X = df.drop('vulnerability', axis=1)
        y = df['vulnerability']
        
        # Encode each feature
        X_encoded = pd.DataFrame()
        for col in X.columns:
            if col not in self.feature_encoders:
                self.feature_encoders[col] = LabelEncoder()
            X_encoded[col] = self.feature_encoders[col].fit_transform(X[col])
        
        # Encode target
        y_encoded = self.label_encoder.fit_transform(y)
        
        print("[*] Training model...")
        self.model.fit(X_encoded, y_encoded)
        self.trained = True
        
        print("[+] Model trained successfully!")
        print(f"    Classes: {self.label_encoder.classes_}")
        
        # Save model
        self.save_model()
    
    def predict_vulnerability(self, device: Dict) -> Dict:
        """Predict vulnerability level for a device"""
        if not self.trained:
            print("[!] Model not trained. Training now...")
            self.train_model()
        
        # Prepare features
        features = {
            "vendor": device.get("vendor", "Generic Camera"),
            "firmware_age": self._assess_firmware_age(device.get("firmware", "Unknown")),
            "port_config": self._assess_port_config(device.get("ports", [])),
            "auth_strength": self._assess_auth_strength(device)
        }
        
        # Encode features
        X = pd.DataFrame([features])
        X_encoded = pd.DataFrame()
        for col in X.columns:
            if col in self.feature_encoders:
                try:
                    X_encoded[col] = self.feature_encoders[col].transform(X[col])
                except:
                    # Handle unknown categories
                    X_encoded[col] = 0
        
        # Predict
        prediction = self.model.predict(X_encoded)[0]
        prediction_proba = self.model.predict_proba(X_encoded)[0]
        
        vulnerability_level = self.label_encoder.inverse_transform([prediction])[0]
        confidence = max(prediction_proba) * 100
        
        return {
            "vulnerability_level": vulnerability_level,
            "confidence": f"{confidence:.2f}%",
            "features_analyzed": features,
            "risk_factors": self._identify_risk_factors(features)
        }
    
    def _assess_firmware_age(self, firmware: str) -> str:
        """Assess firmware age"""
        if firmware == "Unknown" or firmware == "":
            return "old"
        # Simplified logic - in real scenario, compare with known versions
        return "medium"
    
    def _assess_port_config(self, ports: List) -> str:
        """Assess port configuration"""
        if len(ports) > 5:
            return "excessive"
        elif len(ports) > 2:
            return "standard"
        return "minimal"
    
    def _assess_auth_strength(self, device: Dict) -> str:
        """Assess authentication strength"""
        # Simplified - in real scenario, test actual auth
        return "default"
    
    def _identify_risk_factors(self, features: Dict) -> List[str]:
        """Identify specific risk factors"""
        risks = []
        
        if features["firmware_age"] in ["old", "medium"]:
            risks.append("Outdated firmware version")
        if features["port_config"] == "excessive":
            risks.append("Too many open ports")
        if features["auth_strength"] in ["weak", "default"]:
            risks.append("Weak authentication configuration")
        if features["vendor"] in ["Hikvision", "Dahua"]:
            risks.append("Vendor with known vulnerability history")
        
        return risks
    
    def get_exploitation_steps(self, cve: str) -> List[str]:
        """Get exploitation steps for a CVE"""
        return self.exploitation_steps.get(cve, [
            "1. Identify vulnerability type",
            "2. Research available exploits",
            "3. Test in controlled environment",
            "4. Document findings"
        ])
    
    def get_mitigations(self, cve: str) -> List[str]:
        """Get mitigation recommendations for a CVE"""
        return self.mitigations.get(cve, self.mitigations["DEFAULT"])
    
    def analyze_device(self, device: Dict, vulnerabilities: List[Dict]) -> Dict:
        """Complete analysis of a device with ML prediction"""
        # Get ML prediction
        ml_prediction = self.predict_vulnerability(device)
        
        # Enhance vulnerabilities with exploitation and mitigation info
        enhanced_vulns = []
        for vuln in vulnerabilities:
            cve = vuln.get("cve", "")
            enhanced = vuln.copy()
            enhanced["exploitation_steps"] = self.get_exploitation_steps(cve)
            enhanced["mitigations"] = self.get_mitigations(cve)
            enhanced_vulns.append(enhanced)
        
        return {
            "device": device,
            "ml_prediction": ml_prediction,
            "vulnerabilities": enhanced_vulns,
            "overall_risk_score": self._calculate_risk_score(ml_prediction, enhanced_vulns)
        }
    
    def _calculate_risk_score(self, prediction: Dict, vulns: List) -> str:
        """Calculate overall risk score"""
        severity_map = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        
        ml_score = severity_map.get(prediction["vulnerability_level"], 2)
        vuln_score = sum(severity_map.get(v.get("severity", "MEDIUM"), 2) for v in vulns)
        
        total_score = ml_score + vuln_score
        
        if total_score >= 10:
            return "CRITICAL"
        elif total_score >= 7:
            return "HIGH"
        elif total_score >= 4:
            return "MEDIUM"
        return "LOW"
    
    def save_model(self, filename: str = "cctv_ml_model.pkl"):
        """Save trained model"""
        model_data = {
            "model": self.model,
            "label_encoder": self.label_encoder,
            "feature_encoders": self.feature_encoders
        }
        joblib.dump(model_data, filename)
        print(f"[+] Model saved to {filename}")
    
    def load_model(self, filename: str = "cctv_ml_model.pkl"):
        """Load trained model"""
        try:
            model_data = joblib.load(filename)
            self.model = model_data["model"]
            self.label_encoder = model_data["label_encoder"]
            self.feature_encoders = model_data["feature_encoders"]
            self.trained = True
            print(f"[+] Model loaded from {filename}")
        except:
            print(f"[-] Could not load model from {filename}")


if __name__ == "__main__":
    # Test the ML model
    ml_model = CCTVVulnerabilityML()
    ml_model.train_model()
    
    # Test prediction
    test_device = {
        "ip": "192.168.1.100",
        "vendor": "Hikvision",
        "firmware": "5.4.0",
        "ports": [80, 554, 8000, 23]
    }
    
    prediction = ml_model.predict_vulnerability(test_device)
    print("\n" + "="*60)
    print("ML Vulnerability Prediction Test")
    print("="*60)
    print(f"Device: {test_device['ip']}")
    print(f"Vendor: {test_device['vendor']}")
    print(f"Predicted Vulnerability: {prediction['vulnerability_level']}")
    print(f"Confidence: {prediction['confidence']}")
    print(f"Risk Factors: {', '.join(prediction['risk_factors'])}")