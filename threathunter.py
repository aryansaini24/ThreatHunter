#!/usr/bin/env python3
"""
ThreatHunter - Advanced Threat Detection System
Python-based threat detection using scikit-learn for anomaly detection
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from datetime import datetime
import json
import warnings
warnings.filterwarnings('ignore')


class MockSIEM:
    """Mock SIEM function to simulate integration with Security Information and Event Management system"""
    
    def __init__(self):
        self.alerts = []
        
    def log_event(self, event_data):
        """Log security event to SIEM"""
        event = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'event_type': event_data.get('type', 'unknown'),
            'severity': event_data.get('severity', 'medium'),
            'details': event_data.get('details', {})
        }
        self.alerts.append(event)
        print(f"[SIEM] Event logged: {event['event_type']} - Severity: {event['severity']}")
        return event
    
    def get_alerts(self):
        """Retrieve all logged alerts"""
        return self.alerts


class IncidentResponder:
    """Automated incident response system"""
    
    def __init__(self, siem):
        self.siem = siem
        self.response_actions = {
            'high': self._critical_response,
            'medium': self._elevated_response,
            'low': self._standard_response
        }
    
    def _critical_response(self, threat_data):
        """Critical threat response actions"""
        actions = [
            "🚨 CRITICAL ALERT: Isolating affected systems",
            "🔒 Blocking suspicious IP addresses",
            "📧 Notifying security team immediately",
            "📊 Initiating forensic data collection",
            "🛡️ Activating emergency response protocol"
        ]
        return actions
    
    def _elevated_response(self, threat_data):
        """Elevated threat response actions"""
        actions = [
            "⚠️ ELEVATED ALERT: Monitoring affected systems",
            "🔍 Increasing logging verbosity",
            "📋 Creating incident ticket",
            "👥 Alerting on-call security analyst"
        ]
        return actions
    
    def _standard_response(self, threat_data):
        """Standard threat response actions"""
        actions = [
            "ℹ️ STANDARD ALERT: Logging anomaly",
            "📝 Documenting event details",
            "📊 Adding to monitoring dashboard"
        ]
        return actions
    
    def respond_to_threat(self, threat_data, severity):
        """Trigger automated response based on threat severity"""
        print(f"\n{'='*60}")
        print(f"🎯 AUTOMATED INCIDENT RESPONSE TRIGGERED")
        print(f"{'='*60}")
        
        response_function = self.response_actions.get(severity, self._standard_response)
        actions = response_function(threat_data)
        
        for action in actions:
            print(f"  {action}")
        
        # Log to SIEM
        self.siem.log_event({
            'type': 'incident_response',
            'severity': severity,
            'details': {
                'threat_data': threat_data,
                'actions_taken': actions
            }
        })
        
        print(f"{'='*60}\n")
        return actions


class ThreatHunter:
    """Main threat detection and hunting system"""
    
    def __init__(self, contamination=0.1):
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.siem = MockSIEM()
        self.incident_responder = IncidentResponder(self.siem)
        self.is_trained = False
        
    def load_data(self, filepath):
        """Load network traffic data from CSV file"""
        try:
            data = pd.read_csv(filepath)
            print(f"✅ Loaded {len(data)} network traffic records")
            return data
        except Exception as e:
            print(f"❌ Error loading data: {e}")
            return None
    
    def preprocess_data(self, data):
        """Preprocess network traffic data for anomaly detection"""
        # Select numerical features for anomaly detection
        feature_columns = ['bytes_sent', 'bytes_received', 'packets_sent', 
                          'packets_received', 'duration', 'connection_count']
        
        # Check if all required columns exist
        missing_cols = [col for col in feature_columns if col not in data.columns]
        if missing_cols:
            print(f"⚠️ Warning: Missing columns {missing_cols}")
            feature_columns = [col for col in feature_columns if col in data.columns]
        
        X = data[feature_columns].copy()
        
        # Handle missing values
        X = X.fillna(X.mean())
        
        return X, feature_columns
    
    def train(self, data):
        """Train the anomaly detection model"""
        X, features = self.preprocess_data(data)
        
        print(f"\n🔧 Training anomaly detection model...")
        print(f"   Features: {', '.join(features)}")
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Isolation Forest
        self.model.fit(X_scaled)
        self.is_trained = True
        
        print(f"✅ Model training complete!\n")
    
    def detect_threats(self, data):
        """Detect anomalies/threats in network traffic"""
        if not self.is_trained:
            print("❌ Model not trained yet. Please train the model first.")
            return None
        
        X, features = self.preprocess_data(data)
        X_scaled = self.scaler.transform(X)
        
        # Predict anomalies (-1 for anomaly, 1 for normal)
        predictions = self.model.predict(X_scaled)
        anomaly_scores = self.model.score_samples(X_scaled)
        
        # Add predictions to dataframe
        data['anomaly'] = predictions
        data['anomaly_score'] = anomaly_scores
        data['threat_detected'] = data['anomaly'] == -1
        
        return data
    
    def analyze_threats(self, data):
        """Analyze detected threats and determine severity"""
        threats = data[data['threat_detected']].copy()
        
        if len(threats) == 0:
            print("✅ No threats detected. Network traffic appears normal.")
            return
        
        print(f"\n⚠️ THREAT DETECTION SUMMARY")
        print(f"{'='*60}")
        print(f"Total records analyzed: {len(data)}")
        print(f"Threats detected: {len(threats)} ({len(threats)/len(data)*100:.2f}%)")
        print(f"{'='*60}\n")
        
        # Categorize threats by severity based on anomaly score
        for idx, threat in threats.iterrows():
            score = threat['anomaly_score']
            
            # Determine severity based on anomaly score
            if score < -0.5:
                severity = 'high'
            elif score < -0.2:
                severity = 'medium'
            else:
                severity = 'low'
            
            print(f"\n🔍 THREAT #{idx + 1}")
            print(f"   Source IP: {threat.get('source_ip', 'N/A')}")
            print(f"   Destination IP: {threat.get('dest_ip', 'N/A')}")
            print(f"   Protocol: {threat.get('protocol', 'N/A')}")
            print(f"   Anomaly Score: {score:.4f}")
            print(f"   Severity: {severity.upper()}")
            
            # Log to SIEM
            self.siem.log_event({
                'type': 'threat_detected',
                'severity': severity,
                'details': threat.to_dict()
            })
            
            # Trigger automated incident response
            self.incident_responder.respond_to_threat(threat.to_dict(), severity)
    
    def generate_report(self):
        """Generate security report from SIEM alerts"""
        alerts = self.siem.get_alerts()
        
        if not alerts:
            print("No alerts to report.")
            return
        
        print(f"\n📊 SECURITY REPORT")
        print(f"{'='*60}")
        print(f"Total alerts: {len(alerts)}")
        print(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")
        
        # Count alerts by severity
        severity_counts = {}
        for alert in alerts:
            severity = alert['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print("Alert Distribution by Severity:")
        for severity, count in sorted(severity_counts.items()):
            print(f"  {severity.upper()}: {count}")
        
        print(f"\n{'='*60}\n")


def main():
    """Main execution function"""
    print("""   
    ╔════════════════════════════════════════════════════════╗
    ║           🛡️  THREATHUNTER v1.0                       ║
    ║     Advanced Threat Detection & Response System       ║
    ╚════════════════════════════════════════════════════════╝
    """)
    
    # Initialize ThreatHunter
    hunter = ThreatHunter(contamination=0.15)
    
    # Load network traffic data
    print("📁 Loading network traffic data...")
    data = hunter.load_data('network_data.csv')
    
    if data is None:
        print("❌ Failed to load data. Exiting.")
        return
    
    # Display data summary
    print(f"\n📊 Data Summary:")
    print(f"   Columns: {', '.join(data.columns.tolist())}")
    print(f"   Records: {len(data)}")
    
    # Train the model
    hunter.train(data)
    
    # Detect threats
    print("🔍 Scanning for threats...\n")
    results = hunter.detect_threats(data)
    
    if results is not None:
        # Analyze and respond to threats
        hunter.analyze_threats(results)
        
        # Generate final report
        hunter.generate_report()
        
        print("✅ Threat hunting session complete!")


if __name__ == "__main__":
    main()
