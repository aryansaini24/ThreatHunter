# ThreatHunter

An advanced threat hunting platform leveraging machine learning and behavioral analysis to detect sophisticated threats in network traffic. Features integration with multiple SIEM solutions, real-time alerting, and automated incident response playbooks.

## Features

- **ML-based anomaly detection** using Scikit-learn's Isolation Forest algorithm
- **SIEM integration** with mock SIEM function for security event logging
- **Automated incident response** with severity-based playbooks
- **Network traffic analysis** with comprehensive anomaly scoring
- **Real-time threat detection** with triggered alert simulation
- **Detailed security reporting** and threat classification

## Python Prototype

The repository includes a complete Python-based threat detection prototype with the following components:

### Files

1. **`threathunter.py`** - Main threat detection script
   - Implements anomaly detection using scikit-learn's Isolation Forest
   - Includes mock SIEM integration for event logging
   - Features automated incident response system
   - Provides threat analysis and severity classification

2. **`network_data.csv`** - Sample network traffic dataset
   - 100 network traffic records with multiple features
   - Includes normal traffic patterns and anomalous behavior
   - Contains source/destination IPs, protocols, bytes, packets, duration, and connection counts
   - Pre-seeded with realistic anomalies for detection testing

## Installation

### Prerequisites

Ensure you have Python 3.7+ installed on your system.

### Install Required Dependencies

```bash
pip install pandas numpy scikit-learn
```

Or install from requirements:

```bash
pip install -r requirements.txt
```

### Quick Start

1. Clone the repository:
```bash
git clone https://github.com/aryansaini24/ThreatHunter.git
cd ThreatHunter
```

2. Install dependencies:
```bash
pip install pandas numpy scikit-learn
```

3. Run the threat hunter:
```bash
python threathunter.py
```

## Usage

### Basic Usage

Simply run the script to analyze the sample network data:

```bash
python threathunter.py
```

The script will:
1. Load network traffic data from `network_data.csv`
2. Train the anomaly detection model on the data
3. Detect threats and anomalies in network traffic
4. Classify threats by severity (high, medium, low)
5. Trigger automated incident response for each threat
6. Log all events to the mock SIEM system
7. Generate a comprehensive security report

### Understanding the Output

The script provides detailed output including:

- **Data Loading**: Confirmation of loaded records
- **Model Training**: Feature list and training completion status
- **Threat Detection Summary**: Total records analyzed and threats detected
- **Individual Threat Details**: For each detected threat:
  - Source and destination IP addresses
  - Protocol type
  - Anomaly score (lower = more anomalous)
  - Severity classification (high/medium/low)
- **Automated Incident Response**: Actions taken for each threat based on severity
- **Security Report**: Overall statistics and alert distribution

### Example Output

```
╔════════════════════════════════════════════════════════╗
║           🛡️  THREATHUNTER v1.0                       ║
║     Advanced Threat Detection & Response System       ║
╚════════════════════════════════════════════════════════╝

📁 Loading network traffic data...
✅ Loaded 100 network traffic records

📊 Data Summary:
   Columns: source_ip, dest_ip, protocol, bytes_sent, ...
   Records: 100

🔧 Training anomaly detection model...
   Features: bytes_sent, bytes_received, packets_sent, ...
✅ Model training complete!

🔍 Scanning for threats...

⚠️ THREAT DETECTION SUMMARY
============================================================
Total records analyzed: 100
Threats detected: 15 (15.00%)
============================================================

🔍 THREAT #11
   Source IP: 192.168.1.110
   Destination IP: 203.0.113.50
   Protocol: TCP
   Anomaly Score: -0.5234
   Severity: HIGH

============================================================
🎯 AUTOMATED INCIDENT RESPONSE TRIGGERED
============================================================
  🚨 CRITICAL ALERT: Isolating affected systems
  🔒 Blocking suspicious IP addresses
  📧 Notifying security team immediately
  📊 Initiating forensic data collection
  🛡️ Activating emergency response protocol
============================================================
```

### Customizing the Detection

You can customize the threat detection by modifying the `ThreatHunter` class initialization:

```python
# Adjust contamination parameter (expected proportion of anomalies)
hunter = ThreatHunter(contamination=0.15)  # Default: 15% expected anomalies
```

### Using Your Own Data

To analyze your own network traffic data:

1. Prepare a CSV file with the following columns:
   - `source_ip`: Source IP address
   - `dest_ip`: Destination IP address
   - `protocol`: Protocol type (TCP, UDP, HTTP, HTTPS, etc.)
   - `bytes_sent`: Number of bytes sent
   - `bytes_received`: Number of bytes received
   - `packets_sent`: Number of packets sent
   - `packets_received`: Number of packets received
   - `duration`: Connection duration in seconds
   - `connection_count`: Number of connections

2. Update the filename in `threathunter.py`:

```python
data = hunter.load_data('your_network_data.csv')
```

3. Run the script as usual

## Architecture

### Components

#### 1. ThreatHunter Class
Main threat detection engine that:
- Loads and preprocesses network traffic data
- Trains machine learning model using Isolation Forest
- Detects anomalies and classifies threats by severity
- Analyzes threats and generates reports

#### 2. MockSIEM Class
Simulated SIEM integration that:
- Logs security events with timestamps
- Stores event details and severity levels
- Provides alert retrieval functionality

#### 3. IncidentResponder Class
Automated incident response system that:
- Categorizes threats by severity (high, medium, low)
- Executes appropriate response actions
- Logs all responses to SIEM
- Provides security team notifications

### Machine Learning Model

The system uses **Isolation Forest** algorithm for anomaly detection:
- **Algorithm**: Isolation Forest (ensemble method)
- **Library**: scikit-learn
- **Features**: Network traffic metrics (bytes, packets, duration, connections)
- **Output**: Anomaly scores and binary classifications
- **Advantages**: 
  - Effective for high-dimensional data
  - Low computational complexity
  - No assumptions about data distribution
  - Works well with imbalanced datasets

### Severity Classification

Threats are automatically classified based on anomaly scores:
- **High Severity**: Anomaly score < -0.5 (Critical response)
- **Medium Severity**: -0.5 ≤ Anomaly score < -0.2 (Elevated response)
- **Low Severity**: Anomaly score ≥ -0.2 (Standard response)

## Automated Incident Response

The system triggers automated responses based on threat severity:

### High Severity Responses
- 🚨 Isolate affected systems
- 🔒 Block suspicious IP addresses
- 📧 Notify security team immediately
- 📊 Initiate forensic data collection
- 🛡️ Activate emergency response protocol

### Medium Severity Responses
- ⚠️ Monitor affected systems
- 🔍 Increase logging verbosity
- 📋 Create incident ticket
- 👥 Alert on-call security analyst

### Low Severity Responses
- ℹ️ Log anomaly
- 📝 Document event details
- 📊 Add to monitoring dashboard

## Network Data Sample

The `network_data.csv` file includes:
- **100 network traffic records**
- **Normal traffic patterns**: Typical internal network communications
- **Anomalous traffic**: 
  - Unusual data volumes (e.g., record #11: 52,000 bytes sent)
  - Excessive connection counts (e.g., record #30: 100 connections)
  - Extended durations (e.g., record #50: 9,600 seconds)
  - Suspicious external IPs

## Future Enhancements

- [ ] Integration with real SIEM platforms (Splunk, ELK, QRadar)
- [ ] Deep learning models for advanced threat detection
- [ ] Real-time network traffic capture and analysis
- [ ] Threat intelligence feed integration
- [ ] Dashboard and visualization interface
- [ ] Multi-protocol support (DNS, SMB, RDP)
- [ ] Behavioral baselining and drift detection
- [ ] Automated remediation capabilities

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This is a prototype/educational tool. For production use, please ensure proper testing, validation, and integration with your organization's security policies and infrastructure.

## Contact

For questions or support, please open an issue on GitHub.

---

**ThreatHunter** - Advanced Threat Detection Made Simple 🛡️
