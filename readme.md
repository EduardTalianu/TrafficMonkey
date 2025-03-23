# Traffic Monkey

![Traffic Monkey Logo](https://github.com/EdwardDali/TrafficMonkey/blob/main/image.jpg)

A comprehensive network traffic analyzer and security monitoring tool for detecting and alerting on suspicious network activity.

## Overview

Traffic Monkey is a Python-based desktop application that captures and analyzes network traffic in real-time. It employs a rule-based detection system to identify potential security threats, unusual network behavior, and suspicious connections. With an intuitive GUI, system tray integration, and desktop notifications, Traffic Monkey provides continuous network monitoring without getting in your way.

## Key Features

- **Live Traffic Capture**: Capture and analyze network packets in real-time using Wireshark's tshark engine
- **Modular Detection Rules**: Extensible rule system for identifying various network threats
- **VirusTotal Integration**: Check suspicious IPs and URLs against VirusTotal's database
- **System Tray Operation**: Run silently in the system tray with notification alerts
- **Persistent Database**: SQLite storage for historical traffic analysis
- **Customizable Settings**: Adjust detection thresholds to match your network environment
- **False Positive Management**: Mark and exclude known good connections from alerts

### Detection Capabilities

- **RDP Connection Monitoring**: Track Remote Desktop Protocol usage
- **Large Data Transfer Detection**: Identify unusually large data flows
- **Suspicious Connection Detection**: Flag connections to known suspicious IP ranges
- **DNS Anomaly Detection**: Identify potential DNS tunneling and DGA domains
- **External High Port Detection**: Monitor connections on non-standard high ports
- **ICMP Flood Protection**: Detect potential ping-based attacks
- **Port Scan Detection**: Identify port scanning activities

## Requirements

- **Python**: Version 3.6 or higher
- **Wireshark/tshark**: Latest stable version recommended
  - Must be added to system PATH for Traffic Monkey to function
- **Operating System**: Windows 10/11, Linux (Ubuntu 18.04+, Debian 10+), macOS 10.15+
- **System Resources**: 
  - Minimum: 4GB RAM, 100MB disk space
  - Recommended: 8GB RAM, 1GB+ disk space for database growth
- **Network Access**: Admin/root privileges for packet capture
- **VirusTotal API Key**: Free tier API key (optional but recommended)

## Installation

### Prerequisites

1. Install Python 3.6+ from [python.org](https://www.python.org/downloads/)
2. Install Wireshark from [wireshark.org](https://www.wireshark.org/download.html)
   - During installation, ensure "Install TShark" option is selected
   - Make sure tshark is added to your system PATH

### Windows Installation

```powershell
# Clone the repository
git clone https://github.com/EdwardDali/TrafficMonkey.git
cd TrafficMonkey

# Create virtual environment (optional but recommended)
python -m venv venv
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Create .env file for VirusTotal API key
echo "VIRUSTOTAL_API_KEY=your_api_key_here" > .env

# Run the application (as Administrator)
python main.py
```

### Linux Installation

```bash
# Install tshark
sudo apt-get update
sudo apt-get install tshark
# Select 'Yes' when asked about allowing non-root users to capture packets

# Clone the repository
git clone https://github.com/EdwardDali/TrafficMonkey.git
cd TrafficMonkey

# Create virtual environment (optional but recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create .env file for VirusTotal API key
echo "VIRUSTOTAL_API_KEY=your_api_key_here" > .env

# Run the application
sudo python main.py
```

### macOS Installation

```bash
# Install tshark via Homebrew
brew install wireshark

# Clone the repository
git clone https://github.com/EdwardDali/TrafficMonkey.git
cd TrafficMonkey

# Create virtual environment (optional but recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create .env file for VirusTotal API key
echo "VIRUSTOTAL_API_KEY=your_api_key_here" > .env

# Run the application
sudo python main.py
```

## Required Python Packages

The following packages are required (included in requirements.txt):
- tkinter
- pillow
- pystray
- plyer
- python-dotenv
- requests
- sqlite3 (standard library)

## Running Traffic Monkey

Traffic Monkey needs elevated privileges to capture network traffic:

- **Windows**: Right-click and select "Run as Administrator"
- **Linux/macOS**: Run with sudo (`sudo python main.py`)

### First-time Setup

1. Launch the application
2. Select a network interface in the "Network Interfaces" tab
3. Click "Start Capture" to begin monitoring
4. Configure detection rules in the "Rules" tab
5. Explore the other tabs to become familiar with the interface

## Architecture

Traffic Monkey consists of several key components:

- **LiveCaptureGUI**: Main application window and user interface
- **TrafficCaptureEngine**: Handles packet capture using tshark
- **RuleLoader**: Dynamically loads detection rules from the rules directory
- **SystemTrayApp**: Manages system tray icon and desktop notifications
- **Rule**: Base class for all detection rules

The application uses a SQLite database to store:
- Connection information (source/destination IPs, ports, bytes transferred)
- Alerts generated by detection rules
- Rule configuration

## Detection Rules System

Traffic Monkey uses a flexible rule-based system for detecting suspicious network activity. Rules are Python classes that inherit from the base `Rule` class.

### Built-in Rules

- **RDPConnectionRule**: Detects Remote Desktop Protocol connections
- **SuspiciousConnectionRule**: Identifies connections to potentially suspicious IP ranges
- **VirusTotalRule**: Checks IPs and URLs against the VirusTotal API
- **DataSizeRule**: Detects unusually large data transfers
- **DNSAnomalyRule**: Identifies DNS tunneling and algorithm-generated domains
- **HighPortConnectionRule**: Monitors connections on non-standard high ports
- **ICMPFloodRule**: Detects potential ping flood attacks
- **PortScanRule**: Identifies port scanning activities

### Creating Custom Rules

Create new rules by adding Python files to the `rules` directory. Each rule must:

1. Inherit from the `Rule` class
2. Implement the `analyze()` method to detect suspicious activity
3. Return a list of alert messages

Example rule structure:

```python
class MyCustomRule(Rule):
    def __init__(self):
        super().__init__(
            name="My Custom Rule",
            description="Detects something suspicious"
        )
        self.threshold = 1000  # Example configuration parameter
        
    def analyze(self, db_cursor):
        alerts = []
        # Query the database and look for suspicious patterns
        # Add alert messages to the alerts list
        return alerts
    
    def get_params(self):
        # Return configurable parameters
        return {
            "threshold": {
                "type": "int",
                "default": 1000,
                "current": self.threshold,
                "description": "Threshold for detection"
            }
        }
    
    def update_param(self, param_name, value):
        # Handle parameter updates
        if param_name == "threshold":
            self.threshold = int(value)
            return True
        return False
```

## Usage Scenarios

### Home Network Monitoring

Monitor your home network for:
- Unauthorized access attempts
- Malware communication with command and control servers
- Unusual data transfers that might indicate compromised devices

### Small Business Security

- Track Remote Desktop Protocol (RDP) usage for compliance
- Monitor for data exfiltration attempts
- Detect network reconnaissance activities like port scanning

### Network Troubleshooting

- Identify bandwidth hogs and unusual traffic patterns
- Track connection statistics to problematic services
- Monitor DNS queries for resolution issues

## Troubleshooting

### Common Issues

#### "tshark not found" error
- Ensure Wireshark is installed with the TShark component
- Verify tshark is in your system PATH:
  - Windows: Open Command Prompt and type `where tshark`
  - Linux/macOS: Open Terminal and type `which tshark`
- If not found, add the directory containing tshark to your PATH

#### Permission errors on startup
- Run the application with administrator/root privileges
- On Linux, ensure the appropriate capabilities are set:
  
```bash
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
```

#### No interfaces showing in the interface list
- Verify you have at least one active network interface
- Run the application with elevated privileges
- Check if Wireshark can detect interfaces when run manually

#### Database errors
- Check if the `db` directory exists and is writable
- If database is corrupted, delete the `traffic_stats.db` file and restart

### Log File Location

Logs are stored in the `logs` directory and can help diagnose issues:
- Windows: `[installation_path]\logs\traffic_analyzer.log`
- Linux/macOS: `[installation_path]/logs/traffic_analyzer.log`

## Acknowledgments

- Wireshark/TShark for packet capture capabilities
- VirusTotal for threat intelligence

