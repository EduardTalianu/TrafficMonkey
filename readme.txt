# Traffic Monkey



A comprehensive network traffic analyzer and security monitoring tool for detecting and alerting on suspicious network activity.

## Overview

Traffic Monkey is a Python-based desktop application that captures and analyzes network traffic in real-time. It employs a rule-based detection system to identify potential security threats, unusual network behavior, and suspicious connections. With an intuitive GUI, system tray integration, and desktop notifications, Traffic Monkey provides continuous network monitoring without getting in your way.

## Key Features

- **Live Traffic Capture**: Capture and analyze network packets in real-time using Wireshark's TShark engine.
- **Modular Detection Rules**: Extensible rule system for identifying various network threats.
- **VirusTotal Integration**: Check suspicious IPs and URLs against VirusTotal's database.
- **System Tray Operation**: Run silently in the system tray with notification alerts.
- **Persistent Database**: SQLite storage for historical traffic analysis.
- **Customizable Settings**: Adjust detection thresholds to match your network environment.
- **False Positive Management**: Mark and exclude known good connections from alerts.

### Detection Capabilities

- **RDP Connection Monitoring**: Track Remote Desktop Protocol usage.
- **Large Data Transfer Detection**: Identify unusually large data flows.
- **Suspicious Connection Detection**: Flag connections to known suspicious IP ranges.
- **DNS Anomaly Detection**: Identify potential DNS tunneling and DGA domains.
- **External High Port Detection**: Monitor connections on non-standard high ports.
- **ICMP Flood Protection**: Detect potential ping-based attacks.
- **Port Scan Detection**: Identify port scanning activities.

## Requirements

- **Python**: Version 3.6 or higher.
- **Wireshark/TShark**: Latest stable version recommended.
  - Must be added to system PATH for Traffic Monkey to function.
- **Operating System**: Windows 10/11, Linux (Ubuntu 18.04+, Debian 10+), macOS 10.15+.
- **System Resources**:
  - Minimum: 4GB RAM, 100MB disk space.
  - Recommended: 8GB RAM, 1GB+ disk space for database growth.
- **Network Access**: Admin/root privileges for packet capture.
- **VirusTotal API Key**: Free tier API key (optional but recommended).

## Installation

### Prerequisites

1. Install Python 3.6+ from [python.org](https://www.python.org/downloads/).
2. Install Wireshark from [wireshark.org](https://www.wireshark.org/download.html).
   - During installation, ensure "Install TShark" option is selected.
   - Make sure TShark is added to your system PATH.

### Windows Installation

```powershell
# Clone the repository
git clone https://github.com/youruser/traffic-monkey.git
cd traffic-monkey

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
# Install TShark
sudo apt-get update
sudo apt-get install tshark

# Clone the repository
git clone https://github.com/youruser/traffic-monkey.git
cd traffic-monkey

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
# Install TShark via Homebrew
brew install wireshark

# Clone the repository
git clone https://github.com/youruser/traffic-monkey.git
cd traffic-monkey

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

The following packages are required (included in `requirements.txt`):

- `tkinter`
- `pillow`
- `pystray`
- `plyer`
- `python-dotenv`
- `requests`
- `sqlite3` (standard library)

## Running Traffic Monkey

Traffic Monkey needs elevated privileges to capture network traffic:

- **Windows**: Right-click and select "Run as Administrator".
- **Linux/macOS**: Run with sudo (`sudo python main.py`).

## Architecture

Traffic Monkey consists of several key components:

- **LiveCaptureGUI**: Main application window and user interface.
- **TrafficCaptureEngine**: Handles packet capture using TShark.
- **RuleLoader**: Dynamically loads detection rules from the rules directory.
- **SystemTrayApp**: Manages system tray icon and desktop notifications.
- **Rule**: Base class for all detection rules.

The application uses an SQLite database to store:

- Connection information (source/destination IPs, ports, bytes transferred).
- Alerts generated by detection rules.
- Rule configuration.

## Troubleshooting

### Common Issues

#### "TShark not found" error

- Ensure Wireshark is installed with the TShark component.
- Verify TShark is in your system PATH:
  - Windows: Open Command Prompt and type `where tshark`.
  - Linux/macOS: Open Terminal and type `which tshark`.

#### Permission errors on startup

- Run the application with administrator/root privileges.
- On Linux, ensure the appropriate capabilities are set:
  ```bash
  sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
  ```

#### No interfaces showing in the interface list

- Verify you have at least one active network interface.
- Run the application with elevated privileges.

#### Database errors

- Check if the `db` directory exists and is writable.
- If the database is corrupted, delete the `traffic_stats.db` file and restart.

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.

## Contributing

Contributions are welcome! Please feel free to submit pull requests, report bugs, or suggest features.

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/new-feature`.
3. Commit your changes: `git commit -am 'Add new feature'`.
4. Push to the branch: `git push origin feature/new-feature`.
5. Submit a pull request.

## Acknowledgments

- Wireshark/TShark for packet capture capabilities.
- VirusTotal for threat intelligence.
- All contributors and testers.

