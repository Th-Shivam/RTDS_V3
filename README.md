# RTDS - Real-Time Defense System

A comprehensive security monitoring system with network intrusion detection and file monitoring capabilities.

## Features

- **Network Monitoring**: DDoS detection, SYN flood detection, ARP spoofing detection
- **File Monitoring**: Real-time file scanning with VirusTotal integration
- **Web Dashboard**: Real-time monitoring dashboard with live updates
- **Threat Detection**: Automated malware detection and quarantine

## Setup

1. **Install Dependencies**:
   ```bash
   pip3 install -r requirements.txt
   ```

2. **Configure VirusTotal API** (Optional for file monitoring):
   - Get API key from https://www.virustotal.com/gui/join
   - Add to `.env` file:
     ```
     VIRUSTOTAL_API_KEY=your_api_key_here
     ```

## Usage

### Option 1: Easy Startup (Recommended)
```bash
python3 start_rtds.py
```

### Option 2: Individual Components

**Web Dashboard Only**:
```bash
python3 app.py
```

**Network Monitor Only** (requires root):
```bash
sudo python3 rtds_monitor.py --iface eth0
```

## Dashboard

Access the web dashboard at: http://localhost:5000

## Network Interfaces

Common network interfaces:
- `eth0` - Ethernet
- `wlan0` - WiFi
- `lo` - Loopback

Check available interfaces:
```bash
ip link show
```

## File Monitoring

When prompted, enter a directory path to monitor (e.g., `/home/user/Downloads`).
Files will be automatically scanned for malware using VirusTotal.

## Troubleshooting

1. **Permission Issues**: Run network monitoring with `sudo`
2. **Missing Packages**: Run `pip3 install -r requirements.txt`
3. **Interface Not Found**: Check available interfaces with `ip link show`

## Files

- `app.py` - Web dashboard server
- `rtds_monitor.py` - Network monitoring system
- `start_rtds.py` - Easy startup script
- `templates/dashboard.html` - Dashboard UI
- `.env` - Configuration file
