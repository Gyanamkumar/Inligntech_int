# Personal Firewall Monitor

## Overview

This project is a real-time network packet sniffer and firewall analyzer that monitors incoming and outgoing network traffic. It applies configurable firewall rules (allow/block by protocol and port) and logs traffic to files. The tool identifies and alerts on watched IP addresses in real-time, making it useful for network security monitoring and threat detection.

### Key Features

- **Real-time packet sniffing** on both Windows and Linux platforms
- **Protocol and port-based filtering** with allow/block rules (TCP, UDP)
- **Firewall rule management**:
  - Windows: Uses `netsh advfirewall` for Windows Firewall integration
  - Linux: Uses `iptables` for kernel-level firewall rules
- **Dual logging system**:
  - `firewall_log.txt` – logs all blocked traffic (source → destination)
  - `suspicious_log.txt` – detailed logs including ALERT notifications for watched IPs
- **IP-based threat detection**: Configurable list of watched IPs that trigger real-time alerts
- **Cross-platform support**: Runs on Windows (with admin privileges) and Linux
- **L3 socket fallback**: Automatically falls back to Layer-3 sniffing on Windows if Npcap is unavailable

## Project Structure

```
Project-Personal-firewall/
├── Firewall_python_code.py    # Main application
├── requirements.txt             # Python dependencies
├── README.md                    # This file
├── firewall_log.txt            # Traffic log (generated at runtime)
└── suspicious_log.txt          # Alert/suspicious activity log (generated at runtime)
```

## Requirements

- **Python 3.7+**
- **Scapy 2.6.1+** – for packet sniffing and manipulation
- **Administrator/Sudo privileges** – required to sniff packets and manage firewall rules
- **Npcap (Windows)** – optional but recommended for Layer-2 sniffing on Windows
  - Download: [https://nmap.org/npcap/](https://nmap.org/npcap/)

### Installation

1. Create a virtual environment:
   ```powershell
   python -m venv venv
   ```

2. Activate the virtual environment:
   - **Windows**: `.\venv\Scripts\Activate.ps1`
   - **Linux**: `source venv/bin/activate`

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. (Optional on Windows) Install Npcap for full Layer-2 packet capture

## Configuration

Edit `WATCHED_IPS` in `Firewall_python_code.py` to monitor specific IP addresses:

```python
WATCHED_IPS = {
    '192.168.1.100',
    '192.168.1.101',
    # Add more IPs to monitor
}
```

Edit the `rules` list to customize firewall behavior:

```python
rules = [
    {"protocol": "tcp", "port": 80, "action": "allow"},    # Allow HTTP
    {"protocol": "tcp", "port": 22, "action": "block"},    # Block SSH
    {"protocol": "udp", "port": 53, "action": "allow"},    # Allow DNS
]
```

## Usage

### Windows

Run with Administrator privileges:

```powershell
# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Run the script
python .\Firewall_python_code.py
```

### Linux

Run with sudo:

```bash
# Activate virtual environment
source venv/bin/activate

# Run the script
sudo python ./Firewall_python_code.py
```

### Output

The script displays real-time packet summaries:

```
[+] Applying Windows firewall rules...
[+] Windows firewall rules applied successfully.

[+] Starting packet monitoring... Press Ctrl+C to stop.

Ether / IP / TCP 192.168.1.50:54321 > 8.8.8.8:53 S
Ether / IP / UDP 192.168.1.51:12345 > 8.8.4.4:53 A
...
```

### Log Files

**firewall_log.txt** – Compact traffic log:
```
192.168.1.50 -> 8.8.8.8 | BLOCKED
192.168.1.51 -> 1.1.1.1 | BLOCKED
```

**suspicious_log.txt** – Detailed alerts:
```
ALERT! Watched IP 192.168.1.100 seen at 2025-11-30T15:42:30.123456Z
[2025-11-30T15:42:31.234567Z] reason=watched_ip_blocked src=192.168.1.100 dst=8.8.8.8 proto=tcp sport=54321 dport=22 summary=...
```

## How It Works

1. **Initialization**: 
   - Checks for admin/sudo privileges
   - Applies configured firewall rules to the system
   
2. **Packet Capture**:
   - Sniffs all packets on the default network interface
   - Uses Layer-2 sockets (with Npcap on Windows) or falls back to Layer-3
   
3. **Real-time Analysis**:
   - For each packet: checks if source/destination IP is in `WATCHED_IPS`
   - Writes instant ALERT to `suspicious_log.txt` if a watched IP is detected
   
4. **Rule Matching**:
   - Evaluates packets against configured rules
   - Logs blocked traffic to `firewall_log.txt`
   - Writes detailed info to `suspicious_log.txt` for blocked watched IPs

5. **Graceful Shutdown**:
   - Press `Ctrl+C` to stop monitoring
   - Closes all file handles and network sockets cleanly

## Platform-Specific Notes

### Windows

- Requires **Administrator privileges** to run
- Uses `netsh advfirewall` to configure Windows Firewall
- Supports both Layer-2 (with Npcap) and Layer-3 sniffing
- If Npcap is not installed, automatically falls back to L3 sniffing

### Linux

- Requires **sudo** to run
- Uses `iptables` to configure kernel firewall
- Supports standard Layer-2 packet sniffing via libpcap

## Troubleshooting

### "Sniffing and sending packets is not available at layer 2: winpcap is not installed"

**Solution**: Install Npcap or accept Layer-3 fallback (script will retry automatically)

### "This script requires administrator privileges"

**Solution**: 
- **Windows**: Run PowerShell as Administrator
- **Linux**: Use `sudo python ./Firewall_python_code.py`

### No packets are being captured

**Solution**:
- Verify admin/sudo privileges
- Check that the network interface is active
- Try generating traffic (e.g., ping, web browsing) in another terminal

## Future Enhancements

- Add IP blocking at OS level (Windows/Linux)
- Implement packet filtering by IP subnet ranges
- Add GeoIP lookup for flagged IPs
- Dashboard/web UI for live monitoring
- Export logs to CSV/JSON format
- Email/SMS alerts for critical events

## License

This project is for educational and authorized network security testing purposes only.

## Tools Used

- **Scapy** – Packet sniffing and manipulation
- **Python 3** – Core language
- **Windows Firewall (netsh)** – Firewall management on Windows
- **iptables** – Firewall management on Linux
- **Pathlib** – Cross-platform file path handling

