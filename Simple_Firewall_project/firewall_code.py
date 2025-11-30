# download npcap from https://nmap.org/npcap/ giving administrative privileges
# '''
#->To run this, go to powershell with administrative privilege
#-> navigate to the directory where program is stored 
#-> run "python firewall_code.py"
# '''

import os
import platform
from scapy.all import sniff, IP, TCP, UDP
from scapy.config import conf
from scapy.interfaces import resolve_iface
from pathlib import Path

# Place log files next to this script (Project-Personal-firewall folder)
BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "firewall_log.txt"
SUSPICIOUS_LOG = BASE_DIR / "suspicious_log.txt"

# IPs to watch for; when seen in blocked packets they are logged to SUSPICIOUS_LOG
WATCHED_IPS = {'192.128.13.91' , '192.168.11.144','192.168.13.52','192.168.9.77','192.168.14.237','192.168.14','192.168.100.1','192.168.100.77'
    # Example: "192.0.2.10",
}

# The ALERTED_IPS set was removed to log every occurrence of a watched IP.


rules = [
    {"protocol": "tcp", "port": 80, "action": "allow"},   # Allow HTTP
    {"protocol": "tcp", "port": 22, "action": "block"},   # Block SSH
    {"protocol": "udp", "port": 53, "action": "allow"},   # Allow DNS
]


def apply_rules_windows():
    """Applies firewall rules on Windows using netsh."""
    print("[+] Applying Windows firewall rules...")
    for rule in rules:
        rule_name = f"MyFirewall_{rule['protocol'].upper()}_{rule['port']}"
        os.system(f'netsh advfirewall firewall delete rule name="{rule_name}" > nul 2>&1') # Cleanup old rule
        command = (
            f"netsh advfirewall firewall add rule name=\"{rule_name}\" "
            f"dir=in action={rule['action']} protocol={rule['protocol'].upper()} localport={rule['port']}"
        )
        os.system(command + ' > nul 2>&1')
    print("[+] Windows firewall rules applied successfully.\n")


def apply_rules_linux():
    """Applies firewall rules on Linux using iptables."""
    os.system("sudo iptables -F")  # Flush all old rules
    for rule in rules:
        proto = rule["protocol"]
        port = rule["port"]
        action = rule["action"]
        iptables_action = "ACCEPT" if action == "allow" else "DROP"
        os.system(f"sudo iptables -A INPUT -p {proto} --dport {port} -j {iptables_action}")
    print("[+] Firewall rules applied successfully.\n")


logged_packets = set()

def log_packet(packet, status):
    key = (packet[IP].src, packet[IP].dst, status)
    if key not in logged_packets:
        try:
            with open(str(LOG_FILE), "a", encoding="utf-8") as f:
                f.write(f"{packet[IP].src} -> {packet[IP].dst} | {status}\n")
        except Exception:
            pass
        logged_packets.add(key)

from datetime import datetime

def log_suspicious(packet, reason="watched_ip"):
    """Append detailed info about a suspicious packet to `SUSPICIOUS_LOG`.

    The function logs timestamp, src, dst, protocol, ports and a short summary.
    """
    try:
        # Correctly get the source and destination IP from the IP layer
        if IP not in packet:
            return
        src = packet[IP].src
        dst = packet[IP].dst
    except Exception:
        return

    proto = "tcp" if TCP in packet else ("udp" if UDP in packet else "other")
    sport = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else "-")
    dport = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else "-")
    timestamp = datetime.utcnow().isoformat() + "Z"
    entry = (
        f"[{timestamp}] reason={reason} src={src} dst={dst} proto={proto} "
        f"sport={sport} dport={dport} summary={packet.summary()}\n"
    )
    try:
        with open(str(SUSPICIOUS_LOG), "a", encoding="utf-8") as f:
            f.write(entry)
    except Exception:
        pass


def monitor_traffic(packet):
    if IP in packet:
        if TCP in packet or UDP in packet:
            dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
            proto = "tcp" if TCP in packet else "udp"

            for rule in rules:
                if rule["protocol"] == proto and rule["port"] == dst_port:
                    if rule["action"] == "block":
                        log_packet(packet, "BLOCKED")
                        # If either endpoint is a watched IP, create a detailed suspicious log
                        try:
                            src_ip = packet[IP].src
                            dst_ip = packet[IP].dst
                            if src_ip in WATCHED_IPS or dst_ip in WATCHED_IPS:
                                log_suspicious(packet, reason="watched_ip_blocked")
                        except Exception:
                            pass
                    # Skip logging allowed packets


def _prn_wrapper(packet):
    """Print a short summary (for realtime visibility) then apply rules."""
    try:
        print(packet.summary())
    except Exception:
        pass
    try:
        # First, check for watched IPs in every packet (real-time analysis)
        try:
            flag_ip_if_seen(packet)
        except NameError:
            # function may be defined later; ignore
            pass
        monitor_traffic(packet)
    except Exception:
        pass


def flag_ip_if_seen(packet):
    """Check packet for watched IPs and write an ALERT line to the suspicious log.

    This now logs an alert EVERY time a watched IP is seen.
    """
    try:
        if IP not in packet:
            return
        src = packet[IP].src
        dst = packet[IP].dst
    except Exception:
        return

    now = datetime.utcnow().isoformat() + "Z"

    def _check_and_alert(ip):
        if ip in WATCHED_IPS:
            try:
                with open(str(SUSPICIOUS_LOG), "a", encoding="utf-8") as f:
                    f.write(f"ALERT! Watched IP {ip} seen at {now}\n")
            except Exception:
                pass

    _check_and_alert(src)
    _check_and_alert(dst)


if __name__ == "__main__":
    # On Windows, sniffing requires admin rights.
    if platform.system() == "Windows":
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            is_admin = False

        if not is_admin:
            print("[!] On Windows, this script requires administrator privileges to manage the firewall and capture network traffic.")
            print("    Please re-run this script from a shell with administrator rights.")
            exit()
        
        apply_rules_windows()
    else:
        apply_rules_linux()

    print("[+] Starting packet monitoring... Press Ctrl+C to stop.\n")

    try:
        sniff(prn=_prn_wrapper, store=False)
    except (RuntimeError, OSError) as e:
        print(f"[!] Packet sniffing failed: {e}")
        # Try L3 socket fallback on Windows (no Npcap)
        try:
            if platform.system() == "Windows":
                print("[!] Attempting L3 socket fallback (will capture at layer 3)...")
                iface = resolve_iface(conf.iface)
                l3cls = iface.l3socket(False)
                opened = l3cls(promisc=True, filter=None, iface=iface)
                try:
                    sniff(prn=_prn_wrapper, store=False, opened_socket=opened)
                finally:
                    try:
                        opened.close()
                    except Exception:
                        pass
                exit(0)
        except Exception as ex:
            print(f"[!] L3 fallback failed: {ex}")

        print("\n[!] On Windows, please ensure:")
        print("    1. You are running this script with administrator privileges.")
        print("    2. You have Npcap installed for full functionality (download from https://nmap.org/npcap/).")
        print("[!] Exiting.")

