import time
import os
import argparse
import threading
import hashlib
import requests
from collections import OrderedDict, defaultdict
from dotenv import load_dotenv
from scapy.all import sniff, get_if_addr, get_if_list
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Load environment variables
load_dotenv()

# --- Configuration Constants ---
MAX_ARP_ENTRIES = 1000  # Maximum number of entries to store in the ARP cache.

class FileMonitorHandler(FileSystemEventHandler):
    """
    Handler for file system events to detect new files and scan them for malware.
    """
    
    def __init__(self, api_key: str, log_callback, quarantine_dir: str = None, auto_delete: bool = True):
        self.api_key = api_key
        self.log_callback = log_callback
        self.quarantine_dir = quarantine_dir
        self.auto_delete = auto_delete
        
        # Create quarantine directory if specified
        if self.quarantine_dir and not os.path.exists(self.quarantine_dir):
            try:
                os.makedirs(self.quarantine_dir)
                print(f"[*] Created quarantine directory: {self.quarantine_dir}")
            except Exception as e:
                print(f"[!] Failed to create quarantine directory: {e}")
                self.quarantine_dir = None
    
    def scan_file_with_virustotal(self, file_path):
        """
        Scans a file with VirusTotal API for malware detection.
        
        Args:
            file_path: Path to the file to be scanned
        """
        try:
            # Calculate SHA-256 hash of the file
            with open(file_path, 'rb') as f:
                sha256 = hashlib.sha256(f.read()).hexdigest()
            
            # Check with VirusTotal API
            url = f"https://www.virustotal.com/api/v3/files/{sha256}"
            headers = {"x-apikey": self.api_key}
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                # Parse the result
                malicious_count = data['data']['attributes']['last_analysis_stats']['malicious']
                suspicious_count = data['data']['attributes']['last_analysis_stats']['suspicious']
                
                if malicious_count > 0:
                    alert_msg = f"🦠 MALWARE DETECTED: {file_path} - Malicious detections: {malicious_count}"
                    print(f"\033[91m{alert_msg}\033[0m")
                    self.log_callback(alert_msg, "MALWARE")
                    
                    # Automatically delete malicious file
                    self.quarantine_malicious_file(file_path)
                elif suspicious_count > 0:
                    alert_msg = f"⚠️ SUSPICIOUS FILE: {file_path} - Suspicious detections: {suspicious_count}"
                    print(f"\033[93m{alert_msg}\033[0m")
                    self.log_callback(alert_msg, "SUSPICIOUS")
                else:
                    print(f"\033[92m✅ File is clean: {file_path}\033[0m")
            elif response.status_code == 404:
                # File not found in VirusTotal database
                alert_msg = f"📁 NEW FILE: {file_path} - Not in VirusTotal database (uploading for analysis)"
                print(f"\033[96m{alert_msg}\033[0m")
                self.log_callback(alert_msg, "NEW_FILE")
                # Optionally upload file for analysis here
            else:
                error_msg = f"❌ Error checking file on VirusTotal: {response.status_code} - {response.text}"
                print(f"\033[91m{error_msg}\033[0m")
                self.log_callback(error_msg, "VT_ERROR")
                
        except FileNotFoundError:
            print(f"[!] File not found: {file_path}")
        except Exception as e:
            error_msg = f"❌ Error scanning file {file_path}: {e}"
            print(f"\033[91m{error_msg}\033[0m")
            self.log_callback(error_msg, "SCAN_ERROR")
    
    def quarantine_malicious_file(self, file_path):
        """
        Quarantines or deletes a malicious file based on configuration.
        
        Args:
            file_path: Path to the malicious file
        """
        try:
            if not os.path.exists(file_path):
                print(f"[!] File no longer exists: {file_path}")
                return
            
            if self.quarantine_dir:
                # Move file to quarantine directory
                file_name = os.path.basename(file_path)
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                quarantine_path = os.path.join(self.quarantine_dir, f"{timestamp}_{file_name}")
                
                # Ensure unique filename in quarantine
                counter = 1
                original_quarantine_path = quarantine_path
                while os.path.exists(quarantine_path):
                    name, ext = os.path.splitext(original_quarantine_path)
                    quarantine_path = f"{name}_{counter}{ext}"
                    counter += 1
                
                # Move file to quarantine
                import shutil
                shutil.move(file_path, quarantine_path)
                
                quarantine_msg = f"🔒 QUARANTINED: {file_path} → {quarantine_path}"
                print(f"\033[95m{quarantine_msg}\033[0m")
                self.log_callback(quarantine_msg, "QUARANTINED")
                
            elif self.auto_delete:
                # Delete the malicious file
                os.remove(file_path)
                
                delete_msg = f"🗑️ DELETED: Malicious file removed - {file_path}"
                print(f"\033[95m{delete_msg}\033[0m")
                self.log_callback(delete_msg, "DELETED")
                
            else:
                # Just log but don't take action
                warning_msg = f"⚠️ MALWARE FOUND BUT NOT REMOVED: {file_path} (auto-delete disabled)"
                print(f"\033[93m{warning_msg}\033[0m")
                self.log_callback(warning_msg, "MALWARE_IGNORED")
                
        except PermissionError:
            error_msg = f"❌ PERMISSION DENIED: Cannot remove {file_path} (file in use or insufficient permissions)"
            print(f"\033[91m{error_msg}\033[0m")
            self.log_callback(error_msg, "DELETE_FAILED")
            
        except Exception as e:
            error_msg = f"❌ ERROR REMOVING FILE: {file_path} - {e}"
            print(f"\033[91m{error_msg}\033[0m")
            self.log_callback(error_msg, "DELETE_ERROR")
    
    def on_created(self, event):
        """
        Triggered when a new file is created.
        """
        if not event.is_directory:
            print(f"\033[96m📄 New file detected: {event.src_path}\033[0m")
            # Add small delay to ensure file is fully written
            time.sleep(0.5)
            self.scan_file_with_virustotal(event.src_path)
    
    def on_modified(self, event):
        """
        Triggered when a file is modified.
        """
        if not event.is_directory:
            print(f"\033[96m📝 File modified: {event.src_path}\033[0m")
            time.sleep(0.5)
            self.scan_file_with_virustotal(event.src_path)

class IntegratedRTDSMonitor:
    """
    A comprehensive threat detection system that monitors both network traffic and file system activities.
    """
    
    def __init__(self, iface: str, ddos_threshold: int, syn_threshold: int, 
                 log_file: str, monitor_path: str = None, virustotal_api_key: str = None,
                 quarantine_dir: str = None, auto_delete: bool = True):
        """
        Initializes the integrated monitor with user-defined settings.

        Args:
            iface: The network interface to sniff on.
            ddos_threshold: The packets-per-second threshold for volumetric DDoS detection.
            syn_threshold: The packets-per-second threshold for SYN flood detection.
            log_file: The file path to save alert logs.
            monitor_path: The directory path to monitor for file changes.
            virustotal_api_key: API key for VirusTotal integration.
            quarantine_dir: Directory to move malicious files (if None, files will be deleted).
            auto_delete: Whether to automatically remove malicious files.
        """
        self.iface = iface
        self.ddos_threshold = ddos_threshold
        self.syn_threshold = syn_threshold
        self.log_file = log_file
        self.monitor_path = monitor_path
        self.virustotal_api_key = virustotal_api_key
        self.quarantine_dir = quarantine_dir
        self.auto_delete = auto_delete

        # --- Network Monitoring State Variables ---
        self.packet_counts: dict[str, int] = defaultdict(int)
        self.syn_counts: dict[str, int] = defaultdict(int)
        self.arp_table: OrderedDict[str, str] = OrderedDict()
        
        self.total_packets: int = 0
        self.total_attacks: int = 0
        self.total_files_scanned: int = 0
        self.total_malware_found: int = 0
        self.start_time: float = time.time()
        self.last_reset: float = time.time()
        
        # --- File Monitoring Components ---
        self.file_observer = None
        self.file_handler = None
        
        # --- Local Network Info ---
        try:
            self.local_ip: str = get_if_addr(self.iface)
        except Exception:
            self.local_ip: str = "Unknown"
            print(f"[!] Warning: Could not get local IP for interface '{self.iface}'. Check interface name or permissions.")

    def log_alert(self, message: str, attack_type: str = "UNKNOWN"):
        """
        Appends a timestamped alert message to the log file.

        Args:
            message: The alert message string.
            attack_type: A label for the type of attack detected.
        """
        try:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            with open(self.log_file, "a", encoding='utf-8') as f:
                f.write(f"[{timestamp}] [{attack_type}] {message}\n")
        except Exception as e:
            print(f"[!] Log file error: {e}")

    def detect_ddos_attack(self, packet):
        """
        Analyzes a packet for signs of DDoS or SYN flood attacks.
        """
        if not packet.haslayer(IP):
            return
        
        src_ip = packet[IP].src
        
        # Ignore packets from the local machine to avoid false positives.
        if src_ip == self.local_ip:
            return

        # Increment counts for the source IP.
        self.packet_counts[src_ip] += 1
        self.total_packets += 1

        # Check for SYN flag for SYN flood detection.
        if packet.haslayer(TCP) and packet[TCP].flags == 2:  # 0x02 is the SYN flag
            self.syn_counts[src_ip] += 1

    def check_thresholds(self):
        """
        Checks the packet rates against the defined thresholds every second.
        """
        current_time = time.time()
        if current_time - self.last_reset >= 1.0:
            # Volumetric DDoS Check
            for ip, count in self.packet_counts.items():
                if count > self.ddos_threshold:
                    self.total_attacks += 1
                    alert_msg = f"🚨 DDoS Attack from {ip} - Rate: {count} packets/sec"
                    print(f"\033[91m{alert_msg}\033[0m")
                    self.log_alert(alert_msg, "DDOS")

            # SYN Flood Check
            for ip, count in self.syn_counts.items():
                if count > self.syn_threshold:
                    self.total_attacks += 1
                    alert_msg = f"🚨 SYN Flood from {ip} - Rate: {count} SYN packets/sec"
                    print(f"\033[91m{alert_msg}\033[0m")
                    self.log_alert(alert_msg, "SYN_FLOOD")

            # Reset counts for the next second.
            self.packet_counts.clear()
            self.syn_counts.clear()
            self.last_reset = current_time

    def detect_mitm_attack(self, packet):
        """
        Analyzes a packet for signs of an ARP spoofing (MITM) attack.
        """
        if not packet.haslayer(ARP):
            return

        arp_op = packet[ARP].op
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc

        # Skip invalid or link-local addresses.
        if not src_ip or src_ip == "0.0.0.0" or src_ip.startswith("169.254"):
            return

        # Manage ARP table size
        if len(self.arp_table) >= MAX_ARP_ENTRIES:
            self.arp_table.popitem(last=False)

        # Detect ARP Spoofing via conflicting MAC addresses
        if src_ip in self.arp_table and self.arp_table[src_ip] != src_mac:
            self.total_attacks += 1
            alert_msg = (
                f"⚠️ MITM/ARP Spoofing Detected! "
                f"IP: {src_ip} | Old MAC: {self.arp_table[src_ip]} → New MAC: {src_mac}"
            )
            print(f"\033[93m{alert_msg}\033[0m")
            self.log_alert(alert_msg, "MITM")
        
        # Update the ARP table
        self.arp_table[src_ip] = src_mac
        # Only show new device mapping for genuinely new devices
        if src_ip not in self.arp_table or len(self.arp_table) < 10:
            print(f"\033[92m✅ Device mapped: {src_ip} → {src_mac}\033[0m")

    def analyze_packet(self, packet):
        """
        The main handler for each sniffed packet.
        """
        try:
            self.detect_ddos_attack(packet)
            self.check_thresholds()
            self.detect_mitm_attack(packet)
        except Exception as e:
            print(f"[!] Packet analysis error: {e}")

    def file_log_callback(self, message: str, attack_type: str):
        """
        Callback function for file monitoring to log alerts.
        """
        self.log_alert(message, attack_type)
        if attack_type in ["MALWARE", "SUSPICIOUS"]:
            self.total_malware_found += 1
        if attack_type != "VT_ERROR":
            self.total_files_scanned += 1

    def setup_file_monitoring(self):
        """
        Sets up file system monitoring if path and API key are provided.
        """
        if not self.monitor_path or not self.virustotal_api_key:
            print("[*] File monitoring disabled (no path or API key provided)")
            return False
        
        if not os.path.exists(self.monitor_path):
            print(f"[!] Warning: Monitor path '{self.monitor_path}' does not exist")
            return False
        
        try:
            self.file_handler = FileMonitorHandler(
                self.virustotal_api_key, 
                self.file_log_callback,
                self.quarantine_dir,
                self.auto_delete
            )
            self.file_observer = Observer()
            self.file_observer.schedule(self.file_handler, self.monitor_path, recursive=True)
            self.file_observer.start()
            print(f"[*] File monitoring started on: {self.monitor_path}")
            return True
        except Exception as e:
            print(f"[!] Failed to start file monitoring: {e}")
            return False

    def show_statistics(self):
        """
        Displays real-time statistics of the monitoring process.
        """
        uptime = int(time.time() - self.start_time)
        hours, minutes, seconds = uptime // 3600, (uptime % 3600) // 60, uptime % 60
        
        stats_line = (
            f"\033[92m📊 Runtime: {hours:02d}:{minutes:02d}:{seconds:02d} | "
            f"Packets: {self.total_packets} | "
            f"Network Attacks: {self.total_attacks} | "
            f"ARP Entries: {len(self.arp_table)}"
        )
        
        if self.monitor_path and self.virustotal_api_key:
            stats_line += f" | Files Scanned: {self.total_files_scanned} | Malware Found: {self.total_malware_found}"
        
        stats_line += "\033[0m"
        print(stats_line)
        
        # Schedule next statistics display
        threading.Timer(10.0, self.show_statistics).start()

    def start_monitoring(self):
        """
        Starts the integrated monitoring process (network + file system).
        """
        print("\033[2J\033[H")
        print("""
🔍 Integrated RTDS v3.0 - Network & File Protection
🛡️ Detection: DDoS, SYN Floods, MITM & Malware
--------------------------------------------------
""")
        print(f"[*] Network Interface: {self.iface} | Local IP: {self.local_ip}")
        print(f"[*] DDoS Threshold: {self.ddos_threshold} pps | SYN Threshold: {self.syn_threshold} pps")
        print(f"[*] Log File: {self.log_file}")
        
        # Setup file monitoring
        file_monitoring_active = self.setup_file_monitoring()
        
        print(f"\n[*] Starting integrated monitoring... (Press Ctrl+C to stop)\n")

        # Start the statistics timer
        threading.Timer(10.0, self.show_statistics).start()
        
        # Start network packet sniffing
        try:
            sniff(filter="arp or ip", prn=self.analyze_packet, store=False, iface=self.iface)
        except PermissionError:
            print("\n[!] Permission denied! Run as Administrator/Root to capture packets.")
        except KeyboardInterrupt:
            print("\n🛑 MONITORING STOPPED")
        except Exception as e:
            print(f"\n[!] An error occurred during sniffing: {e}")
        finally:
            self.shutdown()

    def shutdown(self):
        """
        Prints final statistics and cleans up resources on shutdown.
        """
        # Stop file monitoring
        if self.file_observer:
            self.file_observer.stop()
            self.file_observer.join()
        
        uptime = int(time.time() - self.start_time)
        print(f"\n📈 Total Runtime: {uptime//3600:02d}:{(uptime%3600)//60:02d}:{uptime%60:02d}")
        print(f"📦 Total Packets Analyzed: {self.total_packets}")
        print(f"🚨 Total Network Attacks Detected: {self.total_attacks}")
        print(f"🗂️ ARP Table Entries: {len(self.arp_table)}")
        
        if self.monitor_path and self.virustotal_api_key:
            print(f"📄 Total Files Scanned: {self.total_files_scanned}")
            print(f"🦠 Total Malware Detected: {self.total_malware_found}")
        
        print(f"📄 Logs saved in: {self.log_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Integrated RTDS - Network & File Threat Detection")
    
    # Network monitoring arguments
    parser.add_argument("--ddos-threshold", type=int, default=100, help="DDoS packet threshold (pps)")
    parser.add_argument("--syn-threshold", type=int, default=50, help="SYN flood threshold (pps)")
    parser.add_argument("--iface", default="Wi-Fi", help="Network interface (Windows example: Wi-Fi)")
    
    # File monitoring arguments
    parser.add_argument("--quarantine-dir", type=str, help="Directory to quarantine malicious files (default: delete)")
    parser.add_argument("--no-auto-delete", action="store_true", help="Disable automatic deletion of malicious files")
    
    # General arguments
    parser.add_argument("--log", type=str, default="integrated_rtds_alerts.log", help="Log file path")
    
    args = parser.parse_args()
    
    # Get VirusTotal API key from environment only
    vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
    
    # Get monitor path from user input
    monitor_path = None
    if vt_api_key:
        print("\n[*] VirusTotal API key found - File monitoring available")
        user_input = input("Enter directory path to monitor (or press Enter to skip file monitoring): ").strip()
        if user_input:
            if os.path.exists(user_input):
                monitor_path = user_input
                print(f"[*] Will monitor directory: {monitor_path}")
            else:
                print(f"[!] Warning: Directory '{user_input}' does not exist")
                print("[*] Continuing with network monitoring only...")
        else:
            print("[*] File monitoring skipped")
    else:
        print("[!] Warning: VIRUSTOTAL_API_KEY not found in environment variables!")
        print("[!] Please set your VirusTotal API key in .env file:")
        print("    VIRUSTOTAL_API_KEY=your_api_key_here")
        print("[*] File monitoring will be disabled without API key")
        print("[*] Continuing with network monitoring only...\n")
    
    # Check if the network interface exists
    if args.iface not in get_if_list():
        print(f"[!] Error: The specified interface '{args.iface}' was not found.")
        print("Available interfaces:")
        for iface in get_if_list():
            print(f"  - {iface}")
        exit(1)
    
    # Create and start the integrated monitor
    monitor = IntegratedRTDSMonitor(
        iface=args.iface,
        ddos_threshold=args.ddos_threshold,
        syn_threshold=args.syn_threshold,
        log_file=args.log,
        monitor_path=monitor_path,
        virustotal_api_key=vt_api_key,
        quarantine_dir=args.quarantine_dir,
        auto_delete=not args.no_auto_delete
    )
    
    monitor.start_monitoring()