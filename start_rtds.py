#!/usr/bin/env python3

import os
import sys
import subprocess
import signal
import time
from pathlib import Path

def signal_handler(sig, frame):
    print('\n\n🛑 Shutting down RTDS system...')
    sys.exit(0)

def main():
    print("🚀 RTDS (Real-Time Defense System) Startup")
    print("=" * 50)
    
    # Check if running as root for network monitoring
    if os.geteuid() != 0:
        print("⚠️  Warning: Not running as root. Network monitoring may have limited functionality.")
        print("   Run with: sudo python3 start_rtds.py")
        print()
    
    # Get user preferences
    print("Select monitoring mode:")
    print("1. Web Dashboard only")
    print("2. Network Monitor only") 
    print("3. Both Dashboard + Network Monitor")
    
    choice = input("\nEnter choice (1-3): ").strip()
    
    if choice == "1":
        print("\n🌐 Starting Web Dashboard...")
        subprocess.run([sys.executable, "app.py"])
        
    elif choice == "2":
        print("\n🔍 Starting Network Monitor...")
        # Get network interface
        interfaces = []
        try:
            from scapy.all import get_if_list
            interfaces = get_if_list()
            print(f"\nAvailable interfaces: {', '.join(interfaces)}")
        except:
            interfaces = ["eth0", "wlan0", "lo"]
            print(f"\nCommon interfaces: {', '.join(interfaces)}")
        
        iface = input("Enter network interface (e.g., eth0, wlan0): ").strip()
        if not iface:
            iface = "eth0"
        
        # Ask about auto-blocking
        auto_block = input("Enable automatic IP blocking? (y/N): ").strip().lower()
        auto_block_flag = "--enable-auto-block" if auto_block == "y" else ""
        
        cmd = [sys.executable, "rtds_monitor.py", "--iface", iface]
        if auto_block_flag:
            cmd.append(auto_block_flag)
        
        subprocess.run(cmd)
        
    elif choice == "3":
        print("\n🔄 Starting both Dashboard and Network Monitor...")
        print("This will start the web dashboard. Run network monitor separately.")
        subprocess.run([sys.executable, "app.py"])
        
    else:
        print("❌ Invalid choice. Exiting.")
        sys.exit(1)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    main()
