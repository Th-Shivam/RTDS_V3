#!/usr/bin/env python3
import subprocess
import threading
import time
import os
import signal
import sys

class RTDSLauncher:
    def __init__(self):
        self.processes = []
        self.running = True

    def run_dashboard(self):
        """Run the Flask dashboard server"""
        try:
            print("🚀 Starting RTDS Dashboard Server...")
            process = subprocess.Popen([
                sys.executable, 'app.py'
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.processes.append(process)
            
            # Monitor output
            for line in iter(process.stdout.readline, ''):
                if self.running:
                    print(f"[DASHBOARD] {line.strip()}")
                else:
                    break
                    
        except Exception as e:
            print(f"❌ Dashboard error: {e}")

    def run_monitor(self):
        """Run the RTDS monitoring system"""
        try:
            print("🛡️ Starting RTDS Monitor...")
            
            # Configure based on OS
            if os.name == 'nt':  # Windows
                monitor_path = os.path.expanduser("~/Downloads")
                quarantine_dir = os.path.join(os.getcwd(), "quarantine")
            else:  # Linux/Mac
                monitor_path = os.path.expanduser("~/Downloads")  
                quarantine_dir = "/tmp/quarantine"
            
            # Create directories if they don't exist
            os.makedirs(monitor_path, exist_ok=True)
            os.makedirs(quarantine_dir, exist_ok=True)
            os.makedirs("logs", exist_ok=True)
            
            process = subprocess.Popen([
                sys.executable, 'rtds_monitor.py',
                '--monitor-path', monitor_path,
                '--quarantine-dir', quarantine_dir,
                '--log', 'logs/integrated_rtds_alerts.log'
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.processes.append(process)
            
            # Monitor output
            for line in iter(process.stdout.readline, ''):
                if self.running:
                    print(f"[MONITOR] {line.strip()}")
                else:
                    break
                    
        except Exception as e:
            print(f"❌ Monitor error: {e}")

    def signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully"""
        print("\n🛑 Shutting down RTDS system...")
        self.running = False
        
        for process in self.processes:
            try:
                process.terminate()
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        
        sys.exit(0)

    def start(self):
        """Start both services in parallel"""
        print("""
🔍 RTDS - Real Time Threat Detection System
🛡️ Starting Integrated Dashboard & Monitor
============================================
""")
        
        # Set up signal handler
        signal.signal(signal.SIGINT, self.signal_handler)
        
        # Start dashboard in separate thread
        dashboard_thread = threading.Thread(target=self.run_dashboard, daemon=True)
        dashboard_thread.start()
        
        # Start monitor in separate thread  
        monitor_thread = threading.Thread(target=self.run_monitor, daemon=True)
        monitor_thread.start()
        
        print("✅ Both services started!")
        print("📊 Dashboard: http://localhost:5000")
        print("🔍 Monitor: Running in background")
        print("\nPress Ctrl+C to stop all services\n")
        
        try:
            # Keep main thread alive
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.signal_handler(None, None)

if __name__ == "__main__":
    launcher = RTDSLauncher()
    launcher.start()