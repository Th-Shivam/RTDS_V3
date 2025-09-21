from flask import Flask, jsonify, render_template, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import json
import time
import threading
import os
import subprocess
import re
from datetime import datetime, timedelta
from collections import defaultdict, deque
import sqlite3
from contextlib import contextmanager
from ip_blocker import IPBlocker
from email_notifier import EmailNotifier

app = Flask(__name__)
app.config['SECRET_KEY'] = 'rtds_secret_key_2024'
socketio = SocketIO(app, cors_allowed_origins="*")
CORS(app)

# Global data storage for real-time updates
class RTDSDataStore:
    def __init__(self):
        self.stats = {
            'total_packets': 0,
            'total_attacks': 0,
            'total_files_scanned': 0,
            'total_malware_found': 0,
            'uptime_start': time.time(),
            'current_threats': 0,
            'network_status': 'MONITORING'
        }
        
        # Real-time data (keep last 100 entries)
        self.recent_attacks = deque(maxlen=100)
        self.packet_timeline = deque(maxlen=60)  # Last 60 seconds
        self.threat_types = defaultdict(int)
        self.top_attackers = defaultdict(int)
        self.file_scan_results = deque(maxlen=50)
        
        # Network devices
        self.network_devices = {}
        self.last_device_scan = 0
        
        # IP Blocker for dashboard management
        self.ip_blocker = IPBlocker()
        
        # Email Notifier for dashboard management
        self.email_notifier = EmailNotifier()
        
        # Initialize packet timeline
        for i in range(60):
            self.packet_timeline.append({
                'timestamp': time.time() - (59 - i),
                'packets': 0,
                'attacks': 0
            })
    
    def add_attack(self, attack_data):
        self.recent_attacks.append({
            'timestamp': time.time(),
            'type': attack_data.get('type', 'UNKNOWN'),
            'source': attack_data.get('source', 'Unknown'),
            'severity': attack_data.get('severity', 'Medium'),
            'details': attack_data.get('details', ''),
            'id': len(self.recent_attacks) + 1
        })
        
        self.threat_types[attack_data.get('type', 'UNKNOWN')] += 1
        if attack_data.get('source'):
            self.top_attackers[attack_data.get('source')] += 1
        
        self.stats['total_attacks'] += 1
        self.stats['current_threats'] = len([a for a in self.recent_attacks if time.time() - a['timestamp'] < 300])  # Last 5 minutes
    
    def add_file_scan(self, file_data):
        self.file_scan_results.append({
            'timestamp': time.time(),
            'filename': file_data.get('filename', 'Unknown'),
            'status': file_data.get('status', 'CLEAN'),
            'detections': file_data.get('detections', 0),
            'action': file_data.get('action', 'NONE')
        })
        
        self.stats['total_files_scanned'] += 1
        if file_data.get('status') in ['MALWARE', 'SUSPICIOUS']:
            self.stats['total_malware_found'] += 1
    
    def scan_network_devices(self):
        """Scan for network devices using ARP table"""
        try:
            devices = {}
            
            # Method 1: ARP table
            try:
                arp_output = subprocess.check_output(['arp', '-a'], text=True, timeout=5)
                for line in arp_output.split('\n'):
                    if line.strip():
                        match = re.search(r'\(([\d.]+)\) at ([a-fA-F0-9:]+)', line)
                        if match:
                            ip, mac = match.groups()
                            hostname = line.split()[0] if line.split()[0] != '?' else 'Unknown'
                            devices[ip] = {
                                'ip': ip,
                                'mac': mac,
                                'hostname': hostname,
                                'status': 'active',
                                'last_seen': datetime.now().isoformat()
                            }
            except:
                pass
            
            # Method 2: IP neighbors (Linux)
            try:
                ip_output = subprocess.check_output(['ip', 'neigh'], text=True, timeout=5)
                for line in ip_output.split('\n'):
                    if 'REACHABLE' in line or 'STALE' in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            ip = parts[0]
                            mac = parts[4]
                            devices[ip] = {
                                'ip': ip,
                                'mac': mac,
                                'hostname': 'Unknown',
                                'status': 'active',
                                'last_seen': datetime.now().isoformat()
                            }
            except:
                pass
            
            self.network_devices = devices
            self.last_device_scan = time.time()
            
        except Exception as e:
            print(f"Error scanning network devices: {e}")
    
    def update_packet_stats(self, packet_count):
        current_time = time.time()
        self.stats['total_packets'] += packet_count
        
        # Update timeline
        self.packet_timeline.append({
            'timestamp': current_time,
            'packets': packet_count,
            'attacks': 0
        })

# Initialize data store
data_store = RTDSDataStore()

# Database setup
def init_db():
    """Initialize SQLite database for persistent storage"""
    with sqlite3.connect('rtds_logs.db') as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                type TEXT NOT NULL,
                source TEXT,
                severity TEXT,
                details TEXT
            )
        ''')
        
        conn.execute('''
            CREATE TABLE IF NOT EXISTS file_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                filename TEXT NOT NULL,
                status TEXT NOT NULL,
                detections INTEGER DEFAULT 0,
                action TEXT
            )
        ''')

@contextmanager
def get_db():
    conn = sqlite3.connect('rtds_logs.db')
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

# API Routes
@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/stats')
def get_stats():
    """Get current system statistics"""
    uptime_seconds = int(time.time() - data_store.stats['uptime_start'])
    uptime_formatted = f"{uptime_seconds//3600:02d}:{(uptime_seconds%3600)//60:02d}:{uptime_seconds%60:02d}"
    
    stats = data_store.stats.copy()
    stats['uptime'] = uptime_formatted
    stats['uptime_seconds'] = uptime_seconds
    
    return jsonify(stats)

@app.route('/api/recent-attacks')
def get_recent_attacks():
    """Get recent attacks (last 20)"""
    recent = list(data_store.recent_attacks)[-20:]
    formatted_attacks = []
    
    for attack in recent:
        formatted_attacks.append({
            **attack,
            'timestamp_formatted': datetime.fromtimestamp(attack['timestamp']).strftime('%H:%M:%S'),
            'time_ago': f"{int(time.time() - attack['timestamp'])}s ago"
        })
    
    return jsonify(formatted_attacks)

@app.route('/api/packet-timeline')
def get_packet_timeline():
    """Get packet timeline data for charts"""
    timeline_data = []
    for point in data_store.packet_timeline:
        timeline_data.append({
            'time': datetime.fromtimestamp(point['timestamp']).strftime('%H:%M:%S'),
            'packets': point['packets'],
            'attacks': point['attacks']
        })
    
    return jsonify(timeline_data)

@app.route('/api/threat-breakdown')
def get_threat_breakdown():
    """Get threat types breakdown"""
    return jsonify(dict(data_store.threat_types))

@app.route('/api/top-attackers')
def get_top_attackers():
    """Get top attacking IPs"""
    top_attackers = sorted(data_store.top_attackers.items(), key=lambda x: x[1], reverse=True)[:10]
    return jsonify([{'ip': ip, 'count': count} for ip, count in top_attackers])

@app.route('/api/file-scans')
def get_file_scans():
    """Get recent file scan results"""
    recent_scans = list(data_store.file_scan_results)[-20:]
    formatted_scans = []
    
    for scan in recent_scans:
        formatted_scans.append({
            **scan,
            'timestamp_formatted': datetime.fromtimestamp(scan['timestamp']).strftime('%H:%M:%S'),
            'time_ago': f"{int(time.time() - scan['timestamp'])}s ago"
        })
    
    return jsonify(formatted_scans)

@app.route('/api/network-devices')
def get_network_devices():
    """Get discovered network devices"""
    # Scan devices if not scanned recently (every 30 seconds)
    if time.time() - data_store.last_device_scan > 30:
        threading.Thread(target=data_store.scan_network_devices, daemon=True).start()
    
    devices_list = []
    for ip, device in data_store.network_devices.items():
        devices_list.append({
            'ip': device['ip'],
            'mac': device['mac'],
            'hostname': device['hostname'],
            'status': device['status'],
            'last_seen': device['last_seen']
        })
    
    return jsonify(devices_list)

# IP Blocker Management Endpoints
@app.route('/api/blocked-ips')
def get_blocked_ips():
    """Get list of currently blocked IPs"""
    blocked_ips = data_store.ip_blocker.get_blocked_ips()
    formatted_blocks = []
    
    for ip, block_info in blocked_ips.items():
        expires = block_info.get('expires', 0)
        remaining = max(0, expires - time.time()) if expires > 0 else 0
        
        formatted_blocks.append({
            'ip': ip,
            'reason': block_info.get('reason', 'Unknown'),
            'blocked_at': datetime.fromtimestamp(block_info['timestamp']).strftime('%Y-%m-%d %H:%M:%S'),
            'duration': block_info.get('duration', 0),
            'expires': expires,
            'remaining_seconds': int(remaining),
            'is_permanent': expires == 0
        })
    
    return jsonify(formatted_blocks)

@app.route('/api/block-ip', methods=['POST'])
def block_ip():
    """Block an IP address"""
    data = request.get_json()
    ip = data.get('ip', '').strip()
    reason = data.get('reason', 'Manual block from dashboard')
    duration = int(data.get('duration', 3600))  # Default 1 hour
    
    if not ip:
        return jsonify({'success': False, 'message': 'IP address is required'}), 400
    
    success = data_store.ip_blocker.block_ip(ip, reason, duration)
    
    if success:
        return jsonify({'success': True, 'message': f'IP {ip} blocked successfully'})
    else:
        return jsonify({'success': False, 'message': f'Failed to block IP {ip}'}), 400

@app.route('/api/unblock-ip', methods=['POST'])
def unblock_ip():
    """Unblock an IP address"""
    data = request.get_json()
    ip = data.get('ip', '').strip()
    
    if not ip:
        return jsonify({'success': False, 'message': 'IP address is required'}), 400
    
    success = data_store.ip_blocker.unblock_ip(ip)
    
    if success:
        return jsonify({'success': True, 'message': f'IP {ip} unblocked successfully'})
    else:
        return jsonify({'success': False, 'message': f'Failed to unblock IP {ip}'}), 400

@app.route('/api/block-stats')
def get_block_stats():
    """Get IP blocking statistics"""
    stats = data_store.ip_blocker.get_block_stats()
    return jsonify(stats)

@app.route('/api/emergency-unblock', methods=['POST'])
def emergency_unblock():
    """Emergency unblock all IPs"""
    data_store.ip_blocker.emergency_unblock_all()
    return jsonify({'success': True, 'message': 'All IP blocks removed'})

@app.route('/api/add-whitelist', methods=['POST'])
def add_to_whitelist():
    """Add IP or range to whitelist"""
    data = request.get_json()
    ip_or_range = data.get('ip_or_range', '').strip()
    
    if not ip_or_range:
        return jsonify({'success': False, 'message': 'IP address or range is required'}), 400
    
    try:
        data_store.ip_blocker.add_to_whitelist(ip_or_range)
        return jsonify({'success': True, 'message': f'Added {ip_or_range} to whitelist'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Failed to add to whitelist: {str(e)}'}), 400

# Email Notification Management Endpoints
@app.route('/api/email-status')
def get_email_status():
    """Get email notification status"""
    status = data_store.email_notifier.get_status()
    return jsonify(status)

@app.route('/api/test-email', methods=['POST'])
def test_email():
    """Send test email"""
    try:
        data_store.email_notifier.send_alert(
            alert_type="Test Alert",
            source="RTDS Dashboard",
            details="This is a test email from RTDS Dashboard to verify email configuration.",
            severity="Low"
        )
        return jsonify({'success': True, 'message': 'Test email sent successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Failed to send test email: {str(e)}'}), 400

@app.route('/api/send-daily-report', methods=['POST'])
def send_daily_report():
    """Send daily security report"""
    try:
        stats = data_store.stats.copy()
        data_store.email_notifier.send_daily_report(stats)
        return jsonify({'success': True, 'message': 'Daily report sent successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Failed to send daily report: {str(e)}'}), 400

# WebSocket events for real-time updates
@socketio.on('connect')
def handle_connect():
    print('Client connected to RTDS Dashboard')
    emit('status', {'message': 'Connected to RTDS Dashboard'})

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected from RTDS Dashboard')

# Log file monitoring
def monitor_log_file(log_file_path='integrated_rtds_alerts.log'):
    """Monitor the RTDS log file for new entries"""
    if not os.path.exists(log_file_path):
        print(f"Log file {log_file_path} not found. Creating empty file.")
        open(log_file_path, 'a').close()
    
    last_position = 0
    
    while True:
        try:
            if os.path.exists(log_file_path):
                with open(log_file_path, 'r', encoding='utf-8') as f:
                    f.seek(last_position)
                    new_lines = f.readlines()
                    last_position = f.tell()
                    
                    for line in new_lines:
                        if line.strip():
                            parse_log_entry(line.strip())
            
            time.sleep(1)  # Check every second
            
        except Exception as e:
            print(f"Error monitoring log file: {e}")
            time.sleep(5)

def parse_log_entry(log_line):
    """Parse a log entry and update data store"""
    try:
        # Parse log format: [timestamp] [type] message
        if '[' in log_line and ']' in log_line:
            parts = log_line.split('] ', 2)
            if len(parts) >= 3:
                timestamp_str = parts[0][1:]  # Remove opening [
                attack_type = parts[1][1:]    # Remove opening [
                message = parts[2]
                
                # Handle packet statistics
                if attack_type == 'PACKET_STATS':
                    parse_packet_stats(message)
                    return
                
                # Determine if it's a network attack or file scan
                if attack_type in ['DDOS', 'SYN_FLOOD', 'MITM']:
                    # Extract source IP if available
                    source_ip = 'Unknown'
                    if 'from ' in message:
                        try:
                            source_ip = message.split('from ')[1].split(' ')[0]
                        except:
                            pass
                    
                    severity = 'High' if attack_type in ['DDOS', 'SYN_FLOOD'] else 'Medium'
                    
                    attack_data = {
                        'type': attack_type,
                        'source': source_ip,
                        'severity': severity,
                        'details': message
                    }
                    
                    data_store.add_attack(attack_data)
                    
                    # Store in database
                    with get_db() as db:
                        db.execute('''
                            INSERT INTO attacks (timestamp, type, source, severity, details)
                            VALUES (?, ?, ?, ?, ?)
                        ''', (timestamp_str, attack_type, source_ip, severity, message))
                        db.commit()
                    
                    # Emit real-time update
                    socketio.emit('new_attack', attack_data)
                    
                elif attack_type in ['MALWARE', 'SUSPICIOUS', 'NEW_FILE', 'QUARANTINED', 'DELETED', 'CLEAN', 'UPLOADED']:
                    # Parse filename from message
                    filename = 'Unknown'
                    if ':' in message:
                        try:
                            filename = message.split(':')[1].split(' ')[0].strip()
                        except:
                            pass
                    
                    detections = 0
                    if 'detections:' in message or 'Detections:' in message:
                        try:
                            detections = int(message.split('etections:')[1].split('/')[0].strip())
                        except:
                            pass
                    
                    file_data = {
                        'filename': os.path.basename(filename),
                        'status': attack_type,
                        'detections': detections,
                        'action': attack_type if attack_type in ['QUARANTINED', 'DELETED'] else 'SCANNED'
                    }
                    
                    data_store.add_file_scan(file_data)
                    
                    # Store in database
                    with get_db() as db:
                        db.execute('''
                            INSERT INTO file_scans (timestamp, filename, status, detections, action)
                            VALUES (?, ?, ?, ?, ?)
                        ''', (timestamp_str, filename, attack_type, detections, file_data['action']))
                        db.commit()
                    
                    # Emit real-time update
                    socketio.emit('new_file_scan', file_data)
                
                # Emit stats update
                socketio.emit('stats_update', data_store.stats)
                
    except Exception as e:
        print(f"Error parsing log entry: {e}")

def parse_packet_stats(message):
    """Parse packet statistics from log message"""
    try:
        # Parse: PACKET_STATS: total=1234, current_rate=56/sec
        if 'total=' in message and 'current_rate=' in message:
            total_part = message.split('total=')[1].split(',')[0]
            rate_part = message.split('current_rate=')[1].split('/sec')[0]
            
            total_packets = int(total_part)
            current_rate = int(rate_part)
            
            # Update data store
            data_store.stats['total_packets'] = total_packets
            
            # Add to packet timeline
            data_store.packet_timeline.append({
                'timestamp': time.time(),
                'packets': current_rate,
                'attacks': 0
            })
            
    except Exception as e:
        print(f"Error parsing packet stats: {e}")

# Background tasks
def start_background_tasks():
    """Start background monitoring tasks"""
    # Start log file monitoring in a separate thread
    log_monitor_thread = threading.Thread(target=monitor_log_file, daemon=True)
    log_monitor_thread.start()
    
    # Start periodic stats broadcasting
    def broadcast_stats():
        while True:
            time.sleep(5)  # Broadcast every 5 seconds
            socketio.emit('stats_update', data_store.stats)
    
    stats_thread = threading.Thread(target=broadcast_stats, daemon=True)
    stats_thread.start()
    
    # Start initial network device scan
    initial_scan_thread = threading.Thread(target=data_store.scan_network_devices, daemon=True)
    initial_scan_thread.start()

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Get monitor path from user
    print("🔧 RTDS Dashboard Configuration")
    print("=" * 40)
    
    try:
        monitor_path = input("Enter directory path to monitor (e.g., /home/user/Downloads) or press Enter to skip: ").strip()
        
        if monitor_path and os.path.exists(monitor_path):
            print(f"✅ Will monitor directory: {monitor_path}")
            # Store monitor path for future use
            with open('.monitor_path', 'w') as f:
                f.write(monitor_path)
        elif monitor_path:
            print(f"❌ Directory '{monitor_path}' does not exist")
            print("⚠️  Continuing without file monitoring...")
        else:
            print("⚠️  No monitor path provided - file monitoring disabled")
    except (EOFError, KeyboardInterrupt):
        print("\n⚠️  No input provided - file monitoring disabled")
        monitor_path = ""
    
    print("\n" + "=" * 40)
    
    # Start background tasks
    start_background_tasks()
    
    print("🚀 RTDS Dashboard Server Starting...")
    print("📊 Dashboard URL: http://localhost:5000")
    print("🔍 Monitoring log file: integrated_rtds_alerts.log")
    print("🛑 Press Ctrl+C to stop")
    
    try:
        # Run the Flask-SocketIO server
        socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        print(f"❌ Server error: {e}")