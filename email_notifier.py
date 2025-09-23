#!/usr/bin/env python3

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import os
import json
import time
from datetime import datetime
from typing import List, Dict, Optional
import threading
from queue import Queue

class EmailNotifier:
    """
    Email notification service for RTDS alerts and reports.
    """
    
    def __init__(self, config_file: str = "email_config.json"):
        self.config_file = config_file
        self.config = self._load_config()
        self.email_queue = Queue()
        self.is_enabled = self.config.get('enabled', False)
        
        # Alert cooldown tracking (IP -> last_alert_time)
        self.alert_cooldown = {}
        self.cooldown_duration = self.config.get('alert_cooldown_minutes', 5) * 60  # Convert to seconds
        
        # Start email processing thread
        if self.is_enabled:
            self._start_email_processor()
    
    def _load_config(self) -> Dict:
        """Load email configuration from file or environment variables"""
        config = {
            'enabled': False,
            'smtp_server': '',
            'smtp_port': 587,
            'username': '',
            'password': '',
            'from_email': '',
            'to_emails': [],
            'use_tls': True,
            'use_ssl': False,
            'subject_prefix': '[RTDS Alert]',
            'max_retries': 3,
            'retry_delay': 5
        }
        
        # Try to load from config file first
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    file_config = json.load(f)
                    config.update(file_config)
            except Exception as e:
                print(f"[!] Error loading email config: {e}")
        
        # Override with environment variables (but keep file setting for enabled if true)
        if not config.get('enabled', False):
            config['enabled'] = os.getenv('EMAIL_ENABLED', 'false').lower() == 'true'
        config['smtp_server'] = os.getenv('SMTP_SERVER', config['smtp_server'])
        config['smtp_port'] = int(os.getenv('SMTP_PORT', config['smtp_port']))
        config['username'] = os.getenv('SMTP_USERNAME', config['username'])
        config['password'] = os.getenv('SMTP_PASSWORD', config['password'])
        config['from_email'] = os.getenv('FROM_EMAIL', config['from_email'])
        
        # Parse recipient emails
        to_emails_env = os.getenv('TO_EMAILS', '')
        if to_emails_env:
            config['to_emails'] = [email.strip() for email in to_emails_env.split(',')]
        
        return config
    
    def _start_email_processor(self):
        """Start background thread for processing email queue"""
        def process_emails():
            while True:
                try:
                    if not self.email_queue.empty():
                        email_data = self.email_queue.get()
                        self._send_email_sync(email_data)
                        self.email_queue.task_done()
                    else:
                        time.sleep(1)
                except Exception as e:
                    print(f"[!] Email processor error: {e}")
                    time.sleep(5)
        
        email_thread = threading.Thread(target=process_emails, daemon=True)
        email_thread.start()
        print(f"[*] Email notifier initialized - SMTP: {self.config['smtp_server']}:{self.config['smtp_port']}")
    
    def _cleanup_cooldown(self):
        """Remove old entries from cooldown tracker"""
        current_time = time.time()
        expired_keys = [key for key, timestamp in self.alert_cooldown.items() 
                       if current_time - timestamp > self.cooldown_duration]
        for key in expired_keys:
            del self.alert_cooldown[key]
    
    def _send_email_sync(self, email_data: Dict) -> bool:
        """Send email synchronously"""
        if not self.is_enabled or not self.config['to_emails']:
            return False
        
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.config['from_email']
            msg['To'] = ', '.join(self.config['to_emails'])
            msg['Subject'] = f"{self.config['subject_prefix']} {email_data['subject']}"
            
            # Add body
            body = email_data['body']
            if email_data.get('html_body'):
                msg.attach(MIMEText(email_data['html_body'], 'html'))
            else:
                msg.attach(MIMEText(body, 'plain'))
            
            # Add attachment if provided
            if email_data.get('attachment_path'):
                self._add_attachment(msg, email_data['attachment_path'])
            
            # Send email
            context = ssl.create_default_context()
            
            with smtplib.SMTP(self.config['smtp_server'], self.config['smtp_port']) as server:
                if self.config['use_tls']:
                    server.starttls(context=context)
                elif self.config['use_ssl']:
                    server = smtplib.SMTP_SSL(self.config['smtp_server'], self.config['smtp_port'], context=context)
                
                server.login(self.config['username'], self.config['password'])
                server.send_message(msg)
            
            print(f"[✓] Email sent successfully to {len(self.config['to_emails'])} recipients")
            return True
            
        except Exception as e:
            print(f"[!] Failed to send email: {e}")
            return False
    
    def _add_attachment(self, msg: MIMEMultipart, file_path: str):
        """Add file attachment to email"""
        try:
            with open(file_path, "rb") as attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
            
            encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition',
                f'attachment; filename= {os.path.basename(file_path)}'
            )
            msg.attach(part)
        except Exception as e:
            print(f"[!] Failed to add attachment: {e}")
    
    def send_alert(self, alert_type: str, source: str, details: str, severity: str = "Medium"):
        """Send security alert email with cooldown to prevent spam"""
        if not self.is_enabled:
            return
        
        # Check cooldown for this IP
        current_time = time.time()
        alert_key = f"{alert_type}_{source}"
        
        if alert_key in self.alert_cooldown:
            time_since_last = current_time - self.alert_cooldown[alert_key]
            if time_since_last < self.cooldown_duration:
                print(f"[*] Alert cooldown active for {source} ({int(self.cooldown_duration - time_since_last)}s remaining)")
                return
        
        # Update cooldown tracker
        self.alert_cooldown[alert_key] = current_time
        
        # Create email content
        subject = f"{alert_type} Alert from {source}"
        
        body = f"""
RTDS Security Alert

Alert Type: {alert_type}
Source: {source}
Severity: {severity}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Details:
{details}

This is an automated alert from RTDS (Real-Time Threat Detection System).
Please investigate this security incident immediately.

---
RTDS Security Team
        """.strip()
        
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: {'#d32f2f' if severity == 'High' else '#f57c00' if severity == 'Medium' else '#388e3c'};">
                    🚨 RTDS Security Alert
                </h2>
                
                <div style="background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <p><strong>Alert Type:</strong> {alert_type}</p>
                    <p><strong>Source:</strong> {source}</p>
                    <p><strong>Severity:</strong> 
                        <span style="color: {'#d32f2f' if severity == 'High' else '#f57c00' if severity == 'Medium' else '#388e3c'};">
                            {severity}
                        </span>
                    </p>
                    <p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                
                <div style="background: #fff3e0; padding: 15px; border-left: 4px solid #ff9800; margin: 20px 0;">
                    <h3>Details:</h3>
                    <p>{details}</p>
                </div>
                
                <div style="background: #e3f2fd; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <p><strong>⚠️ Action Required:</strong> Please investigate this security incident immediately.</p>
                </div>
                
                <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
                <p style="color: #666; font-size: 12px;">
                    This is an automated alert from RTDS (Real-Time Threat Detection System).<br>
                    RTDS Security Team
                </p>
            </div>
        </body>
        </html>
        """
        
        email_data = {
            'subject': subject,
            'body': body,
            'html_body': html_body
        }
        
        self.email_queue.put(email_data)
    
    def send_daily_report(self, stats: Dict):
        """Send daily security report"""
        if not self.is_enabled:
            return
        
        subject = f"Daily Security Report - {datetime.now().strftime('%Y-%m-%d')}"
        
        body = f"""
RTDS Daily Security Report

Date: {datetime.now().strftime('%Y-%m-%d')}
System Uptime: {stats.get('uptime', 'Unknown')}

Security Statistics:
- Total Packets Analyzed: {stats.get('total_packets', 0):,}
- Network Attacks Detected: {stats.get('total_attacks', 0)}
- Files Scanned: {stats.get('total_files_scanned', 0)}
- Malware Detected: {stats.get('total_malware_found', 0)}
- Active Threats: {stats.get('current_threats', 0)}

System Status: {stats.get('network_status', 'Unknown')}

This report was automatically generated by RTDS.

---
RTDS Security Team
        """.strip()
        
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #1976d2;">📊 RTDS Daily Security Report</h2>
                
                <div style="background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d')}</p>
                    <p><strong>System Uptime:</strong> {stats.get('uptime', 'Unknown')}</p>
                    <p><strong>System Status:</strong> {stats.get('network_status', 'Unknown')}</p>
                </div>
                
                <h3 style="color: #1976d2;">Security Statistics</h3>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin: 20px 0;">
                    <div style="background: #e8f5e8; padding: 15px; border-radius: 5px; text-align: center;">
                        <h4 style="margin: 0; color: #2e7d32;">{stats.get('total_packets', 0):,}</h4>
                        <p style="margin: 5px 0 0 0; color: #666;">Packets Analyzed</p>
                    </div>
                    <div style="background: #fff3e0; padding: 15px; border-radius: 5px; text-align: center;">
                        <h4 style="margin: 0; color: #f57c00;">{stats.get('total_attacks', 0)}</h4>
                        <p style="margin: 5px 0 0 0; color: #666;">Network Attacks</p>
                    </div>
                    <div style="background: #e3f2fd; padding: 15px; border-radius: 5px; text-align: center;">
                        <h4 style="margin: 0; color: #1976d2;">{stats.get('total_files_scanned', 0)}</h4>
                        <p style="margin: 5px 0 0 0; color: #666;">Files Scanned</p>
                    </div>
                    <div style="background: #ffebee; padding: 15px; border-radius: 5px; text-align: center;">
                        <h4 style="margin: 0; color: #d32f2f;">{stats.get('total_malware_found', 0)}</h4>
                        <p style="margin: 5px 0 0 0; color: #666;">Malware Detected</p>
                    </div>
                </div>
                
                <div style="background: #e8f5e8; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <p><strong>✅ System Status:</strong> All monitoring systems are operational.</p>
                </div>
                
                <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
                <p style="color: #666; font-size: 12px;">
                    This report was automatically generated by RTDS (Real-Time Threat Detection System).<br>
                    RTDS Security Team
                </p>
            </div>
        </body>
        </html>
        """
        
        email_data = {
            'subject': subject,
            'body': body,
            'html_body': html_body
        }
        
        self.email_queue.put(email_data)
    
    def send_malware_alert(self, filename: str, detections: int, action: str):
        """Send malware detection alert"""
        if not self.is_enabled:
            return
        
        subject = f"Malware Detected: {filename}"
        
        body = f"""
RTDS Malware Alert

File: {filename}
Detections: {detections} engines
Action Taken: {action}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

This file has been identified as malicious by multiple antivirus engines.
Immediate action has been taken to secure your system.

---
RTDS Security Team
        """.strip()
        
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #d32f2f;">🦠 Malware Detection Alert</h2>
                
                <div style="background: #ffebee; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #d32f2f;">
                    <p><strong>File:</strong> {filename}</p>
                    <p><strong>Detections:</strong> {detections} antivirus engines</p>
                    <p><strong>Action Taken:</strong> {action}</p>
                    <p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                
                <div style="background: #fff3e0; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <p><strong>⚠️ Security Notice:</strong> This file has been identified as malicious by multiple antivirus engines. Immediate action has been taken to secure your system.</p>
                </div>
                
                <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
                <p style="color: #666; font-size: 12px;">
                    This is an automated alert from RTDS (Real-Time Threat Detection System).<br>
                    RTDS Security Team
                </p>
            </div>
        </body>
        </html>
        """
        
        email_data = {
            'subject': subject,
            'body': body,
            'html_body': html_body
        }
        
        self.email_queue.put(email_data)
    
    def test_connection(self) -> bool:
        """Test SMTP connection"""
        if not self.is_enabled:
            return False
        
        try:
            context = ssl.create_default_context()
            
            with smtplib.SMTP(self.config['smtp_server'], self.config['smtp_port']) as server:
                if self.config['use_tls']:
                    server.starttls(context=context)
                elif self.config['use_ssl']:
                    server = smtplib.SMTP_SSL(self.config['smtp_server'], self.config['smtp_port'], context=context)
                
                server.login(self.config['username'], self.config['password'])
            
            print("[✓] SMTP connection test successful")
            return True
            
        except Exception as e:
            print(f"[!] SMTP connection test failed: {e}")
            return False
    
    def get_status(self) -> Dict:
        """Get email notifier status"""
        return {
            'enabled': self.is_enabled,
            'smtp_server': self.config['smtp_server'],
            'smtp_port': self.config['smtp_port'],
            'from_email': self.config['from_email'],
            'to_emails': self.config['to_emails'],
            'queue_size': self.email_queue.qsize()
        }

# Example usage and configuration
if __name__ == "__main__":
    # Test email notifier
    notifier = EmailNotifier()
    
    if notifier.is_enabled:
        print("Email notifier is enabled")
        print(f"Status: {notifier.get_status()}")
        
        # Test connection
        if notifier.test_connection():
            # Send test alert
            notifier.send_alert(
                alert_type="TEST",
                source="192.168.1.100",
                details="This is a test alert from RTDS",
                severity="Low"
            )
            print("Test alert sent!")
    else:
        print("Email notifier is disabled")
        print("Configure email settings in email_config.json or environment variables")
