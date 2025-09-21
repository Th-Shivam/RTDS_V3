#!/usr/bin/env python3

"""
Test script for RTDS Email Notifications
Run this to test email functionality before using in production
"""

import os
import sys
from email_notifier import EmailNotifier

def main():
    print("🧪 RTDS Email Notification Test")
    print("=" * 40)
    
    # Initialize email notifier
    notifier = EmailNotifier()
    
    # Check if email is enabled
    if not notifier.is_enabled:
        print("❌ Email notifications are disabled")
        print("\nTo enable email notifications:")
        print("1. Edit email_config.json with your SMTP settings")
        print("2. Or set environment variables:")
        print("   EMAIL_ENABLED=true")
        print("   SMTP_SERVER=smtp.gmail.com")
        print("   SMTP_PORT=587")
        print("   SMTP_USERNAME=your_email@gmail.com")
        print("   SMTP_PASSWORD=your_app_password")
        print("   FROM_EMAIL=rtds@yourdomain.com")
        print("   TO_EMAILS=admin@yourdomain.com,security@yourdomain.com")
        return
    
    print(f"✅ Email notifications enabled")
    print(f"📧 SMTP Server: {notifier.config['smtp_server']}:{notifier.config['smtp_port']}")
    print(f"📤 From: {notifier.config['from_email']}")
    print(f"📥 To: {', '.join(notifier.config['to_emails'])}")
    print()
    
    # Test SMTP connection
    print("🔍 Testing SMTP connection...")
    if notifier.test_connection():
        print("✅ SMTP connection successful")
    else:
        print("❌ SMTP connection failed")
        print("Check your SMTP settings and credentials")
        return
    
    # Send test alerts
    print("\n📤 Sending test alerts...")
    
    # Test 1: Security Alert
    print("1. Sending security alert...")
    notifier.send_alert(
        alert_type="Test DDoS Attack",
        source="192.168.1.100",
        details="This is a test DDoS attack alert from RTDS. The system detected 150 packets per second from 192.168.1.100, exceeding the threshold of 100 pps.",
        severity="High"
    )
    
    # Test 2: Malware Alert
    print("2. Sending malware alert...")
    notifier.send_malware_alert(
        filename="suspicious_file.exe",
        detections=15,
        action="QUARANTINED"
    )
    
    # Test 3: Daily Report
    print("3. Sending daily report...")
    test_stats = {
        'uptime': '02:30:45',
        'total_packets': 15420,
        'total_attacks': 3,
        'total_files_scanned': 25,
        'total_malware_found': 1,
        'current_threats': 0,
        'network_status': 'MONITORING'
    }
    notifier.send_daily_report(test_stats)
    
    print("\n✅ All test emails sent!")
    print("Check your email inbox for the test messages.")
    print("\nNote: Emails are sent asynchronously, so they may take a few seconds to arrive.")

if __name__ == "__main__":
    main()
