#!/usr/bin/env python3

import os
from email_notifier import EmailNotifier

def trigger_test_alert():
    """Manually trigger a test alert"""
    
    # Set environment variable to enable email
    os.environ['EMAIL_ENABLED'] = 'true'
    
    # Initialize email notifier
    notifier = EmailNotifier()
    
    if not notifier.is_enabled:
        print("❌ Email notifications are still disabled")
        return
    
    print("📧 Sending test security alert...")
    
    # Send a test DDoS alert
    notifier.send_alert(
        alert_type="DDoS Attack Detected",
        source="192.168.1.100",
        details="High packet rate detected: 250 packets/second from 192.168.1.100. Threshold exceeded (100 pps).",
        severity="High"
    )
    
    print("✅ Test alert sent! Check your email.")

if __name__ == "__main__":
    trigger_test_alert()
