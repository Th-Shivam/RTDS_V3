#!/usr/bin/env python3

import os
import time
from email_notifier import EmailNotifier

def test_cooldown():
    """Test email cooldown functionality"""
    
    # Set environment variable to enable email
    os.environ['EMAIL_ENABLED'] = 'true'
    
    # Initialize email notifier
    notifier = EmailNotifier()
    
    if not notifier.is_enabled:
        print("❌ Email notifications are disabled")
        return
    
    print("🧪 Testing Email Cooldown Functionality")
    print("=" * 50)
    print(f"Cooldown Duration: {notifier.cooldown_duration} seconds (5 minutes)")
    print()
    
    # Test same IP multiple times
    test_ip = "192.168.1.100"
    
    print("1. Sending first alert...")
    notifier.send_alert(
        alert_type="DDoS Attack",
        source=test_ip,
        details="First alert - should be sent",
        severity="High"
    )
    
    print("2. Sending second alert immediately (should be blocked)...")
    notifier.send_alert(
        alert_type="DDoS Attack", 
        source=test_ip,
        details="Second alert - should be blocked by cooldown",
        severity="High"
    )
    
    print("3. Sending alert from different IP (should be sent)...")
    notifier.send_alert(
        alert_type="DDoS Attack",
        source="192.168.1.200", 
        details="Alert from different IP - should be sent",
        severity="High"
    )
    
    print("4. Sending different attack type from same IP (should be sent)...")
    notifier.send_alert(
        alert_type="MITM Attack",
        source=test_ip,
        details="Different attack type - should be sent", 
        severity="Medium"
    )
    
    print("\n✅ Cooldown test completed!")
    print("Check your email - you should receive 3 emails, not 4")
    print("The second DDoS alert from the same IP should be blocked")

if __name__ == "__main__":
    test_cooldown()
