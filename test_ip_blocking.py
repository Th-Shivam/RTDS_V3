#!/usr/bin/env python3

import sys
import time
from ip_blocker import IPBlocker

def test_log_callback(message, category):
    print(f"[{category}] {message}")

def main():
    print("🧪 RTDS IP Blocking Test")
    print("=" * 40)
    
    # Initialize IP blocker
    blocker = IPBlocker(log_callback=test_log_callback)
    
    # Test IP (use a safe test IP)
    test_ip = "1.2.3.4"  # Safe test IP
    
    print(f"\n1. Testing IP blocking for: {test_ip}")
    
    # Test blocking
    result = blocker.block_ip(test_ip, "Test block", 60)  # 60 seconds
    if result:
        print("✅ IP blocking successful")
    else:
        print("❌ IP blocking failed")
    
    # Check if blocked
    print(f"\n2. Checking if {test_ip} is blocked...")
    is_blocked = blocker.is_blocked(test_ip)
    print(f"Blocked status: {is_blocked}")
    
    # Show blocked IPs
    print(f"\n3. Currently blocked IPs:")
    blocked_ips = blocker.get_blocked_ips()
    for ip, info in blocked_ips.items():
        print(f"   {ip}: {info['reason']}")
    
    # Test unblocking
    print(f"\n4. Testing IP unblocking for: {test_ip}")
    result = blocker.unblock_ip(test_ip)
    if result:
        print("✅ IP unblocking successful")
    else:
        print("❌ IP unblocking failed")
    
    # Show stats
    print(f"\n5. Blocking statistics:")
    stats = blocker.get_block_stats()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    print("\n🏁 Test completed!")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--emergency-unblock":
        blocker = IPBlocker(log_callback=test_log_callback)
        blocker.emergency_unblock_all()
        print("Emergency unblock completed!")
    else:
        main()
