#!/usr/bin/env python3

import sys
import argparse
from ip_blocker import IPBlocker
from datetime import datetime

def log_callback(message, category):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{category}] {message}")

def list_blocked_ips(blocker):
    """List all currently blocked IPs"""
    blocked_ips = blocker.get_blocked_ips()
    
    if not blocked_ips:
        print("No IPs are currently blocked.")
        return
    
    print(f"\n📋 Currently Blocked IPs ({len(blocked_ips)}):")
    print("-" * 80)
    print(f"{'IP Address':<15} {'Reason':<30} {'Duration':<10} {'Status'}")
    print("-" * 80)
    
    current_time = datetime.now().timestamp()
    
    for ip, info in blocked_ips.items():
        reason = info.get('reason', 'Unknown')[:28]
        duration = info.get('duration', 0)
        expires = info.get('expires', 0)
        
        if duration == 0:
            duration_str = "Permanent"
            status = "Active"
        else:
            if expires > current_time:
                remaining = int(expires - current_time)
                duration_str = f"{duration}s"
                status = f"{remaining}s left"
            else:
                duration_str = f"{duration}s"
                status = "Expired"
        
        print(f"{ip:<15} {reason:<30} {duration_str:<10} {status}")

def block_ip_interactive(blocker):
    """Interactive IP blocking"""
    ip = input("Enter IP address to block: ").strip()
    reason = input("Enter reason (default: Manual block): ").strip() or "Manual block"
    
    duration_input = input("Enter duration in seconds (0 for permanent, default: 3600): ").strip()
    try:
        duration = int(duration_input) if duration_input else 3600
    except ValueError:
        duration = 3600
    
    result = blocker.block_ip(ip, reason, duration)
    if result:
        print(f"✅ Successfully blocked {ip}")
    else:
        print(f"❌ Failed to block {ip}")

def unblock_ip_interactive(blocker):
    """Interactive IP unblocking"""
    # Show currently blocked IPs
    list_blocked_ips(blocker)
    
    ip = input("\nEnter IP address to unblock: ").strip()
    result = blocker.unblock_ip(ip)
    if result:
        print(f"✅ Successfully unblocked {ip}")
    else:
        print(f"❌ Failed to unblock {ip}")

def show_stats(blocker):
    """Show blocking statistics"""
    stats = blocker.get_block_stats()
    
    print("\n📊 IP Blocking Statistics:")
    print("-" * 40)
    print(f"Active blocks: {stats['active_blocks']}")
    print(f"Temporary blocks: {stats['temporary_blocks']}")
    print(f"Permanent blocks: {stats['permanent_blocks']}")
    print(f"Whitelist entries: {stats['whitelist_entries']}")
    
    if stats['block_reasons']:
        print("\nBlock reasons:")
        for reason, count in stats['block_reasons'].items():
            print(f"  • {reason}: {count}")

def cleanup_expired(blocker):
    """Clean up expired blocks"""
    print("🧹 Cleaning up expired blocks...")
    blocker.cleanup_expired_blocks()
    print("✅ Cleanup completed")

def main():
    parser = argparse.ArgumentParser(description="RTDS IP Block Management")
    parser.add_argument("--list", "-l", action="store_true", help="List blocked IPs")
    parser.add_argument("--block", "-b", metavar="IP", help="Block an IP address")
    parser.add_argument("--unblock", "-u", metavar="IP", help="Unblock an IP address")
    parser.add_argument("--reason", "-r", default="Manual block", help="Reason for blocking")
    parser.add_argument("--duration", "-d", type=int, default=3600, help="Block duration in seconds")
    parser.add_argument("--stats", "-s", action="store_true", help="Show statistics")
    parser.add_argument("--cleanup", "-c", action="store_true", help="Clean up expired blocks")
    parser.add_argument("--emergency-unblock", action="store_true", help="Emergency unblock all IPs")
    parser.add_argument("--interactive", "-i", action="store_true", help="Interactive mode")
    
    args = parser.parse_args()
    
    # Initialize blocker
    blocker = IPBlocker(log_callback=log_callback)
    
    if args.emergency_unblock:
        print("🚨 EMERGENCY UNBLOCK - This will remove ALL IP blocks!")
        confirm = input("Are you sure? (yes/no): ").strip().lower()
        if confirm == "yes":
            blocker.emergency_unblock_all()
        else:
            print("Operation cancelled.")
        return
    
    if args.interactive:
        while True:
            print("\n🛡️ RTDS IP Block Manager")
            print("1. List blocked IPs")
            print("2. Block an IP")
            print("3. Unblock an IP")
            print("4. Show statistics")
            print("5. Cleanup expired blocks")
            print("6. Exit")
            
            choice = input("\nSelect option (1-6): ").strip()
            
            if choice == "1":
                list_blocked_ips(blocker)
            elif choice == "2":
                block_ip_interactive(blocker)
            elif choice == "3":
                unblock_ip_interactive(blocker)
            elif choice == "4":
                show_stats(blocker)
            elif choice == "5":
                cleanup_expired(blocker)
            elif choice == "6":
                print("Goodbye!")
                break
            else:
                print("Invalid option. Please try again.")
        return
    
    if args.list:
        list_blocked_ips(blocker)
    
    if args.block:
        result = blocker.block_ip(args.block, args.reason, args.duration)
        if result:
            print(f"✅ Successfully blocked {args.block}")
        else:
            print(f"❌ Failed to block {args.block}")
    
    if args.unblock:
        result = blocker.unblock_ip(args.unblock)
        if result:
            print(f"✅ Successfully unblocked {args.unblock}")
        else:
            print(f"❌ Failed to unblock {args.unblock}")
    
    if args.stats:
        show_stats(blocker)
    
    if args.cleanup:
        cleanup_expired(blocker)
    
    # If no arguments provided, show help
    if len(sys.argv) == 1:
        parser.print_help()

if __name__ == "__main__":
    main()
