#!/usr/bin/env python3

import argparse
import sys
import os
from ip_blocker import IPBlocker

def main():
    parser = argparse.ArgumentParser(description='RTDS IP Blocker Management Tool')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Block IP command
    block_parser = subparsers.add_parser('block', help='Block an IP address')
    block_parser.add_argument('ip', help='IP address to block')
    block_parser.add_argument('--reason', default='Manual block', help='Reason for blocking')
    block_parser.add_argument('--duration', type=int, default=3600, help='Block duration in seconds (0 for permanent)')
    
    # Unblock IP command
    unblock_parser = subparsers.add_parser('unblock', help='Unblock an IP address')
    unblock_parser.add_argument('ip', help='IP address to unblock')
    
    # List blocked IPs
    list_parser = subparsers.add_parser('list', help='List all blocked IPs')
    
    # Show statistics
    stats_parser = subparsers.add_parser('stats', help='Show blocking statistics')
    
    # Emergency unblock all
    emergency_parser = subparsers.add_parser('emergency', help='Emergency unblock all IPs')
    
    # Add to whitelist
    whitelist_parser = subparsers.add_parser('whitelist', help='Add IP/range to whitelist')
    whitelist_parser.add_argument('ip_or_range', help='IP address or CIDR range to whitelist')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Check root privileges for iptables operations
    if os.geteuid() != 0:
        print("⚠️  Warning: Not running as root. Some operations may fail.")
        print("   Run with: sudo python3 manage_blocks.py")
    
    # Initialize IP blocker
    def log_callback(message, attack_type):
        print(f"[{attack_type}] {message}")
    
    blocker = IPBlocker(log_callback=log_callback)
    
    try:
        if args.command == 'block':
            success = blocker.block_ip(args.ip, args.reason, args.duration)
            if success:
                duration_str = f"{args.duration}s" if args.duration > 0 else "permanent"
                print(f"✅ Successfully blocked {args.ip} for {duration_str}")
            else:
                print(f"❌ Failed to block {args.ip}")
                sys.exit(1)
        
        elif args.command == 'unblock':
            success = blocker.unblock_ip(args.ip)
            if success:
                print(f"✅ Successfully unblocked {args.ip}")
            else:
                print(f"❌ Failed to unblock {args.ip}")
                sys.exit(1)
        
        elif args.command == 'list':
            blocked_ips = blocker.get_blocked_ips()
            if not blocked_ips:
                print("📋 No IPs are currently blocked")
            else:
                print(f"📋 Currently blocked IPs ({len(blocked_ips)}):")
                print("-" * 80)
                for ip, info in blocked_ips.items():
                    import time
                    from datetime import datetime
                    
                    blocked_time = datetime.fromtimestamp(info['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
                    expires = info.get('expires', 0)
                    
                    if expires > 0:
                        remaining = max(0, expires - time.time())
                        duration_info = f"Expires in {int(remaining)}s"
                    else:
                        duration_info = "Permanent"
                    
                    print(f"🚫 {ip:<15} | {info['reason']:<25} | {blocked_time} | {duration_info}")
        
        elif args.command == 'stats':
            stats = blocker.get_block_stats()
            print("📊 IP Blocking Statistics:")
            print("-" * 40)
            print(f"Active blocks: {stats['active_blocks']}")
            print(f"Temporary blocks: {stats['temporary_blocks']}")
            print(f"Permanent blocks: {stats['permanent_blocks']}")
            print(f"Whitelist entries: {stats['whitelist_entries']}")
            
            if stats['block_reasons']:
                print("\nBlock reasons:")
                for reason, count in stats['block_reasons'].items():
                    print(f"  • {reason}: {count}")
        
        elif args.command == 'emergency':
            confirm = input("⚠️  This will unblock ALL IPs. Are you sure? (yes/no): ")
            if confirm.lower() == 'yes':
                blocker.emergency_unblock_all()
                print("🚨 Emergency unblock completed - All IP blocks removed")
            else:
                print("❌ Emergency unblock cancelled")
        
        elif args.command == 'whitelist':
            blocker.add_to_whitelist(args.ip_or_range)
            print(f"✅ Added {args.ip_or_range} to whitelist")
    
    except KeyboardInterrupt:
        print("\n⚠️  Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
