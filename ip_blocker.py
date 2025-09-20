#!/usr/bin/env python3

import subprocess
import time
import json
import os
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Optional

class IPBlocker:
    """
    Manages automatic IP blocking using iptables for network threat prevention.
    """
    
    def __init__(self, log_callback=None):
        self.log_callback = log_callback
        self.blocked_ips = {}  # {ip: {'timestamp': time, 'reason': str, 'duration': int}}
        self.whitelist = set()
        self.block_history_file = "blocked_ips.json"
        
        # Load existing blocks and whitelist
        self._load_block_history()
        self._setup_whitelist()
        self._check_root_privileges()
        
    def _check_root_privileges(self):
        """Check if running with root privileges for iptables access"""
        if os.geteuid() != 0:
            if self.log_callback:
                self.log_callback("⚠️ Warning: Not running as root. IP blocking will be limited.", "IP_BLOCKER")
            return False
        return True
    
    def _setup_whitelist(self):
        """Setup default whitelist with local networks and critical IPs"""
        # Local network ranges
        local_ranges = [
            "127.0.0.0/8",    # Loopback
            "10.0.0.0/8",     # Private Class A
            "172.16.0.0/12",  # Private Class B
            "192.168.0.0/16", # Private Class C
            "169.254.0.0/16", # Link-local
        ]
        
        for range_str in local_ranges:
            try:
                network = ipaddress.ip_network(range_str)
                self.whitelist.add(network)
            except:
                pass
                
        # Add DNS servers
        dns_servers = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"]
        for dns in dns_servers:
            try:
                self.whitelist.add(ipaddress.ip_address(dns))
            except:
                pass
    
    def _is_whitelisted(self, ip: str) -> bool:
        """Check if IP is in whitelist"""
        try:
            ip_addr = ipaddress.ip_address(ip)
            
            # Check direct IP whitelist
            if ip_addr in self.whitelist:
                return True
                
            # Check network ranges
            for item in self.whitelist:
                if isinstance(item, ipaddress.IPv4Network) or isinstance(item, ipaddress.IPv6Network):
                    if ip_addr in item:
                        return True
                        
        except:
            pass
        return False
    
    def _load_block_history(self):
        """Load previously blocked IPs from file"""
        try:
            if os.path.exists(self.block_history_file):
                with open(self.block_history_file, 'r') as f:
                    data = json.load(f)
                    self.blocked_ips = data.get('blocked_ips', {})
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"Failed to load block history: {e}", "IP_BLOCKER")
    
    def _save_block_history(self):
        """Save blocked IPs to file"""
        try:
            data = {
                'blocked_ips': self.blocked_ips,
                'last_updated': datetime.now().isoformat()
            }
            with open(self.block_history_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"Failed to save block history: {e}", "IP_BLOCKER")
    
    def _execute_iptables_command(self, command: List[str]) -> bool:
        """Execute iptables command safely"""
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                if self.log_callback:
                    self.log_callback(f"iptables command failed: {result.stderr}", "IP_BLOCKER")
                return False
            return True
        except subprocess.TimeoutExpired:
            if self.log_callback:
                self.log_callback("iptables command timed out", "IP_BLOCKER")
            return False
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"iptables execution error: {e}", "IP_BLOCKER")
            return False
    
    def block_ip(self, ip: str, reason: str = "Malicious activity", duration: int = 3600) -> bool:
        """
        Block an IP address using iptables
        
        Args:
            ip: IP address to block
            reason: Reason for blocking
            duration: Block duration in seconds (0 for permanent)
        """
        # Validate IP
        try:
            ipaddress.ip_address(ip)
        except:
            if self.log_callback:
                self.log_callback(f"Invalid IP address: {ip}", "IP_BLOCKER")
            return False
        
        # Check whitelist
        if self._is_whitelisted(ip):
            if self.log_callback:
                self.log_callback(f"IP {ip} is whitelisted, blocking skipped", "IP_BLOCKER")
            return False
        
        # Check if already blocked
        if ip in self.blocked_ips:
            if self.log_callback:
                self.log_callback(f"IP {ip} is already blocked", "IP_BLOCKER")
            return True
        
        # Create iptables rule
        iptables_cmd = [
            "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"
        ]
        
        if self._execute_iptables_command(iptables_cmd):
            # Record the block
            self.blocked_ips[ip] = {
                'timestamp': time.time(),
                'reason': reason,
                'duration': duration,
                'expires': time.time() + duration if duration > 0 else 0
            }
            
            self._save_block_history()
            
            duration_str = f"{duration}s" if duration > 0 else "permanent"
            if self.log_callback:
                self.log_callback(f"🚫 BLOCKED IP: {ip} - Reason: {reason} - Duration: {duration_str}", "IP_BLOCKED")
            
            return True
        
        return False
    
    def unblock_ip(self, ip: str) -> bool:
        """
        Unblock an IP address
        
        Args:
            ip: IP address to unblock
        """
        if ip not in self.blocked_ips:
            if self.log_callback:
                self.log_callback(f"IP {ip} is not currently blocked", "IP_BLOCKER")
            return False
        
        # Remove iptables rule
        iptables_cmd = [
            "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"
        ]
        
        if self._execute_iptables_command(iptables_cmd):
            # Remove from blocked list
            del self.blocked_ips[ip]
            self._save_block_history()
            
            if self.log_callback:
                self.log_callback(f"✅ UNBLOCKED IP: {ip}", "IP_UNBLOCKED")
            
            return True
        
        return False
    
    def is_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked"""
        return ip in self.blocked_ips
    
    def cleanup_expired_blocks(self):
        """Remove expired IP blocks"""
        current_time = time.time()
        expired_ips = []
        
        for ip, block_info in self.blocked_ips.items():
            expires = block_info.get('expires', 0)
            if expires > 0 and current_time > expires:
                expired_ips.append(ip)
        
        for ip in expired_ips:
            self.unblock_ip(ip)
            if self.log_callback:
                self.log_callback(f"⏰ EXPIRED BLOCK: {ip} - Block duration ended", "IP_EXPIRED")
    
    def get_blocked_ips(self) -> Dict:
        """Get list of currently blocked IPs"""
        return self.blocked_ips.copy()
    
    def add_to_whitelist(self, ip_or_range: str):
        """Add IP or IP range to whitelist"""
        try:
            if '/' in ip_or_range:
                network = ipaddress.ip_network(ip_or_range)
                self.whitelist.add(network)
            else:
                ip_addr = ipaddress.ip_address(ip_or_range)
                self.whitelist.add(ip_addr)
            
            if self.log_callback:
                self.log_callback(f"Added to whitelist: {ip_or_range}", "IP_BLOCKER")
            
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"Failed to add to whitelist: {ip_or_range} - {e}", "IP_BLOCKER")
    
    def emergency_unblock_all(self):
        """Emergency function to unblock all IPs"""
        blocked_ips = list(self.blocked_ips.keys())
        
        for ip in blocked_ips:
            self.unblock_ip(ip)
        
        if self.log_callback:
            self.log_callback(f"🚨 EMERGENCY UNBLOCK: Removed {len(blocked_ips)} IP blocks", "IP_EMERGENCY")
    
    def get_block_stats(self) -> Dict:
        """Get blocking statistics"""
        current_time = time.time()
        active_blocks = len(self.blocked_ips)
        
        # Count by reason
        reasons = {}
        for block_info in self.blocked_ips.values():
            reason = block_info.get('reason', 'Unknown')
            reasons[reason] = reasons.get(reason, 0) + 1
        
        # Count temporary vs permanent
        temporary = sum(1 for b in self.blocked_ips.values() if b.get('expires', 0) > 0)
        permanent = active_blocks - temporary
        
        return {
            'active_blocks': active_blocks,
            'temporary_blocks': temporary,
            'permanent_blocks': permanent,
            'block_reasons': reasons,
            'whitelist_entries': len(self.whitelist)
        }
