#!/usr/bin/env python3

import re
import requests
import hashlib
import time
import json
import os
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Tuple, Optional
import threading
from collections import defaultdict
import dns.resolver
import socket
from datetime import datetime, timedelta

class PhishingDetector:
    """
    Advanced Phishing Detection System for RTDS
    Detects phishing attempts through URL analysis, domain reputation, and content analysis
    """
    
    def __init__(self, log_callback=None):
        self.log_callback = log_callback
        self.suspicious_domains = set()
        self.known_phishing_urls = set()
        self.detection_stats = {
            'total_scans': 0,
            'phishing_detected': 0,
            'suspicious_domains': 0,
            'blocked_urls': 0
        }
        
        # Load phishing databases
        self._load_phishing_databases()
        self._setup_detection_patterns()
        
        # DNS cache for performance
        self.dns_cache = {}
        self.cache_expiry = {}
        
    def _load_phishing_databases(self):
        """Load known phishing URLs and suspicious domains"""
        try:
            # Load from local database file
            if os.path.exists('phishing_database.json'):
                with open('phishing_database.json', 'r') as f:
                    data = json.load(f)
                    self.known_phishing_urls = set(data.get('phishing_urls', []))
                    self.suspicious_domains = set(data.get('suspicious_domains', []))
            
            # Load from online sources (optional)
            self._load_online_phishing_database()
            
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"Error loading phishing database: {e}", "PHISHING_DB")
    
    def _load_online_phishing_database(self):
        """Load phishing URLs from online sources"""
        try:
            # Example: Load from PhishTank API (requires API key)
            # This is a placeholder for real implementation
            pass
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"Error loading online phishing database: {e}", "PHISHING_DB")
    
    def _setup_detection_patterns(self):
        """Setup regex patterns for phishing detection"""
        self.phishing_patterns = {
            # Common phishing keywords
            'keywords': [
                r'verify\s+account', r'update\s+information', r'suspended\s+account',
                r'urgent\s+action', r'click\s+here', r'confirm\s+identity',
                r'security\s+alert', r'account\s+locked', r'payment\s+required'
            ],
            
            # Suspicious URL patterns
            'url_patterns': [
                r'bit\.ly', r'tinyurl\.com', r'short\.link', r't\.co',
                r'goo\.gl', r'is\.gd', r'v\.gd', r'ow\.ly'
            ],
            
            # Domain spoofing patterns
            'domain_spoofing': [
                r'paypal-security', r'facebook-login', r'google-account',
                r'apple-id', r'microsoft-support', r'amazon-account'
            ],
            
            # IP address patterns (suspicious)
            'ip_patterns': [
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            ]
        }
    
    def detect_phishing_url(self, url: str) -> Dict:
        """
        Comprehensive phishing detection for a URL
        
        Args:
            url: URL to analyze
            
        Returns:
            Dict with detection results
        """
        self.detection_stats['total_scans'] += 1
        
        result = {
            'url': url,
            'is_phishing': False,
            'confidence': 0.0,
            'reasons': [],
            'severity': 'Low',
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Parse URL
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            # Check against known phishing database
            if self._check_known_phishing(url):
                result['is_phishing'] = True
                result['confidence'] = 1.0
                result['reasons'].append('Known phishing URL in database')
                result['severity'] = 'Critical'
                return result
            
            # Check domain reputation
            domain_score = self._analyze_domain_reputation(domain)
            if domain_score > 0.7:
                result['is_phishing'] = True
                result['confidence'] = domain_score
                result['reasons'].append('Suspicious domain reputation')
                result['severity'] = 'High'
            
            # Check URL structure
            url_analysis = self._analyze_url_structure(url)
            if url_analysis['suspicious']:
                result['confidence'] = max(result['confidence'], url_analysis['score'])
                result['reasons'].extend(url_analysis['reasons'])
                if url_analysis['score'] > 0.6:
                    result['is_phishing'] = True
                    result['severity'] = 'High'
            
            # Check for suspicious patterns
            pattern_analysis = self._check_suspicious_patterns(url)
            if pattern_analysis['suspicious']:
                result['confidence'] = max(result['confidence'], pattern_analysis['score'])
                result['reasons'].extend(pattern_analysis['reasons'])
                if pattern_analysis['score'] > 0.5:
                    result['is_phishing'] = True
                    result['severity'] = 'Medium'
            
            # Check DNS records
            dns_analysis = self._analyze_dns_records(domain)
            if dns_analysis['suspicious']:
                result['confidence'] = max(result['confidence'], dns_analysis['score'])
                result['reasons'].extend(dns_analysis['reasons'])
                if dns_analysis['score'] > 0.6:
                    result['is_phishing'] = True
                    result['severity'] = 'High'
            
            # Final determination
            if result['confidence'] > 0.8:
                result['severity'] = 'Critical'
            elif result['confidence'] > 0.6:
                result['severity'] = 'High'
            elif result['confidence'] > 0.4:
                result['severity'] = 'Medium'
            else:
                result['severity'] = 'Low'
            
            if result['is_phishing']:
                self.detection_stats['phishing_detected'] += 1
                self._log_phishing_detection(result)
            
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"Error in phishing detection: {e}", "PHISHING_ERROR")
        
        return result
    
    def _check_known_phishing(self, url: str) -> bool:
        """Check if URL is in known phishing database"""
        url_hash = hashlib.md5(url.encode()).hexdigest()
        return url in self.known_phishing_urls or url_hash in self.known_phishing_urls
    
    def _analyze_domain_reputation(self, domain: str) -> float:
        """Analyze domain reputation score"""
        score = 0.0
        
        # Check if domain is in suspicious list
        if domain in self.suspicious_domains:
            score += 0.8
        
        # Check domain age (new domains are more suspicious)
        try:
            # This would require WHOIS lookup in real implementation
            # For now, check for common suspicious patterns
            if re.search(r'\d{4,}', domain):  # Domains with many numbers
                score += 0.3
            
            if len(domain.split('.')) > 3:  # Very long domain names
                score += 0.2
                
        except:
            pass
        
        # Check for typosquatting
        if self._check_typosquatting(domain):
            score += 0.6
        
        return min(score, 1.0)
    
    def _check_typosquatting(self, domain: str) -> bool:
        """Check for typosquatting attempts"""
        popular_domains = [
            'google.com', 'facebook.com', 'amazon.com', 'paypal.com',
            'apple.com', 'microsoft.com', 'netflix.com', 'twitter.com'
        ]
        
        for popular_domain in popular_domains:
            if self._calculate_similarity(domain, popular_domain) > 0.8:
                return True
        
        return False
    
    def _calculate_similarity(self, str1: str, str2: str) -> float:
        """Calculate string similarity using Levenshtein distance"""
        if len(str1) < len(str2):
            str1, str2 = str2, str1
        
        if len(str2) == 0:
            return 0.0
        
        distance = self._levenshtein_distance(str1, str2)
        return 1 - (distance / max(len(str1), len(str2)))
    
    def _levenshtein_distance(self, str1: str, str2: str) -> int:
        """Calculate Levenshtein distance between two strings"""
        if len(str1) < len(str2):
            return self._levenshtein_distance(str2, str1)
        
        if len(str2) == 0:
            return len(str1)
        
        previous_row = list(range(len(str2) + 1))
        for i, c1 in enumerate(str1):
            current_row = [i + 1]
            for j, c2 in enumerate(str2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _analyze_url_structure(self, url: str) -> Dict:
        """Analyze URL structure for suspicious patterns"""
        result = {
            'suspicious': False,
            'score': 0.0,
            'reasons': []
        }
        
        parsed_url = urlparse(url)
        
        # Check for suspicious URL patterns
        for pattern in self.phishing_patterns['url_patterns']:
            if re.search(pattern, url, re.IGNORECASE):
                result['suspicious'] = True
                result['score'] += 0.3
                result['reasons'].append('Contains suspicious URL pattern')
        
        # Check for IP addresses in URL
        for pattern in self.phishing_patterns['ip_patterns']:
            if re.search(pattern, url):
                result['suspicious'] = True
                result['score'] += 0.4
                result['reasons'].append('Contains IP address instead of domain')
        
        # Check for excessive subdomains
        if parsed_url.netloc.count('.') > 3:
            result['suspicious'] = True
            result['score'] += 0.2
            result['reasons'].append('Excessive subdomains')
        
        # Check for suspicious characters
        if re.search(r'[^\w\.\-]', parsed_url.netloc):
            result['suspicious'] = True
            result['score'] += 0.3
            result['reasons'].append('Contains suspicious characters')
        
        return result
    
    def _check_suspicious_patterns(self, url: str) -> Dict:
        """Check for suspicious patterns in URL"""
        result = {
            'suspicious': False,
            'score': 0.0,
            'reasons': []
        }
        
        # Check for domain spoofing
        for pattern in self.phishing_patterns['domain_spoofing']:
            if re.search(pattern, url, re.IGNORECASE):
                result['suspicious'] = True
                result['score'] += 0.5
                result['reasons'].append('Potential domain spoofing')
        
        # Check for suspicious keywords
        for pattern in self.phishing_patterns['keywords']:
            if re.search(pattern, url, re.IGNORECASE):
                result['suspicious'] = True
                result['score'] += 0.2
                result['reasons'].append('Contains suspicious keywords')
        
        return result
    
    def _analyze_dns_records(self, domain: str) -> Dict:
        """Analyze DNS records for suspicious patterns"""
        result = {
            'suspicious': False,
            'score': 0.0,
            'reasons': []
        }
        
        try:
            # Check cache first
            if domain in self.dns_cache:
                if time.time() < self.cache_expiry.get(domain, 0):
                    return self.dns_cache[domain]
            
            # Check if domain resolves
            try:
                socket.gethostbyname(domain)
            except socket.gaierror:
                result['suspicious'] = True
                result['score'] += 0.3
                result['reasons'].append('Domain does not resolve')
                return result
            
            # Check MX records (legitimate domains usually have MX)
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                if not mx_records:
                    result['suspicious'] = True
                    result['score'] += 0.2
                    result['reasons'].append('No MX records found')
            except:
                pass
            
            # Cache the result
            self.dns_cache[domain] = result
            self.cache_expiry[domain] = time.time() + 3600  # Cache for 1 hour
            
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"DNS analysis error for {domain}: {e}", "PHISHING_DNS")
        
        return result
    
    def _log_phishing_detection(self, result: Dict):
        """Log phishing detection result"""
        if self.log_callback:
            message = f"🚨 PHISHING DETECTED: {result['url']} - Confidence: {result['confidence']:.2f} - Severity: {result['severity']}"
            self.log_callback(message, "PHISHING")
    
    def scan_network_traffic(self, packet_data: Dict) -> List[Dict]:
        """Scan network traffic for phishing attempts"""
        detections = []
        
        try:
            # Extract URLs from HTTP traffic
            if 'http' in packet_data.get('protocol', '').lower():
                urls = self._extract_urls_from_packet(packet_data)
                
                for url in urls:
                    result = self.detect_phishing_url(url)
                    if result['is_phishing']:
                        detections.append(result)
            
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"Error scanning network traffic: {e}", "PHISHING_SCAN")
        
        return detections
    
    def _extract_urls_from_packet(self, packet_data: Dict) -> List[str]:
        """Extract URLs from network packet data"""
        urls = []
        
        try:
            # This is a simplified version - real implementation would parse HTTP headers
            payload = packet_data.get('payload', '')
            
            # Extract URLs using regex
            url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
            found_urls = re.findall(url_pattern, payload)
            urls.extend(found_urls)
            
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"Error extracting URLs: {e}", "PHISHING_EXTRACT")
        
        return urls
    
    def add_phishing_url(self, url: str, reason: str = "Manual addition"):
        """Add URL to phishing database"""
        self.known_phishing_urls.add(url)
        self._save_phishing_database()
        
        if self.log_callback:
            self.log_callback(f"Added phishing URL to database: {url} - Reason: {reason}", "PHISHING_DB")
    
    def _save_phishing_database(self):
        """Save phishing database to file"""
        try:
            data = {
                'phishing_urls': list(self.known_phishing_urls),
                'suspicious_domains': list(self.suspicious_domains),
                'last_updated': datetime.now().isoformat()
            }
            
            with open('phishing_database.json', 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"Error saving phishing database: {e}", "PHISHING_DB")
    
    def get_detection_stats(self) -> Dict:
        """Get phishing detection statistics"""
        return self.detection_stats.copy()
    
    def get_recent_detections(self, limit: int = 50) -> List[Dict]:
        """Get recent phishing detections"""
        # This would be implemented with a proper database in production
        return []

# Example usage and testing
if __name__ == "__main__":
    def log_callback(message, attack_type):
        print(f"[{attack_type}] {message}")
    
    # Initialize phishing detector
    detector = PhishingDetector(log_callback=log_callback)
    
    # Test URLs
    test_urls = [
        "https://paypal-security-verification.com/login",
        "https://facebook-login-verify.net/account",
        "https://google-account-security.org/verify",
        "https://bit.ly/suspicious-link",
        "https://192.168.1.100/fake-bank-login"
    ]
    
    print("🔍 Testing Phishing Detection System")
    print("=" * 50)
    
    for url in test_urls:
        result = detector.detect_phishing_url(url)
        print(f"\nURL: {url}")
        print(f"Phishing: {result['is_phishing']}")
        print(f"Confidence: {result['confidence']:.2f}")
        print(f"Severity: {result['severity']}")
        print(f"Reasons: {', '.join(result['reasons'])}")
    
    print(f"\n📊 Detection Stats: {detector.get_detection_stats()}")
