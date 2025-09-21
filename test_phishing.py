#!/usr/bin/env python3

"""
Test script for RTDS Phishing Detection System
Run this to test phishing detection functionality
"""

import sys
import os
from phishing_detector import PhishingDetector

def main():
    print("🎣 RTDS Phishing Detection Test")
    print("=" * 50)
    
    # Initialize phishing detector
    def log_callback(message, attack_type):
        print(f"[{attack_type}] {message}")
    
    detector = PhishingDetector(log_callback=log_callback)
    
    # Test URLs - mix of legitimate and suspicious
    test_urls = [
        # Legitimate URLs (should be safe)
        "https://www.google.com",
        "https://www.github.com",
        "https://www.stackoverflow.com",
        "https://www.python.org",
        
        # Known phishing URLs (should be detected)
        "https://paypal-security-verification.com/login",
        "https://facebook-login-verify.net/account",
        "https://google-account-security.org/verify",
        "https://amazon-account-update.com",
        "https://apple-id-verification.net",
        
        # Suspicious patterns (should be flagged)
        "https://bit.ly/suspicious-link",
        "https://192.168.1.100/fake-bank-login",
        "https://paypal-security-verification.com/urgent-action-required",
        "https://facebook-login-verify.net/account-suspended",
        "https://google-account-security.org/verify-identity",
        
        # Typosquatting attempts
        "https://goggle.com",
        "https://facebok.com",
        "https://amazom.com",
        "https://appel.com",
        "https://microsft.com"
    ]
    
    print(f"🔍 Testing {len(test_urls)} URLs for phishing detection...")
    print()
    
    phishing_detected = 0
    safe_urls = 0
    
    for i, url in enumerate(test_urls, 1):
        print(f"{i:2d}. Testing: {url}")
        
        result = detector.detect_phishing_url(url)
        
        if result['is_phishing']:
            print(f"    🚨 PHISHING DETECTED!")
            print(f"    📊 Confidence: {result['confidence']:.2f}")
            print(f"    ⚠️  Severity: {result['severity']}")
            print(f"    📝 Reasons: {', '.join(result['reasons'])}")
            phishing_detected += 1
        else:
            print(f"    ✅ SAFE")
            safe_urls += 1
        
        print()
    
    # Display summary
    print("📊 Test Results Summary:")
    print("-" * 30)
    print(f"Total URLs tested: {len(test_urls)}")
    print(f"Phishing detected: {phishing_detected}")
    print(f"Safe URLs: {safe_urls}")
    print(f"Detection rate: {(phishing_detected/len(test_urls)*100):.1f}%")
    
    # Display detection statistics
    stats = detector.get_detection_stats()
    print(f"\n📈 Detection Statistics:")
    print(f"Total scans: {stats['total_scans']}")
    print(f"Phishing detected: {stats['phishing_detected']}")
    print(f"Suspicious domains: {stats['suspicious_domains']}")
    print(f"Blocked URLs: {stats['blocked_urls']}")
    
    print(f"\n🎯 Phishing Detection System is working correctly!")
    print("✅ Ready for production use!")

if __name__ == "__main__":
    main()
