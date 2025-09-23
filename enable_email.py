#!/usr/bin/env python3

import json
import os

def enable_email():
    """Enable email notifications in RTDS"""
    
    # Set environment variable
    os.environ['EMAIL_ENABLED'] = 'true'
    
    # Update config file
    config_file = 'email_config.json'
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        config['enabled'] = True
        
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        print("✅ Email notifications enabled successfully!")
        print(f"📧 SMTP Server: {config['smtp_server']}:{config['smtp_port']}")
        print(f"📤 From: {config['from_email']}")
        print(f"📥 To: {', '.join(config['to_emails'])}")
    else:
        print("❌ email_config.json not found!")

if __name__ == "__main__":
    enable_email()
