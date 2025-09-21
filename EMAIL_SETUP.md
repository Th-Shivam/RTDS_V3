# 📧 RTDS Email Notifications Setup Guide

## Overview
RTDS now includes comprehensive email notification capabilities for real-time security alerts, malware detection, and daily reports.

## 🚀 Quick Setup

### Method 1: Configuration File (Recommended)
1. Edit `email_config.json`:
```json
{
  "enabled": true,
  "smtp_server": "smtp.gmail.com",
  "smtp_port": 587,
  "username": "your_email@gmail.com",
  "password": "your_app_password",
  "from_email": "rtds@yourdomain.com",
  "to_emails": [
    "admin@yourdomain.com",
    "security@yourdomain.com"
  ],
  "use_tls": true,
  "use_ssl": false,
  "subject_prefix": "[RTDS Alert]"
}
```

### Method 2: Environment Variables
Set these environment variables:
```bash
export EMAIL_ENABLED=true
export SMTP_SERVER=smtp.gmail.com
export SMTP_PORT=587
export SMTP_USERNAME=your_email@gmail.com
export SMTP_PASSWORD=your_app_password
export FROM_EMAIL=rtds@yourdomain.com
export TO_EMAILS=admin@yourdomain.com,security@yourdomain.com
```

## 📧 Supported Email Providers

### Gmail
- **SMTP Server:** smtp.gmail.com
- **Port:** 587 (TLS) or 465 (SSL)
- **Authentication:** Use App Password (not regular password)
- **Setup:** Enable 2FA and generate App Password

### Outlook/Hotmail
- **SMTP Server:** smtp-mail.outlook.com
- **Port:** 587 (TLS)
- **Authentication:** Regular email/password

### Yahoo Mail
- **SMTP Server:** smtp.mail.yahoo.com
- **Port:** 587 (TLS) or 465 (SSL)
- **Authentication:** Use App Password

### Custom SMTP
- Configure your own SMTP server settings
- Ensure proper authentication and security

## 🧪 Testing Email Setup

### Test Script
Run the test script to verify email configuration:
```bash
python test_email.py
```

### Dashboard Test
1. Start RTDS Dashboard: `python app.py`
2. Open http://localhost:5000
3. Click "Test Email" button in Email Notifications section
4. Check your email inbox

## 📨 Email Types

### 1. Security Alerts
- **DDoS Attacks:** High-priority alerts for volumetric attacks
- **SYN Floods:** TCP SYN flood detection alerts
- **MITM/ARP Spoofing:** Man-in-the-middle attack alerts
- **Severity Levels:** High, Medium, Low

### 2. Malware Alerts
- **File Detection:** When malicious files are found
- **Quarantine Actions:** File quarantine/deletion notifications
- **Detection Count:** Number of antivirus engines that flagged the file

### 3. Daily Reports
- **System Statistics:** Packets analyzed, attacks detected
- **File Scan Results:** Files scanned, malware found
- **System Status:** Uptime, current threats
- **Scheduled:** Can be sent manually or automated

## 🎛️ Dashboard Features

### Email Status Panel
- **Connection Status:** Shows if email is enabled/disabled
- **SMTP Server:** Display current SMTP configuration
- **Queue Size:** Number of pending emails
- **Recipients:** List of email recipients

### Test Functions
- **Test Email:** Send immediate test alert
- **Daily Report:** Generate and send daily security report
- **Real-time Status:** Live email queue monitoring

## 🔧 Advanced Configuration

### Email Templates
All emails use HTML templates with:
- **Professional Styling:** Clean, responsive design
- **Color Coding:** Severity-based color schemes
- **Rich Content:** Detailed information and formatting
- **Action Buttons:** Clear call-to-action elements

### Queue Management
- **Asynchronous Processing:** Non-blocking email sending
- **Retry Logic:** Automatic retry on failures
- **Queue Monitoring:** Real-time queue status
- **Error Handling:** Graceful failure management

### Security Features
- **TLS/SSL Support:** Encrypted email transmission
- **Authentication:** Secure SMTP authentication
- **Rate Limiting:** Prevents email spam
- **Error Logging:** Comprehensive error tracking

## 🚨 Alert Examples

### DDoS Attack Alert
```
Subject: [RTDS Alert] DDoS Attack Alert from 192.168.1.100

🚨 RTDS Security Alert

Alert Type: DDoS Attack
Source: 192.168.1.100
Severity: High
Time: 2024-01-20 14:30:25

Details:
Volumetric DDoS attack detected from 192.168.1.100 with 150 packets per second. 
This exceeds the threshold of 100 pps.

⚠️ Action Required: Please investigate this security incident immediately.
```

### Malware Detection Alert
```
Subject: [RTDS Alert] Malware Detected: suspicious_file.exe

🦠 Malware Detection Alert

File: suspicious_file.exe
Detections: 15 antivirus engines
Action Taken: QUARANTINED
Time: 2024-01-20 14:30:25

⚠️ Security Notice: This file has been identified as malicious by multiple 
antivirus engines. Immediate action has been taken to secure your system.
```

## 🔍 Troubleshooting

### Common Issues

#### 1. Authentication Failed
- **Gmail:** Use App Password, not regular password
- **2FA:** Must be enabled for Gmail
- **Credentials:** Double-check username/password

#### 2. Connection Timeout
- **Firewall:** Check if SMTP port is blocked
- **Network:** Verify internet connectivity
- **Port:** Try different ports (587 vs 465)

#### 3. Emails Not Received
- **Spam Folder:** Check spam/junk folder
- **Recipients:** Verify email addresses
- **Queue:** Check if emails are in queue

### Debug Mode
Enable debug logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Test Connection
```python
from email_notifier import EmailNotifier
notifier = EmailNotifier()
notifier.test_connection()
```

## 📊 Monitoring

### Dashboard Integration
- **Real-time Status:** Live email system status
- **Queue Monitoring:** Pending email count
- **Error Tracking:** Failed email attempts
- **Performance Metrics:** Email delivery statistics

### Log Files
- **Email Logs:** Detailed email sending logs
- **Error Logs:** SMTP connection errors
- **Queue Logs:** Email queue processing
- **Alert Logs:** Security alert notifications

## 🎯 Best Practices

### Security
- **Use App Passwords:** Never use regular passwords
- **Enable 2FA:** Two-factor authentication
- **Secure SMTP:** Use TLS/SSL encryption
- **Regular Updates:** Keep credentials updated

### Performance
- **Queue Management:** Monitor email queue size
- **Rate Limiting:** Avoid overwhelming SMTP server
- **Error Handling:** Implement proper retry logic
- **Monitoring:** Track email delivery success

### Maintenance
- **Regular Testing:** Test email functionality
- **Credential Rotation:** Update passwords regularly
- **Log Monitoring:** Check email logs for issues
- **Backup Configuration:** Keep email config backed up

## 🚀 Production Deployment

### Environment Setup
1. **Production SMTP:** Use dedicated email service
2. **Monitoring:** Set up email delivery monitoring
3. **Backup:** Configure backup email providers
4. **Security:** Implement proper authentication

### Scaling
- **Multiple Recipients:** Add more email addresses
- **Load Balancing:** Distribute email load
- **Queue Management:** Handle high email volumes
- **Performance:** Optimize email processing

## 📞 Support

For issues with email notifications:
1. Check the troubleshooting section
2. Review email logs
3. Test with the test script
4. Verify SMTP configuration
5. Check network connectivity

---

**RTDS Email Notifications** - Keep your security team informed with real-time alerts! 🛡️📧
