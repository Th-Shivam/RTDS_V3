#!/usr/bin/env python3

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def test_email():
    # Email configuration
    smtp_server = "smtp.gmail.com"
    port = 587
    sender_email = "anotnet.rudra@gmail.com"
    password = "mukt pryy taml xbew"
    receiver_email = "anotnet.rudrayt@gmail.com"
    
    # Create message
    message = MIMEMultipart("alternative")
    message["Subject"] = "RTDS Test Email"
    message["From"] = sender_email
    message["To"] = receiver_email
    
    # Create the plain-text part
    text = """\
    Hi,
    This is a test email from RTDS system.
    If you receive this, email notifications are working!
    
    Best regards,
    RTDS Team
    """
    
    part1 = MIMEText(text, "plain")
    message.attach(part1)
    
    # Create secure connection and send email
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(smtp_server, port) as server:
            server.starttls(context=context)
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message.as_string())
        print("✅ Email sent successfully!")
        return True
    except Exception as e:
        print(f"❌ Error sending email: {e}")
        return False

if __name__ == "__main__":
    print("🧪 Simple Email Test")
    print("=" * 30)
    test_email()
