"""Email service for sending OTP and notifications."""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
import ssl

from app.config import settings


def send_otp_email(to_email: str, otp: str, username: str, is_password_reset: bool = False) -> bool:
    """
    Send OTP via email using SMTP.
    
    Args:
        to_email: Recipient email address
        otp: The OTP code to send
        username: Username of the recipient
        is_password_reset: Whether this is for password reset (default: False)
        
    Returns:
        True if email sent successfully, False otherwise
    """
    try:
        # Create message
        message = MIMEMultipart("alternative")
        
        if is_password_reset:
            message["Subject"] = "Wiestell - Password Reset OTP"
            purpose = "password reset"
            expiry = "10 minutes"
        else:
            message["Subject"] = "Wiestell - Your Login OTP Code"
            purpose = "login"
            expiry = "5 minutes"
            
        message["From"] = settings.EMAIL_USER
        message["To"] = to_email

        # Create HTML and plain text versions
        text_content = f"""
Hello {username},

Your OTP code for {purpose} on Wiestell Threat Intelligence Platform is: {otp}

This code will expire in {expiry}.

If you did not request this code, please ignore this email.

Best regards,
Wiestell Security Team
"""

        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{
            font-family: 'Courier New', monospace;
            background-color: #0a0e1a;
            color: #e5e7eb;
            padding: 20px;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background-color: #151b2e;
            border: 1px solid #00d9ff;
            border-radius: 8px;
            padding: 30px;
        }}
        .header {{
            text-align: center;
            color: #00d9ff;
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 20px;
            letter-spacing: 2px;
        }}
        .otp-box {{
            background-color: #1a2332;
            border: 2px solid #00d9ff;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            margin: 20px 0;
        }}
        .otp-code {{
            font-size: 36px;
            font-weight: bold;
            color: #00d9ff;
            letter-spacing: 8px;
            margin: 10px 0;
        }}
        .message {{
            color: #9ca3af;
            font-size: 14px;
            line-height: 1.6;
            margin: 15px 0;
        }}
        .warning {{
            color: #fbbf24;
            font-size: 12px;
            margin-top: 20px;
            text-align: center;
        }}
        .footer {{
            text-align: center;
            color: #6b7280;
            font-size: 11px;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #374151;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">🛡️ Wiestell</div>
        <p class="message">Hello <strong>{username}</strong>,</p>
        <p class="message">Your OTP code for <strong>{purpose}</strong> on Wiestell Threat Intelligence Platform:</p>
        
        <div class="otp-box">
            <div class="otp-code">{otp}</div>
        </div>
        
        <p class="message">This code will expire in <strong>{expiry}</strong>.</p>
        <p class="warning">⚠️ If you did not request this code, please ignore this email.</p>
        
        <div class="footer">
            © 2026 Wiestell Threat Intelligence Platform<br>
            This is an automated message. Please do not reply.
        </div>
    </div>
</body>
</html>
"""

        # Attach both versions
        part1 = MIMEText(text_content, "plain")
        part2 = MIMEText(html_content, "html")
        message.attach(part1)
        message.attach(part2)

        # Send email
        if settings.SMTP_SECURE and settings.SMTP_PORT == 465:
            # SSL connection
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT, context=context) as server:
                server.login(settings.EMAIL_USER, settings.EMAIL_PASSWORD)
                server.sendmail(settings.EMAIL_USER, to_email, message.as_string())
        else:
            # TLS connection
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
                server.starttls()
                server.login(settings.EMAIL_USER, settings.EMAIL_PASSWORD)
                server.sendmail(settings.EMAIL_USER, to_email, message.as_string())

        print(f"✓ OTP email sent successfully to {to_email}")
        return True

    except Exception as e:
        print(f"✗ Failed to send OTP email to {to_email}: {str(e)}")
        return False


def send_notification_email(to_email: str, subject: str, message: str) -> bool:
    """
    Send a generic notification email.
    
    Args:
        to_email: Recipient email address
        subject: Email subject
        message: Email message content
        
    Returns:
        True if email sent successfully, False otherwise
    """
    try:
        msg = MIMEMultipart()
        msg["Subject"] = subject
        msg["From"] = settings.EMAIL_USER
        msg["To"] = to_email

        msg.attach(MIMEText(message, "plain"))

        if settings.SMTP_SECURE and settings.SMTP_PORT == 465:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT, context=context) as server:
                server.login(settings.EMAIL_USER, settings.EMAIL_PASSWORD)
                server.sendmail(settings.EMAIL_USER, to_email, msg.as_string())
        else:
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
                server.starttls()
                server.login(settings.EMAIL_USER, settings.EMAIL_PASSWORD)
                server.sendmail(settings.EMAIL_USER, to_email, msg.as_string())

        print(f"✓ Notification email sent successfully to {to_email}")
        return True

    except Exception as e:
        print(f"✗ Failed to send notification email to {to_email}: {str(e)}")
        return False
