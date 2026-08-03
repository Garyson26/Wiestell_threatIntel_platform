"""Email service for sending OTP and notifications."""

import html
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

import structlog

from app.config import settings

logger = structlog.get_logger()


def _smtp_configured() -> bool:
    return bool(settings.SMTP_HOST and settings.EMAIL_USER and settings.EMAIL_PASSWORD)


def _send(to_email: str, message: MIMEMultipart) -> None:
    """Deliver a prepared message over SMTP (SSL or STARTTLS with cert checks)."""
    context = ssl.create_default_context()
    if settings.SMTP_SECURE and settings.SMTP_PORT == 465:
        with smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT, context=context) as server:
            server.login(settings.EMAIL_USER, settings.EMAIL_PASSWORD)
            server.sendmail(settings.EMAIL_USER, to_email, message.as_string())
    else:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.starttls(context=context)
            server.login(settings.EMAIL_USER, settings.EMAIL_PASSWORD)
            server.sendmail(settings.EMAIL_USER, to_email, message.as_string())


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
    if not _smtp_configured():
        logger.error("smtp_not_configured", hint="Set SMTP_HOST, EMAIL_USER and EMAIL_PASSWORD")
        return False

    # The username is rendered inside an HTML email — escape it so a crafted
    # display name cannot inject markup into the message body.
    username = html.escape(username or "", quote=True)

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

        _send(to_email, message)

        # The recipient address and the code itself are deliberately absent from
        # the log line — an OTP in a log file is a bypass of the second factor.
        logger.info("otp_email_sent", is_password_reset=is_password_reset)
        return True

    except Exception as e:
        logger.error("otp_email_failed", error_type=type(e).__name__, error=str(e))
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
    if not _smtp_configured():
        logger.error("smtp_not_configured")
        return False

    try:
        msg = MIMEMultipart()
        msg["Subject"] = subject
        msg["From"] = settings.EMAIL_USER
        msg["To"] = to_email

        msg.attach(MIMEText(message, "plain"))

        _send(to_email, msg)

        logger.info("notification_email_sent")
        return True

    except Exception as e:
        logger.error("notification_email_failed", error_type=type(e).__name__, error=str(e))
        return False


def send_error_alert_email(
    error_type: str,
    error_message: str,
    endpoint: str,
    method: str,
    traceback_info: str,
    request_data: Optional[dict] = None
) -> bool:
    """
    Send error alert email to admin.
    
    Args:
        error_type: Type of error (e.g., "500 Internal Server Error")
        error_message: Error message
        endpoint: API endpoint where error occurred
        method: HTTP method (GET, POST, etc.)
        traceback_info: Traceback information
        request_data: Optional request data for debugging
        
    Returns:
        True if email sent successfully, False otherwise
    """
    if not settings.ENABLE_ERROR_EMAILS or not settings.ADMIN_EMAIL or not _smtp_configured():
        return False

    # Diagnostics are embedded in an HTML email; escape them so error text
    # containing markup cannot inject content into the admin's mail client.
    error_type = html.escape(str(error_type))
    error_message = html.escape(str(error_message))
    endpoint = html.escape(str(endpoint))
    method = html.escape(str(method))
    traceback_info = html.escape(str(traceback_info))
    safe_request_data = html.escape(str(request_data)) if request_data else None

    try:
        from datetime import datetime
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        # Create message
        message = MIMEMultipart("alternative")
        message["Subject"] = f"🚨 Wiestell API Error: {error_type}"
        message["From"] = settings.EMAIL_USER
        message["To"] = settings.ADMIN_EMAIL

        # Create plain text version
        text_content = f"""
🚨 ERROR ALERT - Wiestell Threat Intelligence Platform

Timestamp: {timestamp}
Error Type: {error_type}
Endpoint: {method} {endpoint}

Error Message:
{error_message}

Traceback:
{traceback_info}

Request Data:
{request_data if request_data else "N/A"}

---
This is an automated alert from Wiestell API monitoring.
"""

        # Create HTML version
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
            max-width: 800px;
            margin: 0 auto;
            background-color: #151b2e;
            border: 2px solid #ef4444;
            border-radius: 8px;
            padding: 30px;
        }}
        .header {{
            text-align: center;
            color: #ef4444;
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 20px;
        }}
        .error-box {{
            background-color: #1a2332;
            border-left: 4px solid #ef4444;
            padding: 15px;
            margin: 15px 0;
        }}
        .info-row {{
            margin: 10px 0;
            padding: 8px;
            background-color: #0f1419;
            border-radius: 4px;
        }}
        .label {{
            color: #00d9ff;
            font-weight: bold;
            display: inline-block;
            width: 150px;
        }}
        .value {{
            color: #e5e7eb;
        }}
        .traceback {{
            background-color: #0f1419;
            border: 1px solid #374151;
            border-radius: 4px;
            padding: 15px;
            margin: 15px 0;
            overflow-x: auto;
            font-size: 12px;
            color: #fbbf24;
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
        <div class="header">🚨 API ERROR ALERT</div>
        
        <div class="info-row">
            <span class="label">Timestamp:</span>
            <span class="value">{timestamp}</span>
        </div>
        
        <div class="info-row">
            <span class="label">Error Type:</span>
            <span class="value">{error_type}</span>
        </div>
        
        <div class="info-row">
            <span class="label">Endpoint:</span>
            <span class="value">{method} {endpoint}</span>
        </div>
        
        <div class="error-box">
            <strong style="color: #ef4444;">Error Message:</strong><br>
            <p style="margin: 10px 0; color: #fbbf24;">{error_message}</p>
        </div>
        
        <div class="traceback">
            <strong>Traceback:</strong><br>
            <pre style="margin: 10px 0; white-space: pre-wrap;">{traceback_info}</pre>
        </div>
        
        {f'<div class="info-row"><span class="label">Request Data:</span><br><pre style="margin: 10px 0; color: #9ca3af;">{safe_request_data}</pre></div>' if safe_request_data else ''}
        
        <div class="footer">
            Wiestell Threat Intelligence Platform - Automated Error Monitoring<br>
            This is an automated alert. Check server logs for more details.
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

        _send(settings.ADMIN_EMAIL, message)

        logger.info("error_alert_email_sent")
        return True

    except Exception as e:
        # Don't let email failures cause additional errors
        logger.warning("error_alert_email_failed", error_type=type(e).__name__)
        return False
