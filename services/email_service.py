import smtplib
import secrets
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone, timedelta
from flask import current_app
from models import db, User, ApiActivityLog

def generate_secure_otp():
    """Generate a cryptographically secure 6-digit numeric OTP."""
    return f"{secrets.randbelow(900000) + 100000}"

def send_smtp_email(to_email, subject, html_content, text_content=None):
    """
    Attempt sending an email using configured SMTP settings.
    Returns (success: bool, message: str).
    Strictly follows rule: Never claim an email was sent unless SMTP confirms success.
    """
    server_host = current_app.config.get('MAIL_SERVER')
    server_port = current_app.config.get('MAIL_PORT', 587)
    username = current_app.config.get('MAIL_USERNAME')
    password = current_app.config.get('MAIL_PASSWORD')
    sender = current_app.config.get('MAIL_DEFAULT_SENDER', 'no-reply@digitalfootprint.local')
    use_tls = current_app.config.get('MAIL_USE_TLS', True)
    use_ssl = current_app.config.get('MAIL_USE_SSL', False)
    
    start_time = datetime.now(timezone.utc)
    
    if not server_host or not username or not password:
        log_entry = ApiActivityLog(
            api_name='SMTP',
            endpoint='smtp://' + (server_host or 'unconfigured'),
            status_code=None,
            response_time_ms=0,
            success=False,
            error_message="SMTP credentials not configured in environment.",
            timestamp=datetime.now(timezone.utc)
        )
        try:
            db.session.add(log_entry)
            db.session.commit()
        except Exception:
            db.session.rollback()
            
        return False, "SMTP is not configured in .env. Email was NOT sent."

    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = to_email
    
    if text_content:
        msg.attach(MIMEText(text_content, 'plain'))
    if html_content:
        msg.attach(MIMEText(html_content, 'html'))
        
    try:
        if use_ssl:
            server = smtplib.SMTP_SSL(server_host, server_port, timeout=10)
        else:
            server = smtplib.SMTP(server_host, server_port, timeout=10)
            if use_tls:
                server.starttls()
                
        server.login(username, password)
        server.sendmail(sender, [to_email], msg.as_string())
        server.quit()
        
        elapsed = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
        log_entry = ApiActivityLog(
            api_name='SMTP',
            endpoint=f"smtp://{server_host}:{server_port}",
            status_code=250,
            response_time_ms=elapsed,
            success=True,
            error_message=None,
            timestamp=datetime.now(timezone.utc)
        )
        db.session.add(log_entry)
        db.session.commit()
        
        return True, "Email successfully dispatched via SMTP."
        
    except Exception as e:
        elapsed = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
        log_entry = ApiActivityLog(
            api_name='SMTP',
            endpoint=f"smtp://{server_host}:{server_port}",
            status_code=500,
            response_time_ms=elapsed,
            success=False,
            error_message=str(e),
            timestamp=datetime.now(timezone.utc)
        )
        try:
            db.session.add(log_entry)
            db.session.commit()
        except Exception:
            db.session.rollback()
            
        return False, f"SMTP delivery failed: {str(e)}"

def issue_user_otp(user):
    """
    Generate and assign an OTP to a user, with expiration and attempt reset.
    Returns (otp: str, delivery_success: bool, delivery_msg: str).
    """
    otp = generate_secure_otp()
    expiry_minutes = current_app.config.get('OTP_EXPIRY_MINUTES', 10)
    
    user.otp_code = otp
    user.otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=expiry_minutes)
    user.otp_attempts = 0
    db.session.commit()
    
    subject = "[Digital Footprint Intelligence] Your Verification OTP"
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <body style="background-color: #0b0f19; color: #f1f5f9; font-family: sans-serif; padding: 25px;">
        <div style="max-width: 500px; margin: 0 auto; background: #131b2e; border: 1px solid #1e293b; border-radius: 12px; padding: 25px;">
            <h2 style="color: #38bdf8; margin-top: 0;">Digital Footprint Intelligence</h2>
            <p style="color: #94a3b8;">Use the verification code below to verify your account or authorize action:</p>
            <div style="font-size: 32px; letter-spacing: 6px; font-weight: bold; color: #a855f7; background: #0f172a; padding: 15px; text-align: center; border-radius: 8px; margin: 20px 0; border: 1px solid #334155;">
                {otp}
            </div>
            <p style="color: #64748b; font-size: 13px;">This code expires in {expiry_minutes} minutes. If you did not request this code, no action is required.</p>
        </div>
    </body>
    </html>
    """
    text_body = f"Digital Footprint Intelligence Verification Code: {otp} (Expires in {expiry_minutes} minutes)"
    
    sent, msg = send_smtp_email(user.email, subject, html_body, text_body)
    return otp, sent, msg

def verify_user_otp(user, submitted_code):
    """
    Verifies user OTP respecting expiration and maximum attempt threshold.
    Returns (success: bool, message: str).
    """
    max_attempts = current_app.config.get('OTP_MAX_ATTEMPTS', 5)
    
    if not user.otp_code or not user.otp_expiry:
        return False, "No active OTP found. Please request a new verification code."
        
    # Check attempt limit
    if user.otp_attempts >= max_attempts:
        user.otp_code = None
        user.otp_expiry = None
        db.session.commit()
        return False, f"Maximum verification attempts ({max_attempts}) exceeded. OTP invalidated. Please request a new one."
        
    user.otp_attempts += 1
    
    # Check expiration
    now = datetime.now(timezone.utc)
    # Ensure timezone awareness
    expiry = user.otp_expiry
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
        
    if now > expiry:
        user.otp_code = None
        user.otp_expiry = None
        db.session.commit()
        return False, "The OTP has expired. Please request a new verification code."
        
    # Check match
    if user.otp_code.strip() != submitted_code.strip():
        db.session.commit()
        remaining = max_attempts - user.otp_attempts
        return False, f"Incorrect verification code. {remaining} attempt(s) remaining."
        
    # Success
    user.is_verified = True
    user.otp_code = None
    user.otp_expiry = None
    user.otp_attempts = 0
    db.session.commit()
    return True, "Verification successful."

