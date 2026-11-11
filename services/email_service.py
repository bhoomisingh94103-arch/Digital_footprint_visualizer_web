import smtplib
import socket
import secrets
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone, timedelta
from flask import current_app
from models import db, User, ApiActivityLog
from services.email_verifier import parse_smtp_rejection, validate_email_syntax, check_domain_mx


def generate_secure_otp():
    """Generate a cryptographically secure 6-digit numeric OTP."""
    return f"{secrets.randbelow(900000) + 100000}"


def _log_smtp_activity(server_host, server_port, elapsed, status_code, success, error_message):
    """Helper to record SMTP attempts in the ApiActivityLog."""
    try:
        log_entry = ApiActivityLog(
            api_name='SMTP',
            endpoint=f"smtp://{server_host}:{server_port}",
            status_code=status_code,
            response_time_ms=elapsed,
            success=success,
            error_message=error_message,
            timestamp=datetime.now(timezone.utc)
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception:
        db.session.rollback()


def send_smtp_email(to_email, subject, html_content, text_content=None) -> tuple[bool, str, bool]:
    """
    Attempt sending an email using configured SMTP settings.
    Returns (success: bool, message: str, is_explicit_rejection: bool).
    Rules:
    - Rule C: If mailbox existence cannot be confirmed upfront (e.g. SMTP unconfigured or timeout),
      do NOT automatically reject. is_explicit_rejection is False.
    - Rule D: If SMTP explicitly rejects the recipient (550 5.1.1), is_explicit_rejection is True.
    """
    server_host = current_app.config.get('MAIL_SERVER')
    server_port = current_app.config.get('MAIL_PORT', 587)
    username = current_app.config.get('MAIL_USERNAME')
    password = current_app.config.get('MAIL_PASSWORD')
    sender = current_app.config.get('MAIL_DEFAULT_SENDER', 'no-reply@digitalfootprint.local')
    use_tls = current_app.config.get('MAIL_USE_TLS', True)
    use_ssl = current_app.config.get('MAIL_USE_SSL', False)

    start_time = datetime.now(timezone.utc)

    # Testing mode override if mock delivery is explicitly requested in test suite
    if current_app.config.get('TESTING') and current_app.config.get('MOCK_SMTP_DELIVERY'):
        return True, "Email successfully dispatched via test SMTP provider.", False

    # If SMTP credentials are not configured in environment:
    # Rule C: Do NOT treat unconfigured SMTP as proof that an email does not exist!
    if not server_host or not username or not password:
        _log_smtp_activity(
            server_host or 'unconfigured',
            server_port,
            0,
            None,
            False,
            "SMTP credentials not configured in environment."
        )
        return False, "SMTP is not configured in the environment. Verification code generated.", False

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
        _log_smtp_activity(server_host, server_port, elapsed, 250, True, None)
        return True, "Email successfully dispatched via SMTP.", False

    except smtplib.SMTPRecipientsRefused as e:
        elapsed = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
        recipient_info = e.recipients.get(to_email)
        if recipient_info:
            code, resp = recipient_info
            resp_str = resp.decode('utf-8', errors='ignore') if isinstance(resp, bytes) else str(resp)
            error_msg, is_exp = parse_smtp_rejection(code, resp_str, to_email)
        else:
            error_msg, is_exp = "Mail server rejected recipient.", True

        _log_smtp_activity(server_host, server_port, elapsed, 550, False, error_msg)
        return False, error_msg, is_exp

    except smtplib.SMTPResponseException as e:
        elapsed = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
        resp_str = e.smtp_error.decode('utf-8', errors='ignore') if isinstance(e.smtp_error, bytes) else str(e.smtp_error)
        error_msg, is_exp = parse_smtp_rejection(e.smtp_code, resp_str, to_email)
        _log_smtp_activity(server_host, server_port, elapsed, e.smtp_code, False, error_msg)
        return False, error_msg, is_exp

    except smtplib.SMTPAuthenticationError as e:
        elapsed = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
        _log_smtp_activity(server_host, server_port, elapsed, 535, False, f"SMTP Authentication failed: {e}")
        return False, "SMTP authentication failed on mail server.", False

    except smtplib.SMTPSenderRefused as e:
        elapsed = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
        _log_smtp_activity(server_host, server_port, elapsed, e.smtp_code, False, f"Sender refused: {e.smtp_error}")
        return False, "Mail server refused sender address.", False

    except (smtplib.SMTPConnectError, ConnectionRefusedError) as e:
        elapsed = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
        _log_smtp_activity(server_host, server_port, elapsed, None, False, f"Connection error: {e}")
        return False, "Unable to establish connection to SMTP mail server.", False

    except (socket.timeout, TimeoutError):
        elapsed = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
        _log_smtp_activity(server_host, server_port, elapsed, None, False, "SMTP connection timed out")
        return False, "SMTP mail server connection timed out.", False

    except Exception as e:
        elapsed = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
        _log_smtp_activity(server_host, server_port, elapsed, 500, False, str(e))
        return False, f"SMTP dispatch encountered an inconclusive response: {str(e)}", False


def issue_user_otp(user):
    """
    Generate and assign an OTP to a registered user, with expiration and attempt reset.
    Returns (otp: str, delivery_success: bool, delivery_msg: str, is_explicit_rejection: bool).
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
    <body style="background-color: #030805; color: #ecfdf5; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 25px;">
        <div style="max-width: 500px; margin: 0 auto; background: #07150d; border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 16px; padding: 30px; box-shadow: 0 10px 30px rgba(0,0,0,0.5);">
            <div style="text-align: center; margin-bottom: 20px;">
                <h2 style="color: #6ee7b7; margin: 0; font-size: 22px; font-weight: 800; letter-spacing: -0.5px;">DIGITAL FOOTPRINT INTELLIGENCE</h2>
                <p style="color: #84a98c; font-size: 12px; margin-top: 4px;">Security Profile & Mailbox Verification</p>
            </div>
            <p style="color: #94a3b8; font-size: 13px; line-height: 1.6;">Use the one-time passcode below to authenticate your account and verify mailbox existence:</p>
            <div style="font-size: 34px; letter-spacing: 8px; font-weight: 800; color: #6ee7b7; background: #030805; padding: 18px; text-align: center; border-radius: 12px; margin: 24px 0; border: 1px solid rgba(16, 185, 129, 0.4); font-family: monospace;">
                {otp}
            </div>
            <p style="color: #64748b; font-size: 12px; text-align: center;">This code expires in {expiry_minutes} minutes. If you did not request this verification, please discard this message.</p>
        </div>
    </body>
    </html>
    """
    text_body = f"Digital Footprint Intelligence Verification Code: {otp} (Expires in {expiry_minutes} minutes)"

    sent, msg, is_explicit_rejection = send_smtp_email(user.email, subject, html_body, text_body)
    return otp, sent, msg, is_explicit_rejection


def dispatch_scan_otp(email):
    """
    Dispatch a one-time passcode to verify target email mailbox existence before Mode A scan.
    Returns (otp: str, delivery_success: bool, delivery_msg: str, is_explicit_rejection: bool).
    """
    # 1. Validate syntax (Rule A)
    is_valid_syntax, clean_email, syntax_err = validate_email_syntax(email)
    if not is_valid_syntax:
        return "", False, syntax_err, True

    # 2. Check domain (Rule B)
    is_valid_domain, mx_hosts, mx_err, is_definitive_err = check_domain_mx(clean_email)
    if not is_valid_domain and is_definitive_err:
        return "", False, mx_err, True

    # 3. Generate secure OTP
    otp = generate_secure_otp()
    expiry_minutes = current_app.config.get('OTP_EXPIRY_MINUTES', 10)

    subject = "[Digital Footprint Intelligence] Mode A Assessment Verification Code"
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <body style="background-color: #030805; color: #ecfdf5; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 25px;">
        <div style="max-width: 500px; margin: 0 auto; background: #07150d; border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 16px; padding: 30px; box-shadow: 0 10px 30px rgba(0,0,0,0.5);">
            <div style="text-align: center; margin-bottom: 20px;">
                <h2 style="color: #6ee7b7; margin: 0; font-size: 22px; font-weight: 800; letter-spacing: -0.5px;">DIGITAL FOOTPRINT INTELLIGENCE</h2>
                <p style="color: #84a98c; font-size: 12px; margin-top: 4px;">Mode A: Email Footprint Verification</p>
            </div>
            <p style="color: #94a3b8; font-size: 13px; line-height: 1.6;">
                A digital footprint threat assessment was requested for <b style="color: #ecfdf5;">{clean_email}</b>. 
                Enter the passcode below to confirm mailbox existence and initiate public breach indexing:
            </p>
            <div style="font-size: 34px; letter-spacing: 8px; font-weight: 800; color: #6ee7b7; background: #030805; padding: 18px; text-align: center; border-radius: 12px; margin: 24px 0; border: 1px solid rgba(16, 185, 129, 0.4); font-family: monospace;">
                {otp}
            </div>
            <p style="color: #64748b; font-size: 12px; text-align: center;">This code expires in {expiry_minutes} minutes. Threat intelligence scanning will strictly begin only after verification.</p>
        </div>
    </body>
    </html>
    """
    text_body = f"Digital Footprint Intelligence Mode A Verification Code: {otp} (Expires in {expiry_minutes} minutes)"

    sent, msg, is_explicit_rejection = send_smtp_email(clean_email, subject, html_body, text_body)
    return otp, sent, msg, is_explicit_rejection


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
