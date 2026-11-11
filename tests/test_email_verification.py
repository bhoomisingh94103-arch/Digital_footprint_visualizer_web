import smtplib
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock
from app import create_app
from services.email_verifier import validate_email_syntax, check_domain_mx, parse_smtp_rejection
from services.email_service import send_smtp_email, dispatch_scan_otp

def test_syntax_validation_valid_and_invalid():
    """Requirement 1: Validate email syntax before proceeding."""
    # Valid syntax
    valid_emails = ['user@gmail.com', 'first.last@company.co.uk', 'analyst_01@sub.domain.org']
    for em in valid_emails:
        valid, clean, err = validate_email_syntax(em)
        assert valid is True
        assert err == ""
        assert clean == em.lower()

    # Invalid syntax
    invalid_emails = [
        'plainaddress',
        '@missinguser.com',
        'user@.missingdomain',
        'user@@domain..com',
        'user..double@domain.com',
        '.leadingdot@domain.com',
        'trailingdot.@domain.com',
        ''
    ]
    for em in invalid_emails:
        valid, clean, err = validate_email_syntax(em)
        assert valid is False
        assert "Invalid email syntax" in err or "cannot be empty" in err or "Please provide" in err


def test_domain_mx_records_validation():
    """Requirement 2: Check domain MX records to confirm that domain can receive emails."""
    # 1. Valid reachable domain with MX
    has_mx, hosts, err = check_domain_mx('gmail.com')
    assert has_mx is True
    assert len(hosts) > 0
    assert err == ""

    # 2. Non-existent domain (NXDOMAIN)
    has_mx_fake, hosts_fake, err_fake = check_domain_mx('nonexistent-cyber-domain-xyz998877.com')
    assert has_mx_fake is False
    assert "does not exist" in err_fake or "couldn't verify" in err_fake

    # 3. Reserved test domain or Null MX (RFC 7505)
    has_mx_ex, hosts_ex, err_ex = check_domain_mx('example.com')
    assert has_mx_ex is False
    assert "Null MX" in err_ex or "cannot receive" in err_ex or "couldn't verify" in err_ex


def test_smtp_rejection_code_550_511_handling():
    """Requirement 4: Handle SMTP rejection codes such as 550 5.1.1 and show appropriate message."""
    # Direct 550 5.1.1 error string
    msg_550 = parse_smtp_rejection(550, "5.1.1 The email account that you tried to reach does not exist", "target@gmail.com")
    assert "550 5.1.1: Mailbox does not exist" in msg_550
    assert "Please check the address and try again" in msg_550

    # User unknown
    msg_unknown = parse_smtp_rejection(550, "Recipient rejected: User unknown", "target@gmail.com")
    assert "550 5.1.1: Mailbox does not exist" in msg_unknown

    # Generic or unverifiable response (Requirement 7)
    msg_other = parse_smtp_rejection(421, "Service unavailable", "target@gmail.com")
    assert msg_other == "We couldn't verify whether this email address exists. Please check the address and try again."


def test_unverifiable_when_smtp_unconfigured():
    """Requirement 6 & 7: If OTP delivery fails/unconfigured, display:
    'We couldn't verify whether this email address exists. Please check the address and try again.'
    """
    app = create_app('testing')
    with app.app_context():
        # Ensure SMTP is unconfigured in test environment
        app.config['MAIL_SERVER'] = None
        app.config['MAIL_USERNAME'] = None
        app.config['MAIL_PASSWORD'] = None
        app.config['MOCK_SMTP_DELIVERY'] = False

        sent, msg = send_smtp_email('user@gmail.com', 'Subject', 'Body')
        assert sent is False
        assert msg == "We couldn't verify whether this email address exists. Please check the address and try again."


def test_smtp_recipient_refused_rejection_mock():
    """Requirement 3 & 4: Mock SMTP server throwing SMTPRecipientsRefused with 550 5.1.1."""
    app = create_app('testing')
    with app.app_context():
        app.config['MAIL_SERVER'] = 'smtp.fake.local'
        app.config['MAIL_USERNAME'] = 'user'
        app.config['MAIL_PASSWORD'] = 'pass'
        app.config['MOCK_SMTP_DELIVERY'] = False

        with patch('smtplib.SMTP') as mock_smtp:
            instance = MagicMock()
            mock_smtp.return_value = instance
            # Simulate 550 5.1.1 recipient rejection from SMTP server
            instance.sendmail.side_effect = smtplib.SMTPRecipientsRefused({
                'target@gmail.com': (550, b'5.1.1 The email account that you tried to reach does not exist.')
            })

            sent, msg = send_smtp_email('target@gmail.com', 'Test Subject', '<p>Test</p>')
            assert sent is False
            assert "550 5.1.1: Mailbox does not exist" in msg
            assert "Please check the address and try again" in msg


def test_mode_a_otp_verification_guard():
    """Requirement 5 & 8: Do not generate/display scan report before OTP verification.
    Only allow assessment to proceed after successful OTP verification.
    """
    app = create_app('testing')
    client = app.test_client()

    target_email = 'target_scan@gmail.com'

    # Step 1: Scan directly without OTP -> 403 Forbidden
    res_direct = client.post('/assessment/api/scan-email', json={
        'email': target_email,
        'consent': True
    })
    assert res_direct.status_code == 403
    assert "Email verification required" in res_direct.get_json()['error']

    # Step 2: Request OTP with mock SMTP delivery
    app.config['MOCK_SMTP_DELIVERY'] = True
    res_otp_req = client.post('/assessment/api/request-scan-otp', json={
        'email': target_email,
        'consent': True
    })
    assert res_otp_req.status_code == 200
    assert res_otp_req.get_json()['success'] is True

    with client.session_transaction() as sess:
        otp_code = sess.get('pending_scan_otp')
        assert otp_code is not None
        assert len(otp_code) == 6

    # Step 3: Verify with incorrect OTP code -> 400
    res_wrong_otp = client.post('/assessment/api/verify-scan-otp', json={
        'email': target_email,
        'otp_code': '000000'
    })
    assert res_wrong_otp.status_code == 400
    assert "Incorrect verification code" in res_wrong_otp.get_json()['error']

    # Step 4: Verify with correct OTP code -> 200
    res_correct_otp = client.post('/assessment/api/verify-scan-otp', json={
        'email': target_email,
        'otp_code': otp_code
    })
    assert res_correct_otp.status_code == 200
    assert res_correct_otp.get_json()['verified'] is True

    # Step 5: Now scan proceeds successfully and produces scan report
    res_scan = client.post('/assessment/api/scan-email', json={
        'email': target_email,
        'consent': True
    })
    assert res_scan.status_code == 200
    scan_data = res_scan.get_json()
    assert scan_data['success'] is True
    assert 'assessment_id' in scan_data
    assert scan_data['email'] == target_email

