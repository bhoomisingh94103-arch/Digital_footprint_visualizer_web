import smtplib
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock
from app import create_app
from services.email_verifier import validate_email_syntax, check_domain_mx, parse_smtp_rejection
from services.email_service import send_smtp_email, dispatch_scan_otp

def test_1_valid_gmail_address():
    """Test 1: A valid Gmail address is accepted and allowed to proceed to OTP delivery stage."""
    app = create_app('testing')
    client = app.test_client()

    valid_gmail = 'myuser.security@gmail.com'

    # Check syntax
    is_valid, clean, err = validate_email_syntax(valid_gmail)
    assert is_valid is True
    assert clean == valid_gmail

    # Check domain recognition
    has_mx, hosts, err_domain, is_definitive = check_domain_mx(valid_gmail)
    assert has_mx is True
    assert is_definitive is False

    # Request OTP (Rule B: valid syntax and valid domain allows process to continue to OTP stage)
    res = client.post('/assessment/api/request-scan-otp', json={
        'email': valid_gmail,
        'consent': True
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert data['email'] == valid_gmail


def test_2_invalid_email_format():
    """Test 2: Rule A - Invalid email format is rejected with 'Please enter a valid email address.'"""
    app = create_app('testing')
    client = app.test_client()

    invalid_formats = [
        'invalid-email',
        '@gmail.com',
        'user@',
        'user@@gmail..com',
        'user..name@gmail.com',
        '.user@gmail.com',
        'user.@gmail.com',
        ''
    ]

    for bad in invalid_formats:
        is_valid, clean, err = validate_email_syntax(bad)
        assert is_valid is False
        assert err == "Please enter a valid email address."

        res = client.post('/assessment/api/request-scan-otp', json={
            'email': bad,
            'consent': True
        })
        assert res.status_code == 400
        assert res.get_json()['error'] == "Please enter a valid email address."


def test_3_unreachable_domain():
    """Test 3: Unreachable / non-existent domain is rejected with a domain error."""
    app = create_app('testing')
    client = app.test_client()

    bad_domain_email = 'analyst@nonexistent-fake-domain-xyz998877.org'
    is_valid, clean, err = validate_email_syntax(bad_domain_email)
    assert is_valid is True

    has_mx, hosts, err_domain, is_definitive = check_domain_mx(bad_domain_email)
    assert has_mx is False
    assert is_definitive is True
    assert "does not exist" in err_domain

    res = client.post('/assessment/api/request-scan-otp', json={
        'email': bad_domain_email,
        'consent': True
    })
    assert res.status_code == 400
    assert "does not exist" in res.get_json()['error']


def test_4_verification_service_timeout():
    """Test 4: Rule 3 - Email verification service timeout does not block legitimate users."""
    app = create_app('testing')
    client = app.test_client()

    test_email = 'target@corporate-corp.com'

    # Mock DNS lookup timing out
    with patch('dns.resolver.Resolver.resolve', side_effect=Exception("DNS Timeout")):
        has_mx, hosts, err_domain, is_definitive = check_domain_mx(test_email)
        # Inconclusive timeout must not be marked as definitive error
        assert is_definitive is False

        # Request OTP should proceed to OTP delivery stage rather than rejecting
        res = client.post('/assessment/api/request-scan-otp', json={
            'email': test_email,
            'consent': True
        })
        assert res.status_code == 200
        assert res.get_json()['success'] is True


def test_5_successful_otp_delivery():
    """Test 5: Rule E - Successful OTP delivery and generation."""
    app = create_app('testing')
    app.config['MOCK_SMTP_DELIVERY'] = True
    client = app.test_client()

    target_email = 'valid_delivery@gmail.com'
    res = client.post('/assessment/api/request-scan-otp', json={
        'email': target_email,
        'consent': True
    })
    assert res.status_code == 200
    assert res.get_json()['success'] is True

    with client.session_transaction() as sess:
        otp = sess.get('pending_scan_otp')
        assert otp is not None
        assert len(otp) == 6


def test_6_incorrect_otp():
    """Test 6: Submitting incorrect OTP returns error and tracks remaining attempts."""
    app = create_app('testing')
    app.config['MOCK_SMTP_DELIVERY'] = True
    client = app.test_client()

    target_email = 'target_otp_check@gmail.com'
    client.post('/assessment/api/request-scan-otp', json={
        'email': target_email,
        'consent': True
    })

    # Submit wrong OTP
    res_wrong = client.post('/assessment/api/verify-scan-otp', json={
        'email': target_email,
        'otp_code': '000000'
    })
    assert res_wrong.status_code == 400
    data = res_wrong.get_json()
    assert data['success'] is False
    assert "Incorrect verification code" in data['error']
    assert "4 attempt(s) remaining" in data['error']


def test_7_successful_email_assessment():
    """Test 7: Complete workflow - valid OTP verification allows successful scan report generation."""
    app = create_app('testing')
    app.config['MOCK_SMTP_DELIVERY'] = True
    client = app.test_client()

    target_email = 'verified_analyst@gmail.com'

    # Request OTP
    client.post('/assessment/api/request-scan-otp', json={
        'email': target_email,
        'consent': True
    })

    with client.session_transaction() as sess:
        otp_code = sess.get('pending_scan_otp')

    # Verify correct OTP
    res_ver = client.post('/assessment/api/verify-scan-otp', json={
        'email': target_email,
        'otp_code': otp_code
    })
    assert res_ver.status_code == 200
    assert res_ver.get_json()['verified'] is True

    # Scan email
    res_scan = client.post('/assessment/api/scan-email', json={
        'email': target_email,
        'consent': True
    })
    assert res_scan.status_code == 200
    scan_data = res_scan.get_json()
    assert scan_data['success'] is True
    assert 'risk_score' in scan_data
    assert 'breaches' in scan_data
    assert 'recommendations' in scan_data
    assert 'pdf_url' in scan_data
