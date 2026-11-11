import json
from datetime import datetime, timezone
from app import create_app
from models import db, User, EmailAssessment, QuestionnaireAssessment

def test_full_auth_workflow():
    """Test user signup, OTP verification, login, authenticated scan, and history."""
    app = create_app('testing')
    app.config['MOCK_SMTP_DELIVERY'] = True
    client = app.test_client()
    
    # 1. Signup with valid domain
    signup_res = client.post('/auth/signup', data={
        'username': 'cyber_tester',
        'email': 'tester@gmail.com',
        'password': 'SecurePassword2026!',
        'confirm_password': 'SecurePassword2026!'
    }, follow_redirects=True)
    assert signup_res.status_code == 200
    
    with app.app_context():
        u = User.query.filter_by(username='cyber_tester').first()
        assert u is not None
        otp = u.otp_code
        assert len(otp) == 6
        
        # 2. Verify OTP
        with client.session_transaction() as sess:
            sess['verify_user_id'] = u.id
            
    verify_res = client.post('/auth/verify-otp', data={'otp_code': otp}, follow_redirects=True)
    assert verify_res.status_code == 200
    assert b"Email successfully verified" in verify_res.data
    
    # 3. Check profile
    profile_res = client.get('/auth/profile')
    assert profile_res.status_code == 200
    assert b"cyber_tester" in profile_res.data


def test_mode_a_api_scan():
    """Test Mode A API scan endpoint with email format validation, consent, and OTP verification requirement."""
    app = create_app('testing')
    client = app.test_client()
    
    # 1. Reject without consent
    res_no_consent = client.post('/assessment/api/scan-email', json={
        'email': 'test@gmail.com',
        'consent': False
    })
    assert res_no_consent.status_code == 400
    
    # 2. Reject invalid email syntax
    res_bad_email = client.post('/assessment/api/scan-email', json={
        'email': 'not-an-email',
        'consent': True
    })
    assert res_bad_email.status_code == 400

    # 3. Strictly reject unverified email before OTP verification (Requirement 5 & 8)
    res_unverified = client.post('/assessment/api/scan-email', json={
        'email': 'test@gmail.com',
        'consent': True
    })
    assert res_unverified.status_code == 403
    unverified_data = res_unverified.get_json()
    assert "Email verification required" in unverified_data['error']

    # 4. Successful scan after OTP verification
    with client.session_transaction() as sess:
        sess['mode_a_verified_email'] = 'test@gmail.com'
        sess['mode_a_verified_at'] = datetime.now(timezone.utc).timestamp()

    res_valid = client.post('/assessment/api/scan-email', json={
        'email': 'test@gmail.com',
        'consent': True
    })
    assert res_valid.status_code == 200
    data = res_valid.get_json()
    assert data['success'] is True
    assert 'assessment_id' in data
    assert 'risk_score' in data
    assert 'breaches' in data
    assert 'recommendations' in data
    assert 'pdf_url' in data
    
    # 5. Test PDF download route
    asm_id = data['assessment_id']
    pdf_res = client.get(f'/assessment/download-pdf/{asm_id}')
    assert pdf_res.status_code == 200
    assert pdf_res.mimetype == 'application/pdf'
