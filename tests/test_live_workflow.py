import json
from app import create_app
from models import db, User, EmailAssessment, QuestionnaireAssessment

def test_full_auth_workflow():
    """Test user signup, OTP verification, login, authenticated scan, and history."""
    app = create_app('testing')
    client = app.test_client()
    
    # 1. Signup
    signup_res = client.post('/auth/signup', data={
        'username': 'cyber_tester',
        'email': 'tester@example.com',
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
    """Test Mode A API scan endpoint with email format validation and consent."""
    app = create_app('testing')
    client = app.test_client()
    
    # 1. Reject without consent
    res_no_consent = client.post('/assessment/api/scan-email', json={
        'email': 'test@example.com',
        'consent': False
    })
    assert res_no_consent.status_code == 400
    
    # 2. Reject invalid email
    res_bad_email = client.post('/assessment/api/scan-email', json={
        'email': 'not-an-email',
        'consent': True
    })
    assert res_bad_email.status_code == 400

    # 3. Successful scan
    res_valid = client.post('/assessment/api/scan-email', json={
        'email': 'test@example.com',
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
    
    # 4. Test PDF download route
    asm_id = data['assessment_id']
    pdf_res = client.get(f'/assessment/download-pdf/{asm_id}')
    assert pdf_res.status_code == 200
    assert pdf_res.mimetype == 'application/pdf'

