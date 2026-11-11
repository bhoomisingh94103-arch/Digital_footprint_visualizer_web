import json
from datetime import datetime, timezone
from app import create_app
from models import db, EmailAssessment, BreachFinding, PDFReport

def test_production_csrf_exemptions_return_json():
    """Verify that all API endpoints in production configuration return proper JSON instead of HTML 400."""
    app = create_app('production')
    client = app.test_client()

    # 1. Request OTP without CSRF header (should be exempt and return JSON)
    res = client.post('/assessment/api/request-scan-otp', json={
        'email': 'analyst@gmail.com',
        'consent': True
    })
    assert res.content_type.startswith('application/json')
    data = res.get_json()
    assert data is not None
    assert 'success' in data

    # 2. Verify OTP endpoint returns JSON
    res_v = client.post('/assessment/api/verify-scan-otp', json={
        'email': 'analyst@gmail.com',
        'otp_code': '123456'
    })
    assert res_v.content_type.startswith('application/json')
    data_v = res_v.get_json()
    assert data_v is not None
    assert data_v['success'] is False

    # 3. Direct scan endpoint returns JSON
    res_s = client.post('/assessment/api/scan-email', json={
        'email': 'analyst@gmail.com',
        'consent': True
    })
    assert res_s.content_type.startswith('application/json')
    data_s = res_s.get_json()
    assert data_s is not None
    assert data_s['success'] is False


def test_api_404_returns_json():
    """Verify that unknown API endpoints return JSON error responses rather than HTML templates."""
    app = create_app('production')
    client = app.test_client()

    res = client.post('/api/nonexistent-threat-endpoint', json={'test': True})
    assert res.status_code == 404
    assert res.content_type.startswith('application/json')
    data = res.get_json()
    assert data['success'] is False
    assert "does not exist" in data['error']


def test_invalid_email_syntax_handling():
    """Test entering invalid email syntax."""
    app = create_app('production')
    client = app.test_client()

    res = client.post('/assessment/api/request-scan-otp', json={
        'email': 'invalid@@syntax..com',
        'consent': True
    })
    assert res.status_code == 400
    assert res.content_type.startswith('application/json')
    data = res.get_json()
    assert data['success'] is False
    assert "Invalid email syntax" in data['error']


def test_unreachable_domain_email_handling():
    """Test entering an email with an unreachable or non-existent domain."""
    app = create_app('production')
    client = app.test_client()

    res = client.post('/assessment/api/request-scan-otp', json={
        'email': 'user@nonexistent-fake-domain-192837.org',
        'consent': True
    })
    assert res.status_code == 400
    assert res.content_type.startswith('application/json')
    data = res.get_json()
    assert data['success'] is False
    assert "does not exist" in data['error'] or "cannot receive" in data['error']


def test_unconfigured_smtp_cannot_receive_otp():
    """Test an email when SMTP cannot dispatch OTP."""
    app = create_app('production')
    client = app.test_client()

    res = client.post('/assessment/api/request-scan-otp', json={
        'email': 'realmailbox@gmail.com',
        'consent': True
    })
    assert res.status_code == 400
    assert res.content_type.startswith('application/json')
    data = res.get_json()
    assert data['success'] is False
    assert "We couldn't verify whether this email address exists. Please check the address and try again." in data['error']


def test_complete_assessment_workflow_and_db_saving():
    """Test complete email assessment workflow and verify database persistence."""
    app = create_app('testing')
    app.config['MOCK_SMTP_DELIVERY'] = True
    client = app.test_client()

    test_email = 'cyber_analyst_2026@gmail.com'

    # Step 1: Request OTP
    req_res = client.post('/assessment/api/request-scan-otp', json={
        'email': test_email,
        'consent': True
    })
    assert req_res.status_code == 200
    assert req_res.get_json()['success'] is True

    # Retrieve OTP from session
    with client.session_transaction() as sess:
        otp_code = sess.get('pending_scan_otp')
        assert otp_code is not None

    # Step 2: Verify OTP
    ver_res = client.post('/assessment/api/verify-scan-otp', json={
        'email': test_email,
        'otp_code': otp_code
    })
    assert ver_res.status_code == 200
    assert ver_res.get_json()['verified'] is True

    # Step 3: Run Scan
    scan_res = client.post('/assessment/api/scan-email', json={
        'email': test_email,
        'consent': True
    })
    assert scan_res.status_code == 200
    scan_data = scan_res.get_json()
    assert scan_data['success'] is True
    assessment_id = scan_data['assessment_id']

    # Step 4: Verify Database Persistence
    with app.app_context():
        record = db.session.get(EmailAssessment, assessment_id)
        assert record is not None
        assert record.email == test_email
        assert record.status == 'completed'

        pdf = PDFReport.query.filter_by(assessment_id=assessment_id).first()
        assert pdf is not None
        assert pdf.filename.endswith('.pdf')

