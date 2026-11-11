from app import create_app
from services.xposedornot_service import check_email_breaches
from services.hackmyip_service import analyze_network_ip
from services.emailrep_service import check_email_reputation
from services.hibp_service import check_hibp_breaches
from services.ai_assistant_service import ask_privacy_guardian

def test_ai_assistant_fallback():
    app = create_app('testing')
    with app.app_context():
        # Query known cybersecurity topic
        res = ask_privacy_guardian("How does two factor authentication protect me?")
        assert res['status'] == 'success'
        assert "2fa" in res['response'].lower() or "two-factor" in res['response'].lower() or "authenticator" in res['response'].lower()
        assert "engine" in res

def test_ai_assistant_context_awareness():
    app = create_app('testing')
    with app.app_context():
        # User assessment context injection
        ctx = {
            'risk_score': 85,
            'risk_level': 'Critical',
            'breach_count': 4,
            'scan_type': 'Email Breach Assessment'
        }
        res = ask_privacy_guardian("Why did I get this risk score?", user_context=ctx)
        assert res['status'] == 'success'
        assert "85" in res['response']
        assert "4" in res['response']

def test_emailrep_unconfigured_handling():
    app = create_app('testing')
    with app.app_context():
        res = check_email_reputation("disposable_test@mailinator.com")
        assert res['is_disposable'] is True
        assert res['api_connected'] is False
        assert "mailinator.com" in res['local_analysis']['domain']

def test_hibp_unconfigured_handling():
    app = create_app('testing')
    with app.app_context():
        res = check_hibp_breaches("test@example.com")
        assert res['status'] == 'not_configured'
        assert res['is_configured'] is False

