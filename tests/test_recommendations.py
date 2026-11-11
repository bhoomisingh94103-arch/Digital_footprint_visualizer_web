from app import create_app
from models import db, EmailAssessment, QuestionnaireAssessment
from services.recommendation_engine import (
    seed_recommendations,
    generate_recommendations_for_email_assessment,
    generate_recommendations_for_questionnaire
)

def test_recommendation_catalog_seed():
    app = create_app('testing')
    with app.app_context():
        db.create_all()
        seed_recommendations()
        
        # Mode A: Email with breach finding
        email_asm = EmailAssessment(
            email="victim@example.com",
            risk_score=75,
            risk_level="High",
            breach_count=2,
            paste_count=0
        )
        db.session.add(email_asm)
        db.session.commit()
        
        recs = generate_recommendations_for_email_assessment(email_asm)
        assert len(recs) > 0
        codes = [r.code for r in recs]
        assert 'REC_BREACH_PWD_RESET' in codes
        assert 'REC_ENABLE_2FA_APP' in codes

def test_quiz_recommendations():
    app = create_app('testing')
    with app.app_context():
        db.create_all()
        seed_recommendations()
        
        # Mode B with high password reuse and no 2FA
        quiz_asm = QuestionnaireAssessment(
            overall_score=70,
            risk_level="High",
            category_scores_json='{"Authentication": 85}',
            responses_json='{"q1": 3, "q3": 3, "q8": 2}'
        )
        db.session.add(quiz_asm)
        db.session.commit()
        
        recs = generate_recommendations_for_questionnaire(quiz_asm)
        assert len(recs) > 0
        codes = [r.code for r in recs]
        assert 'REC_PASSWORD_MANAGER' in codes
        assert 'REC_ENABLE_2FA_APP' in codes
        assert 'REC_PUBLIC_WIFI_VPN' in codes

