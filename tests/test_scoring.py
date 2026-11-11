from services.scoring_service import calculate_questionnaire_score, QUESTIONNAIRE_QUESTIONS

def test_questionnaire_count():
    """Ensure at least 15 comprehensive questions exist."""
    assert len(QUESTIONNAIRE_QUESTIONS) >= 15

def test_low_risk_calculation():
    """All safest answers should result in score <= 10 and Low risk level."""
    safe_answers = {q['id']: 0 for q in QUESTIONNAIRE_QUESTIONS}
    res = calculate_questionnaire_score(safe_answers)
    assert res['overall_score'] <= 10
    assert res['risk_level'] == 'Low'
    assert 'Authentication' in res['category_scores']

def test_critical_risk_calculation():
    """All riskiest answers should result in score >= 90 and Critical risk level."""
    risky_answers = {q['id']: 3 for q in QUESTIONNAIRE_QUESTIONS}
    res = calculate_questionnaire_score(risky_answers)
    assert res['overall_score'] >= 90
    assert res['risk_level'] == 'Critical'

def test_mixed_risk_calculation():
    """Mixed responses should yield a moderate or high score."""
    mixed = {
        'q1': 1, 'q2': 1, 'q3': 2, 'q4': 1, 'q5': 2,
        'q6': 1, 'q7': 2, 'q8': 2, 'q9': 1, 'q10': 2,
        'q11': 1, 'q12': 1, 'q13': 2, 'q14': 2, 'q15': 1
    }
    res = calculate_questionnaire_score(mixed)
    assert 20 <= res['overall_score'] <= 80
    assert res['risk_level'] in ('Moderate', 'High')

