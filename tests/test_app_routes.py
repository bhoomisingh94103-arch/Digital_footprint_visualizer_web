import json
from app import create_app
from models import db, User, EmailAssessment, QuestionnaireAssessment

def test_landing_page():
    app = create_app('testing')
    client = app.test_client()
    res = client.get('/')
    assert res.status_code == 200
    assert b"DIGITAL FOOTPRINT" in res.data
    assert b"Mode A" in res.data
    assert b"Mode B" in res.data

def test_mode_a_get():
    app = create_app('testing')
    client = app.test_client()
    res = client.get('/assessment/mode-a')
    assert res.status_code == 200
    assert b"Email-Based Digital Footprint Scan" in res.data

def test_mode_b_get():
    app = create_app('testing')
    client = app.test_client()
    res = client.get('/assessment/mode-b')
    assert res.status_code == 200
    assert b"General Digital Privacy Assessment" in res.data

def test_dashboard_guest():
    app = create_app('testing')
    client = app.test_client()
    res = client.get('/dashboard')
    assert res.status_code == 200
    assert b"Cybersecurity & Risk Dashboard" in res.data

def test_footprint_page():
    app = create_app('testing')
    client = app.test_client()
    res = client.get('/footprint')
    assert res.status_code == 200
    assert b"Digital Footprint Visualization" in res.data

def test_action_center_page():
    app = create_app('testing')
    client = app.test_client()
    res = client.get('/action-center/')
    assert res.status_code == 200
    assert b"Privacy Action Center" in res.data

def test_api_status_page():
    app = create_app('testing')
    client = app.test_client()
    res = client.get('/api-status/')
    assert res.status_code == 200
    assert b"API Management Center" in res.data

def test_mode_b_quiz_submission():
    app = create_app('testing')
    client = app.test_client()
    responses = {f'q{i}': 1 for i in range(1, 16)}
    
    res = client.post(
        '/assessment/api/submit-quiz',
        data=json.dumps({'responses': responses}),
        content_type='application/json'
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'overall_score' in data
    assert 'category_scores' in data
    assert len(data['recommendations']) > 0

def test_chat_api():
    app = create_app('testing')
    client = app.test_client()
    res = client.post(
        '/api/chat/',
        data=json.dumps({'message': 'What is a data breach?'}),
        content_type='application/json'
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert len(data['response']) > 20

