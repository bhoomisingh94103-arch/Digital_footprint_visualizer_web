import json
from flask import Blueprint, render_template, jsonify
from flask_login import current_user, login_required
from models import db, EmailAssessment, BreachFinding, IPAssessment, QuestionnaireAssessment, UserRecommendationProgress, Recommendation

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/dashboard')
def index():
    """
    Main Cybersecurity Dashboard with real aggregated metrics and dynamic charts.
    Accessible to both authenticated users (their isolated data) and guests (summary/empty states).
    """
    if current_user.is_authenticated:
        email_scans = EmailAssessment.query.filter_by(user_id=current_user.id).order_by(EmailAssessment.created_at.desc()).all()
        quiz_scans = QuestionnaireAssessment.query.filter_by(user_id=current_user.id).order_by(QuestionnaireAssessment.created_at.desc()).all()
        latest_ip = IPAssessment.query.filter_by(user_id=current_user.id).order_by(IPAssessment.created_at.desc()).first()
        total_breaches = sum([s.breach_count for s in email_scans])
        completed_recs = UserRecommendationProgress.query.filter_by(user_id=current_user.id, is_completed=True).count()
        total_recs = UserRecommendationProgress.query.filter_by(user_id=current_user.id).count()
    else:
        # For guest / demo view, pull recent session / guest scans if any, else empty
        email_scans = EmailAssessment.query.filter(EmailAssessment.user_id.is_(None)).order_by(EmailAssessment.created_at.desc()).limit(5).all()
        quiz_scans = QuestionnaireAssessment.query.filter(QuestionnaireAssessment.user_id.is_(None)).order_by(QuestionnaireAssessment.created_at.desc()).limit(5).all()
        latest_ip = IPAssessment.query.filter(IPAssessment.user_id.is_(None)).order_by(IPAssessment.created_at.desc()).first()
        total_breaches = sum([s.breach_count for s in email_scans])
        completed_recs = 0
        total_recs = 0

    total_assessments = len(email_scans) + len(quiz_scans)
    
    # Latest risk score
    latest_email = email_scans[0] if email_scans else None
    latest_quiz = quiz_scans[0] if quiz_scans else None
    
    # Calculate average general score or latest
    general_score = latest_quiz.overall_score if latest_quiz else (latest_email.risk_score if latest_email else None)
    
    # Prepare Chart Data
    chart_data = _prepare_chart_data(email_scans, quiz_scans, completed_recs, total_recs)

    return render_template(
        'dashboard/index.html',
        total_assessments=total_assessments,
        total_breaches=total_breaches,
        latest_ip=latest_ip,
        latest_email=latest_email,
        latest_quiz=latest_quiz,
        general_score=general_score,
        completed_recs=completed_recs,
        total_recs=total_recs,
        email_scans=email_scans[:5],
        quiz_scans=quiz_scans[:5],
        chart_data=chart_data,
        has_data=total_assessments > 0
    )


@dashboard_bp.route('/footprint')
def footprint():
    """
    Digital Footprint Visualization page.
    Synthesizes multi-vector digital identity findings with explicit provenance indicators.
    """
    if current_user.is_authenticated:
        latest_email = EmailAssessment.query.filter_by(user_id=current_user.id).order_by(EmailAssessment.created_at.desc()).first()
        latest_quiz = QuestionnaireAssessment.query.filter_by(user_id=current_user.id).order_by(QuestionnaireAssessment.created_at.desc()).first()
        latest_ip = IPAssessment.query.filter_by(user_id=current_user.id).order_by(IPAssessment.created_at.desc()).first()
    else:
        latest_email = EmailAssessment.query.filter(EmailAssessment.user_id.is_(None)).order_by(EmailAssessment.created_at.desc()).first()
        latest_quiz = QuestionnaireAssessment.query.filter(QuestionnaireAssessment.user_id.is_(None)).order_by(QuestionnaireAssessment.created_at.desc()).first()
        latest_ip = IPAssessment.query.filter(IPAssessment.user_id.is_(None)).order_by(IPAssessment.created_at.desc()).first()

    breaches = []
    if latest_email:
        breaches = BreachFinding.query.filter_by(assessment_id=latest_email.id).all()
        
    quiz_categories = latest_quiz.get_category_scores() if latest_quiz else {}

    return render_template(
        'dashboard/footprint.html',
        latest_email=latest_email,
        latest_quiz=latest_quiz,
        latest_ip=latest_ip,
        breaches=breaches,
        quiz_categories=quiz_categories
    )


def _prepare_chart_data(email_scans, quiz_scans, completed_recs, total_recs):
    """Compile JSON-serializable payloads for the 5 dashboard charts."""
    
    # 1. Digital Risk Distribution Pie Chart (Low, Moderate, High, Critical)
    risk_counts = {'Low': 0, 'Moderate': 0, 'High': 0, 'Critical': 0}
    for s in email_scans:
        label = s.risk_level.capitalize() if s.risk_level else 'Low'
        for key in risk_counts:
            if key.lower() in label.lower():
                risk_counts[key] += 1
                break
    for q in quiz_scans:
        label = q.risk_level.capitalize() if q.risk_level else 'Low'
        for key in risk_counts:
            if key.lower() in label.lower():
                risk_counts[key] += 1
                break

    # 2. Email Breach Bar Chart (Breaches per scan target)
    breach_labels = []
    breach_values = []
    for s in reversed(email_scans[:8]):
        # Mask email e.g. j***@domain.com
        parts = s.email.split('@')
        masked = f"{parts[0][:2]}***@{parts[1]}" if len(parts) == 2 else s.email
        breach_labels.append(masked)
        breach_values.append(s.breach_count)

    # 3. Security Radar Chart (6 dimensions)
    # Default baseline scores if quiz hasn't run yet
    radar_labels = ['Authentication', 'Network Security', 'Social Privacy', 'Browsing Tracking', 'Device Hardening', 'Identity Exposure']
    radar_values = [0, 0, 0, 0, 0, 0]
    
    if quiz_scans:
        cat_scores = quiz_scans[0].get_category_scores()
        radar_values = [
            cat_scores.get('Authentication', 20),
            cat_scores.get('Network', 15),
            cat_scores.get('Social & Privacy', 25),
            cat_scores.get('Browsing & Phishing', 20),
            cat_scores.get('Device & Apps', 20),
            min(100, email_scans[0].risk_score if email_scans else 10)
        ]
    elif email_scans:
        radar_values = [30, 20, 20, 20, 20, email_scans[0].risk_score]

    # 4. Privacy Improvement Progress Chart (Doughnut: Completed vs Pending)
    pending_recs = max(0, total_recs - completed_recs)

    # 5. Assessment History Trend Chart (Line chart over time)
    timeline_labels = []
    timeline_scores = []
    # Combine email and quiz chronologically
    combined = []
    for s in email_scans:
        combined.append((s.created_at, s.risk_score, 'Email'))
    for q in quiz_scans:
        combined.append((q.created_at, q.overall_score, 'Quiz'))
        
    combined.sort(key=lambda x: x[0])
    for item in combined[-10:]:
        timeline_labels.append(item[0].strftime("%b %d %H:%M"))
        timeline_scores.append(item[1])

    return {
        'risk_pie': {
            'labels': list(risk_counts.keys()),
            'data': list(risk_counts.values())
        },
        'breach_bar': {
            'labels': breach_labels,
            'data': breach_values
        },
        'security_radar': {
            'labels': radar_labels,
            'data': radar_values
        },
        'progress_doughnut': {
            'labels': ['Completed Action Tasks', 'Pending Recommendations'],
            'data': [completed_recs, pending_recs]
        },
        'history_trend': {
            'labels': timeline_labels,
            'data': timeline_scores
        }
    }

