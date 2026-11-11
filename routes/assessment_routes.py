import os
import json
import re
from datetime import datetime, timezone
from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, send_file, current_app, session
from flask_login import current_user, login_required
from models import db, EmailAssessment, BreachFinding, EmailRepCheck, IPAssessment, QuestionnaireAssessment, Recommendation, UserRecommendationProgress, PDFReport
from services.xposedornot_service import check_email_breaches
from services.hackmyip_service import analyze_network_ip
from services.emailrep_service import check_email_reputation
from services.hibp_service import check_hibp_breaches
from services.scoring_service import calculate_questionnaire_score, QUESTIONNAIRE_QUESTIONS
from services.recommendation_engine import generate_recommendations_for_email_assessment, generate_recommendations_for_questionnaire
from services.pdf_service import generate_pdf_report

assessment_bp = Blueprint('assessment', __name__, url_prefix='/assessment')

EMAIL_REGEX = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

# ==========================================
# MODE A: EMAIL-BASED ASSESSMENT
# ==========================================

@assessment_bp.route('/mode-a')
def mode_a():
    """Mode A email assessment entry page."""
    user_email = current_user.email if current_user.is_authenticated else ''
    return render_template('assessment/mode_a_email.html', prefill_email=user_email)


@assessment_bp.route('/api/scan-email', methods=['POST'])
def api_scan_email():
    """
    Execute real external API scans for an email:
    1. XposedOrNot for data breaches
    2. HackMyIP for visitor network analysis (isolated)
    3. EmailRep for reputation and disposable status
    4. HIBP (optional)
    """
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    consent = data.get('consent', False)
    
    # 1. Validation
    if not email or not re.match(EMAIL_REGEX, email):
        return jsonify({
            'success': False,
            'error': 'Please provide a valid email address (e.g., user@example.com).'
        }), 400
        
    if not consent:
        return jsonify({
            'success': False,
            'error': 'You must acknowledge the privacy notice and authorize public index scanning.'
        }), 400

    user_id = current_user.id if current_user.is_authenticated else None

    # 2. Query XposedOrNot
    xon_result = check_email_breaches(email)
    
    # 3. Query HackMyIP (Separate Network Assessment - Visitor IP)
    ip_result = analyze_network_ip()
    
    # 4. Query EmailRep
    emailrep_result = check_email_reputation(email)
    
    # 5. Query HIBP (Optional)
    hibp_result = check_hibp_breaches(email)

    # 6. Aggregate risk score and metrics
    breach_count = xon_result.get('breach_count', 0)
    risk_score = xon_result.get('risk_score', 0)
    risk_label = xon_result.get('risk_label', 'Low Risk')
    pastes = xon_result.get('pastes', [])
    paste_count = len(pastes) if isinstance(pastes, list) else 0

    # Total exposed records across all breaches
    total_records = sum([b.get('pwn_count', 0) for b in xon_result.get('breaches', [])])
    
    # Save EmailAssessment to Database
    assessment = EmailAssessment(
        user_id=user_id,
        email=email,
        risk_score=risk_score,
        risk_level=risk_label,
        breach_count=breach_count,
        paste_count=paste_count,
        xposed_records_total=total_records,
        reputation_status=emailrep_result.get('reputation', 'Unknown'),
        status='completed',
        raw_data_json=json.dumps({
            'xposedornot': xon_result.get('raw', {}),
            'emailrep': emailrep_result.get('details', {}),
            'hibp': hibp_result.get('breaches', [])
        }),
        created_at=datetime.now(timezone.utc)
    )
    db.session.add(assessment)
    db.session.flush() # obtain assessment.id

    # Save individual BreachFindings
    saved_breaches = []
    for b in xon_result.get('breaches', []):
        bf = BreachFinding(
            assessment_id=assessment.id,
            breach_name=b.get('breach_name', 'Unknown'),
            domain=b.get('domain', ''),
            breach_date=str(b.get('breach_date', '')),
            pwn_count=b.get('pwn_count', 0),
            description=b.get('description', ''),
            data_classes=b.get('data_classes', ''),
            is_verified=b.get('is_verified', True),
            password_risk=b.get('password_risk', 'unknown'),
            logo_url=b.get('logo_url', ''),
            industry=b.get('industry', 'General')
        )
        db.session.add(bf)
        saved_breaches.append(b)

    # Save EmailRepCheck
    rep_check = EmailRepCheck(
        assessment_id=assessment.id,
        email=email,
        reputation=emailrep_result.get('reputation', 'unavailable'),
        suspicious=emailrep_result.get('suspicious', False),
        references_count=emailrep_result.get('references_count', 0),
        is_disposable=emailrep_result.get('is_disposable', False),
        is_free_provider=emailrep_result.get('is_free_provider', False),
        domain_reputation=emailrep_result.get('domain_reputation', 'unknown'),
        details_json=json.dumps(emailrep_result.get('details', {})),
        created_at=datetime.now(timezone.utc)
    )
    db.session.add(rep_check)

    # Save IPAssessment (Isolated)
    if ip_result and ip_result.get('ip') != 'Unavailable':
        ip_rec = IPAssessment(
            user_id=user_id,
            ip_address=ip_result.get('ip', 'Unknown'),
            country=ip_result.get('country', 'Unknown'),
            city=ip_result.get('city', 'Unknown'),
            isp=ip_result.get('isp_org', 'Unknown'),
            org=ip_result.get('isp_org', 'Unknown'),
            asn=ip_result.get('asn', ''),
            is_vpn=ip_result.get('is_vpn', False),
            is_proxy=ip_result.get('is_proxy', False),
            is_tor=ip_result.get('is_tor', False),
            network_type=ip_result.get('network_type', 'residential/other'),
            threat_score=ip_result.get('threat_score', 0),
            raw_response_json=json.dumps(ip_result.get('raw', {})),
            created_at=datetime.now(timezone.utc)
        )
        db.session.add(ip_rec)

    db.session.commit()

    # Generate tailored recommendations
    recs = generate_recommendations_for_email_assessment(assessment, user_id=user_id)
    recs_list = [{
        'id': r.id,
        'code': r.code,
        'title': r.title,
        'category': r.category,
        'priority': r.priority,
        'reason': r.reason,
        'action_steps': r.action_steps,
        'external_url': r.external_url
    } for r in recs]

    # Pre-generate PDF report
    report_folder = current_app.config.get('REPORT_FOLDER')
    pdf_payload = {
        'assessment_id': assessment.id,
        'scan_date': assessment.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        'email': email,
        'risk_score': risk_score,
        'risk_level': risk_label,
        'breach_count': breach_count,
        'breaches': saved_breaches,
        'ip_info': ip_result,
        'reputation_info': emailrep_result,
        'recommendations': recs_list
    }
    
    try:
        f_path, f_name = generate_pdf_report(pdf_payload, report_folder, 'email')
        pdf_entry = PDFReport(
            user_id=user_id,
            assessment_id=assessment.id,
            assessment_type='email',
            filename=f_name,
            file_path=f_path,
            risk_score=risk_score,
            risk_level=risk_label,
            created_at=datetime.now(timezone.utc)
        )
        db.session.add(pdf_entry)
        db.session.commit()
    except Exception as pdf_err:
        current_app.logger.error(f"PDF creation error: {pdf_err}")

    # Store latest assessment in session for chatbot context
    session['last_assessment'] = {
        'id': assessment.id,
        'scan_type': 'Email Footprint (Mode A)',
        'target': email,
        'risk_score': risk_score,
        'risk_level': risk_label,
        'breach_count': breach_count
    }

    return jsonify({
        'success': True,
        'assessment_id': assessment.id,
        'email': email,
        'risk_score': risk_score,
        'risk_level': risk_label,
        'breach_count': breach_count,
        'paste_count': paste_count,
        'total_records': total_records,
        'breaches': saved_breaches,
        'metrics': xon_result.get('metrics', {}),
        'ip_analysis': ip_result,
        'email_reputation': emailrep_result,
        'hibp_summary': hibp_result,
        'recommendations': recs_list,
        'pdf_url': url_for('assessment.download_pdf', assessment_id=assessment.id)
    })


# ==========================================
# MODE B: GENERAL DIGITAL PRIVACY QUESTIONNAIRE
# ==========================================

@assessment_bp.route('/mode-b')
def mode_b():
    """Mode B Questionnaire interface."""
    return render_template(
        'assessment/mode_b_quiz.html',
        questions=QUESTIONNAIRE_QUESTIONS
    )


@assessment_bp.route('/api/submit-quiz', methods=['POST'])
def api_submit_quiz():
    """
    Process questionnaire responses, compute transparent category & overall risk scores,
    generate recommendations, and store assessment record.
    """
    data = request.get_json() or {}
    responses = data.get('responses', {})
    
    if not responses or not isinstance(responses, dict):
        return jsonify({'success': False, 'error': 'Invalid questionnaire responses submitted.'}), 400
        
    result = calculate_questionnaire_score(responses)
    user_id = current_user.id if current_user.is_authenticated else None
    
    # Save QuestionnaireAssessment
    q_assessment = QuestionnaireAssessment(
        user_id=user_id,
        overall_score=result['overall_score'],
        risk_level=result['risk_level'],
        category_scores_json=json.dumps(result['category_scores']),
        responses_json=json.dumps(responses),
        created_at=datetime.now(timezone.utc)
    )
    db.session.add(q_assessment)
    db.session.commit()
    
    # Generate recommendations
    recs = generate_recommendations_for_questionnaire(q_assessment, user_id=user_id)
    recs_list = [{
        'id': r.id,
        'code': r.code,
        'title': r.title,
        'category': r.category,
        'priority': r.priority,
        'reason': r.reason,
        'action_steps': r.action_steps,
        'external_url': r.external_url
    } for r in recs]
    
    # Generate PDF report
    report_folder = current_app.config.get('REPORT_FOLDER')
    pdf_payload = {
        'assessment_id': q_assessment.id,
        'scan_date': q_assessment.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        'target': 'Digital Privacy Questionnaire Profile',
        'risk_score': result['overall_score'],
        'risk_level': result['risk_level'],
        'breach_count': 0,
        'category_scores': result['category_scores'],
        'recommendations': recs_list
    }
    
    try:
        f_path, f_name = generate_pdf_report(pdf_payload, report_folder, 'questionnaire')
        pdf_entry = PDFReport(
            user_id=user_id,
            assessment_id=q_assessment.id,
            assessment_type='questionnaire',
            filename=f_name,
            file_path=f_path,
            risk_score=result['overall_score'],
            risk_level=result['risk_level'],
            created_at=datetime.now(timezone.utc)
        )
        db.session.add(pdf_entry)
        db.session.commit()
    except Exception as pdf_err:
        current_app.logger.error(f"PDF creation error: {pdf_err}")
        
    session['last_assessment'] = {
        'id': q_assessment.id,
        'scan_type': 'Privacy Questionnaire (Mode B)',
        'target': 'Questionnaire Assessment',
        'risk_score': result['overall_score'],
        'risk_level': result['risk_level'],
        'breach_count': 0
    }

    return jsonify({
        'success': True,
        'assessment_id': q_assessment.id,
        'overall_score': result['overall_score'],
        'risk_level': result['risk_level'],
        'category_scores': result['category_scores'],
        'detailed_breakdown': result['detailed_breakdown'],
        'summary': result['summary'],
        'recommendations': recs_list,
        'pdf_url': url_for('assessment.download_pdf', assessment_id=q_assessment.id, quiz=1)
    })


# ==========================================
# DETAILS, HISTORY, PDF DOWNLOAD & DELETE
# ==========================================

@assessment_bp.route('/detail/<int:assessment_id>')
def detail(assessment_id):
    """View detailed results of a past email assessment."""
    assessment = db.session.get(EmailAssessment, assessment_id)
    if not assessment:
        flash('Assessment not found.', 'danger')
        return redirect(url_for('assessment.history'))
    if assessment.user_id and (not current_user.is_authenticated or current_user.id != assessment.user_id):
        flash('Unauthorized to view this assessment report.', 'danger')
        return redirect(url_for('assessment.history'))
        
    breaches = BreachFinding.query.filter_by(assessment_id=assessment.id).all()
    rep_check = EmailRepCheck.query.filter_by(assessment_id=assessment.id).first()
    recs = generate_recommendations_for_email_assessment(assessment, user_id=current_user.id if current_user.is_authenticated else None)
    
    return render_template(
        'assessment/detail.html',
        assessment=assessment,
        breaches=breaches,
        rep_check=rep_check,
        recommendations=recs
    )


@assessment_bp.route('/quiz-detail/<int:assessment_id>')
def quiz_detail(assessment_id):
    """View detailed results of a past questionnaire assessment."""
    q_assessment = db.session.get(QuestionnaireAssessment, assessment_id)
    if not q_assessment:
        flash('Assessment not found.', 'danger')
        return redirect(url_for('assessment.history'))
    if q_assessment.user_id and (not current_user.is_authenticated or current_user.id != q_assessment.user_id):
        flash('Unauthorized to view this assessment report.', 'danger')
        return redirect(url_for('assessment.history'))
        
    cat_scores = q_assessment.get_category_scores()
    recs = generate_recommendations_for_questionnaire(q_assessment, user_id=current_user.id if current_user.is_authenticated else None)
    
    return render_template(
        'assessment/quiz_detail.html',
        assessment=q_assessment,
        category_scores=cat_scores,
        recommendations=recs
    )


@assessment_bp.route('/history')
@login_required
def history():
    """User assessment history."""
    email_scans = EmailAssessment.query.filter_by(user_id=current_user.id).order_by(EmailAssessment.created_at.desc()).all()
    quiz_scans = QuestionnaireAssessment.query.filter_by(user_id=current_user.id).order_by(QuestionnaireAssessment.created_at.desc()).all()
    return render_template(
        'assessment/history.html',
        email_scans=email_scans,
        quiz_scans=quiz_scans
    )


@assessment_bp.route('/delete/<int:assessment_id>', methods=['POST'])
@login_required
def delete_assessment(assessment_id):
    """Delete a specific email assessment record."""
    assessment = EmailAssessment.query.filter_by(id=assessment_id, user_id=current_user.id).first_or_404()
    db.session.delete(assessment)
    db.session.commit()
    flash('Email assessment record successfully deleted.', 'success')
    return redirect(url_for('assessment.history'))


@assessment_bp.route('/delete-quiz/<int:assessment_id>', methods=['POST'])
@login_required
def delete_quiz_assessment(assessment_id):
    """Delete a specific questionnaire assessment record."""
    assessment = QuestionnaireAssessment.query.filter_by(id=assessment_id, user_id=current_user.id).first_or_404()
    db.session.delete(assessment)
    db.session.commit()
    flash('Questionnaire assessment record successfully deleted.', 'success')
    return redirect(url_for('assessment.history'))


@assessment_bp.route('/clear-history', methods=['POST'])
@login_required
def clear_history():
    """Clear all assessment history for current authenticated user."""
    EmailAssessment.query.filter_by(user_id=current_user.id).delete()
    QuestionnaireAssessment.query.filter_by(user_id=current_user.id).delete()
    IPAssessment.query.filter_by(user_id=current_user.id).delete()
    PDFReport.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    flash('All personal assessment records have been permanently cleared.', 'success')
    return redirect(url_for('assessment.history'))


@assessment_bp.route('/download-pdf/<int:assessment_id>')
def download_pdf(assessment_id):
    """Serve generated ReportLab PDF report."""
    is_quiz = request.args.get('quiz', '0') == '1'
    report_type = 'questionnaire' if is_quiz else 'email'
    
    pdf_entry = PDFReport.query.filter_by(assessment_id=assessment_id, assessment_type=report_type).first()
    
    if pdf_entry and os.path.exists(pdf_entry.file_path):
        return send_file(
            pdf_entry.file_path,
            as_attachment=True,
            download_name=pdf_entry.filename,
            mimetype='application/pdf'
        )
        
    # If not on disk, generate on demand
    report_folder = current_app.config.get('REPORT_FOLDER')
    if is_quiz:
        q_item = db.session.get(QuestionnaireAssessment, assessment_id)
        if not q_item:
            return "Assessment not found", 404
        recs = generate_recommendations_for_questionnaire(q_item)
        recs_list = [{'title': r.title, 'category': r.category, 'priority': r.priority, 'reason': r.reason, 'action_steps': r.action_steps} for r in recs]
        payload = {
            'assessment_id': q_item.id,
            'scan_date': q_item.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            'target': 'Privacy Questionnaire Profile',
            'risk_score': q_item.overall_score,
            'risk_level': q_item.risk_level,
            'breach_count': 0,
            'category_scores': q_item.get_category_scores(),
            'recommendations': recs_list
        }
    else:
        e_item = db.session.get(EmailAssessment, assessment_id)
        if not e_item:
            return "Assessment not found", 404
        breaches = BreachFinding.query.filter_by(assessment_id=e_item.id).all()
        recs = generate_recommendations_for_email_assessment(e_item)
        recs_list = [{'title': r.title, 'category': r.category, 'priority': r.priority, 'reason': r.reason, 'action_steps': r.action_steps} for r in recs]
        b_list = [{
            'breach_name': b.breach_name,
            'domain': b.domain,
            'breach_date': b.breach_date,
            'data_classes': b.data_classes,
            'password_risk': b.password_risk
        } for b in breaches]
        payload = {
            'assessment_id': e_item.id,
            'scan_date': e_item.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            'email': e_item.email,
            'risk_score': e_item.risk_score,
            'risk_level': e_item.risk_level,
            'breach_count': e_item.breach_count,
            'breaches': b_list,
            'recommendations': recs_list
        }
        
    f_path, f_name = generate_pdf_report(payload, report_folder, report_type)
    return send_file(f_path, as_attachment=True, download_name=f_name, mimetype='application/pdf')
