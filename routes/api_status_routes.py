import time
import requests
from datetime import datetime, timezone
from flask import Blueprint, render_template, jsonify, current_app
from models import db, ApiActivityLog

api_status_bp = Blueprint('api_status', __name__, url_prefix='/api-status')

@api_status_bp.route('/')
def index():
    """API Management Center overview."""
    # Check current configurations (without exposing keys)
    hibp_configured = bool(current_app.config.get('HIBP_API_KEY'))
    emailrep_configured = bool(current_app.config.get('EMAILREP_API_KEY'))
    gemini_configured = bool(current_app.config.get('GEMINI_API_KEY'))
    openai_configured = bool(current_app.config.get('OPENAI_API_KEY'))
    smtp_configured = bool(current_app.config.get('MAIL_SERVER') and current_app.config.get('MAIL_USERNAME'))
    
    # Query latest activity log for each service
    api_names = ['XposedOrNot', 'HackMyIP', 'EmailRep', 'HIBP', 'SMTP', 'LLM']
    latest_logs = {}
    for name in api_names:
        log = ApiActivityLog.query.filter_by(api_name=name).order_by(ApiActivityLog.timestamp.desc()).first()
        latest_logs[name] = log

    # Recent 20 API transactions
    recent_transactions = ApiActivityLog.query.order_by(ApiActivityLog.timestamp.desc()).limit(20).all()

    return render_template(
        'api_status/index.html',
        hibp_configured=hibp_configured,
        emailrep_configured=emailrep_configured,
        gemini_configured=gemini_configured,
        openai_configured=openai_configured,
        smtp_configured=smtp_configured,
        latest_logs=latest_logs,
        recent_transactions=recent_transactions
    )


@api_status_bp.route('/ping/<service_name>', methods=['POST'])
def ping_service(service_name):
    """
    Perform a live connection diagnosis test against the specified external service.
    Returns status, latency (ms), HTTP status code, and diagnosis message.
    """
    svc = service_name.lower()
    start = time.time()
    
    if svc == 'xposedornot':
        try:
            r = requests.get('https://api.xposedornot.com/v1/breaches', timeout=6)
            elapsed = int((time.time() - start) * 1000)
            success = r.status_code == 200
            status_text = 'Connected' if success else ('Rate Limited' if r.status_code == 429 else 'Service Unavailable')
            msg = f"HTTP {r.status_code}: Successfully queried public breach endpoint." if success else f"HTTP {r.status_code}"
            _record_ping('XposedOrNot', 'https://api.xposedornot.com/v1/breaches', r.status_code, elapsed, success, msg if not success else None)
            return jsonify({'service': 'XposedOrNot', 'status': status_text, 'latency_ms': elapsed, 'code': r.status_code, 'message': msg})
        except Exception as e:
            elapsed = int((time.time() - start) * 1000)
            _record_ping('XposedOrNot', 'https://api.xposedornot.com/v1/breaches', 500, elapsed, False, str(e))
            return jsonify({'service': 'XposedOrNot', 'status': 'Service Unavailable', 'latency_ms': elapsed, 'code': 500, 'message': str(e)})

    elif svc == 'hackmyip':
        try:
            r = requests.get('https://hackmyip.com/json', timeout=6)
            elapsed = int((time.time() - start) * 1000)
            success = r.status_code == 200
            status_text = 'Connected' if success else 'Service Unavailable'
            msg = f"HTTP {r.status_code}: IP geolocation and ASN intelligence online." if success else f"HTTP {r.status_code}"
            _record_ping('HackMyIP', 'https://hackmyip.com/json', r.status_code, elapsed, success, msg if not success else None)
            return jsonify({'service': 'HackMyIP', 'status': status_text, 'latency_ms': elapsed, 'code': r.status_code, 'message': msg})
        except Exception as e:
            elapsed = int((time.time() - start) * 1000)
            _record_ping('HackMyIP', 'https://hackmyip.com/json', 500, elapsed, False, str(e))
            return jsonify({'service': 'HackMyIP', 'status': 'Service Unavailable', 'latency_ms': elapsed, 'code': 500, 'message': str(e)})

    elif svc == 'emailrep':
        key = current_app.config.get('EMAILREP_API_KEY')
        if not key:
            return jsonify({
                'service': 'EmailRep',
                'status': 'Not Configured',
                'latency_ms': 0,
                'code': 400,
                'message': 'EMAILREP_API_KEY is not defined in .env (Free unauthenticated queries are disabled by emailrep.io).'
            })
        try:
            headers = {"Key": key, "User-Agent": "DigitalFootprintIntelligence-Auditor/1.0"}
            r = requests.get('https://emailrep.io/test@example.com', headers=headers, timeout=6)
            elapsed = int((time.time() - start) * 1000)
            success = r.status_code == 200
            status_text = 'Connected' if success else ('Authentication Failed' if r.status_code == 401 else ('Rate Limited' if r.status_code == 429 else 'Error'))
            msg = f"HTTP {r.status_code}: Key verified." if success else f"HTTP {r.status_code}: {r.text[:80]}"
            _record_ping('EmailRep', 'https://emailrep.io/test@example.com', r.status_code, elapsed, success, msg if not success else None)
            return jsonify({'service': 'EmailRep', 'status': status_text, 'latency_ms': elapsed, 'code': r.status_code, 'message': msg})
        except Exception as e:
            elapsed = int((time.time() - start) * 1000)
            return jsonify({'service': 'EmailRep', 'status': 'Service Unavailable', 'latency_ms': elapsed, 'code': 500, 'message': str(e)})

    elif svc == 'hibp':
        key = current_app.config.get('HIBP_API_KEY')
        if not key:
            return jsonify({
                'service': 'Have I Been Pwned',
                'status': 'Not Configured',
                'latency_ms': 0,
                'code': 400,
                'message': 'HIBP_API_KEY is not defined in .env (Optional integration).'
            })
        try:
            headers = {"hibp-api-key": key, "user-agent": "DigitalFootprintIntelligence/1.0"}
            r = requests.get('https://haveibeenpwned.com/api/v3/breaches', headers=headers, timeout=6)
            elapsed = int((time.time() - start) * 1000)
            success = r.status_code == 200
            status_text = 'Connected' if success else ('Authentication Failed' if r.status_code == 401 else ('Rate Limited' if r.status_code == 429 else 'Error'))
            msg = f"HTTP {r.status_code}: HIBP connection active." if success else f"HTTP {r.status_code}"
            _record_ping('HIBP', 'https://haveibeenpwned.com/api/v3/breaches', r.status_code, elapsed, success, msg if not success else None)
            return jsonify({'service': 'Have I Been Pwned', 'status': status_text, 'latency_ms': elapsed, 'code': r.status_code, 'message': msg})
        except Exception as e:
            elapsed = int((time.time() - start) * 1000)
            return jsonify({'service': 'Have I Been Pwned', 'status': 'Service Unavailable', 'latency_ms': elapsed, 'code': 500, 'message': str(e)})

    elif svc == 'smtp':
        host = current_app.config.get('MAIL_SERVER')
        user = current_app.config.get('MAIL_USERNAME')
        if not host or not user:
            return jsonify({
                'service': 'SMTP Service',
                'status': 'Not Configured',
                'latency_ms': 0,
                'code': 400,
                'message': 'MAIL_SERVER / MAIL_USERNAME not configured in .env. OTP simulation active for development.'
            })
        import smtplib
        port = current_app.config.get('MAIL_PORT', 587)
        try:
            s = smtplib.SMTP(host, port, timeout=6)
            s.quit()
            elapsed = int((time.time() - start) * 1000)
            _record_ping('SMTP', f"smtp://{host}:{port}", 250, elapsed, True, None)
            return jsonify({'service': 'SMTP Service', 'status': 'Connected', 'latency_ms': elapsed, 'code': 250, 'message': f"Successfully reached {host}:{port}"})
        except Exception as e:
            elapsed = int((time.time() - start) * 1000)
            _record_ping('SMTP', f"smtp://{host}:{port}", 500, elapsed, False, str(e))
            return jsonify({'service': 'SMTP Service', 'status': 'Service Unavailable', 'latency_ms': elapsed, 'code': 500, 'message': str(e)})

    elif svc == 'llm':
        gemini_key = current_app.config.get('GEMINI_API_KEY')
        openai_key = current_app.config.get('OPENAI_API_KEY')
        if not gemini_key and not openai_key:
            return jsonify({
                'service': 'LLM API',
                'status': 'Not Configured (Expert Engine Active)',
                'latency_ms': 1,
                'code': 200,
                'message': 'No external LLM key provided. High-performance Privacy Guardian Rule-Based Expert Engine is active.'
            })
        if gemini_key:
            try:
                url = f"https://generativelanguage.googleapis.com/v1beta/models?key={gemini_key}"
                r = requests.get(url, timeout=6)
                elapsed = int((time.time() - start) * 1000)
                success = r.status_code == 200
                status_text = 'Connected' if success else ('Authentication Failed' if r.status_code in (400, 401, 403) else 'Error')
                msg = f"HTTP {r.status_code}: Gemini API connection active." if success else f"HTTP {r.status_code}"
                _record_ping('LLM', 'Gemini API', r.status_code, elapsed, success, msg if not success else None)
                return jsonify({'service': 'Gemini LLM', 'status': status_text, 'latency_ms': elapsed, 'code': r.status_code, 'message': msg})
            except Exception as e:
                elapsed = int((time.time() - start) * 1000)
                return jsonify({'service': 'Gemini LLM', 'status': 'Service Unavailable', 'latency_ms': elapsed, 'code': 500, 'message': str(e)})

    return jsonify({'service': service_name, 'status': 'Unknown Service', 'latency_ms': 0, 'code': 404, 'message': 'Invalid service'}), 404

def _record_ping(name, endpoint, code, elapsed, success, err):
    try:
        log = ApiActivityLog(
            api_name=name,
            endpoint=endpoint,
            status_code=code,
            response_time_ms=elapsed,
            success=success,
            error_message=err,
            timestamp=datetime.now(timezone.utc)
        )
        db.session.add(log)
        db.session.commit()
    except Exception:
        db.session.rollback()

