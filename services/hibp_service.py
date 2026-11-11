import requests
from datetime import datetime, timezone
from flask import current_app
from models import db, ApiActivityLog

HIBP_BASE = "https://haveibeenpwned.com/api/v3"

def check_hibp_breaches(email):
    """
    Optional integration with Have I Been Pwned API v3.
    Requires HIBP_API_KEY in .env.
    Never pretends active unless valid API response is received.
    """
    clean_email = email.strip().lower()
    try:
        api_key = current_app.config.get('HIBP_API_KEY', '').strip()
    except Exception:
        import os
        api_key = os.environ.get('HIBP_API_KEY', '').strip()
    endpoint = f"{HIBP_BASE}/breachedaccount/{clean_email}?truncateResponse=false"
    
    if not api_key:
        _log_api("HIBP", endpoint, None, 0, False, "HIBP_API_KEY not configured in .env.")
        return {
            'status': 'not_configured',
            'email': clean_email,
            'breaches': [],
            'count': 0,
            'is_configured': False,
            'message': "Have I Been Pwned (HIBP) is not configured. An API key is optional and can be supplied via HIBP_API_KEY in .env."
        }
        
    start_time = datetime.now(timezone.utc)
    headers = {
        "hibp-api-key": api_key,
        "user-agent": "DigitalFootprintIntelligence-Auditor/1.0",
        "Accept": "application/json"
    }
    
    try:
        res = requests.get(endpoint, headers=headers, timeout=10)
        elapsed = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
        
        if res.status_code == 200:
            breaches = res.json()
            _log_api("HIBP", endpoint, 200, elapsed, True, None)
            return {
                'status': 'success',
                'email': clean_email,
                'breaches': breaches,
                'count': len(breaches),
                'is_configured': True,
                'message': f"Retrieved {len(breaches)} breach records from HIBP."
            }
        elif res.status_code == 404:
            # 404 in HIBP signifies account not pwned
            _log_api("HIBP", endpoint, 404, elapsed, True, None)
            return {
                'status': 'no_breach',
                'email': clean_email,
                'breaches': [],
                'count': 0,
                'is_configured': True,
                'message': "HIBP reported zero breach records for this email address."
            }
        elif res.status_code == 429:
            _log_api("HIBP", endpoint, 429, elapsed, False, "Rate limit exceeded.")
            return {
                'status': 'rate_limited',
                'email': clean_email,
                'breaches': [],
                'count': 0,
                'is_configured': True,
                'message': "HIBP rate limit exceeded (API v3 requires 1.5s between requests)."
            }
        elif res.status_code == 401:
            _log_api("HIBP", endpoint, 401, elapsed, False, "Invalid HIBP API key.")
            return {
                'status': 'auth_failed',
                'email': clean_email,
                'breaches': [],
                'count': 0,
                'is_configured': True,
                'message': "HIBP authentication failed: invalid API key."
            }
        else:
            _log_api("HIBP", endpoint, res.status_code, elapsed, False, f"HTTP {res.status_code}")
            return {
                'status': 'error',
                'email': clean_email,
                'breaches': [],
                'count': 0,
                'is_configured': True,
                'message': f"HIBP returned HTTP status {res.status_code}."
            }
            
    except requests.exceptions.Timeout:
        elapsed = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
        _log_api("HIBP", endpoint, 408, elapsed, False, "Timeout connecting to HIBP.")
        return {
            'status': 'timeout',
            'email': clean_email,
            'breaches': [],
            'count': 0,
            'is_configured': True,
            'message': "Connection to HIBP API timed out."
        }
    except Exception as e:
        elapsed = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
        _log_api("HIBP", endpoint, 500, elapsed, False, str(e))
        return {
            'status': 'error',
            'email': clean_email,
            'breaches': [],
            'count': 0,
            'is_configured': True,
            'message': f"HIBP integration error: {str(e)}"
        }

def _log_api(name, endpoint, code, elapsed, success, err):
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
