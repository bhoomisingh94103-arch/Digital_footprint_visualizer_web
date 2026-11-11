import requests
from datetime import datetime, timezone
from flask import current_app
from models import db, ApiActivityLog

DISPOSABLE_DOMAINS = {
    'mailinator.com', 'tempmail.com', 'guerrillamail.com', '10minutemail.com',
    'throwawaymail.com', 'yopmail.com', 'sharklasers.com', 'dispostable.com',
    'trashmail.com', 'getairmail.com', 'fakeinbox.com', 'mohmal.com',
    'temp-mail.org', 'crazymailing.com', 'mytemp.email', 'dropmail.me',
    'generator.email', 'disposablemail.com', 'inboxkitten.com'
}

FREE_PROVIDERS = {
    'gmail.com', 'googlemail.com', 'yahoo.com', 'ymail.com', 'hotmail.com',
    'outlook.com', 'live.com', 'icloud.com', 'aol.com', 'proton.me', 'protonmail.com'
}

def check_email_reputation(email):
    """
    Check EmailRep.io for email reputation if API key is configured.
    If unavailable or API key is absent, honestly returns unconfigured/unavailable status,
    plus deterministic local domain heuristics (clearly labeled as local, not fake API data).
    """
    clean_email = email.strip().lower()
    domain = clean_email.split('@')[-1] if '@' in clean_email else ''
    
    try:
        api_key = current_app.config.get('EMAILREP_API_KEY', '').strip()
    except Exception:
        import os
        api_key = os.environ.get('EMAILREP_API_KEY', '').strip()
    start_time = datetime.now(timezone.utc)
    endpoint = f"https://emailrep.io/{clean_email}"
    
    # Local heuristics (always transparent)
    is_disposable_domain = domain in DISPOSABLE_DOMAINS
    is_free_provider = domain in FREE_PROVIDERS
    
    if not api_key:
        # Honest status: Not configured
        _log_api("EmailRep", endpoint, None, 0, False, "EMAILREP_API_KEY not configured in environment.")
        return {
            'status': 'not_configured',
            'email': clean_email,
            'reputation': 'unavailable',
            'suspicious': False,
            'references_count': 0,
            'is_disposable': is_disposable_domain,
            'is_free_provider': is_free_provider,
            'domain_reputation': 'unknown',
            'api_connected': False,
            'message': "EmailRep API key is not configured in .env. To activate external reputation intelligence, obtain an API key from emailrep.io.",
            'local_analysis': {
                'domain': domain,
                'is_disposable_list_match': is_disposable_domain,
                'is_major_free_provider': is_free_provider
            }
        }

    headers = {
        "Key": api_key,
        "User-Agent": "DigitalFootprintIntelligence-Scanner/1.0"
    }

    try:
        res = requests.get(endpoint, headers=headers, timeout=8)
        elapsed = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
        
        if res.status_code == 200:
            data = res.json()
            _log_api("EmailRep", endpoint, 200, elapsed, True, None)
            
            details = data.get('details', {})
            return {
                'status': 'success',
                'email': clean_email,
                'reputation': data.get('reputation', 'unknown'),
                'suspicious': data.get('suspicious', False),
                'references_count': data.get('references', 0),
                'is_disposable': details.get('disposable', is_disposable_domain),
                'is_free_provider': details.get('free_provider', is_free_provider),
                'domain_reputation': details.get('domain_reputation', 'unknown'),
                'api_connected': True,
                'message': "Live reputation data successfully retrieved from EmailRep.io.",
                'details': details,
                'local_analysis': {
                    'domain': domain,
                    'is_disposable_list_match': is_disposable_domain,
                    'is_major_free_provider': is_free_provider
                }
            }
        elif res.status_code == 429:
            _log_api("EmailRep", endpoint, 429, elapsed, False, "Rate limited or unauthenticated query blocked.")
            return {
                'status': 'rate_limited',
                'email': clean_email,
                'reputation': 'unavailable',
                'suspicious': False,
                'references_count': 0,
                'is_disposable': is_disposable_domain,
                'is_free_provider': is_free_provider,
                'domain_reputation': 'unknown',
                'api_connected': False,
                'message': "EmailRep.io rate limit reached or key quota exceeded.",
                'local_analysis': {
                    'domain': domain,
                    'is_disposable_list_match': is_disposable_domain,
                    'is_major_free_provider': is_free_provider
                }
            }
        else:
            _log_api("EmailRep", endpoint, res.status_code, elapsed, False, f"HTTP {res.status_code}: {res.text[:100]}")
            return {
                'status': 'error',
                'email': clean_email,
                'reputation': 'unavailable',
                'suspicious': False,
                'references_count': 0,
                'is_disposable': is_disposable_domain,
                'is_free_provider': is_free_provider,
                'domain_reputation': 'unknown',
                'api_connected': False,
                'message': f"EmailRep.io returned HTTP {res.status_code}.",
                'local_analysis': {
                    'domain': domain,
                    'is_disposable_list_match': is_disposable_domain,
                    'is_major_free_provider': is_free_provider
                }
            }

    except requests.exceptions.Timeout:
        elapsed = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
        _log_api("EmailRep", endpoint, 408, elapsed, False, "Request timeout.")
        return {
            'status': 'timeout',
            'email': clean_email,
            'reputation': 'unavailable',
            'suspicious': False,
            'references_count': 0,
            'is_disposable': is_disposable_domain,
            'is_free_provider': is_free_provider,
            'domain_reputation': 'unknown',
            'api_connected': False,
            'message': "EmailRep.io request timed out.",
            'local_analysis': {
                'domain': domain,
                'is_disposable_list_match': is_disposable_domain,
                'is_major_free_provider': is_free_provider
            }
        }
    except Exception as e:
        elapsed = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
        _log_api("EmailRep", endpoint, 500, elapsed, False, str(e))
        return {
            'status': 'error',
            'email': clean_email,
            'reputation': 'unavailable',
            'suspicious': False,
            'references_count': 0,
            'is_disposable': is_disposable_domain,
            'is_free_provider': is_free_provider,
            'domain_reputation': 'unknown',
            'api_connected': False,
            'message': f"Error communicating with EmailRep.io: {str(e)}",
            'local_analysis': {
                'domain': domain,
                'is_disposable_list_match': is_disposable_domain,
                'is_major_free_provider': is_free_provider
            }
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
