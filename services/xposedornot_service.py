import requests
from datetime import datetime, timezone
from models import db, ApiActivityLog

BASE_URL = "https://api.xposedornot.com/v1"
HEADERS = {
    "User-Agent": "DigitalFootprintIntelligence-Scanner/1.0 (Privacy-Research)",
    "Accept": "application/json"
}

def check_email_breaches(email):
    """
    Query XposedOrNot official breach analytics endpoint for an email address.
    Returns a structured dictionary:
    {
        'status': 'success' | 'no_breach' | 'rate_limited' | 'error' | 'timeout',
        'email': email,
        'breach_count': int,
        'paste_count': int,
        'risk_score': int,
        'risk_label': str,
        'breaches': list of breach dicts,
        'pastes': list of pastes,
        'metrics': dict,
        'raw': dict,
        'error_message': str | None
    }
    """
    clean_email = email.strip().lower()
    endpoint = f"{BASE_URL}/breach-analytics?email={clean_email}"
    start_time = datetime.now(timezone.utc)
    
    try:
        response = requests.get(endpoint, headers=HEADERS, timeout=12)
        elapsed = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
        
        status_code = response.status_code
        
        # Rate limit
        if status_code == 429:
            _log_api("XposedOrNot", endpoint, status_code, elapsed, False, "Rate limited by XposedOrNot API.")
            return {
                'status': 'rate_limited',
                'email': clean_email,
                'breach_count': 0,
                'paste_count': 0,
                'risk_score': 0,
                'risk_label': 'Unknown (Rate Limited)',
                'breaches': [],
                'pastes': [],
                'metrics': {},
                'raw': {},
                'error_message': "XposedOrNot API rate limit reached. Please wait a moment before trying again."
            }
            
        # Service unavailable or internal server error
        if status_code >= 500:
            _log_api("XposedOrNot", endpoint, status_code, elapsed, False, f"Server error: HTTP {status_code}")
            return {
                'status': 'error',
                'email': clean_email,
                'breach_count': 0,
                'paste_count': 0,
                'risk_score': 0,
                'risk_label': 'Service Unavailable',
                'breaches': [],
                'pastes': [],
                'metrics': {},
                'raw': {},
                'error_message': f"XposedOrNot service temporarily unavailable (HTTP {status_code})."
            }

        # 404 or empty response
        if status_code == 404:
            _log_api("XposedOrNot", endpoint, 404, elapsed, True, None)
            return {
                'status': 'no_breach',
                'email': clean_email,
                'breach_count': 0,
                'paste_count': 0,
                'risk_score': 0,
                'risk_label': 'Low Risk',
                'breaches': [],
                'pastes': [],
                'metrics': {},
                'raw': {},
                'error_message': None
            }
            
        data = response.json()
        
        # Check if response signifies "Not found"
        if isinstance(data, dict) and data.get("Error") == "Not found":
            _log_api("XposedOrNot", endpoint, 200, elapsed, True, None)
            return {
                'status': 'no_breach',
                'email': clean_email,
                'breach_count': 0,
                'paste_count': 0,
                'risk_score': 0,
                'risk_label': 'Low Risk',
                'breaches': [],
                'pastes': [],
                'metrics': {},
                'raw': data,
                'error_message': None
            }
            
        # Parse breaches
        exposed_breaches_obj = data.get("ExposedBreaches", {})
        breaches_list = []
        if isinstance(exposed_breaches_obj, dict):
            raw_details = exposed_breaches_obj.get("breaches_details", [])
            for b in raw_details:
                breaches_list.append({
                    'breach_name': b.get('breach', 'Unknown Breach'),
                    'domain': b.get('domain', ''),
                    'industry': b.get('industry', 'General'),
                    'breach_date': str(b.get('xposed_date', 'Unknown')),
                    'pwn_count': int(b.get('xposed_records', 0) or 0),
                    'description': b.get('details', ''),
                    'data_classes': b.get('xposed_data', ''),
                    'is_verified': b.get('verified', 'Yes').lower() in ('yes', 'true', '1'),
                    'password_risk': b.get('password_risk', 'unknown').lower(),
                    'logo_url': b.get('logo', '')
                })

        # Parse metrics & risk
        metrics = data.get("BreachMetrics", {})
        risk_score = 0
        risk_label = 'Low Risk'
        if isinstance(metrics, dict) and 'risk' in metrics:
            risk_arr = metrics.get('risk', [])
            if risk_arr and isinstance(risk_arr, list) and len(risk_arr) > 0:
                first_risk = risk_arr[0]
                risk_score = int(first_risk.get('risk_score', 0) or 0)
                risk_label = first_risk.get('risk_label', 'Low')
                
        # If breaches found but API risk_score was 0, calculate baseline
        if len(breaches_list) > 0 and risk_score == 0:
            risk_score = min(100, len(breaches_list) * 20)
            if risk_score > 75:
                risk_label = 'Critical'
            elif risk_score > 50:
                risk_label = 'High'
            elif risk_score > 25:
                risk_label = 'Moderate'
            else:
                risk_label = 'Low'

        pastes = []
        exposed_pastes_obj = data.get("ExposedPastes", {})
        if isinstance(exposed_pastes_obj, dict):
            pastes = exposed_pastes_obj.get("pastes_details", [])

        breach_count = len(breaches_list)
        paste_count = len(pastes) if isinstance(pastes, list) else 0

        _log_api("XposedOrNot", endpoint, 200, elapsed, True, None)
        
        return {
            'status': 'success' if breach_count > 0 else 'no_breach',
            'email': clean_email,
            'breach_count': breach_count,
            'paste_count': paste_count,
            'risk_score': risk_score,
            'risk_label': risk_label,
            'breaches': breaches_list,
            'pastes': pastes,
            'metrics': metrics,
            'raw': data,
            'error_message': None
        }

    except requests.exceptions.Timeout:
        elapsed = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
        _log_api("XposedOrNot", endpoint, 408, elapsed, False, "Request timed out.")
        return {
            'status': 'timeout',
            'email': clean_email,
            'breach_count': 0,
            'paste_count': 0,
            'risk_score': 0,
            'risk_label': 'Scan Timeout',
            'breaches': [],
            'pastes': [],
            'metrics': {},
            'raw': {},
            'error_message': "XposedOrNot server timed out while analyzing email exposure."
        }
    except requests.exceptions.RequestException as e:
        elapsed = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
        _log_api("XposedOrNot", endpoint, 500, elapsed, False, str(e))
        return {
            'status': 'error',
            'email': clean_email,
            'breach_count': 0,
            'paste_count': 0,
            'risk_score': 0,
            'risk_label': 'API Error',
            'breaches': [],
            'pastes': [],
            'metrics': {},
            'raw': {},
            'error_message': f"Unable to reach XposedOrNot: {str(e)}"
        }
    except Exception as e:
        elapsed = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
        _log_api("XposedOrNot", endpoint, 500, elapsed, False, str(e))
        return {
            'status': 'error',
            'email': clean_email,
            'breach_count': 0,
            'paste_count': 0,
            'risk_score': 0,
            'risk_label': 'Data Parsing Error',
            'breaches': [],
            'pastes': [],
            'metrics': {},
            'raw': {},
            'error_message': f"Unexpected response format from XposedOrNot: {str(e)}"
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

