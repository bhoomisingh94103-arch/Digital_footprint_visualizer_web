import requests
from datetime import datetime, timezone
from models import db, ApiActivityLog

HACKMYIP_BASE = "https://hackmyip.com"
HEADERS = {
    "User-Agent": "DigitalFootprintIntelligence-Scanner/1.0",
    "Accept": "application/json"
}

def analyze_network_ip(client_ip=None):
    """
    Query HackMyIP endpoints for network privacy assessment.
    Returns:
    {
        'status': 'success' | 'error' | 'timeout',
        'ip': str,
        'country': str,
        'city': str,
        'isp_org': str,
        'asn': str,
        'is_vpn': bool,
        'is_proxy': bool,
        'is_tor': bool,
        'network_type': str,
        'signal': str,
        'threat_score': int,
        'threat_level': str,
        'raw': dict,
        'error_message': str | None
    }
    """
    start_time = datetime.now(timezone.utc)
    endpoint_json = f"{HACKMYIP_BASE}/json"
    endpoint_proxy = f"{HACKMYIP_BASE}/proxy"
    
    try:
        # 1. Fetch IP & Geo data
        res_json = requests.get(endpoint_json, headers=HEADERS, timeout=8)
        elapsed_json = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
        
        if res_json.status_code != 200:
            _log_api("HackMyIP", endpoint_json, res_json.status_code, elapsed_json, False, f"HTTP {res_json.status_code}")
            return _fallback_ip_result(f"HackMyIP returned HTTP status {res_json.status_code}")
            
        data_json = res_json.json()
        ip_addr = data_json.get("ip", "Unknown")
        city = data_json.get("city", "Unknown")
        country = data_json.get("country", "Unknown")
        asn = data_json.get("asn", "")
        org = data_json.get("org", "")
        
        # 2. Fetch Proxy / VPN status
        start_proxy = datetime.now(timezone.utc)
        is_vpn = False
        is_proxy = False
        is_tor = False
        network_type = "residential/other"
        signal_text = "Clean connection profile"
        
        try:
            res_proxy = requests.get(endpoint_proxy, headers=HEADERS, timeout=8)
            elapsed_proxy = int((datetime.now(timezone.utc) - start_proxy).total_seconds() * 1000)
            
            if res_proxy.status_code == 200:
                _log_api("HackMyIP", endpoint_proxy, 200, elapsed_proxy, True, None)
                proxy_text = res_proxy.text.lower()
                
                # Check for proxy indicators in response text
                if "proxy: yes" in proxy_text or "datacenter" in proxy_text or "hosting" in proxy_text:
                    is_proxy = True
                if "vpn" in proxy_text or "datacenter" in proxy_text:
                    is_vpn = True
                if "tor" in proxy_text:
                    is_tor = True
                    
                for line in res_proxy.text.splitlines():
                    if line.lower().startswith("type:"):
                        network_type = line.split(":", 1)[1].strip()
                    elif line.lower().startswith("signal:"):
                        signal_text = line.split(":", 1)[1].strip()
            else:
                _log_api("HackMyIP", endpoint_proxy, res_proxy.status_code, elapsed_proxy, False, "Proxy check non-200")
        except Exception as proxy_err:
            _log_api("HackMyIP", endpoint_proxy, 500, 0, False, str(proxy_err))
            
        # 3. Calculate network risk/threat score
        threat_score = 10
        threat_level = "Low Risk (Direct / Residential)"
        
        if is_tor:
            threat_score = 85
            threat_level = "High Anonymity (Tor Exit Node)"
        elif is_vpn and is_proxy:
            threat_score = 45
            threat_level = "Moderate (Proxy / Hosting Datacenter)"
        elif is_vpn:
            threat_score = 30
            threat_level = "Privacy Shield Active (VPN Detected)"
        elif is_proxy:
            threat_score = 50
            threat_level = "Moderate Risk (Proxy Intermediary)"
        elif "datacenter" in network_type.lower() or "hosting" in network_type.lower():
            threat_score = 40
            threat_level = "Cloud / Datacenter Node"

        _log_api("HackMyIP", endpoint_json, 200, elapsed_json, True, None)

        return {
            'status': 'success',
            'ip': ip_addr,
            'country': country,
            'city': city,
            'isp_org': org,
            'asn': asn,
            'is_vpn': is_vpn,
            'is_proxy': is_proxy,
            'is_tor': is_tor,
            'network_type': network_type,
            'signal': signal_text,
            'threat_score': threat_score,
            'threat_level': threat_level,
            'raw': {
                'json': data_json,
                'proxy_type': network_type,
                'signal': signal_text
            },
            'error_message': None
        }

    except requests.exceptions.Timeout:
        elapsed = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
        _log_api("HackMyIP", endpoint_json, 408, elapsed, False, "Timeout connecting to HackMyIP")
        return _fallback_ip_result("HackMyIP service connection timed out.")
    except Exception as e:
        elapsed = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
        _log_api("HackMyIP", endpoint_json, 500, elapsed, False, str(e))
        return _fallback_ip_result(f"HackMyIP network lookup failed: {str(e)}")

def _fallback_ip_result(err_msg):
    return {
        'status': 'error',
        'ip': 'Unavailable',
        'country': 'Unknown',
        'city': 'Unknown',
        'isp_org': 'Unknown',
        'asn': 'Unknown',
        'is_vpn': False,
        'is_proxy': False,
        'is_tor': False,
        'network_type': 'Unknown',
        'signal': 'Lookup unavailable',
        'threat_score': 0,
        'threat_level': 'Unknown',
        'raw': {},
        'error_message': err_msg
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

