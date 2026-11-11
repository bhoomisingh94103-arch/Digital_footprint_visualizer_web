import json
import re
import requests
from flask import current_app

EXPERT_KNOWLEDGE_BASE = [
    {
        'keywords': ['breach', 'xposed', 'leak', 'exposed', 'database breach', 'dump'],
        'title': 'Data Breach Analysis & Remediation',
        'response': (
            "**Understanding Data Breaches:**\n\n"
            "When a website or company is breached, threat actors extract internal databases that frequently include usernames, hashed or plaintext passwords, email addresses, and personal profile information.\n\n"
            "**Immediate Action Steps:**\n"
            "1. **Never reuse breached passwords**: If you used the breached password on other services (especially your primary email or banking), change it immediately.\n"
            "2. **Activate 2-Factor Authentication (2FA)**: Even if attackers obtain your password, they cannot bypass hardware or app-based 2FA.\n"
            "3. **Watch for Targeted Phishing**: Breached emails are regularly added to phishing lists. Be suspicious of unsolicited emails mentioning your name or old passwords."
        )
    },
    {
        'keywords': ['password', 'passphrase', 'manager', 'bitwarden', '1password', 'complexity', 'entropy'],
        'title': 'Password Security & Credential Hygiene',
        'response': (
            "**Password Best Practices:**\n\n"
            "• **Length beats complexity**: A 4-word random passphrase like `correct-horse-battery-staple` or 16+ random characters has vastly higher entropy than a short password with symbols (e.g., `P@ss1`).\n"
            "• **Never reuse passwords**: Reusing one password across services turns a single low-security forum breach into a total digital identity compromise.\n"
            "• **Adopt a Password Manager**: Tools like Bitwarden (open source) or 1Password generate, encrypt, and auto-fill unique passwords for every site, protecting you from phishing spoof domains."
        )
    },
    {
        'keywords': ['2fa', 'mfa', 'two factor', 'authenticator', 'otp', 'totp', 'yubikey', 'token'],
        'title': 'Two-Factor Authentication (2FA / MFA)',
        'response': (
            "**Why 2FA is Essential:**\n\n"
            "Two-Factor Authentication introduces an independent verification layer:\n"
            "1. **Hardware Keys (FIDO2 / YubiKey)**: The gold standard. Cryptographically bound to the URL; completely immune to phishing.\n"
            "2. **Authenticator Apps (TOTP)**: Excellent defense. Apps like Aegis (Android) or 2FAS / Ente Auth generate time-based codes locally on your device without transmitting phone numbers.\n"
            "3. **SMS Verification**: Better than nothing, but vulnerable to SIM swapping, SS7 interception, and telecom social engineering.\n\n"
            "**Recommendation**: Upgrade SMS 2FA to an Authenticator app on all your critical accounts."
        )
    },
    {
        'keywords': ['vpn', 'proxy', 'tor', 'ip', 'hackmyip', 'isp', 'dns'],
        'title': 'Network Privacy: VPNs, Proxies & Tor',
        'response': (
            "**Understanding Network Privacy Tools:**\n\n"
            "• **VPN (Virtual Private Network)**: Encrypts your internet traffic tunnel between your device and the VPN server. Prevents your ISP and local Wi-Fi eavesdroppers from seeing the websites you visit.\n"
            "• **Proxy**: Relays your web requests through an intermediate server so the destination sees the proxy's IP. Typically lacks full tunnel encryption unless using HTTPS/SOCKS5 over TLS.\n"
            "• **Tor Network**: Routes your traffic through three encrypted hops across volunteer nodes, offering extreme anonymity at the cost of browsing speed.\n\n"
            "**Important Note**: A VPN protects your network transport, but it does NOT protect against browser fingerprinting, cookies, or signing into personal accounts."
        )
    },
    {
        'keywords': ['phishing', 'scam', 'suspicious link', 'fake email', 'spoof', 'urgent message'],
        'title': 'Phishing Identification & Defense',
        'response': (
            "**How to Spot and Defeat Phishing:**\n\n"
            "1. **Inspect the Sender Domain**: Attackers use lookalike domains (e.g., `support@paypa1-security.com` instead of `paypal.com`). Check the exact domain characters.\n"
            "2. **Beware of Manufactured Urgency**: Phishing emails create panic (e.g. 'Your account will be terminated in 24 hours', 'Unusual login from Russia').\n"
            "3. **Never Click Verification Links**: Instead of clicking links inside unexpected alerts, open your browser and navigate directly to the official website.\n"
            "4. **Never Approve Unexpected MFA Prompts**: If your phone pops up a 2FA prompt you didn't initiate, someone knows your password—decline the prompt and change your password immediately."
        )
    },
    {
        'keywords': ['tracking', 'cookie', 'fingerprint', 'telemetry', 'ublock', 'browser privacy'],
        'title': 'Web Browser Privacy & Anti-Tracking',
        'response': (
            "**Blocking Online Tracking:**\n\n"
            "• **Install uBlock Origin**: The most effective open-source content blocker that eliminates ad trackers, behavioral beacons, and malicious scripts.\n"
            "• **Browser Fingerprinting**: Websites can identify your device via screen resolution, installed fonts, Canvas rendering, and GPU telemetry. Browsers like Brave or LibreWolf actively randomize or spoof these parameters.\n"
            "• **Encrypted DNS**: Enable DNS-over-HTTPS (DoH) with Cloudflare (1.1.1.1) or Quad9 (9.9.9.9) to prevent local network sniffers from logging your domain lookups."
        )
    },
    {
        'keywords': ['score', 'risk score', 'assessment', 'mode a', 'mode b', 'calculate', 'footprint'],
        'title': 'Digital Footprint Intelligence Risk Scoring',
        'response': (
            "**How Your Risk Score is Calculated:**\n\n"
            "Our platform calculates risk objectively using two isolated modes:\n"
            "• **Mode A (Email Exposure)**: Scores based on real external API checks via XposedOrNot. Accounts for breach frequency, plaintext password leaks, and financial exposure.\n"
            "• **Mode B (Privacy Habits)**: Evaluates 15 core cybersecurity categories across Authentication, Network, Social Exposure, Browsing, and Device Security.\n\n"
            "**Risk Brackets:**\n"
            "- 0-25: Low Risk (Strong defenses)\n"
            "- 26-50: Moderate Risk (Good foundation, several exposure gaps)\n"
            "- 51-75: High Risk (Urgent vulnerabilities require remediation)\n"
            "- 76-100: Critical Risk (Imminent danger of account compromise or identity exposure)"
        )
    }
]

def ask_privacy_guardian(query, user_context=None):
    """
    Query Privacy Guardian assistant.
    If GEMINI_API_KEY or OPENAI_API_KEY is configured in .env, connects to live LLM.
    Otherwise, uses robust Rule-Based Expert Engine with honest disclosure.
    """
    clean_query = query.strip()
    try:
        gemini_key = current_app.config.get('GEMINI_API_KEY', '').strip()
        openai_key = current_app.config.get('OPENAI_API_KEY', '').strip()
    except Exception:
        import os
        gemini_key = os.environ.get('GEMINI_API_KEY', '').strip()
        openai_key = os.environ.get('OPENAI_API_KEY', '').strip()
    
    # 1. Try Gemini API if key is present
    if gemini_key:
        try:
            return _query_gemini(clean_query, gemini_key, user_context)
        except Exception as e:
            # Fall back to rule-based engine on API error
            fb = _query_rule_based(clean_query, user_context)
            fb['error_notice'] = f"Gemini API error ({str(e)}). Handled seamlessly via Privacy Guardian Expert Engine."
            return fb

    # 2. Try OpenAI API if key is present
    if openai_key:
        try:
            return _query_openai(clean_query, openai_key, user_context)
        except Exception as e:
            fb = _query_rule_based(clean_query, user_context)
            fb['error_notice'] = f"OpenAI API error ({str(e)}). Handled seamlessly via Privacy Guardian Expert Engine."
            return fb

    # 3. Transparent Expert Rule-Based Engine
    return _query_rule_based(clean_query, user_context)

def _query_gemini(query, api_key, user_context=None):
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
    system_instruction = (
        "You are Privacy Guardian, a professional cybersecurity and digital privacy AI consultant for the "
        "'Digital Footprint Intelligence' platform. Provide practical, accurate, concise, and structured cybersecurity "
        "advice. Never give illegal advice or instructions on how to breach systems. Keep answers formatted in clean markdown."
    )
    
    context_str = ""
    if user_context:
        context_str = f"\nUser Context: {json.dumps(user_context)}\n"
        
    payload = {
        "contents": [
            {
                "parts": [
                    {"text": f"{system_instruction}\n{context_str}\nUser Question: {query}"}
                ]
            }
        ]
    }
    
    res = requests.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=12)
    if res.status_code == 200:
        data = res.json()
        candidates = data.get('candidates', [])
        if candidates and 'content' in candidates[0]:
            parts = candidates[0]['content'].get('parts', [])
            if parts and 'text' in parts[0]:
                return {
                    'engine': 'Gemini 1.5 Flash (AI Model)',
                    'is_ai': True,
                    'response': parts[0]['text'],
                    'status': 'success'
                }
    raise Exception(f"Gemini API returned status {res.status_code}")

def _query_openai(query, api_key, user_context=None):
    url = "https://api.openai.com/v1/chat/completions"
    system_instruction = (
        "You are Privacy Guardian, a professional cybersecurity and digital privacy consultant for the "
        "'Digital Footprint Intelligence' platform. Provide practical, structured, and clear advice."
    )
    messages = [
        {"role": "system", "content": system_instruction}
    ]
    if user_context:
        messages.append({"role": "system", "content": f"User Assessment Context: {json.dumps(user_context)}"})
    messages.append({"role": "user", "content": query})
    
    res = requests.post(
        url,
        json={"model": "gpt-3.5-turbo", "messages": messages, "temperature": 0.4},
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        timeout=12
    )
    if res.status_code == 200:
        data = res.json()
        choices = data.get('choices', [])
        if choices and 'message' in choices[0]:
            return {
                'engine': 'OpenAI GPT (AI Model)',
                'is_ai': True,
                'response': choices[0]['message'].get('content', ''),
                'status': 'success'
            }
    raise Exception(f"OpenAI API returned status {res.status_code}")

def _query_rule_based(query, user_context=None):
    """
    Intelligent cybersecurity expert system with contextual keyword matching and tailored replies.
    """
    q_lower = query.lower()
    
    # 1. Check if user is asking about their personal assessment context
    if user_context and any(w in q_lower for w in ['my score', 'my email', 'my breach', 'my result', 'my assessment', 'why did i get']):
        breach_count = user_context.get('breach_count', 0)
        risk_score = user_context.get('risk_score', 0)
        risk_level = user_context.get('risk_level', 'Unknown')
        scan_type = user_context.get('scan_type', 'Assessment')
        
        ctx_response = (
            f"**Your Recent Assessment Analysis ({scan_type}):**\n\n"
            f"• **Risk Score**: {risk_score}/100 ({risk_level})\n"
            f"• **Identified Breach Matches**: {breach_count} record(s)\n\n"
        )
        if breach_count > 0:
            ctx_response += (
                "Your email was identified in public data leaks. This elevated your risk score because leaked passwords "
                "allow automated attackers to test credentials across other online services. Check your customized recommendations "
                "in the dashboard to remediate each affected service."
            )
        else:
            ctx_response += (
                "No public breach records were found matching your scanned email address on XposedOrNot. "
                "To maintain this clean security posture, continue using unique passwords and app-based 2FA."
            )
            
        return {
            'engine': 'Privacy Guardian Rule-Based Expert Engine',
            'is_ai': False,
            'response': ctx_response,
            'status': 'success'
        }
        
    # 2. Check knowledge base matches
    best_match = None
    max_score = 0
    
    for item in EXPERT_KNOWLEDGE_BASE:
        score = 0
        for kw in item['keywords']:
            if kw in q_lower:
                score += len(kw)
        if score > max_score:
            max_score = score
            best_match = item
            
    if best_match and max_score > 0:
        return {
            'engine': 'Privacy Guardian Rule-Based Expert Engine',
            'is_ai': False,
            'response': best_match['response'],
            'status': 'success'
        }
        
    # 3. Default fallback cybersecurity guidance
    fallback_text = (
        "**Privacy Guardian Cyber Advisory:**\n\n"
        "I am here to guide your cybersecurity and digital privacy decisions. You can ask me questions about:\n\n"
        "• **Data Breaches**: What to do if your credentials appear in an exposure.\n"
        "• **Password Best Practices**: Password managers, passphrases, and entropy.\n"
        "• **Two-Factor Authentication (2FA)**: Differences between SMS, Authenticator apps, and FIDO2 keys.\n"
        "• **Network Privacy**: How VPNs, Proxies, and Tor protect your network traffic.\n"
        "• **Phishing Prevention**: How to detect fraudulent messages and suspicious links.\n"
        "• **Browser Tracking**: Blocking behavioral trackers, fingerprinting, and cookies.\n"
        "• **Your Score**: Ask 'Why did I get this risk score?' for personalized insights."
    )
    
    return {
        'engine': 'Privacy Guardian Rule-Based Expert Engine',
        'is_ai': False,
        'response': fallback_text,
        'status': 'success'
    }
