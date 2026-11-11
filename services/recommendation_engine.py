from models import db, Recommendation, UserRecommendationProgress
from datetime import datetime, timezone

# Standard library of actionable cybersecurity recommendations
RECOMMENDATION_CATALOG = [
    {
        'code': 'REC_BREACH_PWD_RESET',
        'title': 'Reset Passwords for All Breached Services',
        'category': 'Authentication',
        'priority': 'Critical',
        'reason': 'Your email address was identified in known public data breaches. Exposed credentials allow automated credential stuffing attacks.',
        'action_steps': (
            "1. Identify each breached service listed in your scan results.\n"
            "2. Navigate to each service website directly (never click password reset links in emails).\n"
            "3. Change the account password to a completely unique, 16+ character password.\n"
            "4. If you used that same password on any other service, change those immediately as well."
        ),
        'external_url': 'https://www.cisa.gov/secure-our-world/use-strong-passwords'
    },
    {
        'code': 'REC_PASSWORD_MANAGER',
        'title': 'Adopt a Dedicated Password Manager',
        'category': 'Authentication',
        'priority': 'High',
        'reason': 'Human memory cannot securely maintain unique, high-entropy 16+ character passwords across dozens of modern online services.',
        'action_steps': (
            "1. Select an audited, open-source or end-to-end encrypted password manager (e.g. Bitwarden, 1Password, KeePassXC).\n"
            "2. Create a strong, memorable Master Passphrase (e.g., 4 or 5 random words joined by spaces or hyphens).\n"
            "3. Migrate existing browser-saved passwords into the encrypted vault.\n"
            "4. Enable browser and mobile auto-fill to protect against phishing lookalike domains."
        ),
        'external_url': 'https://bitwarden.com/'
    },
    {
        'code': 'REC_ENABLE_2FA_APP',
        'title': 'Activate App-Based Two-Factor Authentication (2FA)',
        'category': 'Authentication',
        'priority': 'Critical',
        'reason': 'Passwords alone are vulnerable to breaches, phishing, and malware. 2FA stops 99% of automated account takeover attempts.',
        'action_steps': (
            "1. Download an open-source authenticator app like Aegis Authenticator (Android) or 2FAS / Ente Auth (iOS/Android).\n"
            "2. Go into account Security Settings for your primary email, banking, and social profiles.\n"
            "3. Select 'Two-Factor Authentication' and scan the QR code using your authenticator app.\n"
            "4. Securely download and store your single-use recovery / backup codes in your encrypted vault."
        ),
        'external_url': 'https://2fas.com/'
    },
    {
        'code': 'REC_SOCIAL_AUDIT',
        'title': 'Lock Down Social Media Privacy Settings',
        'category': 'Social Media',
        'priority': 'High',
        'reason': 'Public profiles disclose date of birth, relatives, employment history, and pet names, which attackers weaponize for social engineering.',
        'action_steps': (
            "1. Switch Instagram, Facebook, and personal platforms from 'Public' to 'Friends / Contacts Only'.\n"
            "2. Hide your phone number, email address, and exact birth year from your public biography.\n"
            "3. Disable search engine indexing so your profile does not appear on Google searches.\n"
            "4. Audit your friends list and remove unfamiliar accounts or bot followers."
        ),
        'external_url': 'https://foundation.mozilla.org/en/privacynotincluded/'
    },
    {
        'code': 'REC_DATA_BROKER_OPTOUT',
        'title': 'Remove Personal Data from Data Broker Directories',
        'category': 'Identity',
        'priority': 'High',
        'reason': 'Data aggregators compile public records, consumer purchases, and breach dumps into searchable personal background dossiers.',
        'action_steps': (
            "1. Search your name and phone number on Google inside quotes (e.g., \"Firstname Lastname\" \"City\").\n"
            "2. Submit opt-out removal requests to major data aggregators (Radaris, Whitepages, Spokeo, FastPeopleSearch).\n"
            "3. Consider automated removal tools (DeleteMe, Incogni) if manual opt-outs are too time-consuming.\n"
            "4. Set up a Google Alert for your full name and primary email address."
        ),
        'external_url': 'https://www.eff.org/issues/privacy'
    },
    {
        'code': 'REC_BROWSER_TRACKING',
        'title': 'Deploy Tracker and Fingerprint Defenses',
        'category': 'Browsing',
        'priority': 'Medium',
        'reason': 'Advertising networks construct behavioral dossiers by tracking your browsing history across thousands of websites.',
        'action_steps': (
            "1. Install the uBlock Origin browser extension to block ad networks, tracking telemetry, and malicious domains.\n"
            "2. Enable Strict Tracking Protection in Firefox, or use Brave / LibreWolf for everyday web browsing.\n"
            "3. Configure Encrypted DNS (DoH) using Cloudflare (1.1.1.1) or Quad9 (9.9.9.9) in browser network settings.\n"
            "4. Periodically clear third-party cookies and local storage."
        ),
        'external_url': 'https://ublockorigin.com/'
    },
    {
        'code': 'REC_PUBLIC_WIFI_VPN',
        'title': 'Use a Trusted VPN or Mobile Hotspot on Public Wi-Fi',
        'category': 'Network',
        'priority': 'Medium',
        'reason': 'Unsecured open Wi-Fi in public spaces exposes DNS queries and unencrypted traffic to local packet interception.',
        'action_steps': (
            "1. Prefer your smartphone's cellular data / mobile hotspot over untrusted public Wi-Fi.\n"
            "2. When connecting to public networks, immediately engage a reputable, audited no-logs VPN (e.g. ProtonVPN, Mullvad).\n"
            "3. Disable 'Automatic Wi-Fi Reconnection' and turn off network file-sharing on your laptop.\n"
            "4. Ensure your browser forces HTTPS-Only mode."
        ),
        'external_url': 'https://protonvpn.com/'
    },
    {
        'code': 'REC_EMAIL_ALIASING',
        'title': 'Implement Email Masking and Aliases',
        'category': 'Identity',
        'priority': 'Medium',
        'reason': 'Using a single personal email everywhere links all your online activities into a unified target for breaches and spammers.',
        'action_steps': (
            "1. Use an email masking service like SimpleLogin, Addy.io, or Apple Hide My Email.\n"
            "2. Generate a unique email alias for each newsletter, e-commerce store, and secondary site.\n"
            "3. If an alias appears in a spam blast or breach, simply disable that alias without changing your real email.\n"
            "4. Reserve your primary clean email exclusively for banking, government, and close personal contacts."
        ),
        'external_url': 'https://simplelogin.io/'
    },
    {
        'code': 'REC_APP_PERMISSIONS_AUDIT',
        'title': 'Audit Device and Application Permissions',
        'category': 'Device Security',
        'priority': 'Medium',
        'reason': 'Apps frequently request background location, camera, and contacts access far beyond their legitimate functional needs.',
        'action_steps': (
            "1. Open device settings on your phone and laptop and navigate to Privacy / Permission Manager.\n"
            "2. Revoke background location, microphone, and contacts permissions for apps that do not require them.\n"
            "3. Delete unused apps that remain installed on your phone.\n"
            "4. Disable precise GPS location sharing for social media cameras."
        ),
        'external_url': 'https://www.consumerreports.org/electronics/privacy/smartphones-privacy-settings/'
    },
    {
        'code': 'REC_OAUTH_TOKEN_REVOCATION',
        'title': 'Revoke Dormant Connected Apps (OAuth Tokens)',
        'category': 'Authentication',
        'priority': 'High',
        'reason': 'Websites connected via "Sign in with Google" or "Sign in with Apple" maintain active API tokens indefinitely.',
        'action_steps': (
            "1. Visit your Google Account Security Dashboard (myaccount.google.com/permissions).\n"
            "2. Review all 'Third-party apps with account access'.\n"
            "3. Remove access for any service, game, or tool you have not utilized in the past 60 days.\n"
            "4. Repeat the audit for Apple ID, Microsoft, and GitHub connected applications."
        ),
        'external_url': 'https://myaccount.google.com/permissions'
    }
]

def seed_recommendations():
    """Ensure standard recommendation entries exist in the database."""
    for rec_data in RECOMMENDATION_CATALOG:
        existing = Recommendation.query.filter_by(code=rec_data['code']).first()
        if not existing:
            rec = Recommendation(
                code=rec_data['code'],
                title=rec_data['title'],
                category=rec_data['category'],
                priority=rec_data['priority'],
                reason=rec_data['reason'],
                action_steps=rec_data['action_steps'],
                external_url=rec_data.get('external_url')
            )
            db.session.add(rec)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()

def generate_recommendations_for_email_assessment(assessment, user_id=None):
    """
    Generate tailored recommendations based on actual findings from email breach and reputation scan.
    """
    seed_recommendations()
    selected_codes = []
    
    # Rule 1: Email found in breaches
    if assessment.breach_count > 0:
        selected_codes.append('REC_BREACH_PWD_RESET')
        selected_codes.append('REC_PASSWORD_MANAGER')
        selected_codes.append('REC_ENABLE_2FA_APP')
        
    # Rule 2: High number of breaches or passwords exposed
    if assessment.breach_count >= 3 or assessment.risk_score >= 50:
        selected_codes.append('REC_EMAIL_ALIASING')
        selected_codes.append('REC_DATA_BROKER_OPTOUT')
        
    # Rule 3: Always add baseline defenses if minimal
    if not selected_codes:
        selected_codes = ['REC_PASSWORD_MANAGER', 'REC_ENABLE_2FA_APP', 'REC_EMAIL_ALIASING']
        
    # Fetch recommendation models
    recs = Recommendation.query.filter(Recommendation.code.in_(selected_codes)).all()
    
    # If user is authenticated, link progress
    if user_id:
        for r in recs:
            existing_prog = UserRecommendationProgress.query.filter_by(
                user_id=user_id,
                recommendation_id=r.id,
                assessment_id=assessment.id
            ).first()
            if not existing_prog:
                prog = UserRecommendationProgress(
                    user_id=user_id,
                    recommendation_id=r.id,
                    assessment_id=assessment.id,
                    assessment_type='email',
                    is_completed=False
                )
                db.session.add(prog)
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            
    return recs

def generate_recommendations_for_questionnaire(questionnaire_assessment, user_id=None):
    """
    Generate tailored recommendations based on vulnerabilities identified in questionnaire responses.
    """
    seed_recommendations()
    cat_scores = questionnaire_assessment.get_category_scores()
    responses = questionnaire_assessment.get_responses()
    
    selected_codes = set()
    
    # Check Authentication vulnerabilities (Q1, Q2, Q3)
    if int(responses.get('q1', 1)) >= 2: # Password reuse
        selected_codes.add('REC_PASSWORD_MANAGER')
    if int(responses.get('q3', 1)) >= 2: # 2FA missing
        selected_codes.add('REC_ENABLE_2FA_APP')
        
    # Check Network vulnerabilities (Q8)
    if int(responses.get('q8', 1)) >= 2: # Public Wi-Fi
        selected_codes.add('REC_PUBLIC_WIFI_VPN')
        
    # Check Social & Privacy (Q4, Q5, Q13, Q15)
    if int(responses.get('q4', 1)) >= 2 or int(responses.get('q13', 1)) >= 2:
        selected_codes.add('REC_SOCIAL_AUDIT')
    if int(responses.get('q5', 1)) >= 2:
        selected_codes.add('REC_DATA_BROKER_OPTOUT')
    if int(responses.get('q15', 1)) >= 2:
        selected_codes.add('REC_EMAIL_ALIASING')
        
    # Check Browsing & Phishing (Q7, Q9, Q10)
    if int(responses.get('q7', 1)) >= 2:
        selected_codes.add('REC_BROWSER_TRACKING')
        
    # Check Device & Apps (Q6, Q11, Q14)
    if int(responses.get('q6', 1)) >= 2:
        selected_codes.add('REC_APP_PERMISSIONS_AUDIT')
    if int(responses.get('q14', 1)) >= 2:
        selected_codes.add('REC_OAUTH_TOKEN_REVOCATION')
        
    # Fallback if score was high but specific answers varied
    if not selected_codes:
        selected_codes = {'REC_PASSWORD_MANAGER', 'REC_ENABLE_2FA_APP', 'REC_BROWSER_TRACKING'}

    recs = Recommendation.query.filter(Recommendation.code.in_(list(selected_codes))).all()
    
    if user_id:
        for r in recs:
            existing_prog = UserRecommendationProgress.query.filter_by(
                user_id=user_id,
                recommendation_id=r.id,
                assessment_id=questionnaire_assessment.id
            ).first()
            if not existing_prog:
                prog = UserRecommendationProgress(
                    user_id=user_id,
                    recommendation_id=r.id,
                    assessment_id=questionnaire_assessment.id,
                    assessment_type='questionnaire',
                    is_completed=False
                )
                db.session.add(prog)
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            
    return recs

