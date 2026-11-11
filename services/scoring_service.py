QUESTIONNAIRE_QUESTIONS = [
    {
        'id': 'q1',
        'category': 'Authentication',
        'title': 'Password Reuse Across Accounts',
        'prompt': 'How often do you reuse the same password or variations of it across multiple accounts?',
        'explanation': 'Reusing passwords allows a credential breach on a low-security site to compromise your primary email, banking, or corporate accounts.',
        'options': [
            {'text': 'Never. Every account has a unique, randomly generated password saved in a password manager.', 'weight': 0, 'risk': 'Low'},
            {'text': 'Rarely. Critical accounts (banking, primary email) have unique passwords; minor sites may share passwords.', 'weight': 35, 'risk': 'Moderate'},
            {'text': 'Sometimes. I use 3 to 4 standard variations of a password for all my accounts.', 'weight': 70, 'risk': 'High'},
            {'text': 'Always. I use virtually the same 1 or 2 passwords for almost everything.', 'weight': 100, 'risk': 'Critical'}
        ]
    },
    {
        'id': 'q2',
        'category': 'Authentication',
        'title': 'Password Complexity and Length',
        'prompt': 'What does your average password construction look like?',
        'explanation': 'Short passwords with common words are vulnerable to dictionary attacks and rainbow table lookups within seconds.',
        'options': [
            {'text': '16+ characters with random alphanumeric characters and symbols, or 4+ word passphrase.', 'weight': 0, 'risk': 'Low'},
            {'text': '10-15 characters including uppercase, lowercase, numbers, and a symbol.', 'weight': 25, 'risk': 'Low'},
            {'text': '8-10 characters usually combining a familiar word, name, or birth year.', 'weight': 65, 'risk': 'High'},
            {'text': 'Fewer than 8 characters or simple predictable words (e.g., password123, family names).', 'weight': 100, 'risk': 'Critical'}
        ]
    },
    {
        'id': 'q3',
        'category': 'Authentication',
        'title': 'Two-Factor Authentication (2FA) Adoption',
        'prompt': 'Where and how do you use Two-Factor Authentication (2FA / MFA)?',
        'explanation': '2FA acts as a secondary defense layer even if your password is stolen or exposed in a data breach.',
        'options': [
            {'text': 'Enabled on all accounts using an Authenticator app (e.g. Aegis, 2FAS) or hardware FIDO2 key.', 'weight': 0, 'risk': 'Low'},
            {'text': 'Enabled on my primary email and financial accounts using SMS verification or authenticator.', 'weight': 30, 'risk': 'Moderate'},
            {'text': 'Only enabled where a service strictly forces me to turn it on.', 'weight': 70, 'risk': 'High'},
            {'text': 'I do not use two-factor authentication anywhere or actively disable it.', 'weight': 100, 'risk': 'Critical'}
        ]
    },
    {
        'id': 'q4',
        'category': 'Social & Privacy',
        'title': 'Social Media Account Visibility',
        'prompt': 'What are the default privacy settings on your primary social media profiles (Instagram, Facebook, LinkedIn, X)?',
        'explanation': 'Public social profiles enable threat actors to scrape your relatives, location, employment history, and personal details for targeted phishing.',
        'options': [
            {'text': 'All personal profiles are strictly private; only approved friends/contacts can view content.', 'weight': 0, 'risk': 'Low'},
            {'text': 'Professional profiles (LinkedIn) are public; personal social media accounts are private.', 'weight': 25, 'risk': 'Low'},
            {'text': 'Mostly public, but I restrict personal photo albums or phone numbers from strangers.', 'weight': 60, 'risk': 'Moderate'},
            {'text': 'Completely public profiles with my full real name, updates, and photos accessible to anyone.', 'weight': 90, 'risk': 'High'}
        ]
    },
    {
        'id': 'q5',
        'category': 'Social & Privacy',
        'title': 'Public Personal Information Exposure',
        'prompt': 'Can your date of birth, personal phone number, or home address be found online?',
        'explanation': 'Personal identifiers are routinely collected by data brokers and utilized to answer security questions or execute SIM swaps.',
        'options': [
            {'text': 'No. I actively audit data brokers and never publish my phone number, address, or full birthday.', 'weight': 0, 'risk': 'Low'},
            {'text': 'My birthday or phone number might be visible on one professional directory or old profile.', 'weight': 40, 'risk': 'Moderate'},
            {'text': 'My full birthdate, phone number, or city of residence are visible across multiple public websites.', 'weight': 75, 'risk': 'High'},
            {'text': 'Yes, my contact details, workplace, birthday, and physical location are easily discoverable online.', 'weight': 95, 'risk': 'Critical'}
        ]
    },
    {
        'id': 'q6',
        'category': 'Device & Apps',
        'title': 'Mobile and Desktop Application Permissions',
        'prompt': 'How do you handle application permission requests (camera, microphone, location, contacts)?',
        'explanation': 'Over-privileged applications continuously harvest telemetry and sensor data in the background.',
        'options': [
            {'text': 'Strictly grant permissions only when actively needed; revoke location, contacts, and mic when unused.', 'weight': 0, 'risk': 'Low'},
            {'text': 'Review permissions during install and generally allow "Only while using the app".', 'weight': 25, 'risk': 'Low'},
            {'text': 'Usually accept whatever permissions an application prompts without looking closely.', 'weight': 70, 'risk': 'High'},
            {'text': 'Grant all permissions immediately so the app stops asking.', 'weight': 100, 'risk': 'Critical'}
        ]
    },
    {
        'id': 'q7',
        'category': 'Browsing & Phishing',
        'title': 'Web Browser Privacy and Tracking Defenses',
        'prompt': 'Which browser configuration and tracker-blocking tools do you use daily?',
        'explanation': 'Third-party tracking cookies and browser fingerprinting assemble comprehensive behavioral profiles across sites.',
        'options': [
            {'text': 'Privacy-hardened browser (Brave / Firefox with uBlock Origin) + DNS privacy + anti-fingerprinting.', 'weight': 0, 'risk': 'Low'},
            {'text': 'Mainstream browser with an ad/tracker blocker extension installed and third-party cookies disabled.', 'weight': 30, 'risk': 'Moderate'},
            {'text': 'Default browser settings (e.g. Chrome, Edge, Safari) with standard cookie tracking allowed.', 'weight': 65, 'risk': 'High'},
            {'text': 'I never adjust privacy settings and accept all cookie consent prompts on every website.', 'weight': 90, 'risk': 'High'}
        ]
    },
    {
        'id': 'q8',
        'category': 'Network',
        'title': 'Public Wi-Fi Network Hygiene',
        'prompt': 'How do you connect to public Wi-Fi networks in cafes, hotels, airports, or colleges?',
        'explanation': 'Unencrypted public Wi-Fi exposes unencrypted traffic to local packet sniffing, ARP spoofing, and malicious captive portals.',
        'options': [
            {'text': 'Never use public Wi-Fi; I use personal mobile hotspot or always tunnel through a trusted VPN.', 'weight': 0, 'risk': 'Low'},
            {'text': 'Use public Wi-Fi only for general reading, but never for banking or confidential work without a VPN.', 'weight': 30, 'risk': 'Moderate'},
            {'text': 'Connect to open public Wi-Fi regularly; rely only on HTTPS browser padlock.', 'weight': 65, 'risk': 'High'},
            {'text': 'Connect to any free, unauthenticated Wi-Fi network and perform sensitive transactions without VPN.', 'weight': 100, 'risk': 'Critical'}
        ]
    },
    {
        'id': 'q9',
        'category': 'Browsing & Phishing',
        'title': 'Phishing Detection and Vigilance',
        'prompt': 'When receiving unexpected emails with urgent warnings (e.g., "Account suspended", "Payment failed"):',
        'explanation': 'Phishing remains the number one vector for credential harvesting and identity theft worldwide.',
        'options': [
            {'text': 'Inspect the sender RFC address, check SPF/DKIM headers, and never click links; visit the site directly.', 'weight': 0, 'risk': 'Low'},
            {'text': 'Carefully inspect the sender address and domain spelling before interacting with links.', 'weight': 25, 'risk': 'Low'},
            {'text': 'Click links if the logo and email formatting look convincing, but back out if it asks for a password.', 'weight': 70, 'risk': 'High'},
            {'text': 'Frequently click links in urgent messages or SMS notifications and follow the on-screen instructions.', 'weight': 100, 'risk': 'Critical'}
        ]
    },
    {
        'id': 'q10',
        'category': 'Browsing & Phishing',
        'title': 'Handling Unknown Links and File Downloads',
        'prompt': 'What is your reaction to unsolicited download links, torrents, or suspicious file attachments?',
        'explanation': 'Trojanized software and cracked installers frequently inject malware, infostealers, and keyloggers.',
        'options': [
            {'text': 'Never download pirated/cracked files; scan all attachments via VirusTotal and sandbox if necessary.', 'weight': 0, 'risk': 'Low'},
            {'text': 'Only download from verified official stores and vendor domains; scan files with antivirus.', 'weight': 20, 'risk': 'Low'},
            {'text': 'Occasionally download files from community forums, Reddit, or unofficial mirrors if recommended.', 'weight': 60, 'risk': 'Moderate'},
            {'text': 'Regularly download cracked software, keygens, or games from file-sharing sites and disable antivirus.', 'weight': 100, 'risk': 'Critical'}
        ]
    },
    {
        'id': 'q11',
        'category': 'Device & Apps',
        'title': 'Operating System and Software Updates',
        'prompt': 'How promptly do you install operating system patches and browser updates?',
        'explanation': 'Known vulnerabilities (CVEs) with published exploits are routinely weaponized against unpatched devices.',
        'options': [
            {'text': 'Automatic updates enabled for OS, browsers, and software; patched within 24-48 hours.', 'weight': 0, 'risk': 'Low'},
            {'text': 'Install updates within 1 to 2 weeks of notification.', 'weight': 30, 'risk': 'Moderate'},
            {'text': 'Postpone update prompts for several weeks or months until forced to restart.', 'weight': 70, 'risk': 'High'},
            {'text': 'Completely disable Windows/OS updates or running an unsupported end-of-life operating system.', 'weight': 100, 'risk': 'Critical'}
        ]
    },
    {
        'id': 'q12',
        'category': 'Device & Apps',
        'title': 'Device Lock and Biometric Security',
        'prompt': 'What security protections are active on your personal laptop, smartphone, or tablet?',
        'explanation': 'Unencrypted or unauthenticated devices give anyone physical access to all sessions, tokens, and data.',
        'options': [
            {'text': 'Full disk encryption (BitLocker / FileVault), 6+ digit PIN / strong passphrase, biometric lock, 2-min auto-lock.', 'weight': 0, 'risk': 'Low'},
            {'text': 'Biometrics / PIN lock active with 5-minute timeout; basic device encryption.', 'weight': 25, 'risk': 'Low'},
            {'text': 'Simple 4-digit PIN (e.g., 1234, 0000) or long screen timeout (15+ minutes).', 'weight': 65, 'risk': 'High'},
            {'text': 'No passcode, swipe to unlock, or shared open computer without password.', 'weight': 100, 'risk': 'Critical'}
        ]
    },
    {
        'id': 'q13',
        'category': 'Social & Privacy',
        'title': 'Location Services and Geo-Tagging',
        'prompt': 'How do you configure location sharing and photo metadata (EXIF GPS)?',
        'explanation': 'Photo EXIF metadata embeds precise latitude/longitude coordinates, revealing home and routine locations.',
        'options': [
            {'text': 'GPS is turned off by default; EXIF metadata is stripped from photos before uploading online.', 'weight': 0, 'risk': 'Low'},
            {'text': 'Location is granted only to navigation apps; camera geotagging is disabled.', 'weight': 20, 'risk': 'Low'},
            {'text': 'Location is left on for social media check-ins and camera geotagging.', 'weight': 60, 'risk': 'Moderate'},
            {'text': 'Constantly share live location with multiple apps, friends, and tag exact coordinates in posts.', 'weight': 90, 'risk': 'High'}
        ]
    },
    {
        'id': 'q14',
        'category': 'Device & Apps',
        'title': 'Third-Party App Access (Sign in with Google/Apple)',
        'prompt': 'How do you audit apps and websites connected to your Google, Apple, or Microsoft accounts?',
        'explanation': 'Dormant OAuth tokens allow third-party developers ongoing API access to your profile data and drive/email.',
        'options': [
            {'text': 'Perform quarterly reviews of connected apps in my Google/Apple security portal and revoke unused tokens.', 'weight': 0, 'risk': 'Low'},
            {'text': 'Review connected apps once a year or whenever I remember.', 'weight': 35, 'risk': 'Moderate'},
            {'text': 'Use "Sign in with Google" everywhere, but have never checked or removed old connected apps.', 'weight': 75, 'risk': 'High'},
            {'text': 'Grant permissions to random quizzes, games, and third-party tools without reviewing access scopes.', 'weight': 100, 'risk': 'Critical'}
        ]
    },
    {
        'id': 'q15',
        'category': 'Social & Privacy',
        'title': 'Data-Sharing Habits and Privacy Policies',
        'prompt': 'When registering for services, signing up for loyalty cards, or entering giveaways:',
        'explanation': 'Free services monetize user contact lists and data through data brokerage and behavioral profiling.',
        'options': [
            {'text': 'Use privacy aliases (SimpleLogin, Apple Hide My Email), decline marketing, and read data retention terms.', 'weight': 0, 'risk': 'Low'},
            {'text': 'Use a secondary "junk" email address for non-essential accounts and uncheck marketing boxes.', 'weight': 25, 'risk': 'Low'},
            {'text': 'Provide my primary personal email and phone number without reviewing privacy consent.', 'weight': 70, 'risk': 'High'},
            {'text': 'Share full personal identity and phone number on any promotional site for discounts or contests.', 'weight': 95, 'risk': 'Critical'}
        ]
    }
]

def calculate_questionnaire_score(responses):
    """
    Calculate questionnaire overall risk score (0-100) and category breakdown.
    responses: dict mapping question_id -> selected option index (0 to 3).
    Returns:
    {
        'overall_score': int,
        'risk_level': str ('Low' | 'Moderate' | 'High' | 'Critical'),
        'category_scores': dict of category -> int score,
        'detailed_breakdown': list of question responses with risk,
        'summary': str
    }
    """
    total_weight = 0
    question_count = 0
    category_weights = {}
    category_counts = {}
    detailed_breakdown = []
    
    for q in QUESTIONNAIRE_QUESTIONS:
        qid = q['id']
        category = q['category']
        
        if category not in category_weights:
            category_weights[category] = 0
            category_counts[category] = 0
            
        selected_idx = responses.get(qid)
        
        # If response was provided
        if selected_idx is not None:
            try:
                selected_idx = int(selected_idx)
                if 0 <= selected_idx < len(q['options']):
                    chosen_opt = q['options'][selected_idx]
                else:
                    chosen_opt = q['options'][1] # default moderate
            except (ValueError, TypeError):
                chosen_opt = q['options'][1]
        else:
            # Unanswered defaults to moderate
            chosen_opt = q['options'][1]
            
        weight = chosen_opt['weight']
        total_weight += weight
        question_count += 1
        
        category_weights[category] += weight
        category_counts[category] += 1
        
        detailed_breakdown.append({
            'question_id': qid,
            'title': q['title'],
            'category': category,
            'chosen_text': chosen_opt['text'],
            'risk_weight': weight,
            'risk_label': chosen_opt['risk'],
            'explanation': q['explanation']
        })

    overall_score = round(total_weight / max(1, question_count))
    overall_score = max(0, min(100, overall_score))
    
    # Risk level classification
    if overall_score <= 25:
        risk_level = 'Low'
        summary = "Your digital privacy habits are strong. You maintain proactive cybersecurity defenses, minimal public exposure, and robust authentication hygiene."
    elif overall_score <= 50:
        risk_level = 'Moderate'
        summary = "You have a solid foundation, but several privacy blind spots (e.g. tracking, permissions, or password reuse) leave you vulnerable to targeted credential attacks."
    elif overall_score <= 75:
        risk_level = 'High'
        summary = "Significant digital footprint exposure detected. Your habits present multiple attack vectors that attackers or data brokers can easily exploit."
    else:
        risk_level = 'Critical'
        summary = "Critical privacy risk. Severe vulnerabilities across authentication, network, and personal data exposure make identity theft and account compromise imminent."

    category_scores = {}
    for cat, w in category_weights.items():
        c_count = category_counts.get(cat, 1)
        category_scores[cat] = round(w / max(1, c_count))

    return {
        'overall_score': overall_score,
        'risk_level': risk_level,
        'category_scores': category_scores,
        'detailed_breakdown': detailed_breakdown,
        'summary': summary
    }

