from flask import Blueprint, render_template, request, jsonify
from flask_login import current_user, login_required
from models import db, ActionChecklistItem, UserRecommendationProgress, Recommendation
from datetime import datetime, timezone

action_center_bp = Blueprint('action_center', __name__, url_prefix='/action-center')

PRIVACY_GUIDES = [
    {
        'id': 'password',
        'title': 'Password Security Guide',
        'badge': 'Authentication',
        'icon': 'key',
        'description': 'Construct uncrackable credentials, master password entropy, and deploy an encrypted password vault.',
        'tasks': [
            {'id': 'pwd_1', 'label': 'Select and install an audited password manager (Bitwarden, 1Password, or KeePassXC)'},
            {'id': 'pwd_2', 'label': 'Generate a 4+ word high-entropy master passphrase that you do not use anywhere else'},
            {'id': 'pwd_3', 'label': 'Audit and replace all duplicate passwords across accounts with unique 16+ character secrets'},
            {'id': 'pwd_4', 'label': 'Deactivate plaintext browser password saving and clear stored autofill entries'}
        ]
    },
    {
        'id': '2fa',
        'title': 'Two-Factor Authentication (2FA) Guide',
        'badge': 'MFA Defenses',
        'icon': 'shield-check',
        'description': 'Block automated account takeovers by upgrading from SMS verification to hardware keys and TOTP authenticators.',
        'tasks': [
            {'id': '2fa_1', 'label': 'Install an open-source authenticator app (Aegis, 2FAS, or Ente Auth) on your phone'},
            {'id': '2fa_2', 'label': 'Enable app-based 2FA on primary email account (Google, Microsoft, or Proton)'},
            {'id': '2fa_3', 'label': 'Enable app-based 2FA on banking, brokerage, and cloud storage accounts'},
            {'id': '2fa_4', 'label': 'Export single-use emergency backup codes and store them in an encrypted vault'}
        ]
    },
    {
        'id': 'social',
        'title': 'Social Media Privacy Guide',
        'badge': 'Identity Shield',
        'icon': 'users',
        'description': 'Minimize public reconnaissance vectors by locking down personal profiles and removing sensitive metadata.',
        'tasks': [
            {'id': 'soc_1', 'label': 'Switch Instagram, Facebook, and TikTok accounts to strictly private (Friends only)'},
            {'id': 'soc_2', 'label': 'Remove date of birth, phone numbers, and physical address from public profiles'},
            {'id': 'soc_3', 'label': 'Disable search engine visibility and external indexing in platform settings'},
            {'id': 'soc_4', 'label': 'Audit friend lists and purge inactive or unknown contacts'}
        ]
    },
    {
        'id': 'browser',
        'title': 'Browser Privacy & Anti-Tracking Guide',
        'badge': 'Browsing',
        'icon': 'globe',
        'description': 'Block invasive advertising networks, eliminate tracking beacons, and prevent cross-site browser fingerprinting.',
        'tasks': [
            {'id': 'brw_1', 'label': 'Install the uBlock Origin extension on all desktop and mobile browsers'},
            {'id': 'brw_2', 'label': 'Configure DNS-over-HTTPS (DoH) with Quad9 (9.9.9.9) or Cloudflare (1.1.1.1)'},
            {'id': 'brw_3', 'label': 'Block third-party cookies and enable Strict Tracking Protection in browser settings'},
            {'id': 'brw_4', 'label': 'Switch default search engine to privacy-centric options like DuckDuckGo or Brave Search'}
        ]
    },
    {
        'id': 'app_permissions',
        'title': 'Application Permissions Guide',
        'badge': 'Device Security',
        'icon': 'smartphone',
        'description': 'Prevent mobile and desktop applications from continuously extracting background sensors and contact lists.',
        'tasks': [
            {'id': 'app_1', 'label': 'Review OS Permission Manager and revoke camera and microphone from non-essential apps'},
            {'id': 'app_2', 'label': 'Switch location access to "Only While Using App" or disable precise location'},
            {'id': 'app_3', 'label': 'Revoke contact list access for social games, shopping apps, and photo editors'},
            {'id': 'app_4', 'label': 'Uninstall dormant applications not used in the past 30 days'}
        ]
    },
    {
        'id': 'phishing',
        'title': 'Phishing Prevention & Link Verification Guide',
        'badge': 'Threat Defense',
        'icon': 'alert-triangle',
        'description': 'Identify advanced spear-phishing lures, suspicious sender domains, and credential-harvesting pages.',
        'tasks': [
            {'id': 'phi_1', 'label': 'Verify the exact domain name in sender addresses before clicking links in urgent notifications'},
            {'id': 'phi_2', 'label': 'Navigate directly to services by typing official URLs rather than clicking embedded email buttons'},
            {'id': 'phi_3', 'label': 'Never provide OTP verification codes or passwords in response to unsolicited SMS alerts'},
            {'id': 'phi_4', 'label': 'Scan unexpected file attachments using VirusTotal before downloading or opening'}
        ]
    },
    {
        'id': 'wifi',
        'title': 'Public Wi-Fi Safety Guide',
        'badge': 'Network Security',
        'icon': 'wifi',
        'description': 'Protect your traffic against malicious captive portals, ARP poisoning, and rogue access points in public spaces.',
        'tasks': [
            {'id': 'wif_1', 'label': 'Prioritize cellular mobile hotspot over unencrypted public Wi-Fi networks'},
            {'id': 'wif_2', 'label': 'Activate a verified, no-logs VPN (ProtonVPN or Mullvad) immediately when joining public Wi-Fi'},
            {'id': 'wif_3', 'label': 'Turn off auto-connect to open Wi-Fi networks in your operating system settings'},
            {'id': 'wif_4', 'label': 'Disable file sharing, printer sharing, and AirDrop / Nearby Share in public areas'}
        ]
    },
    {
        'id': 'data_breach',
        'title': 'Data Breach Rapid Response Guide',
        'badge': 'Incident Response',
        'icon': 'flame',
        'description': 'Structured incident response protocol to contain exposure immediately after a credential breach.',
        'tasks': [
            {'id': 'brc_1', 'label': 'Immediately change password on the breached platform and any service sharing that password'},
            {'id': 'brc_2', 'label': 'Revoke all active login sessions and terminate OAuth access tokens for that account'},
            {'id': 'brc_3', 'label': 'Check connected bank accounts or payment cards for unauthorized transaction attempts'},
            {'id': 'brc_4', 'label': 'Monitor email inbox rules for unauthorized forwarding filters created by attackers'}
        ]
    }
]

@action_center_bp.route('/')
def index():
    """Privacy Action Center overview."""
    completed_task_ids = set()
    if current_user.is_authenticated:
        items = ActionChecklistItem.query.filter_by(user_id=current_user.id, is_completed=True).all()
        completed_task_ids = {item.task_id for item in items}
        
    # Calculate progress metrics
    total_tasks = sum([len(g['tasks']) for g in PRIVACY_GUIDES])
    completed_count = len(completed_task_ids)
    progress_pct = round((completed_count / max(1, total_tasks)) * 100)

    return render_template(
        'action_center/index.html',
        guides=PRIVACY_GUIDES,
        completed_tasks=completed_task_ids,
        total_tasks=total_tasks,
        completed_count=completed_count,
        progress_pct=progress_pct
    )


@action_center_bp.route('/api/toggle-task', methods=['POST'])
def toggle_task():
    """Toggle completion status of a checklist item."""
    data = request.get_json() or {}
    guide_id = data.get('guide_id', '')
    task_id = data.get('task_id', '')
    is_completed = bool(data.get('is_completed', False))
    
    if not guide_id or not task_id:
        return jsonify({'success': False, 'error': 'Missing task or guide ID'}), 400

    if current_user.is_authenticated:
        item = ActionChecklistItem.query.filter_by(
            user_id=current_user.id,
            guide_id=guide_id,
            task_id=task_id
        ).first()
        
        if not item:
            item = ActionChecklistItem(
                user_id=current_user.id,
                guide_id=guide_id,
                task_id=task_id,
                is_completed=is_completed,
                updated_at=datetime.now(timezone.utc)
            )
            db.session.add(item)
        else:
            item.is_completed = is_completed
            item.updated_at = datetime.now(timezone.utc)
            
        db.session.commit()
        
        # Recalculate
        completed_count = ActionChecklistItem.query.filter_by(user_id=current_user.id, is_completed=True).count()
        total_tasks = sum([len(g['tasks']) for g in PRIVACY_GUIDES])
        progress_pct = round((completed_count / max(1, total_tasks)) * 100)
        
        return jsonify({
            'success': True,
            'is_completed': is_completed,
            'completed_count': completed_count,
            'progress_pct': progress_pct
        })
    else:
        # Guest mode (handled in frontend local storage, return echo)
        return jsonify({
            'success': True,
            'is_completed': is_completed,
            'guest': True
        })


@action_center_bp.route('/api/toggle-recommendation/<int:rec_id>', methods=['POST'])
def toggle_recommendation(rec_id):
    """Mark a customized recommendation complete/incomplete."""
    data = request.get_json() or {}
    is_completed = bool(data.get('is_completed', True))
    
    if current_user.is_authenticated:
        prog = UserRecommendationProgress.query.filter_by(
            user_id=current_user.id,
            recommendation_id=rec_id
        ).first()
        
        if not prog:
            prog = UserRecommendationProgress(
                user_id=current_user.id,
                recommendation_id=rec_id,
                is_completed=is_completed,
                completed_at=datetime.now(timezone.utc) if is_completed else None
            )
            db.session.add(prog)
        else:
            prog.is_completed = is_completed
            prog.completed_at = datetime.now(timezone.utc) if is_completed else None
            
        db.session.commit()
        return jsonify({'success': True, 'is_completed': is_completed})
        
    return jsonify({'success': True, 'is_completed': is_completed, 'guest': True})

