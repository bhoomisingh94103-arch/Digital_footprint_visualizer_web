# DIGITAL FOOTPRINT INTELLIGENCE (DFI)

> **"Discover Your Digital Presence. Understand Your Risks. Take Control."**

Digital Footprint Intelligence is an enterprise-grade personal cybersecurity assessment and digital footprint analysis platform. It enables individuals, security teams, and researchers to audit public exposure vectors, examine verified global data breaches, inspect network privacy telemetry, evaluate security hygiene, and execute structured hardening protocols.

Built from scratch with Python, Flask, SQLAlchemy, Chart.js, Tailwind CSS, ReportLab, and documented REST APIs.

---

## 1. KEY ARCHITECTURE & TWO ASSESSMENT MODES

The platform features **TWO completely independent assessment vectors**:

### 🔍 MODE A: Email-Based Digital Footprint Assessment
- **Real-Time Breach Intelligence**: Queries the official **XposedOrNot** API (`https://api.xposedornot.com/v1/breach-analytics`) to uncover exposed credentials, plain-text leaks, cracked hashes, and compromised personal profile data across verified breaches and pastes.
- **Separate Network Privacy Analysis**: Queries **HackMyIP** (`https://hackmyip.com/json` and `/proxy`) to audit visitor IP exposure, ISP/organization, ASN, proxy/VPN status, and connection privacy.
  - *Privacy Rule*: Network IP telemetry is evaluated independently and is **never linked** to the scanned email address.
- **Email Reputation & Domain Auditing**: Integrates with **EmailRep.io** (with transparent fallback to local domain disposable checks for services like Mailinator, TempMail, and GuerrillaMail).
- **Optional Have I Been Pwned (HIBP)**: Supports authenticated HIBP API v3 queries via `.env`.
- **Zero Credential Intrusion**: Never asks for Gmail passwords or inbox permissions.
- **Honest Telemetry**: Zero fabricated breach records. Full handling for timeouts, rate limits, and unbreached accounts.

### 📋 MODE B: General Digital Privacy Assessment
- **Zero-Identifier Evaluation**: Designed for users who prefer not to enter any email address.
- **15+ Cybersecurity Questions** across 5 threat dimensions:
  1. *Authentication Security*: Password reuse, complexity, length, and 2FA adoption.
  2. *Network & Connectivity*: Public Wi-Fi hygiene and VPN tunneling.
  3. *Information Privacy & Social Exposure*: Social profile visibility, personal phone/address exposure, geo-tagging EXIF metadata, and data broker risk.
  4. *Browsing & Phishing Defense*: Tracker blocking, cookie hygiene, anti-phishing vigilance, and unknown link handling.
  5. *Device & Application Hardening*: Mobile permissions, OS patch frequency, full-disk encryption, lock security, and OAuth token revocation.
- **Transparent Mathematical Scoring**: Computes a transparent risk index (0 to 100) with category-level breakdowns and posture classifications (Low, Moderate, High, Critical).

---

## 2. APPLICATION CAPABILITIES

| Component | Description |
|---|---|
| **Cybersecurity Dashboard** | Real-time aggregated metrics and **5 interactive Chart.js visualizations**: Risk Distribution Pie, Email Breach Bar, 6-Dimension Security Radar, Hardening Progress Doughnut, and Risk History Trend. |
| **Footprint Visualizer** | Interactive digital identity mapping with strict provenance labeling: `[Verified API Finding]`, `[Questionnaire-Based Estimate]`, `[Informational Recommendation]`, and `[Unavailable Data]`. |
| **Privacy Action Center** | 8 comprehensive guides with interactive checklists: Password Security, 2FA, Social Media, Browser Privacy, App Permissions, Phishing Defense, Public Wi-Fi Safety, and Breach Rapid Response. |
| **Privacy Guardian Assistant** | Integrated cybersecurity consultant with dual engines: connects to **Gemini 1.5 Flash / OpenAI GPT** when configured in `.env`, or seamlessly utilizes the high-performance **Rule-Based Expert Engine** with contextual awareness. |
| **ReportLab PDF Generator** | Instant multi-page executive security audit reports featuring tables, risk meters, breach details, and privacy limitation disclaimers. |
| **API Management Center** | Real-time diagnostic monitor with live interactive "Test Ping" tools measuring HTTP status and latency for all 6 integrated providers. |
| **Authentication & Vault** | PBKDF2:SHA256 password hashing, cryptographically random OTP generation, attempt limits, expiration, SMTP dispatch, session security, and complete user-level data isolation. |

---

## 3. TECHNOLOGY STACK

- **Backend**: Python 3.10+, Flask, Flask REST API, Flask-Login, Flask-SQLAlchemy, Flask-Migrate, Flask-WTF.
- **Frontend**: HTML5, CSS3, JavaScript (ES6+), Tailwind CSS (Play CDN), Chart.js, Lucide Icons, Canvas API.
- **Database**: SQLite (local development) with PostgreSQL-compatible SQLAlchemy models.
- **Reporting**: ReportLab (vector PDF generation) and Pillow.
- **Security**: PBKDF2 password hashing, CSRF protection, secure HTTP-only cookies, time-limited OTPs.
- **Testing**: Pytest automated test suite.

---

## 4. WINDOWS LOCAL DEVELOPMENT SETUP (VS CODE)

The application is tailored for seamless local execution on **Windows 10 / Windows 11**.

### Quick Start (One-Click Batch Script)
Double-click `run_windows.bat` in the project root, or execute via PowerShell / Command Prompt:

```cmd
.\run_windows.bat
```

The script automatically:
1. Detects your Python runtime.
2. Creates the isolated virtual environment (`.venv`).
3. Installs dependencies from `requirements.txt`.
4. Initializes database tables and recommendation catalogs.
5. Launches the development server at **`http://127.0.0.1:5000`**.

---

### Manual Setup via PowerShell / VS Code Terminal

#### Step 1: Open Project in VS Code
Open the `DFV` folder in VS Code (`File > Open Folder`).

#### Step 2: Create and Activate Virtual Environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```
*(If PowerShell restricts script execution, run: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`)*

#### Step 3: Install Dependencies
```powershell
pip install -r requirements.txt
```

#### Step 4: Configure Environment Variables
Copy `.env.example` to `.env`:
```powershell
copy .env.example .env
```

#### Step 5: Start the Platform
```powershell
python app.py
```

Open your browser to: **`http://127.0.0.1:5000`**

---

## 5. ENVIRONMENT CONFIGURATION & API GUIDE

Edit `.env` to configure optional external services:

```ini
# Flask Secret Key
SECRET_KEY=dfv_cyber_local_session_secret_key_2026_secured

# Database (Default: Local SQLite)
DATABASE_URL=sqlite:///digital_footprint.db

# Flask Environment
FLASK_ENV=development
FLASK_DEBUG=1

# External Threat Intelligence APIs (Optional)
HIBP_API_KEY=               # Have I Been Pwned API Key (https://haveibeenpwned.com/API/Key)
EMAILREP_API_KEY=           # EmailRep API Key (https://emailrep.io/key)
GEMINI_API_KEY=             # Google Gemini API Key (https://aistudio.google.com/)
OPENAI_API_KEY=             # OpenAI API Key (https://platform.openai.com/)

# SMTP Email Configuration (For live OTP email delivery)
# If omitted, OTPs are printed to terminal console / dev flash notification for local testing
MAIL_SERVER=
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USE_SSL=false
MAIL_USERNAME=
MAIL_PASSWORD=
MAIL_DEFAULT_SENDER=no-reply@digitalfootprint.local

# OTP Settings
OTP_EXPIRY_MINUTES=10
OTP_MAX_ATTEMPTS=5
```

---

## 6. EXTERNAL API STATUS MATRIX

| Service | Endpoint Used | Purpose | Auth Required | Status Without API Key |
|---|---|---|---|---|
| **XposedOrNot** | `/v1/breach-analytics` | Email breach detection | No (Free / Public) | **Fully Operational (Live API)** |
| **HackMyIP** | `/json` & `/proxy` | Network privacy analysis | No (Free / Public) | **Fully Operational (Live API)** |
| **EmailRep** | `https://emailrep.io/{email}` | Email reputation & disposable check | Yes (API Key) | **Graceful Fallback**: Local disposable domain check active |
| **HIBP** | `/api/v3/breachedaccount/` | Secondary breach check | Yes (API Key) | **Honest Status**: Marked "Not Configured" |
| **SMTP Service** | `smtp://host:port` | Real OTP delivery | Yes (Credentials) | **Dev Simulation Active**: Codes displayed in secure banner |
| **Privacy Guardian** | Gemini / OpenAI | Conversational AI guidance | Optional | **Expert Engine Active**: Rule-based cybersecurity engine |

---

## 7. AUTOMATED TESTS & VERIFICATION

The codebase includes comprehensive unit, integration, and live workflow tests.

### Running Tests
With the virtual environment active:
```powershell
pytest tests/ -v
```

### Verified Test Results
```text
============================= test session starts =============================
platform win32 -- Python 3.14.7, pytest-9.2.0, pluggy-1.7.0
rootdir: C:\Users\Bhumi Singh\OneDrive\Desktop\DFV
collected 25 items

tests/test_apis.py::test_ai_assistant_fallback PASSED                    [  4%]
tests/test_apis.py::test_ai_assistant_context_awareness PASSED           [  8%]
tests/test_apis.py::test_emailrep_unconfigured_handling PASSED           [ 12%]
tests/test_apis.py::test_hibp_unconfigured_handling PASSED               [ 16%]
tests/test_app_routes.py::test_landing_page PASSED                       [ 20%]
tests/test_app_routes.py::test_mode_a_get PASSED                         [ 24%]
tests/test_app_routes.py::test_mode_b_get PASSED                         [ 28%]
tests/test_app_routes.py::test_dashboard_guest PASSED                    [ 32%]
tests/test_app_routes.py::test_footprint_page PASSED                     [ 36%]
tests/test_app_routes.py::test_action_center_page PASSED                 [ 40%]
tests/test_app_routes.py::test_api_status_page PASSED                    [ 44%]
tests/test_app_routes.py::test_mode_b_quiz_submission PASSED             [ 48%]
tests/test_app_routes.py::test_chat_api PASSED                           [ 52%]
tests/test_auth.py::test_password_hashing PASSED                         [ 56%]
tests/test_auth.py::test_otp_flow_and_expiration PASSED                  [ 60%]
tests/test_auth.py::test_user_isolation PASSED                           [ 64%]
tests/test_live_workflow.py::test_full_auth_workflow PASSED              [ 68%]
tests/test_live_workflow.py::test_mode_a_api_scan PASSED                 [ 72%]
tests/test_pdf.py::test_generate_pdf_report PASSED                       [ 76%]
tests/test_recommendations.py::test_recommendation_catalog_seed PASSED   [ 80%]
tests/test_recommendations.py::test_quiz_recommendations PASSED          [ 84%]
tests/test_scoring.py::test_questionnaire_count PASSED                   [ 88%]
tests/test_scoring.py::test_low_risk_calculation PASSED                  [ 92%]
tests/test_scoring.py::test_critical_risk_calculation PASSED             [ 96%]
tests/test_scoring.py::test_mixed_risk_calculation PASSED                [100%]

============================= 25 passed in 5.68s ==============================
```

---

## 8. SECURITY & PRIVACY ARCHITECTURE

1. **User Isolation**: All queries enforce strict user ID matching. No cross-account leakage.
2. **PBKDF2 Password Hashing**: Passwords hashed with high-entropy cryptographic salt. Plaintext passwords never stored.
3. **Session Hardening**: Cookies configured with `HttpOnly` and `SameSite='Lax'` to prevent XSS hijacking.
4. **CSRF Protection**: Form submissions protected via Flask-WTF tokens.
5. **No Gmail / Google Account Intrusion**: Zero requests for account passwords, OAuth inbox access, or sensitive credentials.
6. **Strict Data Retention Control**: Users can delete individual scans or wipe their entire assessment history with one click.

---

## 9. LICENSE
Academic and Personal Defense Evaluation License. Built for cybersecurity research, college evaluations, hackathon demonstrations, and personal digital privacy audits.

