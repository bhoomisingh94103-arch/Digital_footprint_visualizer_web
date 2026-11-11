/**
 * Digital Footprint Intelligence - Mode A Interactive Email Scanner
 * Sage & Emerald Cyber Theme with Robust Mailbox Existence & OTP Verification
 */

document.addEventListener('DOMContentLoaded', function () {
    const scanForm = document.getElementById('email-scan-form');
    if (!scanForm) return;

    const emailInput = document.getElementById('target-email');
    const consentCheckbox = document.getElementById('consent-checkbox');
    const scanBtn = document.getElementById('scan-btn');
    const scanBtnText = document.getElementById('scan-btn-text');
    
    // OTP verification elements
    const otpBox = document.getElementById('otp-verification-box');
    const otpTargetDisplay = document.getElementById('otp-target-display');
    const otpInput = document.getElementById('scan-otp-input');
    const confirmOtpBtn = document.getElementById('confirm-otp-btn');
    const confirmOtpBtnText = document.getElementById('confirm-otp-btn-text');
    const resendOtpBtn = document.getElementById('resend-otp-btn');
    const changeEmailBtn = document.getElementById('change-email-btn');

    // Scan progress and results
    const scanStatusBox = document.getElementById('scan-status-box');
    const statusText = document.getElementById('status-step-text');
    const resultsContainer = document.getElementById('scan-results');

    let currentTargetEmail = '';

    // Retrieve CSRF token from page meta header
    function getCsrfToken() {
        return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
    }

    // Safely parse JSON responses and gracefully handle HTML error pages
    async function parseJsonResponse(response) {
        const contentType = response.headers.get('content-type') || '';
        if (contentType.includes('application/json')) {
            try {
                return await response.json();
            } catch (jsonErr) {
                throw new Error('Received malformed JSON from cybersecurity endpoint.');
            }
        }

        // Server returned HTML (e.g. 500 fault, 404, or reverse proxy timeout)
        const rawText = await response.text();
        let errMsg = `Security gateway returned HTTP ${response.status}`;

        const match = rawText.match(/<title>([^<]+)<\/title>/i) || rawText.match(/<p>([^<]+)<\/p>/i);
        if (match && match[1]) {
            errMsg += `: ${match[1].replace(/<[^>]*>/g, '').trim()}`;
        } else if (response.status === 404) {
            errMsg = 'Security assessment endpoint not found (404).';
        } else if (response.status === 500) {
            errMsg = 'Internal threat processing fault (500). Please try again.';
        } else if (response.status === 502 || response.status === 504) {
            errMsg = 'Threat intelligence gateway timeout (502/504). Please try again.';
        }

        throw new Error(errMsg);
    }

    // Step 1: Submit Form to Request OTP & Verify Mailbox Existence
    scanForm.addEventListener('submit', async function (e) {
        e.preventDefault();

        const email = emailInput.value.trim().toLowerCase();
        if (!email) {
            showToast('Please enter an email address to analyze.', 'danger');
            return;
        }

        // Basic client-side syntax guard
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            showToast('Invalid email syntax. Please provide a standard address format (e.g. user@example.com).', 'danger');
            return;
        }

        if (!consentCheckbox.checked) {
            showToast('You must check the privacy authorization box to proceed.', 'warning');
            consentCheckbox.focus();
            return;
        }

        currentTargetEmail = email;

        // Button state
        scanBtn.disabled = true;
        scanBtn.classList.add('opacity-50', 'cursor-not-allowed');
        if (scanBtnText) scanBtnText.textContent = 'Verifying syntax, DNS & MX...';

        try {
            const response = await fetch('/assessment/api/request-scan-otp', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'X-CSRFToken': getCsrfToken()
                },
                body: JSON.stringify({
                    email: email,
                    consent: true
                })
            });

            const data = await parseJsonResponse(response);

            if (!response.ok || !data.success) {
                throw new Error(data.error || "We couldn't verify whether this email address exists. Please check the address and try again.");
            }

            // If account is already verified for this exact email
            if (data.already_verified) {
                showToast(data.message || 'Email verified. Initiating security assessment...', 'success');
                await executeScan(email);
                return;
            }

            // OTP successfully dispatched via SMTP
            showToast(data.message || 'Verification passcode dispatched. Please verify mailbox.', 'success');
            
            // Transition to OTP verification stage
            scanBtn.classList.add('hidden');
            if (otpTargetDisplay) otpTargetDisplay.textContent = email;
            if (otpBox) {
                otpBox.classList.remove('hidden');
                if (typeof lucide !== 'undefined') lucide.createIcons();
            }
            if (otpInput) {
                otpInput.value = '';
                otpInput.focus();
            }

        } catch (err) {
            showToast(err.message, 'danger');
        } finally {
            scanBtn.disabled = false;
            scanBtn.classList.remove('opacity-50', 'cursor-not-allowed');
            if (scanBtnText) scanBtnText.textContent = 'Verify Email & Initiate Scan';
        }
    });

    // Step 2: Confirm OTP & Initiate Threat Assessment
    if (confirmOtpBtn) {
        confirmOtpBtn.addEventListener('click', async function () {
            const code = otpInput ? otpInput.value.trim() : '';
            if (!code || code.length < 6) {
                showToast('Please enter the 6-digit one-time passcode.', 'warning');
                if (otpInput) otpInput.focus();
                return;
            }

            confirmOtpBtn.disabled = true;
            confirmOtpBtn.classList.add('opacity-50', 'cursor-not-allowed');
            if (confirmOtpBtnText) confirmOtpBtnText.textContent = 'Verifying Passcode...';

            try {
                const response = await fetch('/assessment/api/verify-scan-otp', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json',
                        'X-CSRFToken': getCsrfToken()
                    },
                    body: JSON.stringify({
                        email: currentTargetEmail,
                        otp_code: code
                    })
                });

                const data = await parseJsonResponse(response);

                if (!response.ok || !data.success) {
                    throw new Error(data.error || 'Verification failed. Please check the code.');
                }

                showToast(data.message || 'Mailbox existence verified! Initiating security scan...', 'success');
                
                // Hide OTP box and proceed to scan
                if (otpBox) otpBox.classList.add('hidden');
                await executeScan(currentTargetEmail);

            } catch (err) {
                showToast(err.message, 'danger');
                if (otpInput) {
                    otpInput.select();
                    otpInput.focus();
                }
            } finally {
                confirmOtpBtn.disabled = false;
                confirmOtpBtn.classList.remove('opacity-50', 'cursor-not-allowed');
                if (confirmOtpBtnText) confirmOtpBtnText.textContent = 'Verify Passcode & Execute Threat Scan';
            }
        });
    }

    // Allow Enter key inside OTP input to submit
    if (otpInput) {
        otpInput.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                if (confirmOtpBtn) confirmOtpBtn.click();
            }
        });
    }

    // Resend OTP Code
    if (resendOtpBtn) {
        resendOtpBtn.addEventListener('click', async function () {
            if (!currentTargetEmail) return;
            resendOtpBtn.disabled = true;
            resendOtpBtn.textContent = 'Resending...';

            try {
                const response = await fetch('/assessment/api/request-scan-otp', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json',
                        'X-CSRFToken': getCsrfToken()
                    },
                    body: JSON.stringify({
                        email: currentTargetEmail,
                        consent: true
                    })
                });
                const data = await parseJsonResponse(response);
                if (!response.ok || !data.success) {
                    throw new Error(data.error || 'Failed to resend verification code.');
                }
                showToast('A fresh verification code has been dispatched to your email.', 'success');
            } catch (err) {
                showToast(err.message, 'danger');
            } finally {
                resendOtpBtn.disabled = false;
                resendOtpBtn.textContent = 'Resend Code';
            }
        });
    }

    // Change Email / Reset to Initial State
    if (changeEmailBtn) {
        changeEmailBtn.addEventListener('click', function () {
            if (otpBox) otpBox.classList.add('hidden');
            if (scanBtn) scanBtn.classList.remove('hidden');
            if (emailInput) {
                emailInput.focus();
                emailInput.select();
            }
        });
    }

    // Step 3: Run Full External Security Scan
    async function executeScan(email) {
        scanStatusBox.classList.remove('hidden');
        resultsContainer.classList.add('hidden');

        updateStatusStep('Connecting to XposedOrNot threat intelligence engine...', '30%');

        try {
            const response = await fetch('/assessment/api/scan-email', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'X-CSRFToken': getCsrfToken()
                },
                body: JSON.stringify({
                    email: email,
                    consent: true
                })
            });

            updateStatusStep('Analyzing visitor network privacy & reputation indicators...', '65%');

            const data = await parseJsonResponse(response);

            if (!response.ok || !data.success) {
                throw new Error(data.error || 'Failed to complete cybersecurity assessment.');
            }

            updateStatusStep('Synthesizing remediation action items...', '90%');

            setTimeout(() => {
                updateStatusStep('Assessment complete!', '100%');
                setTimeout(() => {
                    scanStatusBox.classList.add('hidden');
                    renderResults(data);
                    resultsContainer.classList.remove('hidden');
                    resultsContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
                    if (scanBtn) scanBtn.classList.remove('hidden');
                }, 400);
            }, 500);

        } catch (err) {
            scanStatusBox.classList.add('hidden');
            if (scanBtn) scanBtn.classList.remove('hidden');
            showToast(err.message, 'danger');
        }
    }

    function updateStatusStep(text, progressWidth) {
        if (statusText) statusText.textContent = text;
        const bar = document.getElementById('scan-progress-bar');
        if (bar) bar.style.width = progressWidth;
    }

    function renderResults(data) {
        // 1. Risk Score Gauge & Badges
        const scoreElem = document.getElementById('res-risk-score');
        const levelElem = document.getElementById('res-risk-level');
        const emailElem = document.getElementById('res-target-email');
        const pdfLink = document.getElementById('res-pdf-download');

        if (scoreElem) scoreElem.textContent = data.risk_score;
        if (emailElem) emailElem.textContent = data.email;
        if (pdfLink) pdfLink.href = data.pdf_url;

        if (levelElem) {
            levelElem.textContent = data.risk_level;
            levelElem.className = 'px-3 py-1 rounded-full text-xs font-semibold border ' +
                (data.risk_score > 75 ? 'risk-badge-critical' :
                 data.risk_score > 50 ? 'risk-badge-high' :
                 data.risk_score > 25 ? 'risk-badge-moderate' : 'risk-badge-low');
        }

        // Metrics counts
        document.getElementById('res-breach-count').textContent = data.breach_count;
        document.getElementById('res-paste-count').textContent = data.paste_count;
        document.getElementById('res-records-count').textContent = Number(data.total_records).toLocaleString();

        // 2. Breach Findings List
        const breachList = document.getElementById('res-breach-list');
        const noBreachNotice = document.getElementById('res-no-breach-notice');

        if (data.breaches && data.breaches.length > 0) {
            noBreachNotice.classList.add('hidden');
            breachList.classList.remove('hidden');
            breachList.innerHTML = '';

            data.breaches.forEach(b => {
                const card = document.createElement('div');
                card.className = 'p-5 rounded-2xl bg-[#07150d]/80 border border-[#143321] hover:border-emerald-500/50 transition-all shadow-md';
                
                // Parse exposed data classes into emerald/sage pills
                const dataClasses = (b.data_classes || 'Profile Data').split(';').filter(x => x.trim().length > 0);
                const pillsHtml = dataClasses.map(c => 
                    `<span class="px-2.5 py-0.5 rounded-md bg-emerald-950/70 text-emerald-300 border border-emerald-800/60 text-xs font-mono">${c.trim()}</span>`
                ).join(' ');

                // Password risk badge
                const pwdRisk = (b.password_risk || 'unknown').toLowerCase();
                const pwdBadge = pwdRisk === 'plaintext' ? '<span class="px-2 py-0.5 text-xs rounded bg-rose-950 text-rose-300 border border-rose-700">Plaintext Password Leaked</span>' :
                                 pwdRisk === 'easytocrack' ? '<span class="px-2 py-0.5 text-xs rounded bg-amber-950 text-amber-300 border border-amber-700">Weakly Hashed Password</span>' :
                                 '';

                card.innerHTML = `
                    <div class="flex items-start justify-between flex-wrap gap-2 mb-3">
                        <div class="flex items-center gap-3">
                            <div class="w-10 h-10 rounded-xl bg-[#0d2216] border border-[#1e4a30] flex items-center justify-center font-bold text-emerald-400">
                                ${b.logo_url ? `<img src="${b.logo_url}" class="w-8 h-8 rounded object-contain" onerror="this.parentElement.textContent='${b.breach_name[0]}'">` : b.breach_name[0]}
                            </div>
                            <div>
                                <h4 class="font-bold text-white text-base">${b.breach_name}</h4>
                                <p class="text-xs text-slate-400">${b.domain || 'Domain undisclosed'} • Breach Year: ${b.breach_date || 'N/A'}</p>
                            </div>
                        </div>
                        <div>${pwdBadge}</div>
                    </div>
                    <p class="text-xs sm:text-sm text-slate-300 mb-3 leading-relaxed">${b.description || 'Credentials and user account records were exposed in this third-party security incident.'}</p>
                    <div class="flex flex-wrap items-center gap-1.5 pt-3 border-t border-[#143321]">
                        <span class="text-xs text-slate-400 font-medium mr-1">Exposed Fields:</span>
                        ${pillsHtml}
                    </div>
                `;
                breachList.appendChild(card);
            });
        } else {
            breachList.classList.add('hidden');
            noBreachNotice.classList.remove('hidden');
        }

        // 3. Network IP & Reputation
        if (data.ip_assessment) {
            const ip = data.ip_assessment;
            document.getElementById('res-ip-addr').textContent = ip.ip || 'Unknown';
            document.getElementById('res-ip-location').textContent = `${ip.city || ''}, ${ip.country || 'Unknown'}`;
            document.getElementById('res-ip-isp').textContent = `${ip.isp_org || 'Unknown'} (${ip.asn || 'N/A'})`;

            const vpnBadge = document.getElementById('res-vpn-badge');
            if (vpnBadge) {
                if (ip.is_vpn || ip.is_proxy || ip.is_tor) {
                    vpnBadge.textContent = 'Proxy/VPN Detected';
                    vpnBadge.className = 'px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-amber-950 text-amber-300 border border-amber-700';
                } else {
                    vpnBadge.textContent = 'Clean Residential IP';
                    vpnBadge.className = 'px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-950 text-emerald-300 border border-emerald-700';
                }
            }
        }

        // 4. Recommendations List
        const recList = document.getElementById('res-rec-list');
        if (recList && data.recommendations) {
            recList.innerHTML = '';
            data.recommendations.forEach(r => {
                const item = document.createElement('div');
                item.className = 'p-5 rounded-2xl bg-[#05110a] border border-[#143321] space-y-2.5 shadow-md';
                
                const pColor = r.priority === 'Critical' ? 'text-rose-400 border-rose-800 bg-rose-950/40' :
                               r.priority === 'High' ? 'text-amber-400 border-amber-800 bg-amber-950/40' :
                               'text-mint-400 border-emerald-800 bg-emerald-950/40';

                // Format steps
                const stepsList = r.action_steps.split('\n')
                    .filter(s => s.trim().length > 0)
                    .map(s => `<li class="text-xs text-slate-300 flex items-start gap-2"><span class="text-mint-400 mt-0.5">•</span><span>${s.replace(/^[•\-\*]\s*/, '')}</span></li>`)
                    .join('');

                item.innerHTML = `
                    <div class="flex items-start justify-between flex-wrap gap-2">
                        <div class="flex items-center gap-2">
                            <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${pColor}">${r.priority}</span>
                            <span class="text-xs text-slate-400 font-mono">${r.category}</span>
                        </div>
                    </div>
                    <h4 class="text-sm font-bold text-white">${r.title}</h4>
                    <p class="text-xs text-slate-400">${r.reason}</p>
                    <div class="pt-2 border-t border-[#0d2216]">
                        <div class="text-[11px] font-semibold text-slate-300 mb-1 font-mono uppercase tracking-wider">Action Steps:</div>
                        <ul class="space-y-1">${stepsList}</ul>
                    </div>
                `;
                recList.appendChild(item);
            });
        }

        // Refresh Lucide icons in dynamically created DOM
        if (typeof lucide !== 'undefined') {
            lucide.createIcons();
        }
    }
});
