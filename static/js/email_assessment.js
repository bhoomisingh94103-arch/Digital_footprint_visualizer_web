/**
 * Digital Footprint Intelligence - Mode A Interactive Email Scanner
 * Sage & Emerald Cyber Theme
 */

document.addEventListener('DOMContentLoaded', function () {
    const scanForm = document.getElementById('email-scan-form');
    if (!scanForm) return;

    const emailInput = document.getElementById('target-email');
    const consentCheckbox = document.getElementById('consent-checkbox');
    const scanBtn = document.getElementById('scan-btn');
    const scanStatusBox = document.getElementById('scan-status-box');
    const statusText = document.getElementById('status-step-text');
    const resultsContainer = document.getElementById('scan-results');

    scanForm.addEventListener('submit', async function (e) {
        e.preventDefault();

        const email = emailInput.value.trim().toLowerCase();
        if (!email) {
            showToast('Please enter an email address to analyze.', 'danger');
            return;
        }

        if (!consentCheckbox.checked) {
            showToast('You must check the consent box to proceed.', 'warning');
            consentCheckbox.focus();
            return;
        }

        // UI Scanning State
        scanBtn.disabled = true;
        scanBtn.classList.add('opacity-50', 'cursor-not-allowed');
        scanStatusBox.classList.remove('hidden');
        resultsContainer.classList.add('hidden');

        // Multi-stage visual indicator
        updateStatusStep('Querying XposedOrNot breach analytics engine...', '30%');
        
        try {
            const response = await fetch('/assessment/api/scan-email', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({
                    email: email,
                    consent: true
                })
            });

            updateStatusStep('Synthesizing threat intelligence and generating recommendations...', '80%');

            const data = await response.json();

            if (!response.ok || !data.success) {
                throw new Error(data.error || 'Failed to complete cybersecurity assessment.');
            }

            updateStatusStep('Assessment complete!', '100%');
            setTimeout(() => {
                scanStatusBox.classList.add('hidden');
                renderResults(data);
                resultsContainer.classList.remove('hidden');
                resultsContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }, 500);

        } catch (err) {
            scanStatusBox.classList.add('hidden');
            showToast(err.message, 'danger');
        } finally {
            scanBtn.disabled = false;
            scanBtn.classList.remove('opacity-50', 'cursor-not-allowed');
        }
    });

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
                card.className = 'p-5 rounded-2xl bg-[#07150d]/80 border border-[#143321] hover:border-emerald-500/50 transition-all';
                
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

        // 3. Isolated Network Analysis Box (HackMyIP)
        const ipInfo = data.ip_analysis;
        if (ipInfo && ipInfo.ip !== 'Unavailable') {
            document.getElementById('net-ip').textContent = ipInfo.ip;
            document.getElementById('net-loc').textContent = `${ipInfo.city || 'Unknown'}, ${ipInfo.country || 'Unknown'}`;
            document.getElementById('net-isp').textContent = `${ipInfo.isp_org || 'Unknown'} (${ipInfo.asn || ''})`;
            const proxyBadge = document.getElementById('net-proxy-badge');
            if (proxyBadge) {
                if (ipInfo.is_vpn || ipInfo.is_proxy) {
                    proxyBadge.textContent = 'Proxy / VPN Detected';
                    proxyBadge.className = 'px-2 py-0.5 text-xs rounded bg-emerald-950 text-emerald-300 border border-emerald-700';
                } else {
                    proxyBadge.textContent = 'Direct Connection';
                    proxyBadge.className = 'px-2 py-0.5 text-xs rounded bg-[#0d2216] text-mint-300 border border-emerald-800';
                }
            }
        }

        // 4. Recommendations List
        const recList = document.getElementById('res-rec-list');
        if (recList && data.recommendations) {
            recList.innerHTML = '';
            data.recommendations.forEach(r => {
                const item = document.createElement('div');
                item.className = 'p-4 rounded-xl bg-[#07150d]/80 border border-[#143321] flex flex-col md:flex-row items-start md:items-center justify-between gap-4';
                
                const pColor = r.priority === 'Critical' ? 'text-rose-400 border-rose-500/40 bg-rose-950/30' :
                               r.priority === 'High' ? 'text-amber-400 border-amber-500/40 bg-amber-950/30' :
                               'text-emerald-400 border-emerald-500/40 bg-emerald-950/30';

                item.innerHTML = `
                    <div class="space-y-1">
                        <div class="flex items-center gap-2">
                            <span class="px-2 py-0.5 rounded text-xs font-semibold border ${pColor}">${r.priority}</span>
                            <span class="text-xs text-slate-400 font-mono">${r.category}</span>
                        </div>
                        <h5 class="font-semibold text-white text-sm">${r.title}</h5>
                        <p class="text-xs text-slate-300">${r.reason}</p>
                    </div>
                    <div class="flex items-center gap-2">
                        ${r.external_url ? `<a href="${r.external_url}" target="_blank" rel="noopener" class="text-xs text-emerald-400 hover:text-emerald-300 hover:underline">Guidance Resource →</a>` : ''}
                    </div>
                `;
                recList.appendChild(item);
            });
        }

        if (window.lucide) window.lucide.createIcons();
    }
});
