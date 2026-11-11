/**
 * Digital Footprint Intelligence - Mode B Interactive Privacy Questionnaire Wizard
 * Sage & Emerald Cyber Theme
 */

document.addEventListener('DOMContentLoaded', function () {
    const quizForm = document.getElementById('quiz-wizard-form');
    if (!quizForm) return;

    const cards = document.querySelectorAll('.question-card');
    const totalQuestions = cards.length;
    let currentIdx = 0;
    const userAnswers = {};

    const progressFill = document.getElementById('quiz-progress-fill');
    const questionCounter = document.getElementById('question-counter');
    const prevBtn = document.getElementById('quiz-prev-btn');
    const nextBtn = document.getElementById('quiz-next-btn');
    const submitBtn = document.getElementById('quiz-submit-btn');
    const resultsContainer = document.getElementById('quiz-results');

    function updateView() {
        cards.forEach((c, i) => {
            if (i === currentIdx) {
                c.classList.remove('hidden');
            } else {
                c.classList.add('hidden');
            }
        });

        // Progress calculation
        const pct = Math.round(((currentIdx + 1) / totalQuestions) * 100);
        if (progressFill) progressFill.style.width = `${pct}%`;
        if (questionCounter) questionCounter.textContent = `Question ${currentIdx + 1} of ${totalQuestions}`;

        // Previous button visibility
        if (prevBtn) {
            if (currentIdx === 0) {
                prevBtn.classList.add('opacity-0', 'pointer-events-none');
            } else {
                prevBtn.classList.remove('opacity-0', 'pointer-events-none');
            }
        }

        // Next vs Submit button
        if (currentIdx === totalQuestions - 1) {
            nextBtn.classList.add('hidden');
            submitBtn.classList.remove('hidden');
        } else {
            nextBtn.classList.remove('hidden');
            submitBtn.classList.add('hidden');
        }
    }

    // Option selection click handler
    document.querySelectorAll('.quiz-option').forEach(option => {
        option.addEventListener('click', function () {
            const parent = this.closest('.question-card');
            const qid = parent.dataset.qid;
            const optIndex = this.dataset.index;

            // Highlight choice in emerald/mint
            parent.querySelectorAll('.quiz-option').forEach(opt => {
                opt.classList.remove('border-emerald-400', 'bg-emerald-950/40', 'ring-1', 'ring-emerald-400');
            });
            this.classList.add('border-emerald-400', 'bg-emerald-950/40', 'ring-1', 'ring-emerald-400');

            userAnswers[qid] = parseInt(optIndex);

            // Auto-advance after small pause
            setTimeout(() => {
                if (currentIdx < totalQuestions - 1) {
                    currentIdx++;
                    updateView();
                }
            }, 300);
        });
    });

    if (prevBtn) {
        prevBtn.addEventListener('click', () => {
            if (currentIdx > 0) {
                currentIdx--;
                updateView();
            }
        });
    }

    if (nextBtn) {
        nextBtn.addEventListener('click', () => {
            const currentCard = cards[currentIdx];
            const qid = currentCard.dataset.qid;
            if (userAnswers[qid] === undefined) {
                showToast('Please select an option before moving to the next question.', 'warning');
                return;
            }
            if (currentIdx < totalQuestions - 1) {
                currentIdx++;
                updateView();
            }
        });
    }

    if (submitBtn) {
        submitBtn.addEventListener('click', async () => {
            const unanswered = [];
            cards.forEach(c => {
                const qid = c.dataset.qid;
                if (userAnswers[qid] === undefined) {
                    unanswered.push(qid);
                }
            });

            if (unanswered.length > 0) {
                showToast(`Please answer all questions before submitting (${unanswered.length} remaining).`, 'warning');
                return;
            }

            submitBtn.disabled = true;
            submitBtn.textContent = 'Calculating Privacy Index...';

            const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';

            try {
                const res = await fetch('/assessment/api/submit-quiz', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json',
                        'X-CSRFToken': csrfToken
                    },
                    body: JSON.stringify({ responses: userAnswers })
                });

                const contentType = res.headers.get('content-type') || '';
                let data;
                if (contentType.includes('application/json')) {
                    data = await res.json();
                } else {
                    const text = await res.text();
                    throw new Error(`Server returned HTTP ${res.status}: ${text.substring(0, 100)}...`);
                }

                if (!res.ok || !data.success) {
                    throw new Error(data.error || 'Failed to submit privacy assessment.');
                }

                // Hide wizard, show results
                document.getElementById('quiz-wizard-card').classList.add('hidden');
                renderQuizResults(data);
                resultsContainer.classList.remove('hidden');
                resultsContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });

            } catch (err) {
                showToast(err.message, 'danger');
                submitBtn.disabled = false;
                submitBtn.textContent = 'Calculate My Risk Score';
            }
        });
    }

    function renderQuizResults(data) {
        document.getElementById('qres-overall-score').textContent = data.overall_score;
        document.getElementById('qres-risk-level').textContent = data.risk_level;
        document.getElementById('qres-summary').textContent = data.summary;

        const pdfBtn = document.getElementById('qres-pdf-download');
        if (pdfBtn) pdfBtn.href = data.pdf_url;

        // Render category bars
        const catBox = document.getElementById('qres-categories');
        if (catBox && data.category_scores) {
            catBox.innerHTML = '';
            for (const [cat, score] of Object.entries(data.category_scores)) {
                const barCol = score > 75 ? 'bg-rose-500' : score > 50 ? 'bg-amber-500' : score > 25 ? 'bg-emerald-600' : 'bg-emerald-400';
                const div = document.createElement('div');
                div.className = 'space-y-1.5 p-3 rounded-xl bg-[#0d2216]/60 border border-[#143321]';
                div.innerHTML = `
                    <div class="flex justify-between text-xs font-semibold">
                        <span class="text-slate-300">${cat}</span>
                        <span class="text-mint-300 font-mono">${score}/100</span>
                    </div>
                    <div class="w-full h-2 rounded-full bg-[#05130b] overflow-hidden">
                        <div class="h-full rounded-full ${barCol}" style="width: ${score}%"></div>
                    </div>
                `;
                catBox.appendChild(div);
            }
        }

        // Render recommendations
        const recBox = document.getElementById('qres-recommendations');
        if (recBox && data.recommendations) {
            recBox.innerHTML = '';
            data.recommendations.forEach(r => {
                const item = document.createElement('div');
                item.className = 'p-4 rounded-xl bg-[#07150d]/80 border border-[#143321] flex flex-col md:flex-row items-start md:items-center justify-between gap-4';
                item.innerHTML = `
                    <div>
                        <div class="flex items-center gap-2 mb-1">
                            <span class="px-2 py-0.5 rounded text-xs font-semibold ${r.priority === 'Critical' ? 'bg-rose-950 text-rose-300 border border-rose-700' : 'bg-amber-950 text-amber-300 border border-amber-700'}">${r.priority}</span>
                            <span class="text-xs text-slate-400 font-mono">${r.category}</span>
                        </div>
                        <h5 class="text-sm font-bold text-white">${r.title}</h5>
                        <p class="text-xs text-slate-300">${r.reason}</p>
                    </div>
                    <div>
                        ${r.external_url ? `<a href="${r.external_url}" target="_blank" rel="noopener" class="text-xs text-emerald-400 hover:text-emerald-300 hover:underline">Guidance Resource →</a>` : ''}
                    </div>
                `;
                recBox.appendChild(item);
            });
        }

        if (window.lucide) window.lucide.createIcons();
    }

    updateView();
});
