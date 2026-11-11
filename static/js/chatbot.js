/**
 * Digital Footprint Intelligence - Privacy Guardian Chatbot Assistant
 * Sage & Emerald Cyber Theme
 */

document.addEventListener('DOMContentLoaded', function () {
    const chatWidget = document.getElementById('privacy-guardian-widget');
    if (!chatWidget) return;

    const toggleBtn = document.getElementById('chat-toggle-btn');
    const closeBtn = document.getElementById('chat-close-btn');
    const chatWindow = document.getElementById('chat-window');
    const messagesBox = document.getElementById('chat-messages');
    const chatForm = document.getElementById('chat-form');
    const chatInput = document.getElementById('chat-input');
    const clearBtn = document.getElementById('chat-clear-btn');
    const engineBadge = document.getElementById('chat-engine-badge');

    // Toggle window
    toggleBtn.addEventListener('click', () => {
        chatWindow.classList.toggle('hidden');
        if (!chatWindow.classList.contains('hidden')) {
            chatInput.focus();
            messagesBox.scrollTop = messagesBox.scrollHeight;
        }
    });

    closeBtn.addEventListener('click', () => {
        chatWindow.classList.add('hidden');
    });

    // Form submission
    chatForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const text = chatInput.value.trim();
        if (!text) return;

        appendMessage('user', text);
        chatInput.value = '';

        // Typing indicator
        const typingId = showTypingIndicator();

        try {
            const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
            const res = await fetch('/api/chat/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({ message: text })
            });

            removeTypingIndicator(typingId);
            const contentType = res.headers.get('content-type') || '';
            let data;
            if (contentType.includes('application/json')) {
                data = await res.json();
            } else {
                data = { success: false, error: 'Received unexpected response format from assistant server.' };
            }

            if (data.success) {
                appendMessage('assistant', data.response, data.engine, data.is_ai);
                if (engineBadge && data.engine) {
                    engineBadge.textContent = data.engine;
                }
            } else {
                appendMessage('assistant', data.error || 'Sorry, I encountered an error answering your cybersecurity query.');
            }
        } catch (err) {
            removeTypingIndicator(typingId);
            appendMessage('assistant', 'Network error connecting to Privacy Guardian.');
        }
    });

    // Quick suggestion pills
    document.querySelectorAll('.chat-suggestion-chip').forEach(chip => {
        chip.addEventListener('click', function () {
            const prompt = this.dataset.prompt;
            chatInput.value = prompt;
            chatForm.dispatchEvent(new Event('submit'));
        });
    });

    // Clear chat
    if (clearBtn) {
        clearBtn.addEventListener('click', async () => {
            await fetch('/api/chat/clear', { method: 'POST' });
            messagesBox.innerHTML = `
                <div class="p-3.5 rounded-xl bg-[#0d2216]/80 border border-[#143321] text-xs text-slate-300">
                    <p class="font-semibold text-white mb-1">Privacy Guardian Active</p>
                    <p>Ask anything about data breaches, password entropy, 2FA, tracking defenses, or your personal risk assessment results.</p>
                </div>
            `;
        });
    }

    function appendMessage(role, content, engine = '', isAi = false) {
        const msgDiv = document.createElement('div');
        msgDiv.className = `flex flex-col ${role === 'user' ? 'items-end' : 'items-start'} mb-3`;

        const bubble = document.createElement('div');
        bubble.className = `max-w-[85%] p-3.5 text-xs md:text-sm leading-relaxed ${role === 'user' ? 'chat-bubble-user' : 'chat-bubble-assistant'}`;
        
        // Convert basic markdown formatting (*, **, lists)
        let formatted = escapeHtml(content)
            .replace(/\*\*(.*?)\*\*/g, '<strong class="text-white">$1</strong>')
            .replace(/\*(.*?)\*/g, '<em>$1</em>')
            .replace(/`(.*?)`/g, '<code class="px-1.5 py-0.5 rounded bg-[#05130b] border border-[#143321] font-mono text-xs text-mint-300">$1</code>')
            .replace(/\n\n/g, '<br/><br/>')
            .replace(/\n• /g, '<br/>• ')
            .replace(/\n1\. /g, '<br/>1. ')
            .replace(/\n2\. /g, '<br/>2. ')
            .replace(/\n3\. /g, '<br/>3. ');

        bubble.innerHTML = formatted;

        if (role === 'assistant' && engine) {
            const badge = document.createElement('span');
            badge.className = 'text-[10px] text-slate-400 mt-1 pl-1 flex items-center gap-1 font-mono';
            badge.innerHTML = `<span class="w-1.5 h-1.5 rounded-full ${isAi ? 'bg-mint-400' : 'bg-emerald-400'}"></span> ${engine}`;
            msgDiv.appendChild(bubble);
            msgDiv.appendChild(badge);
        } else {
            msgDiv.appendChild(bubble);
        }

        messagesBox.appendChild(msgDiv);
        messagesBox.scrollTop = messagesBox.scrollHeight;
    }

    function showTypingIndicator() {
        const id = 'typing-' + Date.now();
        const div = document.createElement('div');
        div.id = id;
        div.className = 'flex items-center gap-1.5 p-3 rounded-xl bg-[#0d2216]/80 border border-[#143321] text-emerald-300 text-xs w-20 mb-3';
        div.innerHTML = `
            <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
            <span class="w-1.5 h-1.5 rounded-full bg-mint-400 animate-pulse delay-150"></span>
            <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse delay-300"></span>
        `;
        messagesBox.appendChild(div);
        messagesBox.scrollTop = messagesBox.scrollHeight;
        return id;
    }

    function removeTypingIndicator(id) {
        const elem = document.getElementById(id);
        if (elem) elem.remove();
    }

    function escapeHtml(text) {
        return text
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
});
