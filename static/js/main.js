/**
 * Digital Footprint Intelligence - Main Application Scripts
 * Sage & Emerald Cyber Theme
 */

document.addEventListener('DOMContentLoaded', function () {
    // Mobile sidebar toggle
    const mobileSidebarBtn = document.getElementById('mobile-sidebar-btn');
    const sidebar = document.getElementById('main-sidebar');
    const sidebarOverlay = document.getElementById('sidebar-overlay');
    const sidebarCloseBtn = document.getElementById('sidebar-close-btn');

    function openSidebar() {
        if (sidebar) {
            sidebar.classList.remove('-translate-x-full');
            sidebar.classList.add('translate-x-0');
        }
        if (sidebarOverlay) {
            sidebarOverlay.classList.remove('hidden');
        }
    }

    function closeSidebar() {
        if (sidebar) {
            sidebar.classList.add('-translate-x-full');
            sidebar.classList.remove('translate-x-0');
        }
        if (sidebarOverlay) {
            sidebarOverlay.classList.add('hidden');
        }
    }

    if (mobileSidebarBtn) {
        mobileSidebarBtn.addEventListener('click', openSidebar);
    }
    if (sidebarCloseBtn) {
        sidebarCloseBtn.addEventListener('click', closeSidebar);
    }
    if (sidebarOverlay) {
        sidebarOverlay.addEventListener('click', closeSidebar);
    }

    // Auto-dismiss alert banners after 6 seconds
    const alerts = document.querySelectorAll('.auto-dismiss-alert');
    alerts.forEach(function (alert) {
        setTimeout(function () {
            alert.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
            alert.style.opacity = '0';
            alert.style.transform = 'translateY(-10px)';
            setTimeout(function () { alert.remove(); }, 500);
        }, 6000);
    });

    // Initialize Lucide icons if available
    if (window.lucide) {
        window.lucide.createIcons();
    }
});

// Toast notification utility
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    const borderCol = type === 'success' ? 'border-emerald-500/60 text-emerald-300 bg-emerald-950/90' :
                      type === 'danger' ? 'border-rose-500/60 text-rose-300 bg-rose-950/90' :
                      type === 'warning' ? 'border-amber-500/60 text-amber-300 bg-amber-950/90' :
                      'border-emerald-600/50 text-emerald-200 bg-[#07150d]/95';

    toast.className = `p-4 mb-3 rounded-xl border ${borderCol} shadow-2xl backdrop-blur-md flex items-center justify-between text-xs sm:text-sm transition-all duration-300 transform translate-y-2 opacity-0`;
    toast.innerHTML = `
        <div class="flex items-center gap-3">
            <span class="w-2 h-2 rounded-full ${type === 'success' ? 'bg-emerald-400' : type === 'danger' ? 'bg-rose-400' : type === 'warning' ? 'bg-amber-400' : 'bg-mint-400'}"></span>
            <span>${message}</span>
        </div>
        <button onclick="this.parentElement.remove()" class="text-slate-400 hover:text-white ml-4 text-xs font-bold">✕</button>
    `;

    container.appendChild(toast);
    requestAnimationFrame(() => {
        toast.classList.remove('translate-y-2', 'opacity-0');
    });

    setTimeout(() => {
        toast.classList.add('opacity-0', 'translate-y-[-10px]');
        setTimeout(() => toast.remove(), 400);
    }, 4500);
}

// Copy text utility
function copyToClipboard(text, successMsg = 'Copied to clipboard!') {
    navigator.clipboard.writeText(text).then(() => {
        showToast(successMsg, 'success');
    }).catch(() => {
        showToast('Failed to copy to clipboard', 'danger');
    });
}
