/**
 * Digital Footprint Intelligence - Privacy Action Center Checklists
 */

document.addEventListener('DOMContentLoaded', function () {
    const checkboxes = document.querySelectorAll('.action-checklist-checkbox');
    if (!checkboxes.length) return;

    checkboxes.forEach(cb => {
        cb.addEventListener('change', async function () {
            const taskId = this.dataset.taskId;
            const guideId = this.dataset.guideId;
            const isCompleted = this.checked;

            try {
                const res = await fetch('/action-center/api/toggle-task', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    },
                    body: JSON.stringify({
                        task_id: taskId,
                        guide_id: guideId,
                        is_completed: isCompleted
                    })
                });

                const data = await res.json();
                if (data.success) {
                    if (data.progress_pct !== undefined) {
                        const progFill = document.getElementById('action-progress-fill');
                        const progLabel = document.getElementById('action-progress-pct');
                        const completedCountElem = document.getElementById('completed-count-text');

                        if (progFill) progFill.style.width = `${data.progress_pct}%`;
                        if (progLabel) progLabel.textContent = `${data.progress_pct}%`;
                        if (completedCountElem) completedCountElem.textContent = data.completed_count;
                    }

                    if (isCompleted) {
                        showToast('Task marked complete! Hardening verified.', 'success');
                    }
                }
            } catch (err) {
                console.error(err);
                showToast('Failed to update task status.', 'danger');
            }
        });
    });
});

