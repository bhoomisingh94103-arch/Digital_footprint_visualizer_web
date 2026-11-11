/**
 * Digital Footprint Intelligence - Dynamic Cybersecurity Chart.js Visualizations
 * Sage Green, Emerald Green & Mint Green Palette
 */

function initDashboardCharts(data) {
    if (!window.Chart || !data) return;

    // Global chart typography and green-tinted grid defaults
    Chart.defaults.color = '#9bb0a5';
    Chart.defaults.font.family = "'Inter', sans-serif";
    Chart.defaults.borderColor = 'rgba(24, 60, 39, 0.35)';

    // 1. Digital Risk Distribution Pie Chart
    const pieCtx = document.getElementById('riskPieChart');
    if (pieCtx && data.risk_pie) {
        new Chart(pieCtx, {
            type: 'doughnut',
            data: {
                labels: data.risk_pie.labels,
                datasets: [{
                    data: data.risk_pie.data,
                    backgroundColor: [
                        'rgba(52, 211, 153, 0.85)', // Low - Mint/Emerald
                        'rgba(132, 169, 140, 0.85)',// Moderate - Sage Green
                        'rgba(245, 158, 11, 0.85)', // High - Amber
                        'rgba(244, 63, 94, 0.85)'   // Critical - Crimson
                    ],
                    borderColor: '#07150d',
                    borderWidth: 2,
                    hoverOffset: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { boxWidth: 12, padding: 15, font: { size: 11 }, color: '#9bb0a5' }
                    }
                },
                cutout: '65%'
            }
        });
    }

    // 2. Email Breach Bar Chart
    const barCtx = document.getElementById('breachBarChart');
    if (barCtx && data.breach_bar) {
        new Chart(barCtx, {
            type: 'bar',
            data: {
                labels: data.breach_bar.labels,
                datasets: [{
                    label: 'Breach Matches Identified',
                    data: data.breach_bar.data,
                    backgroundColor: 'rgba(52, 211, 153, 0.75)',
                    hoverBackgroundColor: 'rgba(110, 231, 183, 0.95)',
                    borderRadius: 6,
                    borderSkipped: false
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { stepSize: 1, color: '#9bb0a5' },
                        grid: { color: 'rgba(24, 60, 39, 0.28)' }
                    },
                    x: {
                        ticks: { color: '#9bb0a5' },
                        grid: { display: false }
                    }
                }
            }
        });
    }

    // 3. Security Assessment Radar Chart (6 Dimensions)
    const radarCtx = document.getElementById('securityRadarChart');
    if (radarCtx && data.security_radar) {
        new Chart(radarCtx, {
            type: 'radar',
            data: {
                labels: data.security_radar.labels,
                datasets: [{
                    label: 'Risk Exposure Level (0 = Secure, 100 = Exposed)',
                    data: data.security_radar.data,
                    backgroundColor: 'rgba(16, 185, 129, 0.22)',
                    borderColor: 'rgba(52, 211, 153, 0.95)',
                    pointBackgroundColor: '#6ee7b7',
                    pointBorderColor: '#07150d',
                    pointHoverRadius: 6,
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    r: {
                        angleLines: { color: 'rgba(24, 60, 39, 0.45)' },
                        grid: { color: 'rgba(24, 60, 39, 0.35)' },
                        suggestedMin: 0,
                        suggestedMax: 100,
                        ticks: { display: false },
                        pointLabels: { color: '#9bb0a5', font: { size: 10 } }
                    }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }

    // 4. Privacy Improvement Progress Doughnut Chart
    const progressCtx = document.getElementById('progressChart');
    if (progressCtx && data.progress_doughnut) {
        new Chart(progressCtx, {
            type: 'doughnut',
            data: {
                labels: data.progress_doughnut.labels,
                datasets: [{
                    data: data.progress_doughnut.data,
                    backgroundColor: [
                        'rgba(16, 185, 129, 0.85)', // Emerald
                        'rgba(20, 52, 34, 0.55)'    // Forest green
                    ],
                    borderColor: '#07150d',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'bottom', labels: { boxWidth: 12, padding: 12, font: { size: 11 }, color: '#9bb0a5' } }
                },
                cutout: '70%'
            }
        });
    }

    // 5. Assessment History Trend Line Chart
    const trendCtx = document.getElementById('historyTrendChart');
    if (trendCtx && data.history_trend) {
        new Chart(trendCtx, {
            type: 'line',
            data: {
                labels: data.history_trend.labels,
                datasets: [{
                    label: 'Calculated Risk Index (0 - 100)',
                    data: data.history_trend.data,
                    borderColor: '#34d399',
                    backgroundColor: 'rgba(52, 211, 153, 0.12)',
                    fill: true,
                    tension: 0.35,
                    pointBackgroundColor: '#6ee7b7',
                    pointBorderColor: '#07150d',
                    pointRadius: 4,
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: {
                        suggestedMin: 0,
                        suggestedMax: 100,
                        ticks: { color: '#9bb0a5' },
                        grid: { color: 'rgba(24, 60, 39, 0.28)' }
                    },
                    x: {
                        ticks: { color: '#9bb0a5' },
                        grid: { display: false }
                    }
                }
            }
        });
    }
}
