/**
 * Chart Configuration and Utilities
 * Manages all Chart.js instances
 */

class ChartManager {
    constructor() {
        this.charts = {};
        this.updateIntervals = {};
    }

    /**
     * Create threat timeline chart
     */
    createThreatTimelineChart(canvasId) {
        const ctx = document.getElementById(canvasId).getContext('2d');
        this.charts.timeline = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Threats Detected',
                    data: [],
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    tension: 0.4,
                    fill: true,
                    pointRadius: 3,
                    pointBackgroundColor: '#ef4444'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: { color: '#e0e0e0' }
                    }
                },
                scales: {
                    x: {
                        grid: { color: '#2a2a3e' },
                        ticks: { color: '#888' }
                    },
                    y: {
                        grid: { color: '#2a2a3e' },
                        ticks: { color: '#888' }
                    }
                }
            }
        });
        return this.charts.timeline;
    }

    /**
     * Create threat distribution chart
     */
    createDistributionChart(canvasId) {
        const ctx = document.getElementById(canvasId).getContext('2d');
        this.charts.distribution = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        '#ef4444', '#f59e0b', '#eab308', '#10b981', '#667eea', '#764ba2'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: { color: '#e0e0e0', padding: 15 }
                    }
                }
            }
        });
        return this.charts.distribution;
    }

    /**
     * Create STRIDE analysis chart
     */
    createStrideChart(canvasId) {
        const ctx = document.getElementById(canvasId).getContext('2d');
        this.charts.stride = new Chart(ctx, {
            type: 'radar',
            data: {
                labels: ['Spoofing', 'Tampering', 'Repudiation', 'Info Disclosure', 'DoS', 'Elevation'],
                datasets: [{
                    label: 'Threat Coverage',
                    data: [0, 0, 0, 0, 0, 0],
                    borderColor: '#667eea',
                    backgroundColor: 'rgba(102, 126, 234, 0.2)',
                    pointBackgroundColor: '#667eea'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    r: {
                        grid: { color: '#2a2a3e' },
                        ticks: { color: '#888', backdropColor: 'transparent' },
                        pointLabels: { color: '#e0e0e0' }
                    }
                },
                plugins: {
                    legend: {
                        labels: { color: '#e0e0e0' }
                    }
                }
            }
        });
        return this.charts.stride;
    }

    /**
     * Create traffic analysis chart
     */
    createTrafficChart(canvasId) {
        const ctx = document.getElementById(canvasId).getContext('2d');
        this.charts.traffic = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Packets/sec',
                    data: [],
                    backgroundColor: 'rgba(102, 126, 234, 0.6)',
                    borderColor: '#667eea',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: { color: '#e0e0e0' }
                    }
                },
                scales: {
                    x: {
                        grid: { color: '#2a2a3e' },
                        ticks: { color: '#888' }
                    },
                    y: {
                        grid: { color: '#2a2a3e' },
                        ticks: { color: '#888' }
                    }
                }
            }
        });
        return this.charts.traffic;
    }

    /**
     * Update chart data
     */
    updateChart(chartName, labels, data) {
        if (this.charts[chartName]) {
            this.charts[chartName].data.labels = labels;
            this.charts[chartName].data.datasets[0].data = data;
            this.charts[chartName].update();
        }
    }

    /**
     * Update all charts with threat data
     */
    updateAllCharts(threats) {
        // Timeline data
        const hourlyData = {};
        threats.forEach(threat => {
            const hour = new Date(threat.timestamp * 1000).getHours();
            hourlyData[hour] = (hourlyData[hour] || 0) + 1;
        });

        const timeLabels = Array.from({length: 24}, (_, i) => `${i}:00`);
        const timeCounts = timeLabels.map((_, i) => hourlyData[i] || 0);

        if (this.charts.timeline) {
            this.updateChart('timeline', timeLabels, timeCounts);
        }

        // Distribution data
        const typeCount = {};
        threats.forEach(threat => {
            const type = threat.threat || 'Unknown';
            typeCount[type] = (typeCount[type] || 0) + 1;
        });

        if (this.charts.distribution) {
            this.updateChart('distribution', Object.keys(typeCount), Object.values(typeCount));
        }

        // STRIDE data
        const strideMap = {
            'Spoofing': 0, 'Tampering': 1, 'Repudiation': 2,
            'Information Disclosure': 3, 'Denial of Service': 4,
            'Elevation of Privilege': 5
        };

        const strideCounts = [0, 0, 0, 0, 0, 0];
        threats.forEach(threat => {
            const category = threat.stride_category || 'Unknown';
            const index = strideMap[category];
            if (index !== undefined) {
                strideCounts[index]++;
            }
        });

        if (this.charts.stride) {
            this.charts.stride.data.datasets[0].data = strideCounts;
            this.charts.stride.update();
        }
    }

    /**
     * Start auto-update interval
     */
    startAutoUpdate(interval = 5000) {
        this.updateIntervals.auto = setInterval(async () => {
            try {
                const threats = await api.getThreats(50);
                this.updateAllCharts(threats);
            } catch (error) {
                console.error('Error updating charts:', error);
            }
        }, interval);
    }

    /**
     * Stop auto-update
     */
    stopAutoUpdate() {
        if (this.updateIntervals.auto) {
            clearInterval(this.updateIntervals.auto);
        }
    }

    /**
     * Destroy all charts
     */
    destroyAll() {
        Object.values(this.charts).forEach(chart => {
            if (chart) chart.destroy();
        });
        this.charts = {};
    }
}

// Global chart manager
const chartManager = new ChartManager();
