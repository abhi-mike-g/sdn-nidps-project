/**
 * API Client Library for SDN-NIDPS
 * Handles communication with backend REST API
 */

class SDNNIDPSApi {
    constructor(baseUrl = 'http://localhost:8080/api') {
        this.baseUrl = baseUrl;
        this.timeout = 5000;
    }

    /**
     * Make API request
     */
    async request(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        const config = {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options,
            timeout: this.timeout
        };

        try {
            const response = await fetch(url, config);
            if (!response.ok) {
                throw new Error(`API Error: ${response.status}`);
            }
            return await response.json();
        } catch (error) {
            console.error(`API Request Failed: ${endpoint}`, error);
            throw error;
        }
    }

    /**
     * Get threats
     */
    async getThreats(limit = 100) {
        return this.request(`/threats?limit=${limit}`);
    }

    /**
     * Get blocked hosts
     */
    async getBlockedHosts() {
        return this.request('/blocked');
    }

    /**
     * Get statistics
     */
    async getStats() {
        return this.request('/stats');
    }

    /**
     * Block a host
     */
    async blockHost(ipAddress) {
        return this.request('/block', {
            method: 'POST',
            body: JSON.stringify({
                ip_address: ipAddress,
                action: 'BLOCK'
            })
        });
    }

    /**
     * Unblock a host
     */
    async unblockHost(ipAddress) {
        return this.request('/unblock', {
            method: 'POST',
            body: JSON.stringify({
                ip_address: ipAddress
            })
        });
    }

    /**
     * Get system health
     */
    async getHealth() {
        return this.request('/health');
    }

    /**
     * Get network topology
     */
    async getTopology() {
        return this.request('/topology');
    }

    /**
     * Export data
     */
    async exportData(format = 'json') {
        return this.request(`/export?format=${format}`);
    }

    /**
     * Get performance metrics
     */
    async getMetrics() {
        return this.request('/metrics');
    }

    /**
     * Get alerts
     */
    async getAlerts(limit = 50) {
        return this.request(`/alerts?limit=${limit}`);
    }

    /**
     * Stream alerts (WebSocket)
     */
    connectWebSocket(callback) {
        const wsUrl = this.baseUrl.replace('http', 'ws');
        const ws = new WebSocket(`${wsUrl}/stream`);
        
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            callback(data);
        };
        
        ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
        
        return ws;
    }
}

// Global API instance
const api = new SDNNIDPSApi();
