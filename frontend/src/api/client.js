import axios from 'axios'

const api = axios.create({
    baseURL: '/api/v1',
    timeout: 120000, // 120 seconds
})

// Response interceptor — extract data or throw clean error
api.interceptors.response.use(
    (res) => res.data,
    (err) => {
        const message = err.response?.data?.detail || err.message
        throw new Error(message)
    }
)

// --- Stats ---
export const getStats = () => api.get('/stats')
export const getHealth = () => api.get('/health')

// --- Indicators ---
export const getIndicators = (params) => api.get('/indicators', { params })
export const searchIndicators = (q) => api.get('/indicators/search', { params: { q } })
export const getIndicatorById = (id) => api.get(`/indicators/${id}`)

// --- MITRE ---
export const getMitre = () => api.get('/mitre')
export const getMitreTechnique = (id) => api.get(`/mitre/${id}`)

// --- Sync ---
export const triggerSync = (feedId = null) => api.post('/sync', { feed_id: feedId })
export const getSyncLogs = (params) => api.get('/sync/log', { params })

// --- Feeds ---
export const getFeeds = () => api.get('/feeds')
export const createFeed = (data) => api.post('/feeds', data)
export const updateFeed = (id, data) => api.put(`/feeds/${id}`, data)
export const deleteFeed = (id) => api.delete(`/feeds/${id}`)
export const testFeedConnection = (data) => api.post('/feeds/test', data)

// --- AI Analyst ---
export const getAIStatus = () => api.get('/ai/status')
export const enrichIndicator = (id) => api.post(`/ai/enrich/${id}`)
export const chatWithAnalyst = (message, conversationHistory = null) =>
    api.post('/ai/chat', { message, conversation_history: conversationHistory })
export const triageAlert = (alertData, indicatorValue = null) =>
    api.post('/ai/triage', { alert_data: alertData, indicator_value: indicatorValue })

// --- ML Threat Prediction ---
export const getMLStatus = () => api.get('/ml/status')
export const getMLOverview = () => api.get('/ml/overview')
export const getMLPredictions = (params) => api.get('/ml/predictions', { params })
export const getMLTopThreats = (params) => api.get('/ml/top-threats', { params })
export const predictThreat = (alertData, persist = false) =>
    api.post('/ml/predict', { alert_data: alertData, persist })
export const ingestThreatAlert = (alertData) =>
    api.post('/ml/alerts/ingest', { alert_data: alertData, persist: true })
export const seedThreatPredictionDemo = (count = 12) =>
    api.post('/ml/demo/seed', { count })
export const retrainThreatModel = () => api.post('/ml/retrain')
export const getHostProfiles = () => api.get('/ml/host-profiles')
export const saveHostProfile = (data) => api.post('/ml/host-profiles', data)
export const getWazuhMLIntegrationStatus = () => api.get('/ml/wazuh/status')
export const installWazuhMLIntegration = (data = {}) => api.post('/ml/wazuh/install', data)
