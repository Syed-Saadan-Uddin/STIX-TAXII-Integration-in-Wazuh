import axios from 'axios'

const api = axios.create({
    baseURL: '/api/v1',
    timeout: 30000,
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
