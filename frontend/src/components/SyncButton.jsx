import { useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { triggerSync } from '../api/client'

export default function SyncButton({ feedId = null, onSync, label = 'Sync Now' }) {
    const [loading, setLoading] = useState(false)

    const handleSync = async () => {
        setLoading(true)
        try {
            await triggerSync(feedId)
            if (onSync) onSync('Sync started successfully', 'success')
        } catch (err) {
            if (onSync) onSync(`Sync failed: ${err.message}`, 'error')
        } finally {
            setTimeout(() => setLoading(false), 2000)
        }
    }

    return (
        <button
            onClick={handleSync}
            disabled={loading}
            className="inline-flex items-center px-4 py-2 rounded-lg text-sm font-medium bg-accent/10 text-accent border border-accent/20 hover:bg-accent/20 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
        >
            <RefreshCw className={`w-4 h-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
            {loading ? 'Syncing...' : label}
        </button>
    )
}
