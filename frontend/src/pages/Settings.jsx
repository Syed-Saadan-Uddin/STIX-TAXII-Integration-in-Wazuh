import { useState, useEffect } from 'react'
import { useOutletContext } from 'react-router-dom'
import { Plus, Edit2, Trash2, Power, Server, Clock, Database as DbIcon } from 'lucide-react'
import { getFeeds, createFeed, updateFeed, deleteFeed, getHealth } from '../api/client'
import FeedForm from '../components/FeedForm'
import SyncButton from '../components/SyncButton'

export default function Settings() {
    const { showToast } = useOutletContext()
    const [feeds, setFeeds] = useState([])
    const [health, setHealth] = useState(null)
    const [showForm, setShowForm] = useState(false)
    const [editingFeed, setEditingFeed] = useState(null)
    const [loading, setLoading] = useState(true)

    const fetchData = async () => {
        try {
            const [feedsData, healthData] = await Promise.all([getFeeds(), getHealth()])
            setFeeds(feedsData || [])
            setHealth(healthData)
        } catch (err) {
            showToast(`Failed to load settings: ${err.message}`, 'error')
        } finally {
            setLoading(false)
        }
    }

    useEffect(() => {
        fetchData()
    }, [])

    const handleCreate = async (data) => {
        await createFeed(data)
        showToast('Feed created successfully', 'success')
        fetchData()
    }

    const handleUpdate = async (data) => {
        await updateFeed(editingFeed.id, data)
        showToast('Feed updated successfully', 'success')
        setEditingFeed(null)
        fetchData()
    }

    const handleDelete = async (id) => {
        if (!window.confirm('Delete this feed? All associated indicators will be removed.')) return
        try {
            await deleteFeed(id)
            showToast('Feed deleted', 'success')
            fetchData()
        } catch (err) {
            showToast(`Failed to delete feed: ${err.message}`, 'error')
        }
    }

    const handleToggle = async (feed) => {
        try {
            await updateFeed(feed.id, { is_active: !feed.is_active })
            showToast(`Feed ${!feed.is_active ? 'activated' : 'deactivated'}`, 'success')
            fetchData()
        } catch (err) {
            showToast(`Failed to update feed: ${err.message}`, 'error')
        }
    }

    const formatDate = (dateStr) => {
        if (!dateStr) return 'Never'
        return new Date(dateStr).toLocaleString('en-US', {
            month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit',
        })
    }

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="w-8 h-8 border-2 border-accent border-t-transparent rounded-full animate-spin" />
            </div>
        )
    }

    return (
        <div className="space-y-8 max-w-4xl">
            {/* Section 1: TAXII Feeds */}
            <section>
                <div className="flex items-center justify-between mb-4">
                    <h2 className="text-base font-semibold text-text-primary">TAXII Feeds</h2>
                    <button onClick={() => { setEditingFeed(null); setShowForm(true) }}
                        className="inline-flex items-center px-3 py-2 rounded-lg text-sm font-medium bg-accent text-white hover:bg-accent-hover transition-colors">
                        <Plus className="w-4 h-4 mr-1.5" /> Add Feed
                    </button>
                </div>

                <div className="space-y-3">
                    {feeds.map(feed => (
                        <div key={feed.id} className="glass-card rounded-xl p-4 border border-border hover:border-border-light transition-colors">
                            <div className="flex items-center justify-between">
                                <div className="flex-1 min-w-0">
                                    <div className="flex items-center space-x-3">
                                        <h3 className="text-sm font-semibold text-text-primary">{feed.name}</h3>
                                        <span className={`badge ${feed.is_active ? 'badge-success' : 'badge-failed'}`}>
                                            {feed.is_active ? 'Active' : 'Inactive'}
                                        </span>
                                    </div>
                                    <p className="text-xs text-text-muted font-mono mt-1 truncate">{feed.taxii_url}</p>
                                    <div className="flex items-center space-x-4 mt-2 text-xs text-text-muted">
                                        <span className="flex items-center"><Clock className="w-3 h-3 mr-1" /> {feed.polling_interval}m interval</span>
                                        <span>Last sync: {formatDate(feed.last_sync)}</span>
                                    </div>
                                </div>

                                <div className="flex items-center space-x-2 ml-4">
                                    <SyncButton feedId={feed.id} onSync={(msg, type) => showToast(msg, type)} label="Sync" />
                                    <button onClick={() => handleToggle(feed)}
                                        className={`p-2 rounded-lg border transition-colors ${feed.is_active ? 'border-success/30 text-success hover:bg-success/10' : 'border-border text-text-muted hover:bg-bg-elevated'}`}>
                                        <Power className="w-4 h-4" />
                                    </button>
                                    <button onClick={() => { setEditingFeed(feed); setShowForm(true) }}
                                        className="p-2 rounded-lg border border-border text-text-muted hover:text-accent hover:border-accent/30 transition-colors">
                                        <Edit2 className="w-4 h-4" />
                                    </button>
                                    <button onClick={() => handleDelete(feed.id)}
                                        className="p-2 rounded-lg border border-border text-text-muted hover:text-danger hover:border-danger/30 transition-colors">
                                        <Trash2 className="w-4 h-4" />
                                    </button>
                                </div>
                            </div>
                        </div>
                    ))}

                    {feeds.length === 0 && (
                        <div className="glass-card rounded-xl p-8 border border-border text-center">
                            <Server className="w-10 h-10 mx-auto mb-3 text-text-muted opacity-40" />
                            <p className="text-sm text-text-muted">No feeds configured yet</p>
                            <p className="text-xs text-text-muted mt-1">Click "Add Feed" to connect to a TAXII server</p>
                        </div>
                    )}
                </div>
            </section>

            {/* Section 2: System Info */}
            <section>
                <h2 className="text-base font-semibold text-text-primary mb-4">System Info</h2>
                <div className="glass-card rounded-xl p-5 border border-border">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                        <div>
                            <label className="text-xs text-text-muted">Status</label>
                            <p className="text-sm font-medium text-text-primary mt-0.5 flex items-center">
                                <span className={`w-2 h-2 rounded-full mr-2 ${health?.status === 'ok' ? 'bg-success' : 'bg-danger'}`} />
                                {health?.status || 'Unknown'}
                            </p>
                        </div>
                        <div>
                            <label className="text-xs text-text-muted">Database</label>
                            <p className="text-sm font-medium text-text-primary mt-0.5">{health?.db || '—'}</p>
                        </div>
                        <div>
                            <label className="text-xs text-text-muted">Scheduler</label>
                            <p className="text-sm font-medium text-text-primary mt-0.5">{health?.scheduler || '—'}</p>
                        </div>
                        <div>
                            <label className="text-xs text-text-muted">Version</label>
                            <p className="text-sm font-mono font-medium text-text-primary mt-0.5">{health?.version || '—'}</p>
                        </div>
                    </div>
                </div>
            </section>

            {/* Feed Form Modal */}
            {showForm && (
                <FeedForm
                    feed={editingFeed}
                    onSubmit={editingFeed ? handleUpdate : handleCreate}
                    onClose={() => { setShowForm(false); setEditingFeed(null) }}
                />
            )}
        </div>
    )
}
