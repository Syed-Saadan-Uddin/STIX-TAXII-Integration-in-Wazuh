import { useState, useEffect, useCallback } from 'react'
import { useOutletContext } from 'react-router-dom'
import { Search, Download, ChevronLeft, ChevronRight, X } from 'lucide-react'
import { getIndicators, searchIndicators, getIndicatorById, getFeeds } from '../api/client'
import IndicatorTable from '../components/IndicatorTable'

export default function Indicators() {
    const { showToast } = useOutletContext()
    const [indicators, setIndicators] = useState([])
    const [total, setTotal] = useState(0)
    const [page, setPage] = useState(1)
    const [pages, setPages] = useState(0)
    const [query, setQuery] = useState('')
    const [typeFilter, setTypeFilter] = useState('')
    const [statusFilter, setStatusFilter] = useState('')
    const [feedFilter, setFeedFilter] = useState('')
    const [feeds, setFeeds] = useState([])
    const [loading, setLoading] = useState(true)
    const [drawerOpen, setDrawerOpen] = useState(false)
    const [selectedIndicator, setSelectedIndicator] = useState(null)

    const perPage = 50

    const fetchData = useCallback(async () => {
        setLoading(true)
        try {
            if (query.length > 0) {
                const data = await searchIndicators(query)
                setIndicators(data.items || [])
                setTotal(data.total || 0)
                setPages(1)
            } else {
                const params = { page, per_page: perPage }
                if (typeFilter) params.type = typeFilter
                if (statusFilter !== '') params.is_active = statusFilter === 'active'
                if (feedFilter) params.feed_id = parseInt(feedFilter)
                const data = await getIndicators(params)
                setIndicators(data.items || [])
                setTotal(data.total || 0)
                setPages(data.pages || 0)
            }
        } catch (err) {
            showToast(`Failed to load indicators: ${err.message}`, 'error')
        } finally {
            setLoading(false)
        }
    }, [page, query, typeFilter, statusFilter, feedFilter])

    useEffect(() => {
        getFeeds().then(setFeeds).catch(() => { })
    }, [])

    useEffect(() => {
        const timer = setTimeout(fetchData, query ? 300 : 0) // Debounce search
        return () => clearTimeout(timer)
    }, [fetchData])

    const handleRowClick = async (indicator) => {
        try {
            const detail = await getIndicatorById(indicator.id)
            setSelectedIndicator(detail)
            setDrawerOpen(true)
        } catch {
            setSelectedIndicator(indicator)
            setDrawerOpen(true)
        }
    }

    const exportCSV = () => {
        if (!indicators.length) return
        const headers = ['Value', 'Type', 'Confidence', 'First Seen', 'Expires', 'Status']
        const rows = indicators.map(i => [
            i.value, i.type, i.confidence || '', i.first_seen || '', i.expires || '', i.is_active ? 'Active' : 'Expired'
        ])
        const csv = [headers, ...rows].map(r => r.join(',')).join('\n')
        const blob = new Blob([csv], { type: 'text/csv' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `wazuh-ti-indicators-${new Date().toISOString().slice(0, 10)}.csv`
        a.click()
        URL.revokeObjectURL(url)
        showToast('CSV exported successfully', 'success')
    }

    return (
        <div className="space-y-4">
            {/* Search & Filters */}
            <div className="flex flex-wrap gap-3 items-center">
                <div className="relative flex-1 min-w-[200px]">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
                    <input
                        type="text"
                        value={query}
                        onChange={(e) => { setQuery(e.target.value); setPage(1) }}
                        placeholder="Search indicators..."
                        className="w-full pl-10 pr-4 py-2 rounded-lg bg-bg-surface border border-border text-sm text-text-primary focus:outline-none focus:border-accent transition-colors"
                    />
                </div>

                <select value={typeFilter} onChange={(e) => { setTypeFilter(e.target.value); setPage(1) }}
                    className="px-3 py-2 rounded-lg bg-bg-surface border border-border text-sm text-text-muted focus:outline-none focus:border-accent">
                    <option value="">All Types</option>
                    <option value="ip">IP</option>
                    <option value="domain">Domain</option>
                    <option value="url">URL</option>
                    <option value="hash">Hash</option>
                </select>

                <select value={statusFilter} onChange={(e) => { setStatusFilter(e.target.value); setPage(1) }}
                    className="px-3 py-2 rounded-lg bg-bg-surface border border-border text-sm text-text-muted focus:outline-none focus:border-accent">
                    <option value="">All Status</option>
                    <option value="active">Active</option>
                    <option value="expired">Expired</option>
                </select>

                <select value={feedFilter} onChange={(e) => { setFeedFilter(e.target.value); setPage(1) }}
                    className="px-3 py-2 rounded-lg bg-bg-surface border border-border text-sm text-text-muted focus:outline-none focus:border-accent">
                    <option value="">All Feeds</option>
                    {feeds.map(f => <option key={f.id} value={f.id}>{f.name}</option>)}
                </select>

                <button onClick={exportCSV}
                    className="inline-flex items-center px-3 py-2 rounded-lg text-sm font-medium bg-bg-surface border border-border text-text-muted hover:text-text-primary hover:border-accent/40 transition-all">
                    <Download className="w-4 h-4 mr-1.5" /> Export CSV
                </button>
            </div>

            {/* Results count */}
            <p className="text-xs text-text-muted">
                Showing {indicators.length} of {total.toLocaleString()} indicators
            </p>

            {/* Table */}
            {loading ? (
                <div className="flex items-center justify-center h-48">
                    <div className="w-6 h-6 border-2 border-accent border-t-transparent rounded-full animate-spin" />
                </div>
            ) : (
                <IndicatorTable indicators={indicators} onRowClick={handleRowClick} />
            )}

            {/* Pagination */}
            {pages > 1 && (
                <div className="flex items-center justify-center space-x-2">
                    <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page <= 1}
                        className="p-2 rounded-lg bg-bg-surface border border-border text-text-muted hover:text-text-primary disabled:opacity-30 transition-colors">
                        <ChevronLeft className="w-4 h-4" />
                    </button>
                    <span className="text-sm text-text-muted">
                        Page <span className="text-text-primary font-medium">{page}</span> of {pages}
                    </span>
                    <button onClick={() => setPage(p => Math.min(pages, p + 1))} disabled={page >= pages}
                        className="p-2 rounded-lg bg-bg-surface border border-border text-text-muted hover:text-text-primary disabled:opacity-30 transition-colors">
                        <ChevronRight className="w-4 h-4" />
                    </button>
                </div>
            )}

            {/* Side Drawer */}
            {drawerOpen && selectedIndicator && (
                <div className="fixed inset-0 z-50 flex justify-end">
                    <div className="absolute inset-0 bg-black/50" onClick={() => setDrawerOpen(false)} />
                    <div className="relative w-full max-w-md bg-bg-surface border-l border-border overflow-y-auto animate-slide-in">
                        <div className="p-5 border-b border-border flex items-center justify-between">
                            <h3 className="text-lg font-semibold text-text-primary">Indicator Detail</h3>
                            <button onClick={() => setDrawerOpen(false)} className="p-1 text-text-muted hover:text-text-primary">
                                <X className="w-5 h-5" />
                            </button>
                        </div>
                        <div className="p-5 space-y-4">
                            <div>
                                <label className="text-xs text-text-muted">Value</label>
                                <p className="font-mono text-sm text-text-primary break-all mt-0.5">{selectedIndicator.value}</p>
                            </div>
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <label className="text-xs text-text-muted">Type</label>
                                    <p className="mt-0.5"><span className={`badge badge-${selectedIndicator.type}`}>{selectedIndicator.type?.toUpperCase()}</span></p>
                                </div>
                                <div>
                                    <label className="text-xs text-text-muted">Confidence</label>
                                    <p className="font-mono text-sm text-text-primary mt-0.5">{selectedIndicator.confidence ?? '—'}</p>
                                </div>
                                <div>
                                    <label className="text-xs text-text-muted">Status</label>
                                    <p className="mt-0.5"><span className={`badge ${selectedIndicator.is_active ? 'badge-success' : 'badge-failed'}`}>{selectedIndicator.is_active ? 'Active' : 'Expired'}</span></p>
                                </div>
                                <div>
                                    <label className="text-xs text-text-muted">STIX ID</label>
                                    <p className="font-mono text-xs text-text-muted mt-0.5 truncate">{selectedIndicator.stix_id || '—'}</p>
                                </div>
                            </div>
                            {selectedIndicator.mitre_techniques?.length > 0 && (
                                <div>
                                    <label className="text-xs text-text-muted mb-2 block">MITRE ATT&CK Techniques</label>
                                    <div className="space-y-2">
                                        {selectedIndicator.mitre_techniques.map((t, i) => (
                                            <div key={i} className="flex items-center justify-between p-2.5 rounded-lg bg-bg-primary border border-border">
                                                <span className="font-mono text-sm text-accent font-semibold">{t.technique_id}</span>
                                                <span className="text-xs text-text-muted">{t.name}</span>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            )}
        </div>
    )
}
