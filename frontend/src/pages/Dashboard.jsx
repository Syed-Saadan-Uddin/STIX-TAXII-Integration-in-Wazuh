import { useState, useEffect } from 'react'
import { useOutletContext } from 'react-router-dom'
import { Database, Shield, Rss, AlertTriangle } from 'lucide-react'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'
import { getStats, getSyncLogs, getFeeds } from '../api/client'
import StatCard from '../components/StatCard'
import SyncButton from '../components/SyncButton'

const PIE_COLORS = ['#58a6ff', '#3fb950', '#d29922', '#bc8cff']

export default function Dashboard() {
    const { showToast } = useOutletContext()
    const [stats, setStats] = useState(null)
    const [syncLogs, setSyncLogs] = useState([])
    const [feeds, setFeeds] = useState([])
    const [loading, setLoading] = useState(true)

    const fetchData = async () => {
        try {
            const [statsData, logsData, feedsData] = await Promise.all([
                getStats(),
                getSyncLogs({ page: 1, per_page: 5 }),
                getFeeds(),
            ])
            setStats(statsData)
            setSyncLogs(logsData.items || [])
            setFeeds(feedsData || [])
        } catch (err) {
            showToast(`Failed to load dashboard: ${err.message}`, 'error')
        } finally {
            setLoading(false)
        }
    }

    useEffect(() => {
        fetchData()
        const interval = setInterval(fetchData, 30000) // Refresh every 30s
        return () => clearInterval(interval)
    }, [])

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="w-8 h-8 border-2 border-accent border-t-transparent rounded-full animate-spin" />
            </div>
        )
    }

    // IOC distribution chart data
    const pieData = stats?.ioc_type_distribution
        ? Object.entries(stats.ioc_type_distribution).map(([name, value]) => ({ name: name.toUpperCase(), value }))
        : []

    const formatDate = (dateStr) => {
        if (!dateStr) return '—'
        const d = new Date(dateStr)
        return d.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
    }

    return (
        <div className="space-y-6">
            {/* Header with Sync Button */}
            <div className="flex items-center justify-between">
                <div>
                    <p className="text-sm text-text-muted">
                        {stats?.last_sync ? `Last synced ${formatDate(stats.last_sync)}` : 'No sync yet'}
                    </p>
                </div>
                <SyncButton onSync={(msg, type) => { showToast(msg, type); setTimeout(fetchData, 3000) }} />
            </div>

            {/* Stat Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <StatCard label="Total Indicators" value={stats?.total_indicators || 0} icon={Database} color="accent" />
                <StatCard label="Active" value={stats?.active_indicators || 0} icon={Shield} color="success" />
                <StatCard label="Expired" value={stats?.expired_indicators || 0} icon={AlertTriangle} color="warning" />
                <StatCard label="MITRE Techniques" value={stats?.mitre_techniques_mapped || 0} icon={Shield} color="danger" />
            </div>

            {/* Two-column layout */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* IOC Type Distribution */}
                <div className="glass-card rounded-xl p-5 border border-border">
                    <h3 className="text-sm font-semibold text-text-primary mb-4">IOC Type Distribution</h3>
                    {pieData.length > 0 ? (
                        <div className="h-64">
                            <ResponsiveContainer width="100%" height="100%">
                                <PieChart>
                                    <Pie
                                        data={pieData}
                                        cx="50%"
                                        cy="50%"
                                        innerRadius={60}
                                        outerRadius={90}
                                        paddingAngle={4}
                                        dataKey="value"
                                        stroke="none"
                                    >
                                        {pieData.map((_, index) => (
                                            <Cell key={index} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                                        ))}
                                    </Pie>
                                    <Tooltip
                                        contentStyle={{
                                            backgroundColor: '#161b22',
                                            border: '1px solid #21262d',
                                            borderRadius: '8px',
                                            fontSize: '12px',
                                            color: '#e6edf3',
                                        }}
                                    />
                                </PieChart>
                            </ResponsiveContainer>
                            <div className="flex justify-center space-x-4 -mt-2">
                                {pieData.map((item, i) => (
                                    <div key={item.name} className="flex items-center text-xs text-text-muted">
                                        <div className="w-2.5 h-2.5 rounded-full mr-1.5" style={{ backgroundColor: PIE_COLORS[i] }} />
                                        {item.name}: {item.value.toLocaleString()}
                                    </div>
                                ))}
                            </div>
                        </div>
                    ) : (
                        <p className="text-text-muted text-sm text-center py-12">No data yet — run a sync first</p>
                    )}
                </div>

                {/* Recent Sync Activity */}
                <div className="glass-card rounded-xl p-5 border border-border">
                    <h3 className="text-sm font-semibold text-text-primary mb-4">Recent Sync Activity</h3>
                    <div className="space-y-3">
                        {syncLogs.length > 0 ? syncLogs.map((log) => (
                            <div key={log.id} className="flex items-start space-x-3 p-3 rounded-lg bg-bg-primary/50">
                                <div className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${log.status === 'success' ? 'bg-success' : log.status === 'failed' ? 'bg-danger' : 'bg-warning'
                                    }`} />
                                <div className="flex-1 min-w-0">
                                    <div className="flex items-center justify-between">
                                        <span className="text-sm font-medium text-text-primary truncate">
                                            {log.feed_name || `Feed #${log.feed_id}`}
                                        </span>
                                        <span className={`badge badge-${log.status}`}>{log.status}</span>
                                    </div>
                                    <div className="text-xs text-text-muted mt-0.5">
                                        {formatDate(log.completed_at || log.started_at)}
                                        {log.indicators_added > 0 && ` · +${log.indicators_added} indicators`}
                                    </div>
                                </div>
                            </div>
                        )) : (
                            <p className="text-text-muted text-sm text-center py-8">No sync history yet</p>
                        )}
                    </div>
                </div>
            </div>

            {/* Feed Status Table */}
            <div className="glass-card rounded-xl border border-border overflow-hidden">
                <div className="p-5 border-b border-border">
                    <h3 className="text-sm font-semibold text-text-primary">Feed Status</h3>
                </div>
                <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                        <thead>
                            <tr className="bg-bg-elevated">
                                <th className="text-left px-5 py-3 font-medium text-text-muted">Feed Name</th>
                                <th className="text-left px-5 py-3 font-medium text-text-muted">Last Sync</th>
                                <th className="text-left px-5 py-3 font-medium text-text-muted">Status</th>
                                <th className="text-left px-5 py-3 font-medium text-text-muted">Interval</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-border">
                            {feeds.map((feed) => (
                                <tr key={feed.id} className="hover:bg-bg-elevated transition-colors">
                                    <td className="px-5 py-3 font-medium text-text-primary">{feed.name}</td>
                                    <td className="px-5 py-3 text-text-muted text-xs">{formatDate(feed.last_sync)}</td>
                                    <td className="px-5 py-3">
                                        <span className={`badge ${feed.is_active ? 'badge-success' : 'badge-failed'}`}>
                                            {feed.is_active ? 'Active' : 'Inactive'}
                                        </span>
                                    </td>
                                    <td className="px-5 py-3 text-text-muted text-xs font-mono">{feed.polling_interval}m</td>
                                </tr>
                            ))}
                            {feeds.length === 0 && (
                                <tr>
                                    <td colSpan="4" className="px-5 py-8 text-center text-text-muted">
                                        No feeds configured — add one in Settings
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    )
}
