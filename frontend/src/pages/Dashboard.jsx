import { useEffect, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { Activity, AlertTriangle, Database, Shield, Signal, Waves } from 'lucide-react'
import {
    Bar,
    BarChart,
    CartesianGrid,
    Cell,
    Pie,
    PieChart,
    ResponsiveContainer,
    Tooltip,
    XAxis,
    YAxis,
} from 'recharts'
import { getFeeds, getStats, getSyncLogs } from '../api/client'
import StatCard from '../components/StatCard'
import SyncButton from '../components/SyncButton'

const PIE_COLORS = ['#58a6ff', '#3fb950', '#d29922', '#f85149', '#bc8cff', '#7ee787']
const STATUS_COLORS = {
    Active: '#3fb950',
    Inactive: '#f85149',
    High: '#f85149',
    Medium: '#d29922',
    Low: '#58a6ff',
    Unknown: '#7d8590',
}
const TOOLTIP_STYLE = {
    backgroundColor: '#161b22',
    border: '1px solid #21262d',
    borderRadius: '10px',
    fontSize: '12px',
    color: '#e6edf3',
}

function ChartPanel({ title, subtitle, children }) {
    return (
        <div className="glass-card rounded-xl border border-border p-5">
            <div className="mb-4">
                <h3 className="text-sm font-semibold text-text-primary">{title}</h3>
                {subtitle && <p className="mt-1 text-xs text-text-muted">{subtitle}</p>}
            </div>
            {children}
        </div>
    )
}

function EmptyChart({ message }) {
    return (
        <div className="flex h-64 items-center justify-center rounded-xl border border-dashed border-border text-sm text-text-muted">
            {message}
        </div>
    )
}

function formatDate(dateStr) {
    if (!dateStr) return '-'
    const date = new Date(dateStr)
    return date.toLocaleString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
    })
}

function truncateLabel(value, max = 14) {
    if (!value) return 'Unknown'
    return value.length > max ? `${value.slice(0, max - 1)}...` : value
}

function buildDistributionChart(data) {
    return Object.entries(data || {})
        .map(([name, value]) => ({ name, value }))
        .filter((item) => item.value > 0)
}

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
                getSyncLogs({ page: 1, per_page: 12 }),
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
        const interval = setInterval(fetchData, 30000)
        return () => clearInterval(interval)
    }, [])

    if (loading) {
        return (
            <div className="flex h-64 items-center justify-center">
                <div className="h-8 w-8 animate-spin rounded-full border-2 border-accent border-t-transparent" />
            </div>
        )
    }

    const iocTypeData = buildDistributionChart(
        Object.fromEntries(
            Object.entries(stats?.ioc_type_distribution || {}).map(([name, value]) => [name.toUpperCase(), value])
        )
    )
    const indicatorStatusData = buildDistributionChart(stats?.indicator_status_distribution)
    const feedStatusData =
        buildDistributionChart(stats?.feed_status_distribution).length > 0
            ? buildDistributionChart(stats?.feed_status_distribution)
            : [
                  { name: 'Active', value: feeds.filter((feed) => feed.is_active).length },
                  { name: 'Inactive', value: feeds.filter((feed) => !feed.is_active).length },
              ].filter((item) => item.value > 0)
    const confidenceData = buildDistributionChart(stats?.confidence_distribution)
    const topFeedsData = (stats?.top_feeds_by_indicators || []).map((item) => ({
        name: truncateLabel(item.name || 'Unnamed'),
        fullName: item.name || 'Unnamed',
        indicator_count: item.indicator_count || 0,
    }))
    const syncVolumeData = [...syncLogs]
        .slice(0, 8)
        .reverse()
        .map((log) => ({
            name: truncateLabel(log.feed_name || `Run ${log.id}`, 12),
            added: log.indicators_added || 0,
            updated: log.indicators_updated || 0,
            status: log.status,
        }))

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <p className="text-sm text-text-muted">
                        {stats?.last_sync ? `Last synced ${formatDate(stats.last_sync)}` : 'No sync yet'}
                    </p>
                </div>
                <SyncButton
                    onSync={(message, type) => {
                        showToast(message, type)
                        setTimeout(fetchData, 3000)
                    }}
                />
            </div>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <StatCard label="Total Indicators" value={stats?.total_indicators || 0} icon={Database} color="accent" />
                <StatCard label="Active" value={stats?.active_indicators || 0} icon={Shield} color="success" />
                <StatCard label="Expired" value={stats?.expired_indicators || 0} icon={AlertTriangle} color="warning" />
                <StatCard label="MITRE Techniques" value={stats?.mitre_techniques_mapped || 0} icon={Signal} color="danger" />
            </div>

            <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
                <ChartPanel title="IOC Type Distribution" subtitle="How the threat intel catalog is split across indicator types">
                    {iocTypeData.length > 0 ? (
                        <div className="h-72">
                            <ResponsiveContainer width="100%" height="100%">
                                <PieChart>
                                    <Pie
                                        data={iocTypeData}
                                        cx="50%"
                                        cy="50%"
                                        innerRadius={62}
                                        outerRadius={92}
                                        paddingAngle={3}
                                        dataKey="value"
                                        stroke="none"
                                    >
                                        {iocTypeData.map((entry, index) => (
                                            <Cell key={entry.name} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                                        ))}
                                    </Pie>
                                    <Tooltip contentStyle={TOOLTIP_STYLE} />
                                </PieChart>
                            </ResponsiveContainer>
                            <div className="mt-2 flex flex-wrap justify-center gap-3 text-xs text-text-muted">
                                {iocTypeData.map((item, index) => (
                                    <div key={item.name} className="flex items-center">
                                        <span
                                            className="mr-1.5 inline-block h-2.5 w-2.5 rounded-full"
                                            style={{ backgroundColor: PIE_COLORS[index % PIE_COLORS.length] }}
                                        />
                                        {item.name}: {item.value.toLocaleString()}
                                    </div>
                                ))}
                            </div>
                        </div>
                    ) : (
                        <EmptyChart message="No indicator data yet - run a sync first." />
                    )}
                </ChartPanel>

                <ChartPanel title="Confidence Mix" subtitle="Indicator confidence bands across the current catalog">
                    {confidenceData.length > 0 ? (
                        <div className="h-72">
                            <ResponsiveContainer width="100%" height="100%">
                                <BarChart data={confidenceData}>
                                    <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
                                    <XAxis dataKey="name" stroke="#7d8590" fontSize={12} />
                                    <YAxis stroke="#7d8590" fontSize={12} />
                                    <Tooltip contentStyle={TOOLTIP_STYLE} />
                                    <Bar dataKey="value" radius={[10, 10, 0, 0]}>
                                        {confidenceData.map((entry) => (
                                            <Cell key={entry.name} fill={STATUS_COLORS[entry.name] || '#58a6ff'} />
                                        ))}
                                    </Bar>
                                </BarChart>
                            </ResponsiveContainer>
                        </div>
                    ) : (
                        <EmptyChart message="No confidence data available yet." />
                    )}
                </ChartPanel>

                <ChartPanel title="Indicator Lifecycle" subtitle="Live view of active versus expired indicators">
                    {indicatorStatusData.length > 0 ? (
                        <div className="h-72">
                            <ResponsiveContainer width="100%" height="100%">
                                <PieChart>
                                    <Pie
                                        data={indicatorStatusData}
                                        cx="50%"
                                        cy="50%"
                                        innerRadius={60}
                                        outerRadius={90}
                                        paddingAngle={4}
                                        dataKey="value"
                                        stroke="none"
                                    >
                                        {indicatorStatusData.map((entry) => (
                                            <Cell key={entry.name} fill={STATUS_COLORS[entry.name] || '#58a6ff'} />
                                        ))}
                                    </Pie>
                                    <Tooltip contentStyle={TOOLTIP_STYLE} />
                                </PieChart>
                            </ResponsiveContainer>
                            <div className="mt-2 grid grid-cols-2 gap-3 text-xs text-text-muted">
                                {indicatorStatusData.map((item) => (
                                    <div key={item.name} className="rounded-lg border border-border bg-bg-primary/50 px-3 py-2">
                                        <div className="flex items-center">
                                            <span
                                                className="mr-2 inline-block h-2.5 w-2.5 rounded-full"
                                                style={{ backgroundColor: STATUS_COLORS[item.name] || '#58a6ff' }}
                                            />
                                            {item.name}
                                        </div>
                                        <div className="mt-1 font-mono text-sm text-text-primary">{item.value.toLocaleString()}</div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    ) : (
                        <EmptyChart message="No lifecycle data available yet." />
                    )}
                </ChartPanel>
            </div>

            <div className="grid grid-cols-1 gap-6 xl:grid-cols-[1.05fr_1.15fr]">
                <ChartPanel title="Top Feeds by Indicator Volume" subtitle="Which feeds are contributing the most indicators right now">
                    {topFeedsData.length > 0 ? (
                        <div className="h-80">
                            <ResponsiveContainer width="100%" height="100%">
                                <BarChart data={topFeedsData} layout="vertical" margin={{ left: 24 }}>
                                    <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
                                    <XAxis type="number" stroke="#7d8590" fontSize={12} />
                                    <YAxis
                                        type="category"
                                        dataKey="name"
                                        stroke="#7d8590"
                                        fontSize={12}
                                        width={96}
                                    />
                                    <Tooltip
                                        contentStyle={TOOLTIP_STYLE}
                                        formatter={(value) => [value.toLocaleString(), 'Indicators']}
                                        labelFormatter={(value, payload) => payload?.[0]?.payload?.fullName || value}
                                    />
                                    <Bar dataKey="indicator_count" fill="#58a6ff" radius={[0, 10, 10, 0]} />
                                </BarChart>
                            </ResponsiveContainer>
                        </div>
                    ) : (
                        <EmptyChart message="Feed contribution data will appear after indicators are synced." />
                    )}
                </ChartPanel>

                <ChartPanel title="Recent Sync Throughput" subtitle="Indicators added and updated across the latest synchronization runs">
                    {syncVolumeData.length > 0 ? (
                        <div className="h-80">
                            <ResponsiveContainer width="100%" height="100%">
                                <BarChart data={syncVolumeData}>
                                    <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
                                    <XAxis dataKey="name" stroke="#7d8590" fontSize={12} />
                                    <YAxis stroke="#7d8590" fontSize={12} />
                                    <Tooltip contentStyle={TOOLTIP_STYLE} />
                                    <Bar dataKey="added" stackId="sync" fill="#3fb950" radius={[8, 8, 0, 0]} />
                                    <Bar dataKey="updated" stackId="sync" fill="#58a6ff" radius={[8, 8, 0, 0]} />
                                </BarChart>
                            </ResponsiveContainer>
                            <div className="mt-3 flex flex-wrap gap-4 text-xs text-text-muted">
                                <div className="flex items-center">
                                    <span className="mr-2 inline-block h-2.5 w-2.5 rounded-full bg-green-500" />
                                    Added
                                </div>
                                <div className="flex items-center">
                                    <span className="mr-2 inline-block h-2.5 w-2.5 rounded-full bg-blue-500" />
                                    Updated
                                </div>
                            </div>
                        </div>
                    ) : (
                        <EmptyChart message="No completed sync runs available yet." />
                    )}
                </ChartPanel>
            </div>

            <div className="grid grid-cols-1 gap-6 xl:grid-cols-[0.95fr_1.05fr]">
                <ChartPanel title="Feed Health" subtitle="Active versus inactive feed configurations">
                    {feedStatusData.length > 0 ? (
                        <div className="h-72">
                            <ResponsiveContainer width="100%" height="100%">
                                <PieChart>
                                    <Pie
                                        data={feedStatusData}
                                        cx="50%"
                                        cy="50%"
                                        innerRadius={62}
                                        outerRadius={92}
                                        paddingAngle={4}
                                        dataKey="value"
                                        stroke="none"
                                    >
                                        {feedStatusData.map((entry) => (
                                            <Cell key={entry.name} fill={STATUS_COLORS[entry.name] || '#58a6ff'} />
                                        ))}
                                    </Pie>
                                    <Tooltip contentStyle={TOOLTIP_STYLE} />
                                </PieChart>
                            </ResponsiveContainer>
                            <div className="mt-2 grid grid-cols-2 gap-3 text-xs text-text-muted">
                                {feedStatusData.map((item) => (
                                    <div key={item.name} className="rounded-lg border border-border bg-bg-primary/50 px-3 py-2">
                                        <div className="flex items-center">
                                            <span
                                                className="mr-2 inline-block h-2.5 w-2.5 rounded-full"
                                                style={{ backgroundColor: STATUS_COLORS[item.name] || '#58a6ff' }}
                                            />
                                            {item.name}
                                        </div>
                                        <div className="mt-1 font-mono text-sm text-text-primary">{item.value.toLocaleString()}</div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    ) : (
                        <EmptyChart message="No feed status data available yet." />
                    )}
                </ChartPanel>

                <ChartPanel title="Recent Sync Activity" subtitle="Latest feed synchronization outcomes and timestamps">
                    <div className="space-y-3">
                        {syncLogs.length > 0 ? (
                            syncLogs.map((log) => (
                                <div key={log.id} className="flex items-start space-x-3 rounded-lg bg-bg-primary/50 p-3">
                                    <div
                                        className={`mt-1.5 h-2 w-2 flex-shrink-0 rounded-full ${
                                            log.status === 'success'
                                                ? 'bg-success'
                                                : log.status === 'failed'
                                                  ? 'bg-danger'
                                                  : log.status === 'partial'
                                                    ? 'bg-warning'
                                                    : 'bg-accent'
                                        }`}
                                    />
                                    <div className="min-w-0 flex-1">
                                        <div className="flex items-center justify-between gap-3">
                                            <span className="truncate text-sm font-medium text-text-primary">
                                                {log.feed_name || `Feed #${log.feed_id}`}
                                            </span>
                                            <span className={`badge badge-${log.status}`}>{log.status}</span>
                                        </div>
                                        <div className="mt-0.5 text-xs text-text-muted">
                                            {formatDate(log.completed_at || log.started_at)}
                                            {(log.indicators_added > 0 || log.indicators_updated > 0) &&
                                                ` - +${log.indicators_added || 0} added / ${log.indicators_updated || 0} updated`}
                                        </div>
                                    </div>
                                </div>
                            ))
                        ) : (
                            <p className="py-8 text-center text-sm text-text-muted">No sync history yet.</p>
                        )}
                    </div>
                </ChartPanel>
            </div>

            <div className="glass-card overflow-hidden rounded-xl border border-border">
                <div className="border-b border-border p-5">
                    <h3 className="text-sm font-semibold text-text-primary">Feed Status</h3>
                </div>
                <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                        <thead>
                            <tr className="bg-bg-elevated">
                                <th className="px-5 py-3 text-left font-medium text-text-muted">Feed Name</th>
                                <th className="px-5 py-3 text-left font-medium text-text-muted">Last Sync</th>
                                <th className="px-5 py-3 text-left font-medium text-text-muted">Status</th>
                                <th className="px-5 py-3 text-left font-medium text-text-muted">Interval</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-border">
                            {feeds.map((feed) => (
                                <tr key={feed.id} className="transition-colors hover:bg-bg-elevated">
                                    <td className="px-5 py-3 font-medium text-text-primary">{feed.name}</td>
                                    <td className="px-5 py-3 text-xs text-text-muted">{formatDate(feed.last_sync)}</td>
                                    <td className="px-5 py-3">
                                        <span className={`badge ${feed.is_active ? 'badge-success' : 'badge-failed'}`}>
                                            {feed.is_active ? 'Active' : 'Inactive'}
                                        </span>
                                    </td>
                                    <td className="px-5 py-3 font-mono text-xs text-text-muted">{feed.polling_interval}m</td>
                                </tr>
                            ))}
                            {feeds.length === 0 && (
                                <tr>
                                    <td colSpan="4" className="px-5 py-8 text-center text-text-muted">
                                        No feeds configured - add one in Settings.
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
