import { useEffect, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import {
    AlertTriangle,
    Brain,
    CircleGauge,
    Crosshair,
    Loader2,
    Radar,
    RefreshCw,
    ShieldAlert,
    Sparkles,
    Siren,
    UploadCloud,
} from 'lucide-react'
import {
    Bar,
    BarChart,
    CartesianGrid,
    Cell,
    Line,
    LineChart,
    Pie,
    PieChart,
    ResponsiveContainer,
    Tooltip,
    XAxis,
    YAxis,
} from 'recharts'
import {
    getMLOverview,
    getMLPredictions,
    getMLStatus,
    getMLTopThreats,
    getWazuhMLIntegrationStatus,
    ingestThreatAlert,
    installWazuhMLIntegration,
    predictThreat,
    retrainThreatModel,
    seedThreatPredictionDemo,
} from '../api/client'
import StatCard from '../components/StatCard'

const PRIORITY_COLORS = {
    Low: '#58a6ff',
    Medium: '#d29922',
    High: '#fb923c',
    Critical: '#f85149',
}

const ACTION_COLORS = {
    Ignore: '#7d8590',
    Monitor: '#d29922',
    Investigate: '#fb923c',
    Isolate: '#f85149',
}

const TOOLTIP_STYLE = {
    backgroundColor: '#161b22',
    border: '1px solid #21262d',
    borderRadius: '10px',
    color: '#e6edf3',
    fontSize: '12px',
}

const SAMPLE_ALERT = `{
  "timestamp": "2026-04-24T14:30:00Z",
  "agent": { "id": "777", "name": "finance-ws-12" },
  "rule": {
    "id": "61608",
    "level": 14,
    "description": "Suspicious PowerShell execution detected",
    "mitre": {
      "id": ["T1059.001"],
      "tactic": ["execution"],
      "technique": ["PowerShell"]
    }
  },
  "data": {
    "srcip": "185.220.101.12",
    "user": "svc-finance",
    "process": "powershell.exe -enc SQBFAFgA"
  },
  "decoder": { "name": "windows_eventchannel" }
}`

function PriorityBadge({ value }) {
    const styles = {
        Critical: 'bg-red-500/15 text-red-300 border-red-500/30',
        High: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
        Medium: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30',
        Low: 'bg-blue-500/15 text-blue-300 border-blue-500/30',
    }

    return (
        <span className={`inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-semibold ${styles[value] || styles.Medium}`}>
            {value}
        </span>
    )
}

function ActionBadge({ value }) {
    const styles = {
        Isolate: 'bg-red-500/10 text-red-300 border-red-500/20',
        Investigate: 'bg-orange-500/10 text-orange-300 border-orange-500/20',
        Monitor: 'bg-yellow-500/10 text-yellow-300 border-yellow-500/20',
        Ignore: 'bg-slate-500/10 text-slate-300 border-slate-500/20',
    }

    return (
        <span className={`inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-medium ${styles[value] || styles.Monitor}`}>
            {value}
        </span>
    )
}

function ChartPanel({ title, subtitle, children }) {
    return (
        <div className="glass-card rounded-2xl border border-border p-5">
            <div className="mb-4">
                <h3 className="text-sm font-semibold text-text-primary">{title}</h3>
                {subtitle && <p className="mt-1 text-xs text-text-muted">{subtitle}</p>}
            </div>
            {children}
        </div>
    )
}

function EmptyChart({ message, height = 'h-72' }) {
    return (
        <div className={`flex ${height} items-center justify-center rounded-xl border border-dashed border-border text-sm text-text-muted`}>
            {message}
        </div>
    )
}

function formatDate(value) {
    if (!value) return '-'
    return new Date(value).toLocaleString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
    })
}

function buildDistributionChart(data) {
    return Object.entries(data || {})
        .map(([name, value]) => ({ name, value }))
        .filter((item) => item.value > 0)
        .sort((left, right) => right.value - left.value)
}

function truncateLabel(value, max = 18) {
    if (!value) return 'Unknown'
    return value.length > max ? `${value.slice(0, max - 1)}...` : value
}

export default function ThreatPrediction() {
    const { showToast } = useOutletContext()
    const [overview, setOverview] = useState(null)
    const [status, setStatus] = useState(null)
    const [predictions, setPredictions] = useState([])
    const [topThreats, setTopThreats] = useState([])
    const [wazuhDelivery, setWazuhDelivery] = useState(null)
    const [loading, setLoading] = useState(true)
    const [workbenchJson, setWorkbenchJson] = useState(SAMPLE_ALERT)
    const [preview, setPreview] = useState(null)
    const [actionLoading, setActionLoading] = useState('')

    const fetchData = async () => {
        try {
            const [overviewData, statusData, predictionsData, topThreatsData, wazuhDeliveryData] = await Promise.all([
                getMLOverview(),
                getMLStatus(),
                getMLPredictions({ limit: 12 }),
                getMLTopThreats({ hours: 24, limit: 6 }),
                getWazuhMLIntegrationStatus(),
            ])

            setOverview(overviewData)
            setStatus(statusData)
            setPredictions(predictionsData.items || [])
            setTopThreats(topThreatsData.items || [])
            setWazuhDelivery(wazuhDeliveryData)
        } catch (err) {
            showToast(`Failed to load threat predictions: ${err.message}`, 'error')
        } finally {
            setLoading(false)
        }
    }

    useEffect(() => {
        fetchData()
        const interval = setInterval(fetchData, 30000)
        return () => clearInterval(interval)
    }, [])

    const priorityChartData = buildDistributionChart(overview?.priority_distribution)
    const responseChartData = buildDistributionChart(overview?.recommended_actions)
    const tacticChartData = buildDistributionChart(overview?.tactic_distribution).slice(0, 6)
    const stageChartData = buildDistributionChart(overview?.next_stage_distribution).slice(0, 6)
    const riskTimelineData = (overview?.risk_timeline || []).map((item) => ({
        ...item,
        host_label: truncateLabel(item.host_name || item.source_ip || 'Unknown', 12),
    }))

    const handlePredict = async (persist) => {
        let parsed
        try {
            parsed = JSON.parse(workbenchJson)
        } catch {
            showToast('The JSON workbench payload is not valid.', 'error')
            return
        }

        setActionLoading(persist ? 'ingest' : 'predict')
        try {
            const result = persist ? await ingestThreatAlert(parsed) : await predictThreat(parsed, false)
            setPreview(result)
            showToast(
                persist ? 'Alert ingested and enriched with ML prediction.' : 'Prediction generated successfully.',
                'success'
            )
            if (persist) {
                fetchData()
            }
        } catch (err) {
            showToast(`Prediction failed: ${err.message}`, 'error')
        } finally {
            setActionLoading('')
        }
    }

    const handleSeedDemo = async () => {
        setActionLoading('seed')
        try {
            await seedThreatPredictionDemo(12)
            showToast('Demo Wazuh alerts generated and scored.', 'success')
            fetchData()
        } catch (err) {
            showToast(`Demo seed failed: ${err.message}`, 'error')
        } finally {
            setActionLoading('')
        }
    }

    const handleRetrain = async () => {
        setActionLoading('retrain')
        try {
            const result = await retrainThreatModel()
            setStatus((current) => ({ ...current, ...result.model }))
            showToast('Threat model retrained successfully.', 'success')
        } catch (err) {
            showToast(`Retraining failed: ${err.message}`, 'error')
        } finally {
            setActionLoading('')
        }
    }

    const handleInstallWazuhDelivery = async () => {
        setActionLoading('wazuh-install')
        try {
            const result = await installWazuhMLIntegration({})
            setWazuhDelivery(result)
            showToast('Wazuh ML delivery bridge installed. Restart the Wazuh manager to activate it.', 'success')
        } catch (err) {
            showToast(`Wazuh bridge install failed: ${err.message}`, 'error')
        } finally {
            setActionLoading('')
        }
    }

    if (loading) {
        return (
            <div className="flex h-64 items-center justify-center">
                <div className="h-8 w-8 animate-spin rounded-full border-2 border-accent border-t-transparent" />
            </div>
        )
    }

    return (
        <div className="space-y-6">
            <div className="relative overflow-hidden rounded-2xl border border-border bg-gradient-to-br from-red-500/10 via-bg-surface to-bg-primary p-6">
                <div className="absolute inset-y-0 right-0 w-80 bg-[radial-gradient(circle_at_center,rgba(248,81,73,0.18),transparent_60%)]" />
                <div className="relative flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
                    <div className="max-w-2xl">
                        <div className="mb-3 inline-flex items-center rounded-full border border-red-500/20 bg-red-500/10 px-3 py-1 text-xs font-medium text-red-300">
                            <Siren className="mr-2 h-3.5 w-3.5" />
                            AI-powered Wazuh incident materialization scoring
                        </div>
                        <h2 className="text-2xl font-bold text-text-primary">Threat Prediction Command Center</h2>
                        <p className="mt-2 text-sm text-text-muted">
                            Incoming Wazuh alerts are enriched with live threat intel, host criticality, MITRE context,
                            behavioral history, and model-driven materialization probability.
                        </p>
                    </div>

                    <div className="flex flex-wrap items-center gap-3">
                        <div className="rounded-xl border border-border bg-bg-primary/60 px-4 py-3 text-sm">
                            <div className="flex items-center text-text-primary">
                                <Brain className="mr-2 h-4 w-4 text-accent" />
                                {status?.model_name || 'Model unavailable'}
                            </div>
                            <div className="mt-1 text-xs text-text-muted">
                                {status?.trained_at ? `Trained ${formatDate(status.trained_at)}` : 'No training metadata yet'}
                            </div>
                        </div>

                        <button
                            onClick={handleSeedDemo}
                            disabled={actionLoading !== ''}
                            className="inline-flex items-center rounded-xl border border-border bg-bg-surface px-4 py-3 text-sm font-medium text-text-primary transition-colors hover:bg-bg-elevated disabled:opacity-50"
                        >
                            {actionLoading === 'seed' ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Sparkles className="mr-2 h-4 w-4 text-accent" />}
                            Seed Demo Alerts
                        </button>

                        <button
                            onClick={handleRetrain}
                            disabled={actionLoading !== ''}
                            className="inline-flex items-center rounded-xl bg-accent px-4 py-3 text-sm font-semibold text-white transition-colors hover:bg-accent/80 disabled:opacity-50"
                        >
                            {actionLoading === 'retrain' ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
                            Retrain Model
                        </button>
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
                <StatCard label="Predictions" value={overview?.total_predictions || 0} icon={Radar} color="accent" />
                <StatCard label="High/Critical" value={overview?.critical_or_high || 0} icon={ShieldAlert} color="danger" />
                <StatCard label="Avg Risk Score" value={overview?.average_risk_score || 0} icon={CircleGauge} color="warning" />
                <StatCard
                    label="Avg Materialization %"
                    value={`${overview?.average_materialization_probability || 0}%`}
                    icon={Crosshair}
                    color="success"
                />
            </div>

            <div className="grid grid-cols-1 gap-6 xl:grid-cols-[1.15fr_0.85fr]">
                <ChartPanel
                    title="Priority Distribution"
                    subtitle="Model-assigned threat priority across stored Wazuh alerts"
                >
                    {priorityChartData.length > 0 ? (
                        <div className="h-72">
                            <ResponsiveContainer width="100%" height="100%">
                                <BarChart data={priorityChartData}>
                                    <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
                                    <XAxis dataKey="name" stroke="#7d8590" fontSize={12} />
                                    <YAxis stroke="#7d8590" fontSize={12} />
                                    <Tooltip contentStyle={TOOLTIP_STYLE} />
                                    <Bar dataKey="value" radius={[10, 10, 0, 0]}>
                                        {priorityChartData.map((entry) => (
                                            <Cell key={entry.name} fill={PRIORITY_COLORS[entry.name] || '#58a6ff'} />
                                        ))}
                                    </Bar>
                                </BarChart>
                            </ResponsiveContainer>
                        </div>
                    ) : (
                        <EmptyChart message="No predictions yet. Seed demo alerts or ingest Wazuh alerts to populate this view." />
                    )}
                </ChartPanel>

                <ChartPanel
                    title="Recommended Response Mix"
                    subtitle="How the model is currently routing analyst actions"
                >
                    {responseChartData.length > 0 ? (
                        <div className="space-y-4">
                            <div className="h-64">
                                <ResponsiveContainer width="100%" height="100%">
                                    <PieChart>
                                        <Pie
                                            data={responseChartData}
                                            cx="50%"
                                            cy="50%"
                                            innerRadius={58}
                                            outerRadius={90}
                                            paddingAngle={4}
                                            dataKey="value"
                                            stroke="none"
                                        >
                                            {responseChartData.map((entry) => (
                                                <Cell key={entry.name} fill={ACTION_COLORS[entry.name] || '#58a6ff'} />
                                            ))}
                                        </Pie>
                                        <Tooltip contentStyle={TOOLTIP_STYLE} />
                                    </PieChart>
                                </ResponsiveContainer>
                            </div>
                            <div className="grid grid-cols-1 gap-3 text-xs text-text-muted sm:grid-cols-2">
                                {responseChartData.map((item) => (
                                    <div key={item.name} className="rounded-lg border border-border bg-bg-primary/50 px-3 py-2">
                                        <div className="flex items-center">
                                            <span
                                                className="mr-2 inline-block h-2.5 w-2.5 rounded-full"
                                                style={{ backgroundColor: ACTION_COLORS[item.name] || '#58a6ff' }}
                                            />
                                            {item.name}
                                        </div>
                                        <div className="mt-1 font-mono text-sm text-text-primary">{item.value.toLocaleString()}</div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    ) : (
                        <EmptyChart message="Recommended actions will appear as predictions are stored." />
                    )}
                </ChartPanel>
            </div>

            <div className="grid grid-cols-1 gap-6 xl:grid-cols-[1.2fr_0.8fr]">
                <ChartPanel
                    title="Risk and Materialization Trend"
                    subtitle="Recent prediction scores across the latest enriched alerts"
                >
                    {riskTimelineData.length > 0 ? (
                        <div className="space-y-3">
                            <div className="h-72">
                                <ResponsiveContainer width="100%" height="100%">
                                    <LineChart data={riskTimelineData}>
                                        <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
                                        <XAxis dataKey="time_label" stroke="#7d8590" fontSize={12} />
                                        <YAxis yAxisId="left" stroke="#7d8590" fontSize={12} domain={[0, 100]} />
                                        <YAxis yAxisId="right" orientation="right" stroke="#7d8590" fontSize={12} domain={[0, 100]} />
                                        <Tooltip
                                            contentStyle={TOOLTIP_STYLE}
                                            formatter={(value, name) => [
                                                `${Math.round(value)}${name === 'Materialization %' ? '%' : ''}`,
                                                name,
                                            ]}
                                            labelFormatter={(value, payload) => {
                                                const record = payload?.[0]?.payload
                                                if (!record) return value
                                                return `${formatDate(record.created_at)} - ${record.host_label}`
                                            }}
                                        />
                                        <Line
                                            yAxisId="left"
                                            type="monotone"
                                            dataKey="risk_score"
                                            name="Risk Score"
                                            stroke="#f85149"
                                            strokeWidth={2.5}
                                            dot={false}
                                        />
                                        <Line
                                            yAxisId="right"
                                            type="monotone"
                                            dataKey="materialization_probability"
                                            name="Materialization %"
                                            stroke="#58a6ff"
                                            strokeWidth={2.5}
                                            dot={false}
                                        />
                                    </LineChart>
                                </ResponsiveContainer>
                            </div>
                            <div className="flex flex-wrap gap-4 text-xs text-text-muted">
                                <div className="flex items-center">
                                    <span className="mr-2 inline-block h-2.5 w-2.5 rounded-full bg-red-500" />
                                    Risk Score
                                </div>
                                <div className="flex items-center">
                                    <span className="mr-2 inline-block h-2.5 w-2.5 rounded-full bg-blue-500" />
                                    Materialization %
                                </div>
                            </div>
                        </div>
                    ) : (
                        <EmptyChart message="Trend lines will appear once the model has stored prediction history." height="h-80" />
                    )}
                </ChartPanel>

                <ChartPanel
                    title="MITRE Tactic Spread"
                    subtitle="Which ATT&CK tactics are currently dominating predicted alerts"
                >
                    {tacticChartData.length > 0 ? (
                        <div className="h-80">
                            <ResponsiveContainer width="100%" height="100%">
                                <BarChart data={tacticChartData} layout="vertical" margin={{ left: 24 }}>
                                    <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
                                    <XAxis type="number" stroke="#7d8590" fontSize={12} />
                                    <YAxis
                                        type="category"
                                        dataKey="name"
                                        stroke="#7d8590"
                                        fontSize={12}
                                        width={112}
                                        tickFormatter={(value) => truncateLabel(value, 16)}
                                    />
                                    <Tooltip
                                        contentStyle={TOOLTIP_STYLE}
                                        labelFormatter={(value, payload) => payload?.[0]?.payload?.name || value}
                                    />
                                    <Bar dataKey="value" fill="#8b5cf6" radius={[0, 10, 10, 0]} />
                                </BarChart>
                            </ResponsiveContainer>
                        </div>
                    ) : (
                        <EmptyChart message="MITRE tactic data will appear when alerts include ATT&CK context." height="h-80" />
                    )}
                </ChartPanel>
            </div>

            <div className="grid grid-cols-1 gap-6 xl:grid-cols-[0.95fr_1.05fr]">
                <ChartPanel
                    title="Next Attack Stage Forecast"
                    subtitle="Model projection of the next likely ATT&CK stage if activity progresses"
                >
                    {stageChartData.length > 0 ? (
                        <div className="h-72">
                            <ResponsiveContainer width="100%" height="100%">
                                <BarChart data={stageChartData}>
                                    <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
                                    <XAxis
                                        dataKey="name"
                                        stroke="#7d8590"
                                        fontSize={12}
                                        tickFormatter={(value) => truncateLabel(value, 14)}
                                    />
                                    <YAxis stroke="#7d8590" fontSize={12} />
                                    <Tooltip
                                        contentStyle={TOOLTIP_STYLE}
                                        labelFormatter={(value, payload) => payload?.[0]?.payload?.name || value}
                                    />
                                    <Bar dataKey="value" fill="#3fb950" radius={[10, 10, 0, 0]} />
                                </BarChart>
                            </ResponsiveContainer>
                        </div>
                    ) : (
                        <EmptyChart message="Next-stage forecasts will appear as predictions accumulate." />
                    )}
                </ChartPanel>

                <div className="space-y-6">
                    <div className="glass-card rounded-2xl border border-border p-5">
                        <div className="mb-4 flex items-start justify-between gap-4">
                            <div>
                                <h3 className="text-sm font-semibold text-text-primary">Wazuh Delivery Bridge</h3>
                                <p className="mt-1 text-xs text-text-muted">
                                    Installs the custom Wazuh integration that forwards alerts directly into this ML pipeline.
                                </p>
                            </div>
                            <button
                                onClick={handleInstallWazuhDelivery}
                                disabled={!wazuhDelivery?.available || actionLoading !== ''}
                                className="inline-flex items-center rounded-xl bg-accent px-4 py-2 text-sm font-semibold text-white hover:bg-accent/80 disabled:opacity-50"
                            >
                                {actionLoading === 'wazuh-install' ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <UploadCloud className="mr-2 h-4 w-4" />}
                                Install Bridge
                            </button>
                        </div>

                        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                            <div className="rounded-xl border border-border bg-bg-primary/60 p-4">
                                <div className="text-xs uppercase tracking-wide text-text-muted">Mounted volumes</div>
                                <div className="mt-2 text-sm font-medium text-text-primary">
                                    {wazuhDelivery?.available ? 'Available' : 'Not detected'}
                                </div>
                                <div className="mt-1 text-xs text-text-muted">
                                    {wazuhDelivery?.available
                                        ? `${wazuhDelivery?.etc_dir} + ${wazuhDelivery?.integrations_dir}`
                                        : 'Run the app with the shared Wazuh etc and integrations volumes mounted.'}
                                </div>
                            </div>
                            <div className="rounded-xl border border-border bg-bg-primary/60 p-4">
                                <div className="text-xs uppercase tracking-wide text-text-muted">Bridge status</div>
                                <div className="mt-2 text-sm font-medium text-text-primary">
                                    {wazuhDelivery?.script_installed && wazuhDelivery?.config_installed ? 'Installed' : 'Not installed'}
                                </div>
                                <div className="mt-1 text-xs text-text-muted">
                                    {wazuhDelivery?.hook_url || 'Will use the internal Wazuh-TI service endpoint by default.'}
                                </div>
                            </div>
                        </div>

                        <div className="mt-3 rounded-xl border border-border bg-bg-primary/60 p-4 text-xs text-text-muted">
                            {wazuhDelivery?.script_installed && wazuhDelivery?.config_installed
                                ? 'Restart the Wazuh manager so the new custom integration becomes active.'
                                : 'Once installed, Wazuh alerts will be forwarded to POST /api/v1/ml/alerts/ingest automatically.'}
                        </div>
                    </div>

                    <div className="glass-card rounded-2xl border border-border p-5">
                        <div className="mb-4">
                            <h3 className="text-sm font-semibold text-text-primary">Top Active Threats</h3>
                            <p className="mt-1 text-xs text-text-muted">Most active entities in the last 24 hours</p>
                        </div>
                        <div className="space-y-3">
                            {topThreats.length > 0 ? (
                                topThreats.map((threat) => (
                                    <div key={threat.entity} className="rounded-xl border border-border bg-bg-primary/60 p-4">
                                        <div className="flex items-start justify-between gap-3">
                                            <div className="min-w-0">
                                                <div className="truncate font-mono text-sm text-text-primary">{threat.entity}</div>
                                                <div className="mt-1 text-xs text-text-muted">
                                                    {threat.host_name || 'Unknown host'}
                                                    {threat.mitre_tactic ? ` - ${threat.mitre_tactic}` : ''}
                                                </div>
                                            </div>
                                            <PriorityBadge value={threat.priority} />
                                        </div>
                                        <div className="mt-3 flex items-center justify-between text-xs text-text-muted">
                                            <span>{threat.alert_count} alerts</span>
                                            <span>Risk {threat.max_risk_score}</span>
                                            <span>{Math.round(threat.max_probability)}%</span>
                                        </div>
                                        <div className="mt-3">
                                            <ActionBadge value={threat.recommended_action} />
                                        </div>
                                    </div>
                                ))
                            ) : (
                                <div className="rounded-xl border border-dashed border-border p-6 text-center text-sm text-text-muted">
                                    No active threats ranked yet.
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-1 gap-6 xl:grid-cols-[1.25fr_0.95fr]">
                <div className="glass-card overflow-hidden rounded-2xl border border-border">
                    <div className="border-b border-border px-5 py-4">
                        <h3 className="text-sm font-semibold text-text-primary">Recent Predicted Alerts</h3>
                        <p className="mt-1 text-xs text-text-muted">Latest Wazuh alerts enriched by the threat prediction service</p>
                    </div>

                    <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                            <thead>
                                <tr className="bg-bg-elevated">
                                    <th className="px-5 py-3 text-left font-medium text-text-muted">Time</th>
                                    <th className="px-5 py-3 text-left font-medium text-text-muted">Host</th>
                                    <th className="px-5 py-3 text-left font-medium text-text-muted">Rule</th>
                                    <th className="px-5 py-3 text-left font-medium text-text-muted">Priority</th>
                                    <th className="px-5 py-3 text-left font-medium text-text-muted">Risk</th>
                                    <th className="px-5 py-3 text-left font-medium text-text-muted">Probability</th>
                                    <th className="px-5 py-3 text-left font-medium text-text-muted">Response</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-border">
                                {predictions.length > 0 ? (
                                    predictions.map((item) => (
                                        <tr key={item.prediction_id} className="hover:bg-bg-elevated/60">
                                            <td className="px-5 py-3 text-xs text-text-muted">{formatDate(item.alert?.alert_timestamp)}</td>
                                            <td className="px-5 py-3">
                                                <div className="font-medium text-text-primary">{item.alert?.host_name || 'Unknown host'}</div>
                                                <div className="text-xs text-text-muted">{item.alert?.source_ip || 'No source IP'}</div>
                                            </td>
                                            <td className="px-5 py-3">
                                                <div className="text-text-primary">{item.alert?.rule_id || 'N/A'}</div>
                                                <div className="max-w-xs truncate text-xs text-text-muted">{item.alert?.rule_description || 'No description'}</div>
                                            </td>
                                            <td className="px-5 py-3">
                                                <PriorityBadge value={item.threat_priority} />
                                            </td>
                                            <td className="px-5 py-3 font-mono text-text-primary">{item.risk_score}</td>
                                            <td className="px-5 py-3 font-mono text-text-primary">{Math.round(item.materialization_probability)}%</td>
                                            <td className="px-5 py-3">
                                                <ActionBadge value={item.recommended_action} />
                                            </td>
                                        </tr>
                                    ))
                                ) : (
                                    <tr>
                                        <td colSpan="7" className="px-5 py-8 text-center text-text-muted">
                                            No alerts have been enriched yet.
                                        </td>
                                    </tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>

                <div className="space-y-6">
                    <div className="glass-card rounded-2xl border border-border p-5">
                        <div className="mb-4 flex items-center">
                            <UploadCloud className="mr-2 h-4 w-4 text-accent" />
                            <div>
                                <h3 className="text-sm font-semibold text-text-primary">Prediction Workbench</h3>
                                <p className="mt-1 text-xs text-text-muted">Paste raw Wazuh alert JSON to preview or persist ML enrichment</p>
                            </div>
                        </div>

                        <textarea
                            value={workbenchJson}
                            onChange={(event) => setWorkbenchJson(event.target.value)}
                            spellCheck={false}
                            className="h-72 w-full rounded-xl border border-border bg-bg-primary/70 p-4 font-mono text-xs leading-5 text-text-primary focus:border-accent/50 focus:outline-none"
                        />

                        <div className="mt-4 flex flex-wrap gap-3">
                            <button
                                onClick={() => handlePredict(false)}
                                disabled={actionLoading !== ''}
                                className="inline-flex items-center rounded-xl border border-border bg-bg-surface px-4 py-2.5 text-sm font-medium text-text-primary hover:bg-bg-elevated disabled:opacity-50"
                            >
                                {actionLoading === 'predict' ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Brain className="mr-2 h-4 w-4 text-accent" />}
                                Predict Only
                            </button>
                            <button
                                onClick={() => handlePredict(true)}
                                disabled={actionLoading !== ''}
                                className="inline-flex items-center rounded-xl bg-accent px-4 py-2.5 text-sm font-semibold text-white hover:bg-accent/80 disabled:opacity-50"
                            >
                                {actionLoading === 'ingest' ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <UploadCloud className="mr-2 h-4 w-4" />}
                                Ingest and Store
                            </button>
                        </div>
                    </div>

                    <div className="glass-card rounded-2xl border border-border p-5">
                        <div className="mb-4 flex items-center">
                            <AlertTriangle className="mr-2 h-4 w-4 text-danger" />
                            <div>
                                <h3 className="text-sm font-semibold text-text-primary">Latest Prediction Preview</h3>
                                <p className="mt-1 text-xs text-text-muted">Real-time output from the threat prediction engine</p>
                            </div>
                        </div>

                        {preview ? (
                            <div className="space-y-4">
                                <div className="flex items-center justify-between">
                                    <PriorityBadge value={preview.threat_priority} />
                                    <ActionBadge value={preview.recommended_action} />
                                </div>

                                <div className="grid grid-cols-2 gap-3">
                                    <div className="rounded-xl border border-border bg-bg-primary/60 p-3">
                                        <div className="text-xs text-text-muted">Risk Score</div>
                                        <div className="mt-2 font-mono text-2xl font-bold text-text-primary">{preview.risk_score}</div>
                                    </div>
                                    <div className="rounded-xl border border-border bg-bg-primary/60 p-3">
                                        <div className="text-xs text-text-muted">Materialization</div>
                                        <div className="mt-2 font-mono text-2xl font-bold text-text-primary">
                                            {Math.round(preview.materialization_probability)}%
                                        </div>
                                    </div>
                                </div>

                                <div className="rounded-xl border border-border bg-bg-primary/60 p-4">
                                    <div className="text-xs uppercase tracking-wide text-text-muted">Predicted next stage</div>
                                    <div className="mt-2 text-sm font-semibold text-text-primary">{preview.predicted_next_attack_stage}</div>
                                </div>

                                <div>
                                    <div className="mb-2 text-xs uppercase tracking-wide text-text-muted">Top factors</div>
                                    <div className="space-y-2">
                                        {(preview.top_factors || []).map((factor) => (
                                            <div key={factor.name} className="rounded-xl border border-border bg-bg-primary/60 p-3">
                                                <div className="flex items-center justify-between">
                                                    <span className="text-sm font-medium text-text-primary">{factor.name}</span>
                                                    <span className="text-xs font-mono text-text-muted">{Math.round(factor.weight * 100)}%</span>
                                                </div>
                                                <div className="mt-1 text-xs text-text-muted">{factor.detail}</div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            </div>
                        ) : (
                            <div className="rounded-xl border border-dashed border-border p-8 text-center text-sm text-text-muted">
                                Generate a prediction from the workbench to inspect the output here.
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    )
}
