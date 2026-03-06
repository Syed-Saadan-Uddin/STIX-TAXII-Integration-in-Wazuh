import { useState, useEffect } from 'react'
import { useOutletContext } from 'react-router-dom'
import { Shield, X } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import { getMitre, getMitreTechnique } from '../api/client'
import MitreTechniqueCard from '../components/MitreTechniqueCard'

const BAR_COLORS = ['#58a6ff', '#3fb950', '#d29922', '#f85149', '#bc8cff', '#79c0ff', '#56d364', '#e3b341', '#ff7b72', '#d2a8ff']

export default function MitreView() {
    const { showToast } = useOutletContext()
    const [techniques, setTechniques] = useState([])
    const [loading, setLoading] = useState(true)
    const [tacticFilter, setTacticFilter] = useState('')
    const [drawerOpen, setDrawerOpen] = useState(false)
    const [selectedTechnique, setSelectedTechnique] = useState(null)
    const [drawerLoading, setDrawerLoading] = useState(false)

    useEffect(() => {
        fetchTechniques()
    }, [])

    const fetchTechniques = async () => {
        try {
            const data = await getMitre()
            setTechniques(data || [])
        } catch (err) {
            showToast(`Failed to load MITRE data: ${err.message}`, 'error')
        } finally {
            setLoading(false)
        }
    }

    const handleCardClick = async (technique) => {
        setDrawerOpen(true)
        setDrawerLoading(true)
        try {
            const detail = await getMitreTechnique(technique.technique_id)
            setSelectedTechnique(detail)
        } catch {
            setSelectedTechnique(technique)
        } finally {
            setDrawerLoading(false)
        }
    }

    // Get unique tactics for filter
    const tactics = [...new Set(techniques.map(t => t.tactic).filter(Boolean))]

    // Filter techniques
    const filtered = tacticFilter
        ? techniques.filter(t => t.tactic === tacticFilter)
        : techniques

    // Top 10 for bar chart
    const barData = techniques.slice(0, 10).map(t => ({
        name: t.technique_id,
        count: t.indicator_count,
        fullName: t.name,
    }))

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="w-8 h-8 border-2 border-accent border-t-transparent rounded-full animate-spin" />
            </div>
        )
    }

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                    <Shield className="w-5 h-5 text-accent" />
                    <span className="text-sm text-text-muted">
                        <span className="text-text-primary font-semibold">{techniques.length}</span> techniques mapped
                    </span>
                </div>

                <select value={tacticFilter} onChange={(e) => setTacticFilter(e.target.value)}
                    className="px-3 py-2 rounded-lg bg-bg-surface border border-border text-sm text-text-muted focus:outline-none focus:border-accent">
                    <option value="">All Tactics</option>
                    {tactics.map(t => (
                        <option key={t} value={t}>{t.replace(/-/g, ' ')}</option>
                    ))}
                </select>
            </div>

            {/* Technique Grid */}
            {filtered.length > 0 ? (
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                    {filtered.map(t => (
                        <MitreTechniqueCard key={t.technique_id} technique={t} onClick={handleCardClick} />
                    ))}
                </div>
            ) : (
                <div className="text-center py-16 text-text-muted">
                    <Shield className="w-12 h-12 mx-auto mb-3 opacity-30" />
                    <p>No techniques mapped yet — run a sync first</p>
                </div>
            )}

            {/* Bar Chart: Top 10 Techniques */}
            {barData.length > 0 && (
                <div className="glass-card rounded-xl p-5 border border-border">
                    <h3 className="text-sm font-semibold text-text-primary mb-4">Top 10 Techniques by Indicator Count</h3>
                    <div className="h-64">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={barData} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
                                <XAxis dataKey="name" tick={{ fill: '#7d8590', fontSize: 11 }} axisLine={{ stroke: '#21262d' }} />
                                <YAxis tick={{ fill: '#7d8590', fontSize: 11 }} axisLine={{ stroke: '#21262d' }} />
                                <Tooltip
                                    contentStyle={{
                                        backgroundColor: '#161b22',
                                        border: '1px solid #21262d',
                                        borderRadius: '8px',
                                        fontSize: '12px',
                                        color: '#e6edf3',
                                    }}
                                    formatter={(value, name, props) => [value, props.payload.fullName]}
                                />
                                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                                    {barData.map((_, index) => (
                                        <Cell key={index} fill={BAR_COLORS[index % BAR_COLORS.length]} />
                                    ))}
                                </Bar>
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            )}

            {/* Drawer */}
            {drawerOpen && (
                <div className="fixed inset-0 z-50 flex justify-end">
                    <div className="absolute inset-0 bg-black/50" onClick={() => setDrawerOpen(false)} />
                    <div className="relative w-full max-w-md bg-bg-surface border-l border-border overflow-y-auto">
                        <div className="p-5 border-b border-border flex items-center justify-between">
                            <h3 className="text-lg font-semibold text-text-primary">
                                {selectedTechnique?.technique_id || 'Loading...'}
                            </h3>
                            <button onClick={() => setDrawerOpen(false)} className="p-1 text-text-muted hover:text-text-primary">
                                <X className="w-5 h-5" />
                            </button>
                        </div>
                        {drawerLoading ? (
                            <div className="flex items-center justify-center h-32">
                                <div className="w-6 h-6 border-2 border-accent border-t-transparent rounded-full animate-spin" />
                            </div>
                        ) : selectedTechnique && (
                            <div className="p-5 space-y-4">
                                <div>
                                    <label className="text-xs text-text-muted">Name</label>
                                    <p className="text-sm text-text-primary mt-0.5">{selectedTechnique.name}</p>
                                </div>
                                <div>
                                    <label className="text-xs text-text-muted">Tactic</label>
                                    <p className="text-sm text-text-primary mt-0.5">{selectedTechnique.tactic?.replace(/-/g, ' ')}</p>
                                </div>
                                {selectedTechnique.description && (
                                    <div>
                                        <label className="text-xs text-text-muted">Description</label>
                                        <p className="text-xs text-text-muted mt-0.5">{selectedTechnique.description}</p>
                                    </div>
                                )}
                                {selectedTechnique.indicators?.length > 0 && (
                                    <div>
                                        <label className="text-xs text-text-muted mb-2 block">
                                            Linked Indicators ({selectedTechnique.indicator_count})
                                        </label>
                                        <div className="space-y-1.5 max-h-64 overflow-y-auto">
                                            {selectedTechnique.indicators.map((ind, i) => (
                                                <div key={i} className="flex items-center justify-between p-2 rounded-lg bg-bg-primary border border-border">
                                                    <span className="font-mono text-xs text-text-primary truncate">{ind.value}</span>
                                                    <span className={`badge badge-${ind.type}`}>{ind.type}</span>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                </div>
            )}
        </div>
    )
}
