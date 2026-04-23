import { useState, useEffect, useRef } from 'react'
import { useOutletContext } from 'react-router-dom'
import {
    Bot, Send, Sparkles, Shield, AlertTriangle, Loader2,
    Zap, Brain, Search, ChevronDown, X, RotateCcw
} from 'lucide-react'
import {
    getAIStatus, chatWithAnalyst, enrichIndicator,
    getIndicators, searchIndicators
} from '../api/client'

// Markdown-like renderer for AI responses
function AIMarkdown({ text }) {
    if (!text) return null

    const lines = text.split('\n')
    return (
        <div className="ai-markdown space-y-1.5 text-sm leading-relaxed">
            {lines.map((line, i) => {
                // Bold headers
                if (line.startsWith('**') && line.endsWith('**')) {
                    return <p key={i} className="font-bold text-text-primary mt-3 mb-1">{line.replace(/\*\*/g, '')}</p>
                }
                // Headers with markdown
                if (line.startsWith('## ')) {
                    return <h3 key={i} className="text-base font-bold text-accent mt-4 mb-1">{line.slice(3)}</h3>
                }
                if (line.startsWith('# ')) {
                    return <h2 key={i} className="text-lg font-bold text-accent mt-4 mb-2">{line.slice(2)}</h2>
                }
                // Bullet points
                if (line.startsWith('- ') || line.startsWith('* ')) {
                    return (
                        <div key={i} className="flex items-start ml-2">
                            <span className="text-accent mr-2 mt-0.5 text-xs">▸</span>
                            <span className="text-text-secondary" dangerouslySetInnerHTML={{
                                __html: line.slice(2).replace(/\*\*(.*?)\*\*/g, '<strong class="text-text-primary">$1</strong>')
                            }} />
                        </div>
                    )
                }
                // Numbered list
                if (/^\d+\.\s/.test(line)) {
                    const num = line.match(/^(\d+)\./)[1]
                    const content = line.replace(/^\d+\.\s/, '')
                    return (
                        <div key={i} className="flex items-start ml-2">
                            <span className="text-accent mr-2 font-mono text-xs mt-0.5 w-4">{num}.</span>
                            <span className="text-text-secondary" dangerouslySetInnerHTML={{
                                __html: content.replace(/\*\*(.*?)\*\*/g, '<strong class="text-text-primary">$1</strong>')
                            }} />
                        </div>
                    )
                }
                // Empty line
                if (line.trim() === '') {
                    return <div key={i} className="h-1" />
                }
                // Normal text with inline bold
                return (
                    <p key={i} className="text-text-secondary" dangerouslySetInnerHTML={{
                        __html: line
                            .replace(/\*\*(.*?)\*\*/g, '<strong class="text-text-primary">$1</strong>')
                            .replace(/`(.*?)`/g, '<code class="px-1.5 py-0.5 rounded bg-bg-elevated text-accent font-mono text-xs">$1</code>')
                    }} />
                )
            })}
        </div>
    )
}

// Risk badge component
function RiskBadge({ level }) {
    const config = {
        CRITICAL: { bg: 'bg-red-500/20', text: 'text-red-400', border: 'border-red-500/30', glow: 'shadow-red-500/10' },
        HIGH: { bg: 'bg-orange-500/20', text: 'text-orange-400', border: 'border-orange-500/30', glow: 'shadow-orange-500/10' },
        MEDIUM: { bg: 'bg-yellow-500/20', text: 'text-yellow-400', border: 'border-yellow-500/30', glow: 'shadow-yellow-500/10' },
        LOW: { bg: 'bg-blue-500/20', text: 'text-blue-400', border: 'border-blue-500/30', glow: 'shadow-blue-500/10' },
        INFORMATIONAL: { bg: 'bg-gray-500/20', text: 'text-gray-400', border: 'border-gray-500/30', glow: '' },
    }
    const c = config[level] || config.MEDIUM
    return (
        <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-bold border ${c.bg} ${c.text} ${c.border} shadow-lg ${c.glow}`}>
            <AlertTriangle className="w-3 h-3 mr-1.5" />
            {level}
        </span>
    )
}

// Quick action buttons
const QUICK_ACTIONS = [
    { label: 'Threat Summary', prompt: 'Give me a brief summary of the current threat landscape based on all indicators in the database.', icon: Shield },
    { label: 'Top Risks', prompt: 'What are the top 5 most dangerous indicators in our database and why?', icon: AlertTriangle },
    { label: 'MITRE Analysis', prompt: 'Analyze the MITRE ATT&CK techniques mapped in our database. What attack patterns do they suggest?', icon: Brain },
    { label: 'Recommendations', prompt: 'Based on the current threat intelligence data, what are your top security recommendations for our SOC team?', icon: Zap },
]

export default function AIAnalyst() {
    const { showToast } = useOutletContext()
    const [aiStatus, setAiStatus] = useState(null)
    const [messages, setMessages] = useState([])
    const [input, setInput] = useState('')
    const [loading, setLoading] = useState(false)
    const [statusLoading, setStatusLoading] = useState(true)

    // Enrichment panel
    const [enrichQuery, setEnrichQuery] = useState('')
    const [enrichResults, setEnrichResults] = useState([])
    const [enriching, setEnriching] = useState(null) // indicator id being enriched
    const [enrichReport, setEnrichReport] = useState(null)
    const [showEnrichPanel, setShowEnrichPanel] = useState(false)

    const messagesEndRef = useRef(null)
    const inputRef = useRef(null)

    // Auto-scroll to bottom
    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }, [messages])

    // Check AI status on mount
    useEffect(() => {
        const checkStatus = async () => {
            try {
                const status = await getAIStatus()
                setAiStatus(status)
            } catch {
                setAiStatus({ available: false })
            } finally {
                setStatusLoading(false)
            }
        }
        checkStatus()
    }, [])

    // Send chat message
    const handleSend = async (messageText = null) => {
        const text = messageText || input.trim()
        if (!text || loading) return

        const userMsg = { role: 'user', content: text }
        setMessages(prev => [...prev, userMsg])
        setInput('')
        setLoading(true)

        try {
            const history = messages.map(m => ({
                role: m.role,
                content: m.content,
            }))

            const result = await chatWithAnalyst(text, history)
            setMessages(prev => [...prev, {
                role: 'assistant',
                content: result.response,
                timestamp: result.timestamp,
            }])
        } catch (err) {
            setMessages(prev => [...prev, {
                role: 'assistant',
                content: `⚠️ Error: ${err.message}`,
                error: true,
            }])
            showToast(`AI request failed: ${err.message}`, 'error')
        } finally {
            setLoading(false)
            inputRef.current?.focus()
        }
    }

    // Search indicators for enrichment
    const handleEnrichSearch = async () => {
        if (!enrichQuery.trim()) return
        try {
            const result = await searchIndicators(enrichQuery)
            setEnrichResults(result.items || [])
        } catch (err) {
            showToast(`Search failed: ${err.message}`, 'error')
        }
    }

    // Enrich a specific indicator
    const handleEnrich = async (indicator) => {
        setEnriching(indicator.id)
        setEnrichReport(null)
        try {
            const result = await enrichIndicator(indicator.id)
            setEnrichReport(result)
        } catch (err) {
            showToast(`Enrichment failed: ${err.message}`, 'error')
        } finally {
            setEnriching(null)
        }
    }

    // Clear chat history
    const handleClearChat = () => {
        setMessages([])
    }

    const handleKeyDown = (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault()
            handleSend()
        }
    }

    if (statusLoading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="w-8 h-8 border-2 border-accent border-t-transparent rounded-full animate-spin" />
            </div>
        )
    }

    return (
        <div className="h-full flex flex-col -m-6">
            {/* Top Bar */}
            <div className="flex items-center justify-between px-6 py-3 border-b border-border bg-bg-surface">
                <div className="flex items-center space-x-3">
                    <div className={`p-2 rounded-lg ${aiStatus?.available ? 'bg-accent/10' : 'bg-danger/10'}`}>
                        <Bot className={`w-5 h-5 ${aiStatus?.available ? 'text-accent' : 'text-danger'}`} />
                    </div>
                    <div>
                        <h2 className="text-sm font-semibold text-text-primary">AI Threat Analyst</h2>
                        <p className="text-xs text-text-muted">
                            {aiStatus?.available
                                ? `Powered by ${aiStatus.model} · ${aiStatus.features?.length || 0} capabilities`
                                : 'Offline — no API key configured'}
                        </p>
                    </div>
                </div>
                <div className="flex items-center space-x-2">
                    <button
                        onClick={() => setShowEnrichPanel(!showEnrichPanel)}
                        className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${showEnrichPanel
                            ? 'bg-accent/20 text-accent border border-accent/30'
                            : 'bg-bg-elevated text-text-muted hover:text-text-primary border border-border'
                            }`}
                    >
                        <Sparkles className="w-3.5 h-3.5" />
                        <span>IOC Enrichment</span>
                    </button>
                    {messages.length > 0 && (
                        <button
                            onClick={handleClearChat}
                            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-bg-elevated text-text-muted hover:text-text-primary border border-border transition-all"
                        >
                            <RotateCcw className="w-3.5 h-3.5" />
                            <span>Clear</span>
                        </button>
                    )}
                </div>
            </div>

            {/* Main Content Area */}
            <div className="flex-1 flex overflow-hidden">
                {/* Chat Panel */}
                <div className={`flex-1 flex flex-col ${showEnrichPanel ? 'border-r border-border' : ''}`}>
                    {/* Messages */}
                    <div className="flex-1 overflow-y-auto px-6 py-4 space-y-4">
                        {messages.length === 0 ? (
                            /* Welcome Screen */
                            <div className="flex flex-col items-center justify-center h-full space-y-6 py-8">
                                <div className="relative">
                                    <div className="absolute inset-0 bg-accent/20 rounded-full blur-xl animate-pulse" />
                                    <div className="relative p-5 bg-gradient-to-br from-accent/20 to-purple-500/20 rounded-2xl border border-accent/20">
                                        <Brain className="w-10 h-10 text-accent" />
                                    </div>
                                </div>
                                <div className="text-center max-w-md">
                                    <h3 className="text-lg font-bold text-text-primary mb-2">AI Threat Intelligence Analyst</h3>
                                    <p className="text-sm text-text-muted">
                                        Ask me about threats, indicators, MITRE techniques, or get security recommendations based on your intelligence data.
                                    </p>
                                </div>
                                {/* Quick Actions */}
                                <div className="grid grid-cols-2 gap-3 w-full max-w-lg">
                                    {QUICK_ACTIONS.map((action) => (
                                        <button
                                            key={action.label}
                                            onClick={() => handleSend(action.prompt)}
                                            disabled={!aiStatus?.available || loading}
                                            className="flex items-center space-x-2.5 px-4 py-3 rounded-xl bg-bg-surface border border-border hover:border-accent/30 hover:bg-bg-elevated transition-all text-left group disabled:opacity-50"
                                        >
                                            <action.icon className="w-4 h-4 text-accent flex-shrink-0 group-hover:scale-110 transition-transform" />
                                            <span className="text-xs font-medium text-text-secondary group-hover:text-text-primary">{action.label}</span>
                                        </button>
                                    ))}
                                </div>
                            </div>
                        ) : (
                            /* Chat Messages */
                            messages.map((msg, i) => (
                                <div
                                    key={i}
                                    className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
                                >
                                    <div className={`max-w-[80%] ${msg.role === 'user'
                                        ? 'bg-accent/10 border border-accent/20 rounded-2xl rounded-br-md px-4 py-3'
                                        : 'bg-bg-surface border border-border rounded-2xl rounded-bl-md px-5 py-4'
                                        }`}>
                                        {msg.role === 'assistant' && (
                                            <div className="flex items-center space-x-2 mb-2 pb-2 border-b border-border/50">
                                                <Bot className="w-3.5 h-3.5 text-accent" />
                                                <span className="text-xs font-medium text-accent">AI Analyst</span>
                                                {msg.timestamp && (
                                                    <span className="text-xs text-text-muted">
                                                        {new Date(msg.timestamp).toLocaleTimeString()}
                                                    </span>
                                                )}
                                            </div>
                                        )}
                                        {msg.role === 'user' ? (
                                            <p className="text-sm text-text-primary">{msg.content}</p>
                                        ) : (
                                            <AIMarkdown text={msg.content} />
                                        )}
                                    </div>
                                </div>
                            ))
                        )}

                        {/* Loading indicator */}
                        {loading && (
                            <div className="flex justify-start">
                                <div className="bg-bg-surface border border-border rounded-2xl rounded-bl-md px-5 py-4">
                                    <div className="flex items-center space-x-2 mb-2 pb-2 border-b border-border/50">
                                        <Bot className="w-3.5 h-3.5 text-accent" />
                                        <span className="text-xs font-medium text-accent">AI Analyst</span>
                                    </div>
                                    <div className="flex items-center space-x-2 text-sm text-text-muted">
                                        <Loader2 className="w-4 h-4 animate-spin text-accent" />
                                        <span>Analyzing threat intelligence...</span>
                                    </div>
                                </div>
                            </div>
                        )}

                        <div ref={messagesEndRef} />
                    </div>

                    {/* Input Area */}
                    <div className="px-6 py-4 border-t border-border bg-bg-surface">
                        <div className="flex items-end space-x-3">
                            <div className="flex-1 relative">
                                <textarea
                                    ref={inputRef}
                                    value={input}
                                    onChange={(e) => setInput(e.target.value)}
                                    onKeyDown={handleKeyDown}
                                    placeholder={aiStatus?.available
                                        ? "Ask about threats, indicators, MITRE techniques..."
                                        : "AI Analyst is offline"}
                                    disabled={!aiStatus?.available || loading}
                                    rows={1}
                                    className="w-full px-4 py-3 bg-bg-primary border border-border rounded-xl text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-accent/50 focus:ring-1 focus:ring-accent/20 transition-all resize-none disabled:opacity-50"
                                    style={{ minHeight: '44px', maxHeight: '120px' }}
                                    onInput={(e) => {
                                        e.target.style.height = '44px'
                                        e.target.style.height = Math.min(e.target.scrollHeight, 120) + 'px'
                                    }}
                                />
                            </div>
                            <button
                                onClick={() => handleSend()}
                                disabled={!input.trim() || !aiStatus?.available || loading}
                                className="p-3 bg-accent hover:bg-accent/80 disabled:bg-bg-elevated disabled:text-text-muted text-white rounded-xl transition-all flex-shrink-0"
                            >
                                <Send className="w-4 h-4" />
                            </button>
                        </div>
                    </div>
                </div>

                {/* IOC Enrichment Panel */}
                {showEnrichPanel && (
                    <div className="w-96 flex flex-col bg-bg-surface overflow-hidden">
                        <div className="p-4 border-b border-border flex items-center justify-between">
                            <div className="flex items-center space-x-2">
                                <Sparkles className="w-4 h-4 text-accent" />
                                <h3 className="text-sm font-semibold text-text-primary">IOC Enrichment</h3>
                            </div>
                            <button onClick={() => setShowEnrichPanel(false)} className="text-text-muted hover:text-text-primary">
                                <X className="w-4 h-4" />
                            </button>
                        </div>

                        {/* Search */}
                        <div className="p-4 border-b border-border">
                            <div className="flex space-x-2">
                                <input
                                    type="text"
                                    value={enrichQuery}
                                    onChange={(e) => setEnrichQuery(e.target.value)}
                                    onKeyDown={(e) => e.key === 'Enter' && handleEnrichSearch()}
                                    placeholder="Search an IP, domain, hash..."
                                    className="flex-1 px-3 py-2 bg-bg-primary border border-border rounded-lg text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-accent/50 transition-all"
                                />
                                <button
                                    onClick={handleEnrichSearch}
                                    className="p-2 bg-accent/10 text-accent rounded-lg hover:bg-accent/20 transition-all"
                                >
                                    <Search className="w-4 h-4" />
                                </button>
                            </div>
                        </div>

                        {/* Results */}
                        <div className="flex-1 overflow-y-auto p-4 space-y-2">
                            {enrichResults.length > 0 ? (
                                enrichResults.map((ind) => (
                                    <div key={ind.id} className="p-3 rounded-lg bg-bg-primary border border-border hover:border-accent/20 transition-all">
                                        <div className="flex items-center justify-between mb-1">
                                            <span className={`badge badge-${ind.type}`}>{ind.type}</span>
                                            <button
                                                onClick={() => handleEnrich(ind)}
                                                disabled={enriching === ind.id}
                                                className="flex items-center space-x-1 px-2 py-1 rounded-md text-xs font-medium bg-accent/10 text-accent hover:bg-accent/20 disabled:opacity-50 transition-all"
                                            >
                                                {enriching === ind.id
                                                    ? <Loader2 className="w-3 h-3 animate-spin" />
                                                    : <Sparkles className="w-3 h-3" />
                                                }
                                                <span>Analyze</span>
                                            </button>
                                        </div>
                                        <p className="text-xs font-mono text-text-primary truncate">{ind.value}</p>
                                        {ind.confidence && (
                                            <p className="text-xs text-text-muted mt-1">Confidence: {ind.confidence}%</p>
                                        )}
                                    </div>
                                ))
                            ) : (
                                <div className="text-center py-8">
                                    <Search className="w-8 h-8 text-text-muted/30 mx-auto mb-2" />
                                    <p className="text-xs text-text-muted">Search for an indicator to analyze</p>
                                </div>
                            )}

                            {/* Enrichment Report */}
                            {enrichReport && (
                                <div className="mt-4 p-4 rounded-xl bg-bg-elevated border border-accent/20 space-y-3">
                                    <div className="flex items-center justify-between">
                                        <div className="flex items-center space-x-2">
                                            <Bot className="w-4 h-4 text-accent" />
                                            <span className="text-xs font-semibold text-accent">AI Threat Briefing</span>
                                        </div>
                                        {enrichReport.ai_risk_score && (
                                            <RiskBadge level={enrichReport.ai_risk_score} />
                                        )}
                                    </div>
                                    <div className="text-xs font-mono text-text-muted">
                                        {enrichReport.indicator_type}: {enrichReport.indicator_value}
                                    </div>
                                    <AIMarkdown text={enrichReport.ai_summary} />
                                    {enrichReport.analyzed_at && (
                                        <p className="text-xs text-text-muted mt-2 pt-2 border-t border-border/50">
                                            Analyzed: {new Date(enrichReport.analyzed_at).toLocaleString()}
                                        </p>
                                    )}
                                </div>
                            )}
                        </div>
                    </div>
                )}
            </div>
        </div>
    )
}
