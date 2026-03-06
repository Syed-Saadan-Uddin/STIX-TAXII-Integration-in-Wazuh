export default function IndicatorTable({ indicators, onRowClick }) {
    const typeBadge = (type) => {
        const map = { ip: 'badge-ip', domain: 'badge-domain', url: 'badge-url', hash: 'badge-hash' }
        return map[type] || 'badge-ip'
    }

    const confidenceColor = (conf) => {
        if (conf === null || conf === undefined) return 'bg-gray-600'
        if (conf < 40) return 'bg-danger'
        if (conf <= 70) return 'bg-warning'
        return 'bg-success'
    }

    const formatDate = (dateStr) => {
        if (!dateStr) return '—'
        return new Date(dateStr).toLocaleDateString('en-US', {
            month: 'short', day: 'numeric', year: 'numeric',
        })
    }

    return (
        <div className="overflow-x-auto rounded-xl border border-border">
            <table className="w-full text-sm">
                <thead>
                    <tr className="bg-bg-elevated border-b border-border">
                        <th className="text-left px-4 py-3 font-medium text-text-muted">Value</th>
                        <th className="text-left px-4 py-3 font-medium text-text-muted">Type</th>
                        <th className="text-left px-4 py-3 font-medium text-text-muted">Confidence</th>
                        <th className="text-left px-4 py-3 font-medium text-text-muted">First Seen</th>
                        <th className="text-left px-4 py-3 font-medium text-text-muted">Expires</th>
                        <th className="text-left px-4 py-3 font-medium text-text-muted">Status</th>
                    </tr>
                </thead>
                <tbody className="divide-y divide-border">
                    {indicators.map((ind) => (
                        <tr
                            key={ind.id}
                            onClick={() => onRowClick && onRowClick(ind)}
                            className="hover:bg-bg-elevated transition-colors cursor-pointer group"
                        >
                            <td className="px-4 py-3 font-mono text-sm text-text-primary max-w-xs truncate">
                                {ind.value}
                            </td>
                            <td className="px-4 py-3">
                                <span className={`badge ${typeBadge(ind.type)}`}>
                                    {ind.type?.toUpperCase()}
                                </span>
                            </td>
                            <td className="px-4 py-3">
                                <div className="flex items-center space-x-2">
                                    <div className="w-16 h-1.5 bg-bg-primary rounded-full overflow-hidden">
                                        <div
                                            className={`h-full rounded-full transition-all ${confidenceColor(ind.confidence)}`}
                                            style={{ width: `${ind.confidence || 0}%` }}
                                        />
                                    </div>
                                    <span className="text-xs text-text-muted w-8">
                                        {ind.confidence ?? '—'}
                                    </span>
                                </div>
                            </td>
                            <td className="px-4 py-3 text-text-muted text-xs">{formatDate(ind.first_seen)}</td>
                            <td className="px-4 py-3 text-text-muted text-xs">{formatDate(ind.expires)}</td>
                            <td className="px-4 py-3">
                                <span className={`badge ${ind.is_active ? 'badge-success' : 'badge-failed'}`}>
                                    {ind.is_active ? 'Active' : 'Expired'}
                                </span>
                            </td>
                        </tr>
                    ))}
                    {indicators.length === 0 && (
                        <tr>
                            <td colSpan="6" className="px-4 py-12 text-center text-text-muted">
                                No indicators found
                            </td>
                        </tr>
                    )}
                </tbody>
            </table>
        </div>
    )
}
