export default function MitreTechniqueCard({ technique, onClick }) {
    const tacticColors = {
        'initial-access': 'border-red-500/30 hover:border-red-500/60',
        'execution': 'border-orange-500/30 hover:border-orange-500/60',
        'persistence': 'border-yellow-500/30 hover:border-yellow-500/60',
        'privilege-escalation': 'border-amber-500/30 hover:border-amber-500/60',
        'defense-evasion': 'border-green-500/30 hover:border-green-500/60',
        'credential-access': 'border-teal-500/30 hover:border-teal-500/60',
        'discovery': 'border-cyan-500/30 hover:border-cyan-500/60',
        'lateral-movement': 'border-blue-500/30 hover:border-blue-500/60',
        'collection': 'border-indigo-500/30 hover:border-indigo-500/60',
        'command-and-control': 'border-purple-500/30 hover:border-purple-500/60',
        'exfiltration': 'border-pink-500/30 hover:border-pink-500/60',
        'impact': 'border-rose-500/30 hover:border-rose-500/60',
    }

    const tacticBadgeColors = {
        'initial-access': 'bg-red-500/15 text-red-400',
        'execution': 'bg-orange-500/15 text-orange-400',
        'command-and-control': 'bg-purple-500/15 text-purple-400',
        'defense-evasion': 'bg-green-500/15 text-green-400',
    }

    const borderColor = tacticColors[technique.tactic] || 'border-border hover:border-accent/40'
    const badgeColor = tacticBadgeColors[technique.tactic] || 'bg-accent/15 text-accent'

    return (
        <div
            onClick={() => onClick && onClick(technique)}
            className={`glass-card rounded-xl p-5 border cursor-pointer transition-all duration-300 hover:scale-[1.02] hover:shadow-lg ${borderColor}`}
        >
            {/* Technique ID */}
            <div className="text-2xl font-bold font-mono text-text-primary mb-1">
                {technique.technique_id}
            </div>

            {/* Technique Name */}
            <div className="text-sm text-text-muted mb-3 line-clamp-2">
                {technique.name}
            </div>

            {/* Footer: Tactic badge + count */}
            <div className="flex items-center justify-between">
                {technique.tactic && (
                    <span className={`badge text-xs ${badgeColor}`}>
                        {technique.tactic.replace(/-/g, ' ')}
                    </span>
                )}
                <span className="text-sm font-mono text-accent font-semibold">
                    {technique.indicator_count} IOCs
                </span>
            </div>
        </div>
    )
}
