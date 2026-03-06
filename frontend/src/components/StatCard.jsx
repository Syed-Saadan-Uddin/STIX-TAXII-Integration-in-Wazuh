import { TrendingUp, TrendingDown, Minus } from 'lucide-react'

export default function StatCard({ label, value, icon: Icon, trend, color = 'accent' }) {
    const colorMap = {
        accent: 'from-blue-500/10 to-transparent border-blue-500/20 text-accent',
        success: 'from-green-500/10 to-transparent border-green-500/20 text-success',
        warning: 'from-yellow-500/10 to-transparent border-yellow-500/20 text-warning',
        danger: 'from-red-500/10 to-transparent border-red-500/20 text-danger',
    }

    const TrendIcon = trend === 'up' ? TrendingUp : trend === 'down' ? TrendingDown : Minus

    return (
        <div className={`glass-card rounded-xl p-5 bg-gradient-to-br ${colorMap[color] || colorMap.accent} transition-all duration-300 hover:scale-[1.02] hover:shadow-lg`}>
            <div className="flex items-center justify-between mb-3">
                <span className="text-sm font-medium text-text-muted">{label}</span>
                {Icon && <Icon className="w-5 h-5 text-text-muted" />}
            </div>
            <div className="flex items-end justify-between">
                <span className="text-3xl font-bold font-mono tracking-tight text-text-primary">
                    {typeof value === 'number' ? value.toLocaleString() : value}
                </span>
                {trend && (
                    <TrendIcon className={`w-4 h-4 ${trend === 'up' ? 'text-success' : trend === 'down' ? 'text-danger' : 'text-text-muted'}`} />
                )}
            </div>
        </div>
    )
}
