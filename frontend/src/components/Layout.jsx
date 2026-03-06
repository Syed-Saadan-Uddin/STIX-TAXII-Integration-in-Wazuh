import { useState, useEffect } from 'react'
import { Outlet, NavLink, useLocation } from 'react-router-dom'
import { LayoutDashboard, Database, Shield, Settings, Activity, Menu, X } from 'lucide-react'
import { getHealth } from '../api/client'
import Toast from './Toast'

const navItems = [
    { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
    { to: '/indicators', icon: Database, label: 'Indicators' },
    { to: '/mitre', icon: Shield, label: 'MITRE ATT&CK' },
    { to: '/settings', icon: Settings, label: 'Settings' },
]

export default function Layout() {
    const location = useLocation()
    const [health, setHealth] = useState(null)
    const [sidebarOpen, setSidebarOpen] = useState(true)
    const [toast, setToast] = useState(null)

    // Get page title from current route
    const currentPage = navItems.find(item => location.pathname.startsWith(item.to))
    const pageTitle = currentPage?.label || 'Wazuh-TI'

    // Poll health every 30 seconds
    useEffect(() => {
        const checkHealth = async () => {
            try {
                const data = await getHealth()
                setHealth(data)
            } catch {
                setHealth(null)
            }
        }
        checkHealth()
        const interval = setInterval(checkHealth, 30000)
        return () => clearInterval(interval)
    }, [])

    const showToast = (message, type = 'info') => {
        setToast({ message, type })
        setTimeout(() => setToast(null), 4000)
    }

    return (
        <div className="flex h-screen overflow-hidden bg-bg-primary">
            {/* Sidebar */}
            <aside className={`${sidebarOpen ? 'w-60' : 'w-0 -ml-60'} transition-all duration-300 ease-in-out flex-shrink-0 bg-bg-surface border-r border-border flex flex-col`}>
                {/* Logo */}
                <div className="h-16 flex items-center px-5 border-b border-border">
                    <Shield className="w-7 h-7 text-accent mr-3" />
                    <span className="text-lg font-bold text-text-primary tracking-tight">Wazuh-TI</span>
                </div>

                {/* Nav Links */}
                <nav className="flex-1 px-3 py-4 space-y-1">
                    {navItems.map(({ to, icon: Icon, label }) => (
                        <NavLink
                            key={to}
                            to={to}
                            className={({ isActive }) =>
                                `flex items-center px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 group ${isActive
                                    ? 'bg-accent/10 text-accent glow-blue'
                                    : 'text-text-muted hover:text-text-primary hover:bg-bg-elevated'
                                }`
                            }
                        >
                            <Icon className="w-5 h-5 mr-3 flex-shrink-0" />
                            {label}
                        </NavLink>
                    ))}
                </nav>

                {/* Footer */}
                <div className="p-4 border-t border-border">
                    <div className="flex items-center text-xs text-text-muted">
                        <Activity className="w-3.5 h-3.5 mr-2" />
                        <span>v1.0.0</span>
                    </div>
                </div>
            </aside>

            {/* Main Content */}
            <div className="flex-1 flex flex-col min-w-0">
                {/* Top Bar */}
                <header className="h-16 flex items-center justify-between px-6 border-b border-border bg-bg-surface flex-shrink-0">
                    <div className="flex items-center">
                        <button
                            onClick={() => setSidebarOpen(!sidebarOpen)}
                            className="p-2 rounded-lg text-text-muted hover:text-text-primary hover:bg-bg-elevated transition-colors mr-4"
                        >
                            {sidebarOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
                        </button>
                        <h1 className="text-lg font-semibold text-text-primary">{pageTitle}</h1>
                    </div>

                    <div className="flex items-center space-x-4">
                        {/* Connection Status */}
                        <div className="flex items-center text-sm">
                            <div className={`w-2 h-2 rounded-full mr-2 ${health ? 'bg-success animate-pulse-dot' : 'bg-danger'}`} />
                            <span className="text-text-muted">
                                {health ? 'API Connected' : 'Disconnected'}
                            </span>
                        </div>
                    </div>
                </header>

                {/* Page Content */}
                <main className="flex-1 overflow-auto p-6">
                    <Outlet context={{ showToast }} />
                </main>
            </div>

            {/* Toast Notification */}
            {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
        </div>
    )
}
