import { useState, useEffect } from 'react'
import { Outlet, NavLink, useLocation, Navigate } from 'react-router-dom'
import { LayoutDashboard, Database, Shield, Settings, Activity, Menu, X, Bot, ExternalLink, Lock } from 'lucide-react'
import { getHealth } from '../api/client'
import Toast from './Toast'

const navItems = [
    { to: '/wazuh', icon: Shield, label: 'Wazuh SIEM' },
    { to: '/dashboard', icon: LayoutDashboard, label: 'TI Dashboard', locked: true },
    { to: '/ai-analyst', icon: Bot, label: 'AI Analyst', locked: true },
    { to: '/indicators', icon: Database, label: 'Indicators', locked: true },
    { to: '/mitre', icon: Activity, label: 'MITRE Mapping', locked: true },
    { to: '/settings', icon: Settings, label: 'Settings', locked: true },
]

export default function Layout() {
    const location = useLocation()
    const [health, setHealth] = useState(null)
    const [sidebarOpen, setSidebarOpen] = useState(true)
    const [toast, setToast] = useState(null)
    const [isUnlocked, setIsUnlocked] = useState(false)

    // Get page title from current route
    const currentPage = navItems.find(item => location.pathname.startsWith(item.to))
    const pageTitle = currentPage?.label || 'Wazuh-TI'

    // Poll Wazuh Auth status to unlock TI features
    useEffect(() => {
        const checkWazuhAuth = async () => {
            if (isUnlocked) return;
            try {
                // Try to hit Wazuh status API. Requires CORS enabled on Wazuh Dashboard.
                // We use 'include' to send cookies.
                const resp = await fetch('http://localhost:5601/api/status', {
                    method: 'GET',
                    mode: 'cors',
                    credentials: 'include'
                });
                
                if (resp.ok) {
                    setIsUnlocked(true);
                    showToast('Wazuh session detected! Threat-TI features unlocked.', 'success');
                }
            } catch (err) {
                // Ignore errors (means not logged in or CORS blocked)
                console.debug('Wazuh auth check failed:', err);
            }
        }

        const interval = setInterval(checkWazuhAuth, 3000);
        checkWazuhAuth();
        return () => clearInterval(interval);
    }, [isUnlocked]);

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

    // Redirect to wazuh if trying to access locked page
    const isAccessingLockedPage = currentPage?.locked && !isUnlocked;

    if (isAccessingLockedPage) {
        return <Navigate to="/wazuh" replace />;
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
                    {navItems.map(({ to, icon: Icon, label, locked }) => {
                        const isDisabled = locked && !isUnlocked;
                        return (
                            <NavLink
                                key={to}
                                to={isDisabled ? '#' : to}
                                onClick={(e) => isDisabled && e.preventDefault()}
                                className={({ isActive }) =>
                                    `flex items-center px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 group ${
                                        isDisabled ? 'opacity-40 cursor-not-allowed text-text-muted' :
                                        isActive ? 'bg-accent/10 text-accent glow-blue' : 
                                        'text-text-muted hover:text-text-primary hover:bg-bg-elevated'
                                    }`
                                }
                            >
                                <Icon className="w-5 h-5 mr-3 flex-shrink-0" />
                                <span className="flex-1">{label}</span>
                                {isDisabled && <Lock className="w-3.5 h-3.5 ml-2" />}
                            </NavLink>
                        );
                    })}
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
                        {/* Auth Status */}
                        {!isUnlocked && (
                            <button 
                                onClick={() => {
                                    setIsUnlocked(true);
                                    showToast('Interface unlocked manually!', 'success');
                                }}
                                className="flex items-center px-3 py-1 rounded-full bg-warning/10 text-warning text-xs font-medium border border-warning/20 hover:bg-warning/20 transition-colors cursor-pointer"
                                title="Click to unlock if you are already signed in"
                            >
                                <Lock className="w-3 h-3 mr-1.5" />
                                Sign in to Wazuh to Unlock
                            </button>
                        )}
                        {isUnlocked && (
                            <div className="flex items-center px-3 py-1 rounded-full bg-success/10 text-success text-xs font-medium border border-success/20">
                                <Shield className="w-3 h-3 mr-1.5" />
                                Authenticated
                            </div>
                        )}

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
                    <Outlet context={{ showToast, isUnlocked }} />
                </main>
            </div>

            {/* Toast Notification */}
            {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
        </div>
    )
}
