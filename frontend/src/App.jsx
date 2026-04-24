import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Indicators from './pages/Indicators'
import MitreView from './pages/MitreView'
import Settings from './pages/Settings'
import AIAnalyst from './pages/AIAnalyst'
import WazuhView from './pages/WazuhView'

function App() {
    return (
        <BrowserRouter>
            <Routes>
                <Route element={<Layout />}>
                    <Route path="/" element={<Navigate to="/wazuh" replace />} />
                    <Route path="/wazuh" element={<WazuhView />} />
                    <Route path="/dashboard" element={<Dashboard />} />
                    <Route path="/indicators" element={<Indicators />} />
                    <Route path="/mitre" element={<MitreView />} />
                    <Route path="/settings" element={<Settings />} />
                    <Route path="/ai-analyst" element={<AIAnalyst />} />
                </Route>
            </Routes>
        </BrowserRouter>
    )
}

export default App
