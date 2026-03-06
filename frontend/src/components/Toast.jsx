import { useEffect, useState } from 'react'
import { CheckCircle, AlertCircle, XCircle, Info, X } from 'lucide-react'

const icons = {
    success: CheckCircle,
    error: XCircle,
    warning: AlertCircle,
    info: Info,
}

const styles = {
    success: 'bg-green-500/10 border-green-500/30 text-green-400',
    error: 'bg-red-500/10 border-red-500/30 text-red-400',
    warning: 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400',
    info: 'bg-blue-500/10 border-blue-500/30 text-blue-400',
}

export default function Toast({ message, type = 'info', onClose }) {
    const [visible, setVisible] = useState(false)
    const Icon = icons[type] || icons.info

    useEffect(() => {
        setTimeout(() => setVisible(true), 10)
    }, [])

    const handleClose = () => {
        setVisible(false)
        setTimeout(onClose, 300)
    }

    return (
        <div className={`fixed bottom-6 right-6 z-50 transition-all duration-300 ${visible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'}`}>
            <div className={`flex items-center space-x-3 px-4 py-3 rounded-xl border backdrop-blur-md ${styles[type]}`}>
                <Icon className="w-5 h-5 flex-shrink-0" />
                <span className="text-sm font-medium">{message}</span>
                <button onClick={handleClose} className="ml-2 opacity-60 hover:opacity-100 transition-opacity">
                    <X className="w-4 h-4" />
                </button>
            </div>
        </div>
    )
}
