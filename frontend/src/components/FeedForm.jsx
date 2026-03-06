import { useState } from 'react'
import { X, Loader2, CheckCircle, AlertCircle } from 'lucide-react'
import { testFeedConnection } from '../api/client'

export default function FeedForm({ feed, onSubmit, onClose }) {
    const isEdit = !!feed
    const [form, setForm] = useState({
        name: feed?.name || '',
        taxii_url: feed?.taxii_url || '',
        collection_id: feed?.collection_id || '',
        username: feed?.username || '',
        password: '',
        polling_interval: feed?.polling_interval || 60,
    })
    const [testing, setTesting] = useState(false)
    const [testResult, setTestResult] = useState(null)
    const [submitting, setSubmitting] = useState(false)

    const handleChange = (e) => {
        setForm({ ...form, [e.target.name]: e.target.value })
        setTestResult(null)
    }

    const handleTest = async () => {
        setTesting(true)
        setTestResult(null)
        try {
            const result = await testFeedConnection({
                taxii_url: form.taxii_url,
                username: form.username || null,
                password: form.password || null,
            })
            setTestResult(result)
        } catch (err) {
            setTestResult({ success: false, message: err.message, collections: [] })
        } finally {
            setTesting(false)
        }
    }

    const handleSubmit = async (e) => {
        e.preventDefault()
        setSubmitting(true)
        try {
            const data = { ...form }
            if (!data.password && isEdit) delete data.password
            if (!data.username) data.username = null
            if (!data.collection_id) data.collection_id = null
            data.polling_interval = parseInt(data.polling_interval)
            await onSubmit(data)
            onClose()
        } catch (err) {
            setTestResult({ success: false, message: err.message })
        } finally {
            setSubmitting(false)
        }
    }

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
            <div className="glass-card rounded-2xl w-full max-w-lg mx-4 max-h-[90vh] overflow-y-auto">
                {/* Header */}
                <div className="flex items-center justify-between p-5 border-b border-border">
                    <h2 className="text-lg font-semibold text-text-primary">
                        {isEdit ? 'Edit Feed' : 'Add TAXII Feed'}
                    </h2>
                    <button onClick={onClose} className="p-1 text-text-muted hover:text-text-primary transition-colors">
                        <X className="w-5 h-5" />
                    </button>
                </div>

                {/* Form */}
                <form onSubmit={handleSubmit} className="p-5 space-y-4">
                    <div>
                        <label className="block text-sm font-medium text-text-muted mb-1.5">Feed Name</label>
                        <input name="name" value={form.name} onChange={handleChange} required
                            className="w-full px-3 py-2 rounded-lg bg-bg-primary border border-border text-text-primary text-sm focus:outline-none focus:border-accent transition-colors" />
                    </div>

                    <div>
                        <label className="block text-sm font-medium text-text-muted mb-1.5">TAXII URL</label>
                        <input name="taxii_url" value={form.taxii_url} onChange={handleChange} required placeholder="http://taxii-mock:9000/taxii/"
                            className="w-full px-3 py-2 rounded-lg bg-bg-primary border border-border text-text-primary text-sm focus:outline-none focus:border-accent transition-colors font-mono" />
                    </div>

                    <div>
                        <label className="block text-sm font-medium text-text-muted mb-1.5">Collection ID <span className="text-text-muted/60">(optional)</span></label>
                        <input name="collection_id" value={form.collection_id} onChange={handleChange}
                            className="w-full px-3 py-2 rounded-lg bg-bg-primary border border-border text-text-primary text-sm focus:outline-none focus:border-accent transition-colors font-mono" />
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                        <div>
                            <label className="block text-sm font-medium text-text-muted mb-1.5">Username</label>
                            <input name="username" value={form.username} onChange={handleChange}
                                className="w-full px-3 py-2 rounded-lg bg-bg-primary border border-border text-text-primary text-sm focus:outline-none focus:border-accent transition-colors" />
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-text-muted mb-1.5">Password</label>
                            <input name="password" value={form.password} onChange={handleChange} type="password"
                                placeholder={isEdit ? '••••••••' : ''}
                                className="w-full px-3 py-2 rounded-lg bg-bg-primary border border-border text-text-primary text-sm focus:outline-none focus:border-accent transition-colors" />
                        </div>
                    </div>

                    <div>
                        <label className="block text-sm font-medium text-text-muted mb-1.5">Polling Interval (minutes)</label>
                        <input name="polling_interval" type="number" min="1" value={form.polling_interval} onChange={handleChange}
                            className="w-full px-3 py-2 rounded-lg bg-bg-primary border border-border text-text-primary text-sm focus:outline-none focus:border-accent transition-colors" />
                    </div>

                    {/* Test Connection */}
                    <div className="pt-2">
                        <button type="button" onClick={handleTest} disabled={testing || !form.taxii_url}
                            className="inline-flex items-center px-3 py-1.5 rounded-lg text-xs font-medium bg-bg-elevated border border-border text-text-muted hover:text-text-primary hover:border-accent/40 transition-all disabled:opacity-50">
                            {testing ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : null}
                            {testing ? 'Testing...' : 'Test Connection'}
                        </button>

                        {testResult && (
                            <div className={`mt-2 flex items-start space-x-2 text-xs p-2.5 rounded-lg ${testResult.success ? 'bg-green-500/10 text-green-400' : 'bg-red-500/10 text-red-400'}`}>
                                {testResult.success ? <CheckCircle className="w-4 h-4 flex-shrink-0 mt-0.5" /> : <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />}
                                <div>
                                    <p>{testResult.message}</p>
                                    {testResult.collections?.length > 0 && (
                                        <p className="mt-1 text-text-muted">
                                            Collections: {testResult.collections.map(c => c.title || c.id).join(', ')}
                                        </p>
                                    )}
                                </div>
                            </div>
                        )}
                    </div>

                    {/* Actions */}
                    <div className="flex justify-end space-x-3 pt-3 border-t border-border">
                        <button type="button" onClick={onClose}
                            className="px-4 py-2 rounded-lg text-sm font-medium text-text-muted hover:text-text-primary transition-colors">
                            Cancel
                        </button>
                        <button type="submit" disabled={submitting}
                            className="px-4 py-2 rounded-lg text-sm font-medium bg-accent text-white hover:bg-accent-hover transition-colors disabled:opacity-50">
                            {submitting ? 'Saving...' : isEdit ? 'Update Feed' : 'Add Feed'}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    )
}
