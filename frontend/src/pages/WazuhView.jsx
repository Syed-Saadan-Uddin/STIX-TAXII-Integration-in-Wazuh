import React from 'react';

export default function WazuhView() {
    return (
        <div className="h-full flex flex-col -m-6">
            <div className="flex-1 relative overflow-hidden">
                <iframe
                    src="http://localhost:5601"
                    className="absolute inset-0 w-full h-full border-0"
                    title="Wazuh Dashboard"
                    allow="clipboard-write"
                />
            </div>
            
            {/* Simple instruction overlay if not logged in */}
            <div className="bg-bg-surface border-t border-border p-3 text-center text-sm text-text-muted">
                <p>Sign in to the Wazuh Dashboard above. Threat-TI features will unlock automatically once authenticated.</p>
            </div>
        </div>
    );
}
