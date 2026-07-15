import { useState } from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';

const severityConfig = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  info: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
};

export default function AlertList({ alerts = [] }) {
  const [expanded, setExpanded] = useState(null);

  return (
    <div className="space-y-2">
      {alerts.map((alert, i) => {
        const isOpen = expanded === i;
        const severity = (alert.severity || 'info').toLowerCase();

        return (
          <div
            key={alert.id || i}
            className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden transition-colors hover:border-gray-600"
          >
            <button
              onClick={() => setExpanded(isOpen ? null : i)}
              className="w-full flex items-center gap-3 px-4 py-3 text-left"
            >
              <span
                className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${severityConfig[severity] || severityConfig.info}`}
              >
                {severity}
              </span>
              <span className="flex-1 text-sm text-gray-200 font-medium">
                {alert.name || alert.title || 'Alert'}
              </span>
              {alert.source_ip && (
                <span className="text-xs font-mono text-gray-500">{alert.source_ip}</span>
              )}
              <span className="text-xs text-gray-500">
                {alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : ''}
              </span>
              {isOpen ? (
                <ChevronUp className="w-4 h-4 text-gray-500" />
              ) : (
                <ChevronDown className="w-4 h-4 text-gray-500" />
              )}
            </button>

            {isOpen && (
              <div className="px-4 pb-3 border-t border-gray-700/50 pt-3">
                <p className="text-sm text-gray-400">{alert.message || alert.description || 'No additional details.'}</p>
                {alert.details && (
                  <pre className="mt-2 p-2 bg-gray-900 rounded text-xs text-gray-400 overflow-x-auto">
                    {typeof alert.details === 'string' ? alert.details : JSON.stringify(alert.details, null, 2)}
                  </pre>
                )}
              </div>
            )}
          </div>
        );
      })}

      {alerts.length === 0 && (
        <div className="text-center py-8 text-gray-500 text-sm">No alerts</div>
      )}
    </div>
  );
}
