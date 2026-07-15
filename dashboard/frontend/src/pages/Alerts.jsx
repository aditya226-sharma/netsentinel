import { useEffect, useState } from 'react';
import { AlertTriangle, AlertCircle, AlertOctagon, Info } from 'lucide-react';
import StatCard from '../components/StatCard';
import AlertList from '../components/AlertList';
import SearchBar from '../components/SearchBar';
import { fetchAlerts } from '../utils/api';

export default function Alerts() {
  const [alerts, setAlerts] = useState([]);
  const [filter, setFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchAlerts(200)
      .then(setAlerts)
      .catch(() => setAlerts([]))
      .finally(() => setLoading(false));
  }, []);

  const counts = {
    critical: alerts.filter((a) => a.severity === 'critical').length,
    high: alerts.filter((a) => a.severity === 'high').length,
    medium: alerts.filter((a) => a.severity === 'medium').length,
    low: alerts.filter((a) => a.severity === 'low').length,
  };

  const filtered = alerts.filter((a) => {
    const matchesSeverity = !severityFilter || a.severity === severityFilter;
    const matchesSearch =
      !filter ||
      (a.name || a.title || '').toLowerCase().includes(filter.toLowerCase()) ||
      (a.message || '').toLowerCase().includes(filter.toLowerCase()) ||
      (a.source_ip || '').toLowerCase().includes(filter.toLowerCase());
    return matchesSeverity && matchesSearch;
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-emerald-400" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-100">Alerts</h1>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard title="Critical" value={counts.critical} icon={AlertOctagon} color="red" />
        <StatCard title="High" value={counts.high} icon={AlertTriangle} color="yellow" />
        <StatCard title="Medium" value={counts.medium} icon={AlertCircle} color="yellow" />
        <StatCard title="Low" value={counts.low} icon={Info} color="blue" />
      </div>

      <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center">
        <SearchBar onSearch={setFilter} />
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-200 focus:outline-none focus:ring-2 focus:ring-emerald-500/50"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      <div className="bg-gray-800 rounded-xl border border-gray-700 p-5">
        <AlertList alerts={filtered} />
      </div>
    </div>
  );
}
