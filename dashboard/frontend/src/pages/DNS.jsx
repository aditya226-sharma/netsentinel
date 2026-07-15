import { useEffect, useState } from 'react';
import { Globe, Search, AlertCircle } from 'lucide-react';
import StatCard from '../components/StatCard';
import DnsTable from '../components/DnsTable';
import { fetchDnsQueries, fetchTopDomains, fetchStats } from '../utils/api';

export default function Dns() {
  const [queries, setQueries] = useState([]);
  const [topDomains, setTopDomains] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      fetchDnsQueries(100).catch(() => []),
      fetchTopDomains().catch(() => []),
      fetchStats().catch(() => null),
    ]).then(([q, td, s]) => {
      setQueries(q);
      setTopDomains(td);
      setStats(s);
      setLoading(false);
    });
  }, []);

  const errors = queries.filter((q) => q.response_code && q.response_code !== 'NOERROR' && q.response_code !== '0');

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-emerald-400" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-100">DNS</h1>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <StatCard title="Total Queries" value={stats?.dns?.total_queries || queries.length} icon={Globe} color="blue" />
        <StatCard title="Unique Domains" value={stats?.dns?.unique_domains || topDomains.length} icon={Search} color="green" />
        <StatCard title="DNS Errors" value={errors.length} icon={AlertCircle} color="red" />
      </div>

      <div className="bg-gray-800 rounded-xl border border-gray-700 p-5">
        <h2 className="text-sm font-medium text-gray-400 mb-4">Top Domains</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Domain</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Count</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Bar</th>
              </tr>
            </thead>
            <tbody>
              {topDomains.slice(0, 15).map((d, i) => {
                const maxCount = topDomains[0]?.count || 1;
                const pct = (d.count / maxCount) * 100;
                return (
                  <tr key={i} className="border-b border-gray-700/50 hover:bg-gray-700/30">
                    <td className="px-4 py-3 text-xs text-gray-200">{d.domain}</td>
                    <td className="px-4 py-3 text-xs text-gray-400">{d.count}</td>
                    <td className="px-4 py-3">
                      <div className="w-full bg-gray-700 rounded-full h-2">
                        <div
                          className="bg-emerald-400 h-2 rounded-full transition-all"
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      <div className="bg-gray-800 rounded-xl border border-gray-700 p-5">
        <h2 className="text-sm font-medium text-gray-400 mb-4">DNS Queries</h2>
        <DnsTable queries={queries} />
      </div>

      {errors.length > 0 && (
        <div className="bg-gray-800 rounded-xl border border-gray-700 p-5">
          <h2 className="text-sm font-medium text-gray-400 mb-4">DNS Errors</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700">
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Time</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Source</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Query</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Response</th>
                </tr>
              </thead>
              <tbody>
                {errors.map((q, i) => (
                  <tr key={i} className="border-b border-gray-700/50 hover:bg-gray-700/30">
                    <td className="px-4 py-3 text-xs text-gray-400">{q.timestamp ? new Date(q.timestamp).toLocaleTimeString() : '-'}</td>
                    <td className="px-4 py-3 font-mono text-xs text-gray-300">{q.source_ip || '-'}</td>
                    <td className="px-4 py-3 text-xs text-gray-200">{q.query || '-'}</td>
                    <td className="px-4 py-3 text-xs text-red-400">{q.response_code || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
