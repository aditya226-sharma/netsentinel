import { useState, useMemo } from 'react';
import { Search } from 'lucide-react';

const typeColors = {
  A: 'text-emerald-400',
  AAAA: 'text-blue-400',
  CNAME: 'text-purple-400',
  MX: 'text-yellow-400',
  TXT: 'text-gray-400',
};

export default function DnsTable({ queries = [] }) {
  const [filter, setFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');

  const filtered = useMemo(() => {
    return queries.filter((q) => {
      const matchesText =
        !filter ||
        (q.query || '').toLowerCase().includes(filter.toLowerCase()) ||
        (q.source_ip || '').toLowerCase().includes(filter.toLowerCase());
      const matchesType = !typeFilter || q.type === typeFilter;
      return matchesText && matchesType;
    });
  }, [queries, filter, typeFilter]);

  const types = useMemo(() => {
    const s = new Set(queries.map((q) => q.type).filter(Boolean));
    return [...s].sort();
  }, [queries]);

  return (
    <div>
      <div className="flex flex-col sm:flex-row gap-3 mb-4">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input
            type="text"
            placeholder="Filter by query or source..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/50"
          />
        </div>
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-200 focus:outline-none focus:ring-2 focus:ring-emerald-500/50"
        >
          <option value="">All Types</option>
          {types.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-700">
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Time</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Source</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Query</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Type</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">RCode</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Answers</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((q, i) => (
              <tr
                key={i}
                className="border-b border-gray-700/50 hover:bg-gray-700/30 transition-colors"
              >
                <td className="px-4 py-3 text-xs text-gray-400">
                  {q.timestamp ? new Date(q.timestamp).toLocaleTimeString() : '-'}
                </td>
                <td className="px-4 py-3 font-mono text-xs text-gray-300">{q.source_ip || '-'}</td>
                <td className="px-4 py-3 text-xs text-gray-200 max-w-xs truncate">{q.query || '-'}</td>
                <td className="px-4 py-3">
                  <span className={`text-xs font-medium ${typeColors[q.type] || 'text-gray-400'}`}>
                    {q.type || '-'}
                  </span>
                </td>
                <td className="px-4 py-3 text-xs text-gray-400">{q.response_code || '-'}</td>
                <td className="px-4 py-3 text-xs text-gray-400 max-w-xs truncate">
                  {Array.isArray(q.answers) ? q.answers.join(', ') : q.answers || '-'}
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-gray-500">
                  No DNS queries found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
