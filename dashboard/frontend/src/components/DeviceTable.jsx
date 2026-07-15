import { useState, useMemo } from 'react';
import { ArrowUpDown, Search } from 'lucide-react';

export default function DeviceTable({ devices = [] }) {
  const [sortKey, setSortKey] = useState('ip');
  const [sortDir, setSortDir] = useState('asc');
  const [search, setSearch] = useState('');

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return devices.filter(
      (d) =>
        (d.ip || '').toLowerCase().includes(q) ||
        (d.mac || '').toLowerCase().includes(q) ||
        (d.hostname || '').toLowerCase().includes(q) ||
        (d.vendor || '').toLowerCase().includes(q)
    );
  }, [devices, search]);

  const sorted = useMemo(() => {
    return [...filtered].sort((a, b) => {
      const av = (a[sortKey] || '').toString().toLowerCase();
      const bv = (b[sortKey] || '').toString().toLowerCase();
      return sortDir === 'asc' ? av.localeCompare(bv) : bv.localeCompare(av);
    });
  }, [filtered, sortKey, sortDir]);

  const toggleSort = (key) => {
    if (sortKey === key) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    else { setSortKey(key); setSortDir('asc'); }
  };

  const columns = [
    { key: 'mac', label: 'MAC' },
    { key: 'ip', label: 'IP' },
    { key: 'hostname', label: 'Hostname' },
    { key: 'vendor', label: 'Vendor' },
    { key: 'os', label: 'OS' },
    { key: 'status', label: 'Status' },
    { key: 'last_seen', label: 'Last Seen' },
  ];

  return (
    <div>
      <div className="relative mb-4 max-w-sm">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
        <input
          type="text"
          placeholder="Search devices..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full pl-9 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/50"
        />
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-700">
              {columns.map((col) => (
                <th
                  key={col.key}
                  onClick={() => toggleSort(col.key)}
                  className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider cursor-pointer hover:text-gray-200 transition-colors"
                >
                  <span className="inline-flex items-center gap-1">
                    {col.label}
                    <ArrowUpDown className="w-3 h-3" />
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sorted.map((device, i) => (
              <tr
                key={device.mac || i}
                className="border-b border-gray-700/50 hover:bg-gray-700/30 transition-colors"
              >
                <td className="px-4 py-3 font-mono text-xs text-gray-300">{device.mac || '-'}</td>
                <td className="px-4 py-3 font-mono text-xs text-gray-300">{device.ip || '-'}</td>
                <td className="px-4 py-3 text-gray-200">{device.hostname || '-'}</td>
                <td className="px-4 py-3 text-gray-400">{device.vendor || '-'}</td>
                <td className="px-4 py-3 text-gray-400">{device.os || '-'}</td>
                <td className="px-4 py-3">
                  <span
                    className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${
                      device.status === 'active'
                        ? 'bg-emerald-500/20 text-emerald-400'
                        : 'bg-gray-600/30 text-gray-400'
                    }`}
                  >
                    {device.status || 'unknown'}
                  </span>
                </td>
                <td className="px-4 py-3 text-gray-400 text-xs">
                  {device.last_seen ? new Date(device.last_seen).toLocaleString() : '-'}
                </td>
              </tr>
            ))}
            {sorted.length === 0 && (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-gray-500">
                  No devices found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
