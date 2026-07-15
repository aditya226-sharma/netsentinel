import { useEffect, useState } from 'react';
import { Play, Square, Wifi, Settings as SettingsIcon, RefreshCw } from 'lucide-react';
import StatCard from '../components/StatCard';
import { fetchCaptureStatus, fetchInterfaces, startCapture, stopCapture } from '../utils/api';

const PLUGINS = [
  { name: 'DNS Logger', description: 'Logs all DNS queries and responses', enabled: true },
  { name: 'TLS Inspector', description: 'Extracts TLS certificate and SNI data', enabled: true },
  { name: 'HTTP Parser', description: 'Parses HTTP headers and URLs', enabled: false },
  { name: 'GeoIP Resolver', description: 'Resolves IPs to geolocations', enabled: false },
  { name: 'Bandwidth Monitor', description: 'Tracks bandwidth per device', enabled: true },
  { name: 'Alert Engine', description: 'Generates alerts based on rules', enabled: true },
];

export default function Settings() {
  const [status, setStatus] = useState(null);
  const [interfaces, setInterfaces] = useState([]);
  const [selectedIface, setSelectedIface] = useState('');
  const [bpfFilter, setBpfFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);

  const loadStatus = () => {
    Promise.all([
      fetchCaptureStatus().catch(() => null),
      fetchInterfaces().catch(() => []),
    ]).then(([s, ifaces]) => {
      setStatus(s);
      setInterfaces(Array.isArray(ifaces) ? ifaces : []);
      if (s?.interface) setSelectedIface(s.interface);
      else if (Array.isArray(ifaces) && ifaces.length > 0) {
        setSelectedIface(typeof ifaces[0] === 'string' ? ifaces[0] : ifaces[0].name || '');
      }
      setLoading(false);
    });
  };

  useEffect(() => { loadStatus(); }, []);

  const handleStart = async () => {
    if (!selectedIface) return;
    setActionLoading(true);
    try {
      await startCapture(selectedIface);
      await loadStatus();
    } catch (e) {
      console.error(e);
    } finally {
      setActionLoading(false);
    }
  };

  const handleStop = async () => {
    setActionLoading(true);
    try {
      await stopCapture();
      await loadStatus();
    } catch (e) {
      console.error(e);
    } finally {
      setActionLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-emerald-400" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-100">Settings</h1>
        <button
          onClick={loadStatus}
          className="flex items-center gap-2 px-3 py-1.5 text-sm text-gray-400 hover:text-gray-200 bg-gray-800 rounded-lg border border-gray-700 transition-colors"
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <StatCard
          title="Capture Status"
          value={status?.running ? 'Running' : 'Stopped'}
          icon={Wifi}
          color={status?.running ? 'green' : 'red'}
        />
        <StatCard
          title="Interface"
          value={status?.interface || selectedIface || 'None'}
          icon={SettingsIcon}
          color="blue"
        />
        <StatCard
          title="Packets Captured"
          value={(status?.packets_captured || 0).toLocaleString()}
          subtitle={`${((status?.bytes_captured || 0) / 1024 / 1024).toFixed(1)} MB`}
          icon={SettingsIcon}
          color="purple"
        />
      </div>

      <div className="bg-gray-800 rounded-xl border border-gray-700 p-5 space-y-4">
        <h2 className="text-sm font-medium text-gray-400">Capture Control</h2>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs text-gray-500 mb-1">Interface</label>
            <select
              value={selectedIface}
              onChange={(e) => setSelectedIface(e.target.value)}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm text-gray-200 focus:outline-none focus:ring-2 focus:ring-emerald-500/50"
            >
              {interfaces.map((iface) => {
                const name = typeof iface === 'string' ? iface : iface.name;
                return (
                  <option key={name} value={name}>{name}</option>
                );
              })}
            </select>
          </div>
          <div>
            <label className="block text-xs text-gray-500 mb-1">BPF Filter</label>
            <input
              type="text"
              value={bpfFilter}
              onChange={(e) => setBpfFilter(e.target.value)}
              placeholder="e.g. tcp port 443"
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm text-gray-200 placeholder-gray-600 font-mono focus:outline-none focus:ring-2 focus:ring-emerald-500/50"
            />
          </div>
        </div>

        <div className="flex gap-3">
          <button
            onClick={handleStart}
            disabled={actionLoading || status?.running || !selectedIface}
            className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:bg-gray-700 disabled:text-gray-500 text-white rounded-lg text-sm font-medium transition-colors"
          >
            <Play className="w-4 h-4" />
            Start Capture
          </button>
          <button
            onClick={handleStop}
            disabled={actionLoading || !status?.running}
            className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-500 disabled:bg-gray-700 disabled:text-gray-500 text-white rounded-lg text-sm font-medium transition-colors"
          >
            <Square className="w-4 h-4" />
            Stop Capture
          </button>
        </div>
      </div>

      <div className="bg-gray-800 rounded-xl border border-gray-700 p-5">
        <h2 className="text-sm font-medium text-gray-400 mb-4">Plugins</h2>
        <div className="space-y-3">
          {PLUGINS.map((plugin) => (
            <div
              key={plugin.name}
              className="flex items-center justify-between p-3 bg-gray-900 rounded-lg border border-gray-700/50"
            >
              <div>
                <p className="text-sm font-medium text-gray-200">{plugin.name}</p>
                <p className="text-xs text-gray-500">{plugin.description}</p>
              </div>
              <button
                disabled
                className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                  plugin.enabled ? 'bg-emerald-500' : 'bg-gray-600'
                }`}
              >
                <span
                  className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                    plugin.enabled ? 'translate-x-4.5' : 'translate-x-0.5'
                  }`}
                />
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
