import { useEffect, useState } from 'react';
import { Activity, ArrowUpRight, ArrowDownRight, Layers } from 'lucide-react';
import StatCard from '../components/StatCard';
import BandwidthChart from '../components/BandwidthChart';
import TopTalkers from '../components/TopTalkers';
import ProtocolPie from '../components/ProtocolPie';
import {
  fetchBandwidthHistory,
  fetchTopTalkers,
  fetchTopDestinations,
  fetchProtocolDistribution,
  fetchFlows,
} from '../utils/api';

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

export default function Traffic() {
  const [bandwidth, setBandwidth] = useState([]);
  const [topTalkers, setTopTalkers] = useState([]);
  const [topDest, setTopDest] = useState([]);
  const [protocols, setProtocols] = useState({});
  const [flows, setFlows] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      fetchBandwidthHistory(120).catch(() => []),
      fetchTopTalkers().catch(() => []),
      fetchTopDestinations().catch(() => []),
      fetchProtocolDistribution().catch(() => ({})),
      fetchFlows().catch(() => []),
    ]).then(([bw, tt, td, p, f]) => {
      setBandwidth(bw);
      setTopTalkers(tt);
      setTopDest(td);
      setProtocols(p);
      setFlows(f);
      setLoading(false);
    });
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-emerald-400" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-100">Traffic</h1>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        <StatCard title="Top Talker" value={topTalkers[0]?.ip || '-'} subtitle={topTalkers[0] ? formatBytes(topTalkers[0].bytes) : ''} icon={ArrowUpRight} color="green" />
        <StatCard title="Top Destination" value={topDest[0]?.ip || '-'} subtitle={topDest[0] ? formatBytes(topDest[0].bytes) : ''} icon={ArrowDownRight} color="blue" />
        <StatCard title="Active Flows" value={flows.length} icon={Layers} color="purple" />
      </div>

      <div className="bg-gray-800 rounded-xl border border-gray-700 p-5">
        <h2 className="text-sm font-medium text-gray-400 mb-4">Bandwidth History (2h)</h2>
        <BandwidthChart data={bandwidth} height={350} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-gray-800 rounded-xl border border-gray-700 p-5">
          <h2 className="text-sm font-medium text-gray-400 mb-4">Top Talkers</h2>
          <TopTalkers data={topTalkers} height={300} />
        </div>
        <div className="bg-gray-800 rounded-xl border border-gray-700 p-5">
          <h2 className="text-sm font-medium text-gray-400 mb-4">Protocol Distribution</h2>
          <ProtocolPie data={protocols} height={300} />
        </div>
      </div>

      <div className="bg-gray-800 rounded-xl border border-gray-700 p-5">
        <h2 className="text-sm font-medium text-gray-400 mb-4">Top Destinations</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">IP</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Bytes</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Packets</th>
              </tr>
            </thead>
            <tbody>
              {topDest.map((d, i) => (
                <tr key={i} className="border-b border-gray-700/50 hover:bg-gray-700/30">
                  <td className="px-4 py-3 font-mono text-xs text-gray-300">{d.ip}</td>
                  <td className="px-4 py-3 text-xs text-gray-300">{formatBytes(d.bytes)}</td>
                  <td className="px-4 py-3 text-xs text-gray-400">{d.packets?.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="bg-gray-800 rounded-xl border border-gray-700 p-5">
        <h2 className="text-sm font-medium text-gray-400 mb-4">Active Flows</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Source</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Destination</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Protocol</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Packets</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Bytes</th>
              </tr>
            </thead>
            <tbody>
              {flows.slice(0, 20).map((f, i) => (
                <tr key={i} className="border-b border-gray-700/50 hover:bg-gray-700/30">
                  <td className="px-4 py-3 font-mono text-xs text-gray-300">{f.src_ip || f.source || '-'}</td>
                  <td className="px-4 py-3 font-mono text-xs text-gray-300">{f.dst_ip || f.destination || '-'}</td>
                  <td className="px-4 py-3 text-xs text-gray-400">{f.protocol || '-'}</td>
                  <td className="px-4 py-3 text-xs text-gray-400">{f.packets?.toLocaleString() || '-'}</td>
                  <td className="px-4 py-3 text-xs text-gray-300">{formatBytes(f.bytes)}</td>
                </tr>
              ))}
              {flows.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-gray-500">No active flows</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
