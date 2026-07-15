import { useEffect, useState } from 'react';
import { Activity, Monitor, Layers, AlertTriangle } from 'lucide-react';
import StatCard from '../components/StatCard';
import BandwidthChart from '../components/BandwidthChart';
import ProtocolPie from '../components/ProtocolPie';
import TrafficTimeline from '../components/TrafficTimeline';
import TopTalkers from '../components/TopTalkers';
import AlertList from '../components/AlertList';
import DnsTable from '../components/DnsTable';
import useWebSocket from '../hooks/useWebSocket';
import {
  fetchStats,
  fetchBandwidthHistory,
  fetchProtocolDistribution,
  fetchTopTalkers,
  fetchAlerts,
  fetchDnsQueries,
} from '../utils/api';

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

export default function Dashboard() {
  const { stats: wsStats } = useWebSocket('ws://localhost:8000/ws');
  const [stats, setStats] = useState(null);
  const [bandwidth, setBandwidth] = useState([]);
  const [protocols, setProtocols] = useState({});
  const [topTalkers, setTopTalkers] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [dnsQueries, setDnsQueries] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      fetchStats().catch(() => null),
      fetchBandwidthHistory(60).catch(() => []),
      fetchProtocolDistribution().catch(() => ({})),
      fetchTopTalkers().catch(() => []),
      fetchAlerts(5).catch(() => []),
      fetchDnsQueries(5).catch(() => []),
    ]).then(([s, bw, proto, tt, al, dns]) => {
      setStats(s);
      setBandwidth(bw);
      setProtocols(proto);
      setTopTalkers(tt);
      setAlerts(al);
      setDnsQueries(dns);
      setLoading(false);
    });
  }, []);

  const live = wsStats || stats;
  const bwIn = live?.bandwidth?.bytes_per_sec_in || 0;
  const bwOut = live?.bandwidth?.bytes_per_sec_out || 0;

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-emerald-400" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-100">Dashboard</h1>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Bandwidth In"
          value={`${formatBytes(bwIn)}/s`}
          subtitle={`${formatBytes(live?.traffic?.total_bytes)} total`}
          icon={Activity}
          color="green"
        />
        <StatCard
          title="Bandwidth Out"
          value={`${formatBytes(bwOut)}/s`}
          subtitle={`${formatBytes(live?.traffic?.total_bytes)} total`}
          icon={Activity}
          color="blue"
        />
        <StatCard
          title="Active Devices"
          value={live?.devices?.active || 0}
          subtitle={`${live?.devices?.total || 0} total`}
          icon={Monitor}
          color="purple"
        />
        <StatCard
          title="Alerts"
          value={live?.alerts?.total || 0}
          subtitle={`${live?.alerts?.critical || 0} critical`}
          icon={AlertTriangle}
          color="red"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-gray-800 rounded-xl border border-gray-700 p-5">
          <h2 className="text-sm font-medium text-gray-400 mb-4">Bandwidth Over Time</h2>
          <BandwidthChart data={bandwidth} height={280} />
        </div>
        <div className="bg-gray-800 rounded-xl border border-gray-700 p-5">
          <h2 className="text-sm font-medium text-gray-400 mb-4">Protocol Distribution</h2>
          <ProtocolPie data={protocols} height={280} />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-gray-800 rounded-xl border border-gray-700 p-5">
          <h2 className="text-sm font-medium text-gray-400 mb-4">Traffic Timeline</h2>
          <TrafficTimeline data={bandwidth} height={280} />
        </div>
        <div className="bg-gray-800 rounded-xl border border-gray-700 p-5">
          <h2 className="text-sm font-medium text-gray-400 mb-4">Top Talkers</h2>
          <TopTalkers data={topTalkers} height={280} />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-gray-800 rounded-xl border border-gray-700 p-5">
          <h2 className="text-sm font-medium text-gray-400 mb-4">Recent Alerts</h2>
          <AlertList alerts={alerts} />
        </div>
        <div className="bg-gray-800 rounded-xl border border-gray-700 p-5">
          <h2 className="text-sm font-medium text-gray-400 mb-4">Recent DNS Queries</h2>
          <DnsTable queries={dnsQueries} />
        </div>
      </div>
    </div>
  );
}
