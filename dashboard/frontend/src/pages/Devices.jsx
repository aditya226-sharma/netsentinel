import { useEffect, useState } from 'react';
import { Monitor, Wifi, WifiOff } from 'lucide-react';
import StatCard from '../components/StatCard';
import DeviceTable from '../components/DeviceTable';
import { fetchDevices } from '../utils/api';

export default function Devices() {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDevices()
      .then(setDevices)
      .catch(() => setDevices([]))
      .finally(() => setLoading(false));
  }, []);

  const active = devices.filter((d) => d.status === 'active').length;

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-emerald-400" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-100">Devices</h1>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <StatCard title="Total Devices" value={devices.length} icon={Monitor} color="blue" />
        <StatCard title="Active" value={active} icon={Wifi} color="green" />
        <StatCard title="Inactive" value={devices.length - active} icon={WifiOff} color="red" />
      </div>

      <div className="bg-gray-800 rounded-xl border border-gray-700 p-5">
        <DeviceTable devices={devices} />
      </div>
    </div>
  );
}
