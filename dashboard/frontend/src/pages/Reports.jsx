import { useState } from 'react';
import { Download, FileJson, FileText, File } from 'lucide-react';
import { fetchStats, fetchDevices, fetchAlerts, fetchDnsQueries } from '../utils/api';

export default function Reports() {
  const [preview, setPreview] = useState('');
  const [loading, setLoading] = useState(false);

  const getData = async () => {
    setLoading(true);
    try {
      const [stats, devices, alerts, dns] = await Promise.all([
        fetchStats().catch(() => ({})),
        fetchDevices().catch(() => []),
        fetchAlerts(100).catch(() => []),
        fetchDnsQueries(100).catch(() => []),
      ]);
      return { stats, devices, alerts, dns, generated_at: new Date().toISOString() };
    } finally {
      setLoading(false);
    }
  };

  const exportJSON = async () => {
    const data = await getData();
    setPreview(JSON.stringify(data, null, 2));
    download(`netsentinel-report-${Date.now()}.json`, JSON.stringify(data, null, 2), 'application/json');
  };

  const exportCSV = async () => {
    const data = await getData();
    let csv = 'Type,Data\n';
    csv += `Stats,${JSON.stringify(data.stats)}\n`;
    csv += `Devices,${data.devices.length} total\n`;
    csv += `Alerts,${data.alerts.length} total\n`;
    csv += `DNS Queries,${data.dns.length} total\n`;
    setPreview(csv);
    download(`netsentinel-report-${Date.now()}.csv`, csv, 'text/csv');
  };

  const exportPDF = async () => {
    const data = await getData();
    const html = `
      <html><head><title>NetSentinel Report</title>
      <style>body{font-family:monospace;padding:40px;background:#111;color:#eee;}
      h1{color:#34d399;}table{width:100%;border-collapse:collapse;margin:20px 0;}
      td,th{padding:8px;border:1px solid #333;text-align:left;}</style></head>
      <body><h1>NetSentinel Report</h1>
      <p>Generated: ${data.generated_at}</p>
      <h2>Overview</h2><pre>${JSON.stringify(data.stats, null, 2)}</pre>
      <h2>Devices (${data.devices.length})</h2>
      <table><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Status</th></tr>
      ${data.devices.slice(0, 50).map((d) => `<tr><td>${d.ip}</td><td>${d.mac}</td><td>${d.hostname || '-'}</td><td>${d.status}</td></tr>`).join('')}
      </table>
      <h2>Alerts (${data.alerts.length})</h2>
      <table><tr><th>Severity</th><th>Name</th><th>Source</th></tr>
      ${data.alerts.slice(0, 50).map((a) => `<tr><td>${a.severity}</td><td>${a.name || a.title || '-'}</td><td>${a.source_ip || '-'}</td></tr>`).join('')}
      </table></body></html>`;
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    window.open(url, '_blank');
    setPreview('PDF report opened in new tab (use Ctrl/Cmd+P to save as PDF)');
  };

  const download = (name, content, type) => {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-100">Reports</h1>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <button
          onClick={exportJSON}
          disabled={loading}
          className="flex items-center gap-3 p-5 bg-gray-800 rounded-xl border border-gray-700 hover:border-emerald-500/50 transition-colors group"
        >
          <FileJson className="w-8 h-8 text-emerald-400 group-hover:text-emerald-300" />
          <div className="text-left">
            <p className="font-medium text-gray-200">Export JSON</p>
            <p className="text-xs text-gray-500">Full data dump</p>
          </div>
        </button>
        <button
          onClick={exportCSV}
          disabled={loading}
          className="flex items-center gap-3 p-5 bg-gray-800 rounded-xl border border-gray-700 hover:border-blue-500/50 transition-colors group"
        >
          <FileText className="w-8 h-8 text-blue-400 group-hover:text-blue-300" />
          <div className="text-left">
            <p className="font-medium text-gray-200">Export CSV</p>
            <p className="text-xs text-gray-500">Spreadsheet format</p>
          </div>
        </button>
        <button
          onClick={exportPDF}
          disabled={loading}
          className="flex items-center gap-3 p-5 bg-gray-800 rounded-xl border border-gray-700 hover:border-yellow-500/50 transition-colors group"
        >
          <File className="w-8 h-8 text-yellow-400 group-hover:text-yellow-300" />
          <div className="text-left">
            <p className="font-medium text-gray-200">Export PDF</p>
            <p className="text-xs text-gray-500">Printable report</p>
          </div>
        </button>
      </div>

      {loading && (
        <div className="flex items-center justify-center py-8">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-emerald-400" />
        </div>
      )}

      {preview && (
        <div className="bg-gray-800 rounded-xl border border-gray-700 p-5">
          <h2 className="text-sm font-medium text-gray-400 mb-4">Preview</h2>
          <pre className="bg-gray-900 rounded-lg p-4 text-xs text-gray-300 overflow-auto max-h-96 whitespace-pre-wrap">
            {preview}
          </pre>
        </div>
      )}
    </div>
  );
}
