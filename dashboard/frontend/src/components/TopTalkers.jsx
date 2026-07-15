import { Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Tooltip,
} from 'chart.js';

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip);

const COLORS = ['#34d399', '#60a5fa', '#f59e0b', '#ef4444', '#a78bfa', '#f472b6', '#38bdf8', '#fbbf24'];

export default function TopTalkers({ data = [], height = 300 }) {
  const sorted = [...data].sort((a, b) => b.bytes - a.bytes).slice(0, 8);

  const chartData = {
    labels: sorted.map((d) => d.ip),
    datasets: [
      {
        label: 'Bytes',
        data: sorted.map((d) => d.bytes),
        backgroundColor: sorted.map((_, i) => COLORS[i % COLORS.length]),
        borderRadius: 4,
        barThickness: 20,
      },
    ],
  };

  const options = {
    indexAxis: 'y',
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: '#1f2937',
        titleColor: '#e5e7eb',
        bodyColor: '#9ca3af',
        borderColor: '#374151',
        borderWidth: 1,
        callbacks: {
          label: (ctx) => formatBytes(ctx.raw),
        },
      },
    },
    scales: {
      x: {
        ticks: { color: '#6b7280', callback: (v) => formatBytes(v) },
        grid: { color: 'rgba(75,85,99,0.3)' },
      },
      y: {
        ticks: { color: '#9ca3af', font: { size: 11 } },
        grid: { display: false },
      },
    },
  };

  return (
    <div style={{ height }}>
      <Bar data={chartData} options={options} />
    </div>
  );
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}
