import { Line } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Filler,
} from 'chart.js';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Filler);

export default function TrafficTimeline({ data = [], height = 300 }) {
  const labels = data.map((d) => {
    const date = new Date(d.timestamp);
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  });

  const chartData = {
    labels,
    datasets: [
      {
        label: 'Packets/sec',
        data: data.map((d) => d.bytes_in + d.bytes_out),
        borderColor: '#a78bfa',
        backgroundColor: 'rgba(167,139,250,0.15)',
        fill: true,
        tension: 0.4,
        pointRadius: 0,
        borderWidth: 2,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    interaction: { intersect: false, mode: 'index' },
    plugins: {
      legend: {
        labels: { color: '#9ca3af', usePointStyle: true, pointStyle: 'circle' },
      },
      tooltip: {
        backgroundColor: '#1f2937',
        titleColor: '#e5e7eb',
        bodyColor: '#9ca3af',
        borderColor: '#374151',
        borderWidth: 1,
      },
    },
    scales: {
      x: {
        ticks: { color: '#6b7280', maxTicksLimit: 10 },
        grid: { color: 'rgba(75,85,99,0.3)' },
      },
      y: {
        ticks: { color: '#6b7280' },
        grid: { color: 'rgba(75,85,99,0.3)' },
      },
    },
  };

  return (
    <div style={{ height }}>
      <Line data={chartData} options={options} />
    </div>
  );
}
