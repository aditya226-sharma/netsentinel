const colorMap = {
  blue: 'from-blue-500/20 to-blue-600/5 border-blue-500/30 text-blue-400',
  green: 'from-emerald-500/20 to-emerald-600/5 border-emerald-500/30 text-emerald-400',
  yellow: 'from-yellow-500/20 to-yellow-600/5 border-yellow-500/30 text-yellow-400',
  red: 'from-red-500/20 to-red-600/5 border-red-500/30 text-red-400',
  purple: 'from-purple-500/20 to-purple-600/5 border-purple-500/30 text-purple-400',
};

export default function StatCard({ title, value, subtitle, icon: Icon, color = 'blue' }) {
  return (
    <div
      className={`bg-gray-800 rounded-xl border border-gray-700 p-5 bg-gradient-to-br ${colorMap[color] || colorMap.blue} transition-transform hover:scale-[1.02]`}
    >
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm text-gray-400">{title}</p>
          <p className="mt-1 text-2xl font-bold text-gray-100">{value}</p>
          {subtitle && (
            <p className="mt-1 text-xs text-gray-500">{subtitle}</p>
          )}
        </div>
        {Icon && (
          <div className={`p-2 rounded-lg bg-gray-700/50 ${colorMap[color]?.split(' ').pop() || 'text-gray-400'}`}>
            <Icon className="w-5 h-5" />
          </div>
        )}
      </div>
    </div>
  );
}
