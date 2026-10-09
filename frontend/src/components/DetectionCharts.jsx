import { BarChart3, PieChart as PieIcon } from 'lucide-react'
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
} from 'recharts'

const COLORS = {
  malicious:  '#ef4444',
  suspicious: '#f59e0b',
  harmless:   '#10b981',
  undetected: '#64748b',
  timeout:    '#6366f1',
}

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null
  const d = payload[0]
  return (
    <div style={{
      background: '#1a2035',
      border: '1px solid #334155',
      borderRadius: '8px',
      padding: '8px 14px',
      fontSize: '.82rem',
      color: '#e2e8f0',
    }}>
      <span style={{ color: d.payload.fill || d.color }}>{d.name}</span>: {d.value}
    </div>
  )
}

export default function DetectionCharts({ vtData, otxData }) {
  const stats = vtData?.stats
  if (!stats || !vtData?.found) return null

  const pieData = [
    { name: 'Malicious (Threats)',  value: stats.malicious  || 0, fill: COLORS.malicious },
    { name: 'Suspicious (Risky)',   value: stats.suspicious || 0, fill: COLORS.suspicious },
    { name: 'Harmless (Clean)',     value: stats.harmless   || 0, fill: COLORS.harmless },
    { name: 'Undetected (No Flags)', value: stats.undetected || 0, fill: COLORS.undetected },
    { name: 'Timeout',              value: stats.timeout    || 0, fill: COLORS.timeout },
  ].filter(d => d.value > 0)

  const barData = [
    { category: 'Malicious',  count: stats.malicious  || 0, fill: COLORS.malicious },
    { category: 'Suspicious', count: stats.suspicious || 0, fill: COLORS.suspicious },
    { category: 'Harmless',   count: stats.harmless   || 0, fill: COLORS.harmless },
    { category: 'Undetected', count: stats.undetected || 0, fill: COLORS.undetected },
  ]

  return (
    <div className="charts-grid">
      {/* Pie chart */}
      <div className="chart-panel">
        <h3>
          <PieIcon size={18} style={{ color: 'var(--accent)' }} />
          Detection Breakdown
        </h3>
        <ResponsiveContainer width="100%" height={280}>
          <PieChart>
            <Pie
              data={pieData}
              cx="50%"
              cy="50%"
              innerRadius={60}
              outerRadius={100}
              paddingAngle={3}
              dataKey="value"
              stroke="none"
              animationBegin={0}
              animationDuration={800}
            >
              {pieData.map((entry, i) => (
                <Cell key={i} fill={entry.fill} />
              ))}
            </Pie>
            <Tooltip content={<CustomTooltip />} />
            <Legend
              iconType="circle"
              wrapperStyle={{ fontSize: '.78rem', color: '#94a3b8' }}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>

      {/* Bar chart */}
      <div className="chart-panel">
        <h3>
          <BarChart3 size={18} style={{ color: 'var(--cyan)' }} />
          Security Engine Verdicts
        </h3>
        <ResponsiveContainer width="100%" height={280}>
          <BarChart data={barData} barSize={36}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
            <XAxis
              dataKey="category"
              tick={{ fill: '#94a3b8', fontSize: 12 }}
              axisLine={{ stroke: '#1e293b' }}
              tickLine={false}
            />
            <YAxis
              tick={{ fill: '#94a3b8', fontSize: 12 }}
              axisLine={{ stroke: '#1e293b' }}
              tickLine={false}
              allowDecimals={false}
            />
            <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(59,130,246,.08)' }} />
            <Bar dataKey="count" radius={[6, 6, 0, 0]} animationDuration={800}>
              {barData.map((entry, i) => (
                <Cell key={i} fill={entry.fill} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
