import { useEffect, useState, useCallback } from 'react'
import { RefreshCw, ShieldCheck, ShieldAlert, Clock, Activity } from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from 'recharts'
import { getStats } from '../api'
import type { Stats } from '../types'

const SEVERITY_COLOURS: Record<string, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#3b82f6',
}

const PALETTE = [
  '#6366f1', '#8b5cf6', '#ec4899', '#f97316',
  '#14b8a6', '#22c55e', '#eab308', '#ef4444',
]

export function StatsView() {
  const [stats, setStats] = useState<Stats | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      setStats(await getStats())
    } catch (e: any) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  if (loading) return <div className="text-sm text-gray-500 py-12 text-center">Loading stats…</div>
  if (error)   return <div className="text-sm text-red-400 py-12 text-center">{error}</div>
  if (!stats)  return null

  const threatTypeData = Object.entries(stats.threat_type_counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([name, count]) => ({ name: name.replace(/_/g, ' '), count }))

  const severityData = Object.entries(stats.severity_counts).map(([name, value]) => ({
    name, value, fill: SEVERITY_COLOURS[name] ?? '#6b7280',
  }))

  const sourceData = Object.entries(stats.scan_sources).map(([name, value], i) => ({
    name, value, fill: PALETTE[i % PALETTE.length],
  }))

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100">Statistics</h1>
          <p className="text-sm text-gray-400 mt-1">Aggregate metrics across all scans.</p>
        </div>
        <button
          onClick={load}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm text-gray-300 transition-colors"
        >
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {/* KPI cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <KpiCard
          icon={<Activity size={18} className="text-indigo-400" />}
          label="Total Scans"
          value={stats.total_scans.toLocaleString()}
        />
        <KpiCard
          icon={<ShieldCheck size={18} className="text-green-400" />}
          label="Safe"
          value={stats.safe_count.toLocaleString()}
          sub={stats.total_scans > 0 ? `${((stats.safe_count / stats.total_scans) * 100).toFixed(0)}%` : '—'}
          accent="green"
        />
        <KpiCard
          icon={<ShieldAlert size={18} className="text-red-400" />}
          label="Unsafe"
          value={stats.unsafe_count.toLocaleString()}
          sub={stats.total_scans > 0 ? `${((stats.unsafe_count / stats.total_scans) * 100).toFixed(0)}%` : '—'}
          accent="red"
        />
        <KpiCard
          icon={<Clock size={18} className="text-blue-400" />}
          label="Avg Scan Time"
          value={`${stats.mean_scan_time_ms.toFixed(1)}ms`}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Threat types bar chart */}
        <ChartCard title="Top Threat Types">
          {threatTypeData.length === 0
            ? <EmptyState />
            : (
              <ResponsiveContainer width="100%" height={260}>
                <BarChart data={threatTypeData} layout="vertical" margin={{ left: 8, right: 16 }}>
                  <XAxis type="number" tick={{ fill: '#9ca3af', fontSize: 11 }} />
                  <YAxis type="category" dataKey="name" width={130} tick={{ fill: '#9ca3af', fontSize: 11 }} />
                  <Tooltip
                    contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: 8 }}
                    labelStyle={{ color: '#f3f4f6', fontSize: 12 }}
                    itemStyle={{ color: '#d1d5db', fontSize: 12 }}
                  />
                  <Bar dataKey="count" fill="#6366f1" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )
          }
        </ChartCard>

        {/* Severity pie */}
        <ChartCard title="Severity Distribution">
          {severityData.length === 0
            ? <EmptyState />
            : (
              <ResponsiveContainer width="100%" height={260}>
                <PieChart>
                  <Pie
                    data={severityData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    outerRadius={90}
                    label={({ name, percent }) => `${name} ${((percent ?? 0) * 100).toFixed(0)}%`}
                    labelLine={{ stroke: '#6b7280' }}
                  >
                    {severityData.map((entry, i) => (
                      <Cell key={i} fill={entry.fill} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: 8 }}
                    labelStyle={{ color: '#f3f4f6', fontSize: 12 }}
                    itemStyle={{ color: '#d1d5db', fontSize: 12 }}
                  />
                  <Legend wrapperStyle={{ color: '#9ca3af', fontSize: 12 }} />
                </PieChart>
              </ResponsiveContainer>
            )
          }
        </ChartCard>

        {/* Scan sources */}
        <ChartCard title="Scan Sources">
          {sourceData.length === 0
            ? <EmptyState />
            : (
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={sourceData} margin={{ left: 0, right: 16 }}>
                  <XAxis dataKey="name" tick={{ fill: '#9ca3af', fontSize: 12 }} />
                  <YAxis tick={{ fill: '#9ca3af', fontSize: 12 }} />
                  <Tooltip
                    contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: 8 }}
                    labelStyle={{ color: '#f3f4f6', fontSize: 12 }}
                    itemStyle={{ color: '#d1d5db', fontSize: 12 }}
                  />
                  <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                    {sourceData.map((entry, i) => (
                      <Cell key={i} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )
          }
        </ChartCard>

        {/* Raw counts */}
        <ChartCard title="Severity Counts">
          {severityData.length === 0
            ? <EmptyState />
            : (
              <div className="space-y-3 pt-2">
                {severityData.map(s => (
                  <div key={s.name} className="flex items-center gap-3">
                    <span className="w-16 text-sm capitalize text-gray-400">{s.name}</span>
                    <div className="flex-1 bg-gray-700 rounded-full h-2 overflow-hidden">
                      <div
                        className="h-full rounded-full"
                        style={{
                          width: `${(s.value / Math.max(...severityData.map(x => x.value))) * 100}%`,
                          background: s.fill,
                        }}
                      />
                    </div>
                    <span className="text-sm font-semibold text-gray-200 w-8 text-right">{s.value}</span>
                  </div>
                ))}
              </div>
            )
          }
        </ChartCard>
      </div>
    </div>
  )
}

function KpiCard({
  icon, label, value, sub, accent,
}: {
  icon: React.ReactNode
  label: string
  value: string
  sub?: string
  accent?: 'green' | 'red'
}) {
  const border = accent === 'green' ? 'border-green-800' : accent === 'red' ? 'border-red-800' : 'border-gray-700'
  return (
    <div className={`rounded-xl border ${border} bg-gray-800/60 p-4 space-y-1`}>
      <div className="flex items-center gap-2 text-xs text-gray-500 font-medium uppercase tracking-wide">
        {icon} {label}
      </div>
      <div className="text-2xl font-bold text-gray-100">{value}</div>
      {sub && <div className="text-xs text-gray-500">{sub}</div>}
    </div>
  )
}

function ChartCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-gray-700 bg-gray-800/40 p-5">
      <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-4">{title}</h3>
      {children}
    </div>
  )
}

function EmptyState() {
  return <p className="text-sm text-gray-600 text-center py-8">No data yet — run some scans first.</p>
}
