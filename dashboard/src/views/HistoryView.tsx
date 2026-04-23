import { useEffect, useState, useCallback } from 'react'
import { Trash2, RefreshCw, ChevronLeft, ChevronRight } from 'lucide-react'
import { getHistory, clearHistory, getHistoryItem } from '../api'
import type { HistoryItem, ScanResponse } from '../types'
import { SeverityBadge } from '../components/SeverityBadge'
import { ThreatCard } from '../components/ThreatCard'

export function HistoryView() {
  const [items, setItems] = useState<HistoryItem[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [filter, setFilter] = useState<'all' | 'unsafe' | 'safe'>('all')
  const [loading, setLoading] = useState(false)
  const [selected, setSelected] = useState<ScanResponse | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)

  const PAGE_SIZE = 20

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const safeOnly = filter === 'safe' ? true : filter === 'unsafe' ? false : undefined
      const data = await getHistory(page, PAGE_SIZE, safeOnly)
      setItems(data.items)
      setTotal(data.total)
    } catch {
      setItems([])
    } finally {
      setLoading(false)
    }
  }, [page, filter])

  useEffect(() => { load() }, [load])

  const handleClear = async () => {
    if (!confirm('Clear all scan history?')) return
    await clearHistory()
    setItems([])
    setTotal(0)
    setSelected(null)
  }

  const handleSelect = async (id: string) => {
    setDetailLoading(true)
    try {
      const data = await getHistoryItem(id)
      setSelected(data)
    } finally {
      setDetailLoading(false)
    }
  }

  const totalPages = Math.ceil(total / PAGE_SIZE)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-gray-100">History</h1>
          <p className="text-sm text-gray-400 mt-1">{total} scan{total !== 1 ? 's' : ''} recorded</p>
        </div>
        <div className="flex gap-2">
          <button onClick={load} className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm text-gray-300 transition-colors">
            <RefreshCw size={14} /> Refresh
          </button>
          <button onClick={handleClear} className="flex items-center gap-1.5 px-3 py-1.5 bg-red-900/50 hover:bg-red-800/70 border border-red-700 rounded-lg text-sm text-red-300 transition-colors">
            <Trash2 size={14} /> Clear
          </button>
        </div>
      </div>

      {/* Filter */}
      <div className="flex gap-1 bg-gray-800 rounded-lg p-1 w-fit">
        {(['all', 'unsafe', 'safe'] as const).map(f => (
          <button
            key={f}
            onClick={() => { setFilter(f); setPage(1) }}
            className={`px-3 py-1 rounded-md text-sm font-medium transition-colors ${
              filter === f ? 'bg-indigo-600 text-white' : 'text-gray-400 hover:text-gray-200'
            }`}
          >
            {f.charAt(0).toUpperCase() + f.slice(1)}
          </button>
        ))}
      </div>

      <div className="flex gap-4 items-start">
        {/* Table */}
        <div className="flex-1 min-w-0 space-y-2">
          {loading && <p className="text-sm text-gray-500">Loading…</p>}
          {!loading && items.length === 0 && (
            <p className="text-sm text-gray-500 text-center py-12">No scans yet. Run a scan from the Scan tab.</p>
          )}
          {items.map(item => (
            <button
              key={item.id}
              onClick={() => handleSelect(item.id)}
              className={`w-full text-left rounded-lg border px-4 py-3 transition-colors ${
                selected?.id === item.id
                  ? 'border-indigo-500 bg-indigo-900/20'
                  : 'border-gray-700 bg-gray-800/50 hover:bg-gray-700/40'
              }`}
            >
              <div className="flex items-start gap-3">
                <span className={`mt-1 w-2 h-2 rounded-full shrink-0 ${item.safe ? 'bg-green-400' : 'bg-red-400'}`} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm text-gray-200 truncate font-medium">{item.source_hint}</span>
                    <span className="text-xs text-gray-500 bg-gray-700 px-1.5 py-0.5 rounded">{item.source}</span>
                    {item.max_severity && <SeverityBadge severity={item.max_severity} />}
                  </div>
                  <div className="mt-0.5 flex gap-3 text-xs text-gray-500">
                    <span>{new Date(item.timestamp * 1000).toLocaleString()}</span>
                    <span>{item.threat_count} threat{item.threat_count !== 1 ? 's' : ''}</span>
                    <span>{item.scan_time_ms.toFixed(1)}ms</span>
                  </div>
                </div>
              </div>
            </button>
          ))}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between pt-2">
              <button
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1}
                className="flex items-center gap-1 px-3 py-1.5 text-sm text-gray-400 disabled:opacity-40 hover:text-gray-200 transition-colors"
              >
                <ChevronLeft size={14} /> Prev
              </button>
              <span className="text-xs text-gray-500">Page {page} of {totalPages}</span>
              <button
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="flex items-center gap-1 px-3 py-1.5 text-sm text-gray-400 disabled:opacity-40 hover:text-gray-200 transition-colors"
              >
                Next <ChevronRight size={14} />
              </button>
            </div>
          )}
        </div>

        {/* Detail panel */}
        {(selected || detailLoading) && (
          <div className="w-80 shrink-0 space-y-3 sticky top-4">
            {detailLoading && <p className="text-sm text-gray-500">Loading…</p>}
            {selected && !detailLoading && (
              <>
                <div className="flex items-center justify-between">
                  <span className={`text-sm font-semibold ${selected.safe ? 'text-green-400' : 'text-red-400'}`}>
                    {selected.safe ? '✓ Safe' : `✗ ${selected.threat_count} threats`}
                  </span>
                  <span className="text-xs text-gray-500">{selected.scan_time_ms.toFixed(1)}ms</span>
                </div>
                <div className="space-y-2">
                  {selected.threats.length === 0
                    ? <p className="text-sm text-gray-500">No threats detected.</p>
                    : selected.threats.map((t, i) => <ThreatCard key={i} threat={t} />)
                  }
                </div>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
