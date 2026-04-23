import { ChevronDown, ChevronRight } from 'lucide-react'
import { useState } from 'react'
import type { Threat } from '../types'
import { SeverityBadge } from './SeverityBadge'

export function ThreatCard({ threat }: { threat: Threat }) {
  const [open, setOpen] = useState(false)

  return (
    <div className="rounded-lg border border-gray-700 bg-gray-800/50 overflow-hidden">
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-start gap-3 p-4 text-left hover:bg-gray-700/40 transition-colors"
      >
        <span className="mt-0.5">
          {open ? <ChevronDown size={16} className="text-gray-400" /> : <ChevronRight size={16} className="text-gray-400" />}
        </span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <SeverityBadge severity={threat.severity} />
            <span className="text-xs text-gray-400 font-mono">T{threat.tier}</span>
            <span className="text-sm font-medium text-gray-100">{threat.label}</span>
          </div>
          <p className="mt-1 text-sm text-gray-300">{threat.plain_summary}</p>
        </div>
      </button>

      {open && (
        <div className="px-4 pb-4 pt-0 border-t border-gray-700 space-y-2">
          <Row label="Location"  value={threat.location} />
          <Row label="Technique" value={threat.technique} />
          <Row label="Outcome"   value={threat.outcome} />
          <Row label="Type"      value={threat.type} mono />
          <div className="pt-1">
            <span className="text-xs text-gray-500 font-semibold uppercase tracking-wide">Technical detail</span>
            <p className="mt-1 text-xs text-gray-400 font-mono whitespace-pre-wrap break-all">{threat.detail}</p>
          </div>
        </div>
      )}
    </div>
  )
}

function Row({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex gap-2 text-xs">
      <span className="text-gray-500 font-semibold uppercase tracking-wide w-20 shrink-0">{label}</span>
      <span className={`text-gray-300 ${mono ? 'font-mono' : ''}`}>{value}</span>
    </div>
  )
}
