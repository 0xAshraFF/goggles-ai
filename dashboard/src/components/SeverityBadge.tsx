const COLOURS: Record<string, string> = {
  critical: 'bg-red-900 text-red-200 border border-red-700',
  high:     'bg-orange-900 text-orange-200 border border-orange-700',
  medium:   'bg-yellow-900 text-yellow-200 border border-yellow-700',
  low:      'bg-blue-900 text-blue-200 border border-blue-700',
}

export function SeverityBadge({ severity }: { severity: string }) {
  const cls = COLOURS[severity] ?? 'bg-gray-800 text-gray-300 border border-gray-600'
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wide ${cls}`}>
      {severity}
    </span>
  )
}
