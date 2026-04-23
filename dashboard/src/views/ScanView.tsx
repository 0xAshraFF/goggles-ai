import { useState, useRef, useCallback } from 'react'
import { Shield, ShieldAlert, Loader2, Link2, FileText, Upload } from 'lucide-react'
import { scanUrl, scanContent, scanFile, openWsScan } from '../api'
import type { ScanResponse, WsEvent } from '../types'
import { ThreatCard } from '../components/ThreatCard'
import { SeverityBadge } from '../components/SeverityBadge'

type Mode = 'url' | 'content' | 'file'

export function ScanView() {
  const [mode, setMode] = useState<Mode>('url')
  const [input, setInput] = useState('')
  const [contentType, setContentType] = useState('text/html')
  const [file, setFile] = useState<File | null>(null)
  const [deep, setDeep] = useState(false)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<ScanResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [wsEvents, setWsEvents] = useState<string[]>([])
  const [useWs, setUseWs] = useState(false)

  const wsRef = useRef<WebSocket | null>(null)

  const runScan = useCallback(async () => {
    setLoading(true)
    setError(null)
    setResult(null)
    setWsEvents([])

    try {
      if (useWs && (mode === 'url' || mode === 'content')) {
        const ws = openWsScan()
        wsRef.current = ws
        const events: string[] = []

        await new Promise<void>((resolve, reject) => {
          ws.onopen = () => {
            const msg = mode === 'url'
              ? { type: 'scan_url', url: input, deep }
              : { type: 'scan_content', content: input, content_type: contentType, deep }
            ws.send(JSON.stringify(msg))
          }
          ws.onmessage = (e) => {
            const ev: WsEvent = JSON.parse(e.data)
            events.push(`[${ev.event}] ${JSON.stringify(ev)}`)
            setWsEvents([...events])
            if (ev.event === 'complete' || ev.event === 'error') {
              ws.close()
              resolve()
            }
          }
          ws.onerror = () => reject(new Error('WebSocket error'))
        })
        return
      }

      let res: ScanResponse
      if (mode === 'url') {
        res = await scanUrl(input, deep)
      } else if (mode === 'content') {
        res = await scanContent(input, contentType, '', deep)
      } else {
        if (!file) throw new Error('No file selected')
        res = await scanFile(file, deep)
      }
      setResult(res)
    } catch (err: any) {
      setError(err.message ?? 'Scan failed')
    } finally {
      setLoading(false)
    }
  }, [mode, input, contentType, file, deep, useWs])

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-100">Scan</h1>
        <p className="text-sm text-gray-400 mt-1">Detect prompt injection, steganography, and cloaking attacks.</p>
      </div>

      {/* Mode tabs */}
      <div className="flex gap-1 bg-gray-800 rounded-lg p-1 w-fit">
        {(['url', 'content', 'file'] as Mode[]).map(m => (
          <button
            key={m}
            onClick={() => setMode(m)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
              mode === m ? 'bg-indigo-600 text-white' : 'text-gray-400 hover:text-gray-200'
            }`}
          >
            {m === 'url' && <Link2 size={14} />}
            {m === 'content' && <FileText size={14} />}
            {m === 'file' && <Upload size={14} />}
            {m.charAt(0).toUpperCase() + m.slice(1)}
          </button>
        ))}
      </div>

      {/* Inputs */}
      <div className="space-y-3">
        {mode === 'url' && (
          <input
            type="url"
            value={input}
            onChange={e => setInput(e.target.value)}
            placeholder="https://example.com"
            className="w-full bg-gray-800 border border-gray-600 rounded-lg px-4 py-2.5 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:border-indigo-500"
          />
        )}

        {mode === 'content' && (
          <>
            <div className="flex gap-2 items-center">
              <select
                value={contentType}
                onChange={e => setContentType(e.target.value)}
                className="bg-gray-800 border border-gray-600 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-indigo-500"
              >
                <option value="text/html">text/html</option>
                <option value="text/plain">text/plain</option>
                <option value="image/png">image/png (base64)</option>
                <option value="image/jpeg">image/jpeg (base64)</option>
              </select>
            </div>
            <textarea
              value={input}
              onChange={e => setInput(e.target.value)}
              placeholder="Paste HTML, text, or base64-encoded image..."
              rows={8}
              className="w-full bg-gray-800 border border-gray-600 rounded-lg px-4 py-2.5 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:border-indigo-500 font-mono resize-y"
            />
          </>
        )}

        {mode === 'file' && (
          <div
            className="border-2 border-dashed border-gray-600 rounded-lg p-8 text-center hover:border-indigo-500 transition-colors cursor-pointer"
            onClick={() => document.getElementById('file-input')?.click()}
            onDragOver={e => e.preventDefault()}
            onDrop={e => { e.preventDefault(); const f = e.dataTransfer.files[0]; if (f) setFile(f) }}
          >
            <Upload size={24} className="mx-auto text-gray-500 mb-2" />
            {file
              ? <p className="text-sm text-indigo-400 font-medium">{file.name} ({(file.size / 1024).toFixed(1)} KB)</p>
              : <p className="text-sm text-gray-500">Drop a file here or click to browse</p>
            }
            <input id="file-input" type="file" className="hidden" onChange={e => setFile(e.target.files?.[0] ?? null)} />
          </div>
        )}

        <div className="flex items-center gap-4 flex-wrap">
          <label className="flex items-center gap-2 text-sm text-gray-400 cursor-pointer select-none">
            <input type="checkbox" checked={deep} onChange={e => setDeep(e.target.checked)} className="rounded" />
            Deep scan (Tier 3 — requires torch)
          </label>
          {(mode === 'url' || mode === 'content') && (
            <label className="flex items-center gap-2 text-sm text-gray-400 cursor-pointer select-none">
              <input type="checkbox" checked={useWs} onChange={e => setUseWs(e.target.checked)} className="rounded" />
              Stream via WebSocket
            </label>
          )}
        </div>
      </div>

      <button
        onClick={runScan}
        disabled={loading || (!input && !file)}
        className="flex items-center gap-2 px-5 py-2.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg text-sm font-semibold text-white transition-colors"
      >
        {loading ? <Loader2 size={16} className="animate-spin" /> : <Shield size={16} />}
        {loading ? 'Scanning…' : 'Run Scan'}
      </button>

      {error && (
        <div className="rounded-lg border border-red-700 bg-red-900/30 p-4 text-sm text-red-300">
          {error}
        </div>
      )}

      {/* WebSocket event log */}
      {useWs && wsEvents.length > 0 && (
        <div className="rounded-lg border border-gray-700 bg-gray-900 p-4 space-y-1 font-mono text-xs text-gray-400 max-h-48 overflow-y-auto">
          {wsEvents.map((ev, i) => <div key={i}>{ev}</div>)}
        </div>
      )}

      {/* Scan result */}
      {result && <ScanResultPanel result={result} />}
    </div>
  )
}

function ScanResultPanel({ result }: { result: ScanResponse }) {
  return (
    <div className="space-y-4">
      {/* Summary bar */}
      <div className={`rounded-xl border p-5 flex items-start gap-4 ${
        result.safe
          ? 'border-green-700 bg-green-900/20'
          : 'border-red-700 bg-red-900/20'
      }`}>
        {result.safe
          ? <Shield size={28} className="text-green-400 shrink-0 mt-0.5" />
          : <ShieldAlert size={28} className="text-red-400 shrink-0 mt-0.5" />
        }
        <div className="flex-1">
          <div className="flex items-center gap-3 flex-wrap">
            <span className={`text-lg font-bold ${result.safe ? 'text-green-300' : 'text-red-300'}`}>
              {result.safe ? 'Safe' : `Unsafe — ${result.threat_count} threat${result.threat_count !== 1 ? 's' : ''}`}
            </span>
            {result.max_severity && <SeverityBadge severity={result.max_severity} />}
          </div>
          <div className="mt-1 flex gap-4 text-xs text-gray-400 flex-wrap">
            <span>Confidence: <strong className="text-gray-200">{(result.confidence * 100).toFixed(0)}%</strong></span>
            <span>Scan time: <strong className="text-gray-200">{result.scan_time_ms.toFixed(1)}ms</strong></span>
            {Object.entries(result.tier_timings).map(([k, v]) => (
              <span key={k}>{k.toUpperCase()}: <strong className="text-gray-200">{v.toFixed(1)}ms</strong></span>
            ))}
          </div>
        </div>
      </div>

      {/* Threats */}
      {result.threats.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wide">Threats</h3>
          {result.threats.map((t, i) => <ThreatCard key={i} threat={t} />)}
        </div>
      )}

      {/* Sanitized content */}
      {result.sanitized_content && (
        <details className="rounded-lg border border-gray-700 bg-gray-800/50">
          <summary className="px-4 py-3 text-sm font-medium text-gray-300 cursor-pointer hover:text-gray-100">
            Sanitized content ({result.sanitized_content.length} chars)
          </summary>
          <pre className="px-4 pb-4 text-xs text-gray-400 font-mono whitespace-pre-wrap overflow-auto max-h-64">
            {result.sanitized_content}
          </pre>
        </details>
      )}
    </div>
  )
}
