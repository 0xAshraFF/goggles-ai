import type { ScanResponse, HistoryPage, Stats } from './types'

const BASE = ''  // proxied by Vite dev server

export async function scanUrl(url: string, deep = false): Promise<ScanResponse> {
  const res = await fetch(`${BASE}/scan/url`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, deep }),
  })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

export async function scanContent(
  content: string,
  contentType = 'text/html',
  filename = '',
  deep = false,
): Promise<ScanResponse> {
  const res = await fetch(`${BASE}/scan/content`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content, content_type: contentType, filename, deep }),
  })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

export async function scanFile(file: File, deep = false): Promise<ScanResponse> {
  const form = new FormData()
  form.append('file', file)
  form.append('deep', String(deep))
  const res = await fetch(`${BASE}/scan/file`, { method: 'POST', body: form })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

export async function getHistory(page = 1, pageSize = 20, safeOnly?: boolean): Promise<HistoryPage> {
  const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) })
  if (safeOnly !== undefined) params.set('safe_only', String(safeOnly))
  const res = await fetch(`${BASE}/history?${params}`)
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

export async function getHistoryItem(id: string): Promise<ScanResponse> {
  const res = await fetch(`${BASE}/history/${id}`)
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

export async function clearHistory(): Promise<void> {
  await fetch(`${BASE}/history`, { method: 'DELETE' })
}

export async function getStats(): Promise<Stats> {
  const res = await fetch(`${BASE}/stats`)
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

export function openWsScan(): WebSocket {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  return new WebSocket(`${proto}://${location.host}/ws/scan`)
}
