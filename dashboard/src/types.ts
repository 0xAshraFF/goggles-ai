export interface Threat {
  type: string
  label: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  tier: number
  detail: string
  plain_summary: string
  technique: string
  outcome: string
  location: string
}

export type Action = 'allow' | 'sanitize' | 'block'

export interface ScanResponse {
  id: string
  timestamp: number
  hidden_content_found: boolean
  action: Action
  confidence: number
  threat_count: number
  max_severity: string | null
  scan_time_ms: number
  threats: Threat[]
  sanitized_content: string | null
  tier_timings: Record<string, number>
}

export interface HistoryItem {
  id: string
  timestamp: number
  source: string
  source_hint: string
  hidden_content_found: boolean
  action: Action
  threat_count: number
  max_severity: string | null
  scan_time_ms: number
}

export interface HistoryPage {
  total: number
  page: number
  page_size: number
  items: HistoryItem[]
}

export interface Stats {
  total_scans: number
  action_counts: Record<Action, number>
  threat_type_counts: Record<string, number>
  severity_counts: Record<string, number>
  mean_scan_time_ms: number
  scan_sources: Record<string, number>
}

export type WsEvent =
  | { event: 'start'; id: string; source: string }
  | { event: 'progress'; message: string }
  | { event: 'tier'; tier: string; time_ms: number }
  | { event: 'threat'; threat: Threat }
  | { event: 'complete'; id: string; result: ScanResponse }
  | { event: 'error'; message: string }
