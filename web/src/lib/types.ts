export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type Action = 'act' | 'attend' | 'track'
export type RunStatus = 'queued' | 'running' | 'completed' | 'incomplete' | 'failed'
export type Summary = { planned?: number; executed?: number; confirmed?: number; needs_follow_up?: number; passed?: number; total?: number; files?: number; dependencies?: number; candidates?: number; sast?: number; secrets?: number; sca?: number; iac?: number; cicd?: number; severities?: Record<string, number>; priorities?: Record<string, number>; kev?: number; fixable?: number; tools?: { name: string; version: string; status: string }[] }
export type RunRow = { id: string; type: string; status: RunStatus | string; created_at: string; fixture: string; variant?: string; context?: string; started_at?: string; finished_at?: string; source?: { name: string; provider: string; sha256?: string; files?: number }; summary: Summary }
export type Page<T> = { items: T[]; total: number; limit: number; offset: number }
export type OwaspCoverage = { id: string; title: string; status: 'partial' | 'not_tested' | 'inconclusive'; probe_ids: string[]; rules?: number; findings?: number; reason: string }
export type ScanStep = { id: string; name: string; status: string; detail: string; tool?: { name: string; version: string; image: string; duration_s: number | null } }
export type Dashboard = {
  window_days: number; generated_at: string
  kpis: { security_score: { value: number; formula: string }; open: { total: number; critical: number; high: number; medium: number; low: number }; found_in_window: number; fixed_in_window: number; fix_rate: number | null; mttr_days: number | null; runs_in_window: number; assets: number; kev_open: number }
  issues_over_time: { day: string; critical: number; high: number; medium: number; low: number }[]
  open_vs_fixed: { day: string; found: number; fixed: number }[]
  top_assets: { name: string; last_run: string; last_run_at: string; open: number; critical: number; high: number; medium: number; low: number; kev: number; trend: number | null }[]
  by_cwe: { cwe: number; name: string | null; count: number }[]
  exploitability: { kev: { cve: string; package: string | null; asset: string; fixed_version: string | null; ransomware: boolean }[]; high_epss: { cve: string; package: string | null; asset: string; epss: number; fixed_version: string | null }[]; kev_total?: number; epss_total?: number }
  activity: { day: string; runs: number }[]
  recent_runs: RunRow[]
  top_issues: { title: string; severity: string; asset: string; action: string | null; run_id: string | null; epss: number | null; kev: boolean; fingerprint: string }[]
  kev_news: { added_7d: number; added_30d: number; catalog_version: string | null; items: { cve: string; name: string | null; date_added: string | null; ransomware: boolean; affects: boolean }[] }
  cve_news: { published_7d: number; published_30d: number | null; per_day: { day: string; count: number }[]; fetched_at: string | null; refreshing: boolean; sample: number; by_severity: Record<string, number>; total_reported: number | null; items: { cve: string; published: string | null; score: number | null; severity: string | null; description: string; affects: boolean }[] }
  tools: { name: string; version: string; status: string }[]
}
export const severityLabel: Record<string, string> = { critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja', info: 'Info' }
export const actionLabel: Record<string, string> = { act: 'Actuar ya', attend: 'Atender', track: 'Seguimiento' }
export const statusLabel = (status: string) => ({ completed: 'Completada', incomplete: 'Incompleta', failed: 'Fallida', queued: 'En cola', running: 'Analizando…' }[status] ?? status)
export const formatDate = (stamp: string) => new Date(stamp).toLocaleString('es-CO', { dateStyle: 'medium', timeStyle: 'short' })

// «1 hallazgo», «2 hallazgos»: el número siempre concuerda con el sustantivo.
export const plural = (count: number, one: string, many: string) => `${count} ${count === 1 ? one : many}`
