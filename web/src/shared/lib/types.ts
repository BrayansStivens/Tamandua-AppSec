import i18n from '@/shared/i18n'

// Plazo de corrección de un hallazgo (tamandua/modules/findings/sla.py); lo reexporta features/findings/sla.
export type Sla = { days: number; due: string; days_left: number; state: 'overdue' | 'soon' | 'ok' }
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type Action = 'act' | 'attend' | 'track'
export type RunStatus = 'queued' | 'running' | 'completed' | 'incomplete' | 'failed'
export type Summary = { files?: number; dependencies?: number; candidates?: number; sast?: number; secrets?: number; sca?: number; iac?: number; cicd?: number; severities?: Record<string, number>; priorities?: Record<string, number>; kev?: number; fixable?: number; tools?: { name: string; version: string; status: string }[] }
// Why a run exists: a branch push, new advisories, an import (with the tool and its scope)…
export type RunTrigger = { kind: string; head_sha?: string; tool?: string; scope?: string; commit?: string; branch?: string }
export type RunRow = { id: string; type: string; status: RunStatus | string; created_at: string; target?: string; variant?: string; context?: string; trigger?: RunTrigger; started_at?: string; finished_at?: string; source?: { name: string; provider: string; sha256?: string; files?: number }; summary: Summary }
export type Page<T> = { items: T[]; total: number; limit: number; offset: number }
export type OwaspCoverage = { id: string; title: string; status: 'partial' | 'not_tested' | 'inconclusive'; rules?: number; findings?: number; reason: string }
export type ScanStep = { id: string; name: string; status: string; detail: string; tool?: { name: string; version: string; image: string; duration_s: number | null } }
export type Dashboard = {
  window_days: number; generated_at: string
  kpis: { security_score: { value: number; formula: string }; open: { total: number; critical: number; high: number; medium: number; low: number }; found_in_window: number; fixed_in_window: number; fix_rate: number | null; mttr_days: number | null; runs_in_window: number; assets: number; kev_open: number
    sla?: { overdue: number; soon: number; overdue_by_severity: Record<string, number>; days: Record<string, number | null> } }
  issues_over_time: { day: string; critical: number; high: number; medium: number; low: number }[]
  open_vs_fixed: { day: string; found: number; fixed: number }[]
  top_assets: { name: string; last_run: string; last_run_at: string; open: number; critical: number; high: number; medium: number; low: number; kev: number; trend: number | null }[]
  by_cwe: { cwe: number; name: string | null; count: number }[]
  exploitability: { kev: { cve: string; package: string | null; asset: string; fixed_version: string | null; ransomware: boolean }[]; high_epss: { cve: string; package: string | null; asset: string; epss: number; fixed_version: string | null }[]; kev_total?: number; epss_total?: number }
  activity: { day: string; runs: number }[]
  recent_runs: RunRow[]
  top_issues: { title: string; severity: string; asset: string; action: string | null; run_id: string | null; epss: number | null; kev: boolean; fingerprint: string; sla?: Sla | null }[]
  kev_news: { added_7d: number; added_30d: number; catalog_version: string | null; items: { cve: string; name: string | null; date_added: string | null; ransomware: boolean; affects: boolean }[] }
  cve_news: { published_7d: number; published_30d: number | null; per_day: { day: string; count: number }[]; fetched_at: string | null; refreshing: boolean; sample: number; by_severity: Record<string, number>; total_reported: number | null; items: { cve: string; published: string | null; score: number | null; severity: string | null; description: string; affects: boolean }[] }
  tools: { name: string; version: string; status: string }[]
}
// Getters so each read follows the current language.
export const severityLabel: Record<string, string> = {
  get critical() { return i18n.t('common:severity.critical') }, get high() { return i18n.t('common:severity.high') },
  get medium() { return i18n.t('common:severity.medium') }, get low() { return i18n.t('common:severity.low') }, get info() { return i18n.t('common:severity.info') },
}
export const actionLabel: Record<string, string> = {
  get act() { return i18n.t('common:priority.act') }, get attend() { return i18n.t('common:priority.attend') }, get track() { return i18n.t('common:priority.track') },
}
const RUN_STATUS: Record<string, string> = {
  completed: 'common:run_status.completed', incomplete: 'common:run_status.incomplete', failed: 'common:run_status.failed',
  queued: 'common:run_status.queued', running: 'common:run_status.running',
}
export const statusLabel = (status: string) => RUN_STATUS[status] ? i18n.t(RUN_STATUS[status]) : status
export { formatDate } from '@/shared/i18n/format'

// Deprecated: use i18next plurals (`key_one` / `key_other` with `count`). Kept while other screens still call it.
export const plural = (count: number, one: string, many: string) => `${count} ${count === 1 ? one : many}`
