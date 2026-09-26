import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { TFunction } from 'i18next'
import { formatDate } from '@/shared/i18n/format'
import { usePaged } from '@/shared/lib/usePaged'
import { Pagination } from '@/shared/ui/pagination'
import { BellRing, Boxes, Code2, GitPullRequest, Plus, Radar, Search, ShieldCheck } from 'lucide-react'
import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { Card, CardContent } from '@/shared/ui/card'
import { Input } from '@/shared/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger } from '@/shared/ui/select'
import { SkeletonTable } from '@/shared/ui/loading'
import { BatchPanel, useBatches } from '@/features/analyses/batches'

export type AnalysisRow = { id: string; type: string; status: string; created_at: string; variant?: string; target?: string; source?: { name: string }; trigger?: { kind: string; head_sha?: string }; summary: { candidates?: number; severities?: Record<string, number>; kev?: number } }

type T = TFunction<'analyses'>
const TYPE = { repository_scan: 'run_type.repository_scan', image_scan: 'run_type.image_scan', pr_review: 'run_type.pr_review', advisory_watch: 'run_type.advisory_watch' } as const
const STATUS = { completed: 'common:run_status.completed', incomplete: 'common:run_status.incomplete', failed: 'common:run_status.failed', queued: 'common:run_status.queued', running: 'common:run_status.running' } as const
const typeLabel = (t: T, type: string) => type in TYPE ? t(TYPE[type as keyof typeof TYPE]) : type
const statusLabel = (t: T, status: string) => status in STATUS ? t(STATUS[status as keyof typeof STATUS]) : status
const typeIcon = (type: string) => type === 'advisory_watch' ? BellRing : type === 'repository_scan' ? Code2 : type === 'image_scan' ? Boxes : type === 'pr_review' ? GitPullRequest : ShieldCheck
const rowName = (t: T, row: AnalysisRow) => row.type === 'advisory_watch' ? row.source?.name ?? row.target ?? t('list.fallback.asset') : row.type === 'repository_scan' ? row.source?.name ?? t('list.fallback.repository') : row.type === 'image_scan' ? row.target ?? row.source?.name ?? t('list.fallback.image') : row.type === 'pr_review' ? row.target ?? row.source?.name ?? t('list.fallback.pull_request') : row.target ?? t('list.fallback.analysis')
const rowIssues = (t: T, row: AnalysisRow) => { const count = row.summary.candidates ?? 0
  return { value: count, hint: row.type === 'pr_review' ? t('list.hint.pr_review', { count }) : row.type === 'advisory_watch' ? t('list.hint.advisory_watch', { count }) : t('list.hint.candidates', { count }) } }
const SEVERITIES = [['critical', 'list.severity_letter.critical', 'common:severity.critical', 'bg-danger-solid text-on-solid'], ['high', 'list.severity_letter.high', 'common:severity.high', 'bg-attention-soft text-attention'],
  ['medium', 'list.severity_letter.medium', 'common:severity.medium', 'bg-warning-soft text-warning'], ['low', 'list.severity_letter.low', 'common:severity.low', 'bg-info-soft text-info']] as const

export function AnalysisList({ refreshKey, onOpen, onNew, viewer }: { refreshKey: number; onOpen: (id: string) => void; onNew: () => void; viewer: { username: string; admin: boolean } }) {
  const { t } = useTranslation('analyses')
  const [query, setQuery] = useState('')
  const [status, setStatus] = useState('all')
  const [type, setType] = useState('all')
  // La lista se pide paginada al servidor: con mil ejecuciones no se cargan mil filas.
  const page = usePaged<AnalysisRow>('/api/runs/page', { q: query.trim() || undefined, status: status === 'all' ? undefined : status, type: type === 'all' ? undefined : type }, 25, refreshKey)
  const visible = page.items
  // Lotes (varios repositorios, una organización o varias imágenes): su progreso, arriba de la lista.
  const { active: batch, last: lastBatch, reload: reloadBatches } = useBatches()

  return <Card className="border-app-line bg-panel"><CardContent className="space-y-5 p-5">
    <BatchPanel active={batch} last={lastBatch} viewer={viewer} onChanged={() => void reloadBatches()} />
    <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
      <div className="relative min-w-0 flex-1 sm:max-w-xs"><Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-app-subtle" /><Input aria-label={t('list.search')} placeholder={t('list.search_placeholder')} value={query} onChange={event => setQuery(event.target.value)} className="border-app-line bg-app-soft pl-9" /></div>
      <Select value={status} onValueChange={value => setStatus(value ?? 'all')}><SelectTrigger aria-label={t('list.filter_status')} size="sm" className="min-w-40 border-app-line bg-app-soft text-app-secondary">{status === 'all' ? t('list.all_statuses') : statusLabel(t, status)}</SelectTrigger><SelectContent align="start" className="border border-app-line bg-panel p-1 text-app-fg shadow-xl"><SelectItem value="all">{t('list.all_statuses')}</SelectItem><SelectItem value="running">{t('list.status_running')}</SelectItem><SelectItem value="completed">{t('common:run_status.completed')}</SelectItem><SelectItem value="incomplete">{t('common:run_status.incomplete')}</SelectItem><SelectItem value="failed">{t('common:run_status.failed')}</SelectItem></SelectContent></Select>
      <Select value={type} onValueChange={value => setType(value ?? 'all')}><SelectTrigger aria-label={t('list.filter_type')} size="sm" className="min-w-44 border-app-line bg-app-soft text-app-secondary">{type === 'all' ? t('list.all_types') : typeLabel(t, type)}</SelectTrigger><SelectContent align="start" className="border border-app-line bg-panel p-1 text-app-fg shadow-xl"><SelectItem value="all">{t('list.all_types')}</SelectItem><SelectItem value="repository_scan">{t('run_type.repository_scan')}</SelectItem><SelectItem value="image_scan">{t('run_type.image_scan')}</SelectItem><SelectItem value="pr_review">{t('run_type.pr_review')}</SelectItem><SelectItem value="advisory_watch">{t('run_type.advisory_watch')}</SelectItem></SelectContent></Select>
    </div>
    {page.error && <p role="alert" className="text-sm text-danger">{page.error}</p>}
    {page.total === 0 && page.loading ? <SkeletonTable rows={6} columns={5} label={t('list.loading')} />
      : page.total === 0
      ? <div className="flex flex-col items-center gap-3 py-16 text-center"><Radar className="size-7 text-app-subtle" /><p className="font-medium">{t('list.empty_title')}</p><p className="max-w-sm text-sm text-app-muted">{t('list.empty_text')}</p><Button onClick={onNew} className="mt-1 bg-primary text-primary-foreground hover:bg-primary/90"><Plus /> {t('list.new')}</Button></div>
      : <div className="overflow-hidden rounded-xl border border-app-line">
        <div className="hidden grid-cols-[110px_minmax(0,1fr)_170px_120px_150px] gap-3 border-b border-app-line px-4 py-3 text-xs text-app-subtle md:grid"><span>{t('list.columns.status')}</span><span>{t('list.columns.analysis')}</span><span>{t('list.columns.type')}</span><span>{t('list.columns.findings')}</span><span>{t('list.columns.started')}</span></div>
        {visible.map(row => { const Icon = typeIcon(row.type); const issues = rowIssues(t, row)
          return <button key={row.id} onClick={() => onOpen(row.id)} className="grid w-full gap-2 border-b border-app-line px-4 py-3 text-left transition last:border-b-0 hover:bg-app-soft md:grid-cols-[110px_minmax(0,1fr)_170px_120px_150px] md:items-center">
            <Badge variant="outline" className={`w-fit ${row.status === 'completed' ? 'border-brand/30 text-brand' : row.status === 'failed' ? 'border-danger-line text-danger' : row.status === 'running' || row.status === 'queued' ? 'motion-safe:animate-pulse border-brand/30 text-brand' : 'border-warning-line text-warning'}`}>{statusLabel(t, row.status)}</Badge>
            <span className="flex min-w-0 items-center gap-2"><Icon className="size-4 shrink-0 text-app-muted" /><span className="min-w-0"><span className="block truncate text-sm font-medium">{rowName(t, row)}</span><span className="font-mono text-xs text-app-subtle">{row.id.slice(0, 8)}</span>{row.trigger?.kind === 'branch' && <span className="ml-2 text-xs text-app-subtle">{row.trigger.head_sha ? t('list.trigger_branch_sha', { sha: row.trigger.head_sha.slice(0, 7) }) : t('list.trigger_branch')}</span>}{row.trigger?.kind === 'advisories' && <span className="ml-2 text-xs text-app-subtle">{t('list.trigger_advisories')}</span>}</span></span>
            <span className="text-xs text-app-muted">{typeLabel(t, row.type)}</span>
            {row.summary.severities
              ? <span className="flex flex-wrap items-center gap-1 text-[11px]">{SEVERITIES.map(([level, letter, name, cls]) => (row.summary.severities?.[level] ?? 0) > 0 ? <span key={level} role="img" className={`rounded px-1.5 py-0.5 font-mono ${cls}`} title={t(name)} aria-label={t('list.severity_count', { severity: t(name), value: row.summary.severities?.[level] })}>{t(letter)}{row.summary.severities?.[level]}</span> : null)}{row.summary.kev ? <span className="rounded bg-danger-solid px-1.5 py-0.5 font-mono text-on-solid" title="CISA KEV">KEV</span> : null}{issues.value === 0 && <span className="text-app-subtle">0</span>}</span>
              : <span className="text-xs text-app-muted"><span className="font-mono text-sm text-app-secondary">{issues.value}</span> {issues.hint}</span>}
            <span className="text-xs text-app-muted">{formatDate(row.created_at)}</span>
          </button> })}
        <Pagination total={page.total} limit={page.limit} offset={page.offset} onPrev={page.prev} onNext={page.next} noun={t('list.noun')} />
      </div>}
  </CardContent></Card>
}
