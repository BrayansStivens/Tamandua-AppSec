import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { useCallback, useState, type FormEvent } from 'react'
import { Trans, useTranslation } from 'react-i18next'
import { ArrowRight, ExternalLink, Flame, LoaderCircle, Search, ShieldCheck, ShieldAlert, X } from 'lucide-react'
import { sevColor } from '@/shared/charts/charts'
import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import { Input } from '@/shared/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger } from '@/shared/ui/select'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/shared/ui/sheet'
import { Bone, Skeleton, SkeletonList } from '@/shared/ui/loading'
import { Pagination } from '@/shared/ui/pagination'
import { api, query } from '@/shared/api/http'
import { usePaged } from '@/shared/lib/usePaged'
import { readRoute, writeRoute } from '@/shared/lib/route'
import { formatDay, formatNumber, formatPercent } from '@/shared/i18n/format'

export type CveRow = { id: string; published: string | null; severity: string | null; score: number | null; version: string | null; description: string; kev: boolean; epss: number | null; epss_percentile: number | null; affects?: boolean }
type CvePage = { items: CveRow[]; total: number; limit: number; offset: number; mine_total?: number }
export type CveOverview = {
  count: number; kev_total: number; years: { year: number; count: number }[]
  latest_kev: { id: string; date_added: string; name: string | null; ransomware: boolean; severity: string | null; score: number | null }[]
  daily: { day: string; severity: string; count: number }[]
  sync: { phase: 'pending' | 'backfill' | 'ready'; progress: number; nvd_total: number | null; synced_at: string | null; running: boolean; error: string | null }
}
type Euvd = { id: string; url: string | null; score: number | null; severity: string | null; exploited_since: string | null }
type CveDetail = CveRow & { vector: string | null; modified: string | null; cwe: string[]; references: { url: string; tags: string[] }[]; score_source?: 'nvd' | 'euvd' | null; euvd?: Euvd | null
  kev_detail: { date_added: string; due_date?: string; ransomware: boolean; name: string | null } | null }
type AffectedAsset = { asset: string; name: string; open: number; fixed: number; packages: string[] }
const AFFECTED_PAGE = 10

// [value, catalog key]
const SEVERITIES: [string, string][] = [['', 'cves:filters.all_severities'], ['critical', 'common:severity.critical'], ['high', 'common:severity.high'], ['medium', 'common:severity.medium'], ['low', 'common:severity.low'], ['none', 'cves:unscored']]
const SORTS: [string, string][] = [['published', 'cves:sort.published'], ['score', 'cves:sort.score'], ['epss', 'cves:sort.epss']]
const SIZES = [25, 50, 100]
const SEVERITY_LABEL: Record<string, string> = Object.fromEntries(SEVERITIES.filter(([value]) => value))
const day = (stamp: string | null) => stamp ? formatDay(stamp, { day: '2-digit', month: 'short', year: 'numeric' }).replace(/ de /g, ' ') : '—'
const percent = (value: number | null) => value === null ? '—' : formatPercent(value, value >= 0.1 ? 0 : 1)

export function SeverityPill({ severity, score }: { severity: string | null; score?: number | null }) {
  const { t } = useTranslation('cves')
  if (!severity) return <Badge variant="outline" className="border-app-line text-[11px] text-app-subtle">{t('unscored')}</Badge>
  return <Badge variant="outline" className="gap-1.5 border-app-line text-[11px] text-app-secondary"><span className="size-2 rounded-full" style={{ background: sevColor[severity] ?? 'var(--axis-line)' }} />{SEVERITY_LABEL[severity] ? t(SEVERITY_LABEL[severity]) : severity}{score !== undefined && score !== null ? <span className="font-mono text-app-muted">{score.toFixed(1)}</span> : null}</Badge>
}

type Filters = { q: string; severity: string; kev: boolean; mine: boolean; year: string; sort: string; page: number; size: number }
const fromRoute = (): Filters => {
  const params = readRoute().params
  const size = Number(params.get('size'))
  return { q: params.get('q') ?? '', severity: params.get('severity') ?? '', kev: params.get('kev') === '1', mine: params.get('mine') === '1', year: params.get('year') ?? '',
    sort: SORTS.some(([value]) => value === params.get('sort')) ? params.get('sort')! : 'published', page: Math.max(1, Number(params.get('page')) || 1), size: SIZES.includes(size) ? size : 25 }
}

export function CveTracker({ onNew }: { onNew: () => void }) {
  const { t } = useTranslation('cves')
  const [filters, setFilters] = useState<Filters>(fromRoute)
  const [draft, setDraft] = useState(filters.q)
  const [open, setOpen] = useState<string | null>(readRoute().params.get('id'))

  // La URL guarda la búsqueda: refrescar o compartir el enlace deja la misma vista.
  const apply = useCallback((next: Partial<Filters>) => setFilters(current => {
    const merged = { ...current, ...next, page: next.page ?? 1 }
    writeRoute('cves', { q: merged.q, severity: merged.severity, kev: merged.kev ? '1' : null, mine: merged.mine ? '1' : null, year: merged.year, sort: merged.sort === 'published' ? null : merged.sort,
      page: merged.page > 1 ? String(merged.page) : null, size: merged.size === 25 ? null : String(merged.size), id: open }, { replace: true })
    return merged
  }), [open])

  // Resumen y búsqueda en caché (TanStack Query). Al paginar o filtrar se conservan los resultados anteriores
  // mientras llega la página nueva, en lugar de vaciar la tabla.
  const overview = useQuery({ queryKey: ['cve-db', 'overview'], queryFn: ({ signal }) => api.get<CveOverview>('/api/cve-db/overview', { signal }), staleTime: 60_000 }).data ?? null
  const search = useQuery({
    queryKey: ['cve-db', 'search', filters],
    queryFn: ({ signal }) => api.get<CvePage>(`/api/cve-db?${query({ q: filters.q, severity: filters.severity || undefined, kev: filters.kev ? 1 : undefined, mine: filters.mine ? 1 : undefined, year: filters.year || undefined,
      sort: filters.sort, limit: filters.size, offset: Math.min(10000, (filters.page - 1) * filters.size) })}`, { signal }),
    placeholderData: keepPreviousData,
  })
  const page = search.data ?? null
  const loading = search.isFetching
  const error = search.error ? (search.error instanceof Error ? search.error.message : String(search.error)) : ''
  const show = (id: string | null) => {
    setOpen(id)
    const params = Object.fromEntries(readRoute().params.entries())
    writeRoute('cves', { ...params, id }, { replace: true })
  }
  const submit = (event: FormEvent) => { event.preventDefault(); apply({ q: draft.trim() }) }
  const mineTotal = page?.mine_total ?? null
  const pages = page ? Math.max(1, Math.ceil(Math.min(page.total, 10000 + filters.size) / filters.size)) : 1

  return <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_320px]">
    <div className="min-w-0 space-y-4">
      {overview && overview.sync.phase !== 'ready' && <SyncBanner overview={overview} />}
      <Card className="gap-0 border-app-line bg-panel py-0"><CardContent className="space-y-3 p-4">
        <form onSubmit={submit} className="space-y-2">
          <div className="flex gap-2"><div className="relative min-w-0 flex-1"><Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-app-subtle" />
            <Input value={draft} onChange={event => setDraft(event.target.value)} maxLength={100} aria-label={t('search.label')} placeholder={t('search.placeholder')} className="h-9 border-app-line bg-app-soft pl-9" /></div>
          <Button type="submit" className="h-9 bg-primary px-5 text-primary-foreground hover:bg-primary/90">{t('common:actions.search')}</Button></div>
          <div className="flex flex-wrap gap-2">
          <Select value={filters.severity || 'all'} onValueChange={value => apply({ severity: !value || value === 'all' ? '' : value })}><SelectTrigger aria-label={t('filters.severity')} className="h-9 min-w-44 border-app-line bg-app-soft">{t(SEVERITIES.find(([value]) => value === filters.severity)?.[1] ?? 'cves:filters.all_severities')}</SelectTrigger>
            <SelectContent className="border border-app-line bg-panel p-1 text-app-fg shadow-xl">{SEVERITIES.map(([value, label]) => <SelectItem key={value || 'all'} value={value || 'all'}>{t(label)}</SelectItem>)}</SelectContent></Select>
          <Select value={filters.sort} onValueChange={value => apply({ sort: value ?? 'published' })}><SelectTrigger aria-label={t('filters.sort')} className="h-9 min-w-36 border-app-line bg-app-soft">{t(SORTS.find(([value]) => value === filters.sort)?.[1] ?? 'cves:sort.published')}</SelectTrigger>
            <SelectContent className="border border-app-line bg-panel p-1 text-app-fg shadow-xl">{SORTS.map(([value, label]) => <SelectItem key={value} value={value}>{t(label)}</SelectItem>)}</SelectContent></Select>
          <label className="flex h-9 cursor-pointer items-center gap-2 rounded-lg border border-app-line bg-app-soft px-3 text-sm whitespace-nowrap"><input type="checkbox" checked={filters.kev} onChange={event => apply({ kev: event.target.checked })} className="size-3.5 accent-[var(--primary)]" />{t('filters.kev_only')}</label>
          <label className="flex h-9 cursor-pointer items-center gap-2 rounded-lg border border-app-line bg-app-soft px-3 text-sm whitespace-nowrap"><input type="checkbox" checked={filters.mine} onChange={event => apply({ mine: event.target.checked })} className="size-3.5 accent-[var(--primary)]" />{t('filters.mine')}{mineTotal !== null ? <span className="text-xs text-app-subtle tabular-nums">({formatNumber(mineTotal)})</span> : null}</label>
          </div>
        </form>
        {(filters.q || filters.year || filters.severity || filters.kev || filters.mine) && <div className="flex flex-wrap items-center gap-1.5 text-xs">
          <span className="text-app-subtle">{t('filters.label')}</span>
          {filters.q && <Chip label={t('filters.query_chip', { q: filters.q })} onClear={() => { setDraft(''); apply({ q: '' }) }} />}
          {filters.year && <Chip label={t('filters.year_chip', { year: filters.year })} onClear={() => apply({ year: '' })} />}
          {filters.severity && <Chip label={SEVERITY_LABEL[filters.severity] ? t(SEVERITY_LABEL[filters.severity]) : filters.severity} onClear={() => apply({ severity: '' })} />}
          {filters.kev && <Chip label={t('filters.kev_only')} onClear={() => apply({ kev: false })} />}
          {filters.mine && <Chip label={t('filters.mine_chip')} onClear={() => apply({ mine: false })} />}
          <button type="button" onClick={() => { setDraft(''); apply({ q: '', year: '', severity: '', kev: false, mine: false }) }} className="text-app-muted underline-offset-2 hover:underline">{t('filters.clear_all')}</button>
        </div>}
      </CardContent></Card>

      <Card className="gap-0 overflow-hidden border-app-line bg-panel py-0">
        {error ? <div role="alert" className="m-4 rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-sm text-danger">{error}</div>
          : !page ? <div className="p-4"><Skeleton rows={6} /></div>
          : <div className={`overflow-x-auto transition-opacity ${loading ? 'opacity-60' : ''}`}>
            <table className="w-full min-w-[720px] table-fixed text-sm">
              <thead><tr className="border-b border-app-line text-left text-xs text-app-subtle">
                <th className="w-40 px-4 py-2.5 font-normal">CVE</th><th className="w-24 px-3 py-2.5 font-normal">{t('table.severity')}</th><th className="w-16 px-3 py-2.5 text-right font-normal">CVSS</th>
                <th className="w-16 px-3 py-2.5 text-right font-normal">EPSS</th><th className="w-28 px-3 py-2.5 font-normal">{t('table.published')}</th><th className="px-4 py-2.5 font-normal">{t('table.description')}</th></tr></thead>
              <tbody>{page.items.map(item => <tr key={item.id} onClick={() => show(item.id)} className="cursor-pointer border-b border-app-line align-top last:border-0 hover:bg-app-soft">
                <td className="px-4 py-3 whitespace-nowrap"><button type="button" className="font-mono text-xs font-medium hover:underline" onClick={event => { event.stopPropagation(); show(item.id) }}>{item.id}</button>
                  {item.kev && <span className="ml-2 inline-flex items-center gap-0.5 rounded bg-danger-solid px-1 py-0.5 align-middle text-[11px] font-semibold text-on-solid" title={t('table.kev_title')}><Flame className="size-2.5" />KEV</span>}
                  {item.affects && !filters.mine && <span className="mt-1 block w-fit rounded border border-danger-line px-1 text-[11px] text-danger" title={t('table.affects_title')}>{t('table.affects')}</span>}</td>
                <td className="px-3 py-3"><SeverityPill severity={item.severity} /></td>
                <td className="px-3 py-3 text-right font-mono text-xs tabular-nums">{item.score?.toFixed(1) ?? '—'}</td>
                <td className="px-3 py-3 text-right font-mono text-xs tabular-nums">{percent(item.epss)}</td>
                <td className="px-3 py-3 text-xs whitespace-nowrap text-app-muted">{day(item.published)}</td>
                <td className="px-4 py-3 text-xs leading-5 text-app-muted"><span className="line-clamp-2">{item.description}</span></td>
              </tr>)}</tbody>
            </table>
            {!page.items.length && <div className="flex flex-col items-center gap-2 py-12 text-center"><Search className="size-6 text-app-subtle" /><p className="font-medium">{filters.mine && !mineTotal ? t('empty.mine_title') : t('empty.title')}</p><p className="max-w-sm text-sm text-app-muted">{filters.mine && !mineTotal ? t('empty.mine_none') : filters.mine ? t('empty.mine_filtered') : overview?.count ? t('empty.fewer_words') : t('empty.downloading')}</p></div>}
          </div>}
        {page && page.total > 0 && <div className="flex flex-wrap items-center justify-between gap-3 border-t border-app-line px-4 py-2.5 text-xs text-app-subtle">
          <span className="tabular-nums">{t('pagination.showing', { from: formatNumber(page.offset + 1), to: formatNumber(Math.min(page.offset + page.limit, page.total)), total: formatNumber(page.total) })}</span>
          <div className="flex items-center gap-2">
            <Select value={String(filters.size)} onValueChange={value => apply({ size: Number(value) })}><SelectTrigger size="sm" aria-label={t('pagination.per_page_label')} className="border-app-line bg-app-soft">{t('pagination.per_page', { size: filters.size })}</SelectTrigger>
              <SelectContent className="border border-app-line bg-panel p-1 text-app-fg shadow-xl">{SIZES.map(size => <SelectItem key={size} value={String(size)}>{t('pagination.per_page', { size })}</SelectItem>)}</SelectContent></Select>
            <Button variant="outline" size="sm" disabled={filters.page <= 1} onClick={() => apply({ page: filters.page - 1 })} className="border-app-line bg-app-soft">{t('pagination.previous')}</Button>
            <span className="tabular-nums">{formatNumber(filters.page)} / {formatNumber(pages)}</span>
            <Button variant="outline" size="sm" disabled={filters.page >= pages} onClick={() => apply({ page: filters.page + 1 })} className="border-app-line bg-app-soft">{t('common:actions.next')}</Button>
          </div>
        </div>}
      </Card>
    </div>

    <aside className="space-y-4">
      <Card className="border-app-line bg-panel"><CardHeader className="pb-2"><CardTitle className="text-base">{t('mine.title')}</CardTitle><CardDescription className="text-xs leading-5">{mineTotal === null && error ? t('mine.unavailable')
          : mineTotal === null ? <span role="status" aria-label={t('mine.loading')} className="block space-y-1.5"><Bone className="h-3 w-full" /><Bone className="h-3 w-2/3" /></span>
          : mineTotal ? <Trans t={t} i18nKey="mine.count" count={mineTotal} values={{ value: formatNumber(mineTotal) }} components={{ strong: <strong className="text-app-fg tabular-nums" /> }} />
          : t('mine.cta')}</CardDescription></CardHeader>
        <CardContent>{mineTotal === null ? (error ? null : <Bone className="h-9" />)
          : mineTotal ? <Button variant="outline" onClick={() => apply({ mine: !filters.mine })} className="w-full border-app-line bg-app-soft">{filters.mine ? t('mine.show_all') : t('mine.show_mine')} <ArrowRight /></Button>
          : <Button variant="outline" onClick={onNew} className="w-full border-app-line bg-app-soft">{t('mine.new_scan')} <ArrowRight /></Button>}</CardContent></Card>
      <Card className="border-app-line bg-panel"><CardHeader className="pb-2"><CardTitle className="text-base">{t('years.title')}</CardTitle><CardDescription className="text-xs">{overview ? t('years.local_count', { value: formatNumber(overview.count) }) : <Bone className="h-3 w-32" />}</CardDescription></CardHeader>
        {/* Ley de Hick: un selector con los años (y sus cifras) en lugar de una rejilla de ~30 botones. */}
        <CardContent>{overview?.years.length ? <Select value={filters.year || 'all'} onValueChange={value => apply({ year: !value || value === 'all' ? '' : value })}>
            <SelectTrigger aria-label={t('years.aria', { year: filters.year || t('years.any') })} className="w-full border-app-line bg-app-soft">{filters.year ? t('years.option', { year: filters.year, value: formatNumber(overview.years.find(item => String(item.year) === filters.year)?.count ?? 0) }) : t('years.all')}</SelectTrigger>
            <SelectContent className="border border-app-line bg-panel p-1 text-app-fg shadow-xl"><SelectItem value="all">{t('years.all')}</SelectItem>{overview.years.map(item => <SelectItem key={item.year} value={String(item.year)}>{t('years.option', { year: item.year, value: formatNumber(item.count) })}</SelectItem>)}</SelectContent></Select>
          : <div role="status" aria-label={t('years.loading')}><Bone className="h-9" /></div>}</CardContent></Card>
      <Card className="border-app-line bg-panel"><CardHeader className="pb-2"><CardTitle className="flex items-center gap-2 text-base"><Flame className="size-4 text-danger" />{t('kev.title')}</CardTitle><CardDescription className="text-xs">{overview?.kev_total ? t('kev.latest_total', { value: formatNumber(overview.kev_total) }) : t('kev.latest')}</CardDescription></CardHeader>
        <CardContent className="space-y-0.5">{overview?.latest_kev.length ? overview.latest_kev.map(item => <button key={item.id} type="button" onClick={() => show(item.id)} className="flex w-full items-start justify-between gap-2 rounded-md px-1.5 py-1.5 text-left hover:bg-app-soft">
          <span className="min-w-0"><span className="block font-mono text-xs font-medium">{item.id}</span><span className="block truncate text-[11px] text-app-muted" title={item.name ?? ''}>{item.name}</span></span>
          <span className="flex shrink-0 flex-col items-end gap-0.5 text-[11px] text-app-subtle">{item.date_added}{item.ransomware && <span className="text-danger">{t('kev.ransomware')}</span>}</span></button>)
          : !overview ? <SkeletonList rows={5} dense label={t('kev.loading')} /> : <p className="text-xs text-app-subtle">{t('kev.empty')}</p>}
          <button type="button" onClick={() => apply({ kev: true, sort: 'published' })} className="mt-2 flex items-center gap-1 px-1.5 text-xs text-app-muted hover:text-app-fg">{t('kev.show_all')} <ArrowRight className="size-3" /></button></CardContent></Card>
    </aside>
    <CveSheet id={open} onClose={() => show(null)} />
  </div>
}

function Chip({ label, onClear }: { label: string; onClear: () => void }) {
  const { t } = useTranslation('cves')
  return <span className="inline-flex items-center gap-1 rounded-full border border-app-line bg-app-soft py-0.5 pr-1 pl-2.5">{label}<button type="button" aria-label={t('filters.remove_chip', { label })} onClick={onClear} className="grid size-6 place-items-center rounded-full text-app-subtle hover:bg-accent hover:text-app-fg"><X className="size-3.5" /></button></span>
}

function SyncBanner({ overview }: { overview: CveOverview }) {
  const { t } = useTranslation('cves')
  const { sync } = overview
  return <div className="rounded-xl border border-app-line bg-panel px-4 py-3 text-sm">
    <div className="flex flex-wrap items-center justify-between gap-2"><span className="flex items-center gap-2">{sync.error ? <ShieldAlert className="size-4 text-warning" /> : <LoaderCircle className="size-4 animate-spin text-app-muted" />}
      {sync.phase === 'pending' ? t('sync.preparing') : t('sync.downloading', { percent: formatPercent(sync.progress) })}</span>
      <span className="text-xs text-app-subtle">{sync.nvd_total ? t('sync.count_of', { value: formatNumber(overview.count), total: formatNumber(sync.nvd_total) }) : t('sync.count', { value: formatNumber(overview.count) })}</span></div>
    <div role="progressbar" aria-label={t('sync.aria')} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(sync.progress * 100)} className="mt-2 h-1 overflow-hidden rounded-full bg-app-soft"><div className="h-full rounded-full bg-primary transition-all" style={{ width: `${Math.max(2, sync.progress * 100)}%` }} /></div>
    <p className="mt-2 text-xs text-app-subtle">{sync.error ? t('sync.error') : t('sync.hint')}</p>
  </div>
}

function CveSheet({ id, onClose }: { id: string | null; onClose: () => void }) {
  const { t } = useTranslation('cves')
  const detail = useQuery({ queryKey: ['cve-db', 'item', id], enabled: !!id,
    queryFn: ({ signal }) => api.get<CveDetail>(`/api/cve-db/item?${query({ id: id ?? '' })}`, { signal }) })
  const item = detail.data ?? null
  const error = detail.error ? (detail.error instanceof Error ? detail.error.message : String(detail.error)) : ''
  // Which of your repositories cite it: paged on the server (a widespread CVE can be in hundreds).
  const affected = usePaged<AffectedAsset>('/api/cve-db/affected', { id: id ?? '' }, AFFECTED_PAGE, 0, !!id)
  return <Sheet open={!!id} onOpenChange={next => { if (!next) onClose() }}>
    <SheetContent side="right" className="w-full overflow-y-auto border-app-line sm:max-w-xl">
      <SheetHeader className="border-b border-app-line pb-4"><SheetTitle className="font-mono text-lg">{id}</SheetTitle>
        <SheetDescription>{item ? item.modified ? t('sheet.published_modified', { date: day(item.published), modified: day(item.modified) }) : t('sheet.published', { date: day(item.published) }) : <Bone className="h-3 w-48" />}</SheetDescription></SheetHeader>
      <div className="space-y-5 px-4 pb-6">
        {error && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-sm text-danger">{error}</div>}
        {!item && !error && <Skeleton rows={4} />}
        {item && <>
          <div className="grid grid-cols-3 gap-2">
            <Metric label={`CVSS${item.version ? ` ${item.version}` : ''}${item.score_source === 'euvd' ? ` · ${t('sheet.per_euvd')}` : ''}`} value={item.score?.toFixed(1) ?? '—'} extra={<SeverityPill severity={item.severity} />} />
            <Metric label="EPSS" value={percent(item.epss)} extra={item.epss_percentile !== null ? <span className="text-[11px] text-app-subtle">{t('sheet.percentile', { value: formatNumber(Math.round(item.epss_percentile * 100)) })}</span> : null} />
            <Metric label="CISA KEV" value={item.kev ? t('common:state.yes') : t('common:state.no')} extra={item.kev_detail ? <span className="text-[11px] text-app-subtle">{t('sheet.since', { date: item.kev_detail.date_added })}</span> : null} />
          </div>
          {item.kev_detail && <div className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2.5 text-sm text-danger"><p className="flex items-center gap-2 font-medium"><Flame className="size-4" />{t('sheet.kev_known')}{item.kev_detail.ransomware ? ` · ${t('sheet.kev_ransomware')}` : ''}</p>
            <p className="mt-1 text-xs">{item.kev_detail.name}{item.kev_detail.due_date ? ` · ${t('sheet.federal_due', { date: item.kev_detail.due_date })}` : ''}</p></div>}
          {!item.kev_detail && item.euvd?.exploited_since && <div className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2.5 text-sm text-danger"><p className="flex items-center gap-2 font-medium"><Flame className="size-4" />{t('sheet.enisa')}</p>
            <p className="mt-1 text-xs">{t('sheet.enisa_since', { date: item.euvd.exploited_since })}</p></div>}
          {item.score_source === 'euvd' && <p className="text-xs text-app-subtle">{t('sheet.euvd_score')}</p>}
          <section><h3 className="mb-1.5 text-xs font-medium text-app-muted">{t('table.description')}</h3><p className="text-sm leading-6">{item.description}</p></section>
          {item.vector && <section><h3 className="mb-1.5 text-xs font-medium text-app-muted">{t('sheet.vector')}</h3><code className="block rounded-md bg-inset px-2.5 py-1.5 font-mono text-xs break-all">{item.vector}</code></section>}
          {item.cwe.length > 0 && <section><h3 className="mb-1.5 text-xs font-medium text-app-muted">{t('sheet.weakness')}</h3><div className="flex flex-wrap gap-1.5">{item.cwe.map(cwe => <a key={cwe} href={`https://cwe.mitre.org/data/definitions/${cwe.slice(4)}.html`} target="_blank" rel="noreferrer" className="rounded-md border border-app-line px-2 py-0.5 font-mono text-xs hover:bg-app-soft">{cwe}</a>)}</div></section>}
          <section><h3 className="mb-1.5 text-xs font-medium text-app-muted">{t('sheet.in_repos')}</h3>
            {affected.error ? <p role="alert" className="text-sm text-danger">{affected.error}</p>
              : !affected.items.length && affected.loading ? <SkeletonList rows={2} dense label={t('sheet.loading_repos')} />
              : affected.total ? <div className={`space-y-1.5 transition-opacity ${affected.loading ? 'opacity-60' : ''}`}>{affected.items.map(asset => <div key={asset.asset} className="flex items-center justify-between gap-2 rounded-lg border border-app-line px-3 py-2 text-sm"><span className="min-w-0"><span className="block truncate font-medium">{asset.name}</span><span className="text-xs text-app-subtle">{asset.packages.join(', ')}</span></span>
              {asset.open ? <Badge variant="outline" className="border-transparent bg-danger-solid text-[11px] text-on-solid">{t('sheet.open', { count: asset.open })}</Badge> : <Badge variant="outline" className="border-app-line text-[11px] text-app-muted"><ShieldCheck className="size-3" />{t('sheet.fixed')}</Badge>}</div>)}
                {affected.total > affected.limit && <div className="rounded-lg border border-app-line"><Pagination total={affected.total} limit={affected.limit} offset={affected.offset} onPrev={affected.prev} onNext={affected.next} noun={t('sheet.repos_noun')} /></div>}</div>
              : <p className="text-sm text-app-muted">{t('sheet.not_affected')}</p>}</section>
          {item.references.length > 0 && <section><h3 className="mb-1.5 text-xs font-medium text-app-muted">{t('sheet.references')}</h3><ul className="space-y-1">{item.references.map(reference => <li key={reference.url} className="flex items-start gap-1.5 text-xs"><ExternalLink className="mt-0.5 size-3 shrink-0 text-app-subtle" /><a href={reference.url} target="_blank" rel="noreferrer noopener" className="min-w-0 break-all text-app-secondary hover:underline">{reference.url}</a>{reference.tags[0] && <span className="shrink-0 text-app-subtle">{reference.tags[0]}</span>}</li>)}</ul></section>}
          <div className="flex flex-wrap gap-2 border-t border-app-line pt-4"><a href={`https://nvd.nist.gov/vuln/detail/${item.id}`} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-app-muted hover:text-app-fg">NVD <ExternalLink className="size-3" /></a><a href={`https://www.cve.org/CVERecord?id=${item.id}`} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-app-muted hover:text-app-fg">CVE.org <ExternalLink className="size-3" /></a>{item.euvd?.url && <a href={item.euvd.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-app-muted hover:text-app-fg">EUVD <ExternalLink className="size-3" /></a>}</div>
        </>}
      </div>
    </SheetContent>
  </Sheet>
}

function Metric({ label, value, extra }: { label: string; value: string; extra?: React.ReactNode }) {
  return <div className="rounded-lg border border-app-line bg-app-soft px-3 py-2.5"><div className="text-[11px] text-app-subtle">{label}</div><div className="mt-0.5 text-xl font-semibold tabular-nums">{value}</div><div className="mt-1">{extra}</div></div>
}
