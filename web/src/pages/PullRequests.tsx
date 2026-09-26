import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useCallback, useEffect, useState } from 'react'
import { Trans, useTranslation } from 'react-i18next'
import type { TFunction } from 'i18next'
import { ChevronDown, ExternalLink, GitPullRequest, LoaderCircle, Play, RefreshCw, Search } from 'lucide-react'
import { Input } from '@/shared/ui/input'
import type { SessionUser } from '@/features/auth/session'
import { Pager } from '@/features/sources/source-search'
import { Menu, MenuContent, MenuItem, MenuTrigger } from '@/shared/ui/menu'
import { SkeletonCard, SkeletonList } from '@/shared/ui/loading'
import { fetchSource, type SourcePage } from '@/features/sources/sources'
import { TargetBranches } from '@/features/pulls/target-branches'
import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import { Select, SelectContent, SelectItem, SelectTrigger } from '@/shared/ui/select'
import { api, query as toQuery } from '@/shared/api/http'
import { readRoute, setRouteParam } from '@/shared/lib/route'
import { formatDate } from '@/shared/lib/types'
import { formatList } from '@/shared/i18n/format'

type Review = { run_id: string; status: string; head_sha: string; created_at: string; current: boolean; new: number; severities: Record<string, number> }
type Pull = { number: number; title: string; url: string; author: string; draft: boolean; head_sha: string; head_ref: string; base_ref: string; updated_at: string; review: Review | null }
// Vigilancia de un repositorio: sus PRs y, con `branch`, su rama principal (se reanaliza cuando cambia).
type BranchScan = { head_sha: string; run_id: string; at: string; branch?: string }
type Settings = { enabled: boolean; post_comment: boolean; gate: 'critical' | 'high' | 'medium' | 'never'; branch: boolean; base_branches?: string[]; branch_scan?: BranchScan | null; branch_min_minutes?: number; updated_by?: string; uid?: string; default_branch?: string | null }
type Listing = { settings: Settings; pulls: Pull[]; pulls_error?: string }
type Installation = { permissions?: Record<string, string> }
const gateLabel = { critical: 'gate.critical', high: 'gate.high', medium: 'gate.medium', never: 'gate.never' } as const
const gateInline = { critical: 'gate_inline.critical', high: 'gate_inline.high', medium: 'gate_inline.medium', never: 'gate_inline.never' } as const

function reviewBadge(pull: Pull, t: TFunction<'pulls'>) {
  const review = pull.review
  if (!review) return <Badge variant="outline" className="border-app-line text-app-muted">{t('badge.not_reviewed')}</Badge>
  if (review.status === 'queued' || review.status === 'running') return <Badge variant="outline" className="border-info-line text-info"><LoaderCircle className="size-3 animate-spin" />{t('badge.reviewing')}</Badge>
  if (review.status === 'failed') return <Badge variant="outline" className="border-danger-line text-danger">{t('badge.failed')}</Badge>
  if (!review.current) return <Badge variant="outline" className="border-warning-line text-warning">{t('badge.new_commits')}</Badge>
  const blocking = (review.severities.critical ?? 0) + (review.severities.high ?? 0)
  return review.new === 0 ? <Badge variant="outline" className="border-brand/30 text-brand">{t('badge.clean')}</Badge>
    : <Badge variant="outline" className={blocking ? 'border-danger-line text-danger' : 'border-warning-line text-warning'}>{t('badge.new', { count: review.new })}{blocking ? ` · ${t('badge.blocking', { count: blocking })}` : ''}</Badge>
}

export function PullRequests({ user, onOpenRun }: { user: SessionUser; onOpenRun: (id: string) => void }) {
  const { t } = useTranslation('pulls')
  // Solo el repositorio elegido: el enlace directo lo trae por id y, si no, se toma el primero de GitHub.
  const [selected, setSelected] = useState<{ id: string; name: string } | null>(null)
  const [connected, setConnected] = useState<boolean | null>(null)
  const sourceId = selected?.id ?? null
  const [permissions, setPermissions] = useState<Record<string, string>>({})
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')
  const [version, setVersion] = useState(0)
  const admin = user.role === 'admin'

  useEffect(() => {
    const fail = (caught: unknown) => setError(caught instanceof Error ? caught.message : String(caught))
    const wanted = readRoute().params.get('repo')
    api.get<SourcePage>(`/api/sources?${toQuery({ provider: 'github', per_page: 1 })}`).then(async data => {
      setConnected(data.providers.github?.configured && data.total > 0)
      const chosen = (wanted ? await fetchSource(wanted) : null) ?? data.sources[0] ?? null
      setSelected(current => current ?? chosen)
    }).catch(fail)
    api.get<{ installation: Installation | null }>('/api/integrations/github').then(data => setPermissions(data.installation?.permissions ?? {})).catch(() => {})
  }, [])
  // La lista de PRs se sondea sola cada 4 s mientras haya revisiones en cola o corriendo.
  const queryClient = useQueryClient()
  const result = useQuery({
    queryKey: ['pull-requests', sourceId],
    enabled: !!sourceId,
    queryFn: ({ signal }) => api.get<Listing>(`/api/pull-requests?source_id=${encodeURIComponent(sourceId ?? '')}`, { signal }),
    refetchInterval: query => query.state.data?.pulls.some(pull => pull.review && ['queued', 'running'].includes(pull.review.status)) ? 4000 : false,
  })
  const listing = result.data ?? null
  const setListing = (update: Listing | null | ((previous: Listing | null) => Listing | null)) =>
    queryClient.setQueryData<Listing | null>(['pull-requests', sourceId], previous => typeof update === 'function' ? update(previous ?? null) : update)
  const load = useCallback(async () => { await result.refetch() }, [result])
  useEffect(() => { if (result.error) setError(result.error instanceof Error ? result.error.message : String(result.error)) }, [result.error])
  useEffect(() => { if (sourceId) setRouteParam('repo', sourceId) }, [sourceId])

  const save = async (change: Partial<Settings>) => {
    if (!sourceId) return
    setBusy('settings'); setError('')
    try { const settings = await api.post<Settings>('/api/pull-requests/settings', 'pr-settings', { source_id: sourceId, ...change }); setListing(previous => previous ? { ...previous, settings: { ...previous.settings, ...settings } } : previous); setVersion(value => value + 1) }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy('') }
  }
  const review = async (number: number) => {
    if (!sourceId) return
    setBusy(`pr-${number}`); setError('')
    try { await api.post('/api/pull-requests/review', 'review-pr', { source_id: sourceId, number }); await load() }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy('') }
  }
  const canWrite = permissions.pull_requests === 'write' && permissions.statuses === 'write'
  const settings = listing?.settings

  if (connected === null) return error ? <div role="alert" className="rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{error}</div>
    : <div className="grid gap-5 xl:grid-cols-[minmax(0,420px)_minmax(0,1fr)]"><SkeletonList rows={8} dense label={t('loading.watched')} /><div className="space-y-5"><SkeletonCard lines={2} label={t('loading.repository')} /><SkeletonList rows={4} action label={t('loading.pulls')} /></div></div>
  if (!connected) return <Card className="border-app-line bg-panel"><CardContent className="flex flex-col items-center gap-2 py-14 text-center"><GitPullRequest className="size-7 text-app-subtle" /><p className="font-medium">{t('connect.title')}</p><p className="max-w-md text-sm text-app-muted">{t('connect.body')}</p></CardContent></Card>

  return <div className="grid gap-5 xl:grid-cols-[minmax(0,420px)_minmax(0,1fr)]">
    <WatchPanel key={version} admin={admin} onChanged={() => void load()} onSelect={setSelected} selected={sourceId} />
    <div className="min-w-0 space-y-5">
    <Card className="border-app-line bg-panel"><CardHeader className="gap-3">
      <div className="flex flex-wrap items-start justify-between gap-3"><div className="min-w-0"><CardTitle className="truncate">{selected?.name ?? t('repo.choose')}</CardTitle><CardDescription className="mt-1 leading-6">{t('repo.description')}</CardDescription></div>
        {settings && <Badge variant="outline" className={settings.enabled ? 'border-brand/30 text-brand' : 'border-app-line text-app-muted'}>{settings.enabled ? t('repo.watching') : t('repo.not_watching')}</Badge>}</div>
      {settings && <div className="flex flex-wrap items-center gap-x-6 gap-y-3 rounded-xl border border-app-line bg-inset px-4 py-3 text-sm">
        <label className="flex items-center gap-2"><input type="checkbox" className="size-4 accent-brand" checked={settings.post_comment} disabled={!admin || !!busy} onChange={event => void save({ post_comment: event.target.checked })} />{t('repo.post_comment')}</label>
        <label className="flex items-center gap-2"><input type="checkbox" className="size-4 accent-brand" checked={settings.branch} disabled={!admin || !!busy} onChange={event => void save({ branch: event.target.checked })} />{t('repo.branch')}</label>
        <span className="flex items-center gap-2">{t('repo.gate')}<Select value={settings.gate} disabled={!admin || !!busy} onValueChange={value => value && void save({ gate: value as Settings['gate'] })}><SelectTrigger size="sm" aria-label={t('repo.gate_label')} className="min-w-40 border-app-line bg-app-soft">{t(gateLabel[settings.gate])}</SelectTrigger><SelectContent className="border border-app-line bg-panel p-1 text-app-fg shadow-xl">{(Object.keys(gateLabel) as Settings['gate'][]).map(key => <SelectItem key={key} value={key}>{t(gateLabel[key])}</SelectItem>)}</SelectContent></Select></span>
        {!admin && <span className="text-xs text-app-subtle">{t('repo.admin_only')}</span>}
      </div>}
      {settings?.uid && <TargetBranches key={settings.uid} uid={settings.uid} name={selected?.name ?? ''}
        saved={settings.base_branches ?? []} defaultBranch={settings.default_branch ?? null} admin={admin}
        onSaved={branches => { setListing(previous => previous ? { ...previous, settings: { ...previous.settings, base_branches: branches } } : previous); setVersion(value => value + 1) }} />}
      {settings && !settings.enabled && <p className="text-xs leading-5 text-app-subtle">{t('repo.enable_hint')}</p>}
      {settings?.enabled && settings.branch && <p className="text-xs leading-5 text-app-subtle">{settings.branch_scan
        ? <Trans t={t} i18nKey="repo.branch_scanned" values={{ branch: settings.branch_scan.branch ?? settings.default_branch ?? '—', date: formatDate(settings.branch_scan.at), sha: settings.branch_scan.head_sha.slice(0, 7), minutes: settings.branch_min_minutes ?? 60 }} components={{ code: <span className="font-mono" /> }} />
        : t('repo.branch_pending', { minutes: settings.branch_min_minutes ?? 60 })}</p>}
      {settings?.post_comment && !canWrite && admin && <p className="text-xs leading-5 text-warning"><Trans t={t} i18nKey="repo.missing_write" components={{ b: <strong /> }} /></p>}
    </CardHeader></Card>
    {error && <div role="alert" className="rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{error}</div>}
    <Card className="border-app-line bg-panel"><CardContent className="p-0">
      <div className="flex items-center justify-between border-b border-app-line px-5 py-3 text-sm"><span className="font-medium">{listing ? t('list.title_count', { total: listing.pulls.length }) : t('list.title')}</span><Button size="sm" variant="ghost" onClick={() => void load()}><RefreshCw />{t('common:actions.refresh')}</Button></div>
      {!listing ? <SkeletonList rows={4} action label={t('loading.pulls')} />
        : listing.pulls_error ? <p className="px-5 py-8 text-sm leading-6 text-warning">{listing.pulls_error}</p>
        : listing.pulls.length === 0 ? <p className="px-5 py-10 text-center text-sm text-app-subtle">{t('list.empty')}</p>
        : <div className="divide-y divide-app-line">{listing.pulls.map(pull => <div key={pull.number} className="flex flex-wrap items-center gap-3 px-5 py-3">
          <div className="min-w-0 flex-1"><a href={pull.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 text-sm font-medium hover:underline"><GitPullRequest className="size-4 text-app-subtle" />#{pull.number} {pull.title}<ExternalLink className="size-3 text-app-subtle" /></a>
            <p className="mt-0.5 text-xs text-app-subtle">{pull.author} · {pull.head_ref} → {pull.base_ref} · <span className="font-mono">{pull.head_sha?.slice(0, 7)}</span>{pull.draft ? ` · ${t('list.draft')}` : ''}{pull.review ? ` · ${t('list.reviewed', { date: formatDate(pull.review.created_at) })}` : ''}</p></div>
          {reviewBadge(pull, t)}
          {/* Una acción según el estado: con revisión al día, verla; si no (o hay commits nuevos), revisar. */}
          {pull.review && pull.review.current && pull.review.status !== 'queued' && pull.review.status !== 'running'
            ? <Button size="sm" variant="outline" className="border-app-line bg-app-soft" onClick={() => onOpenRun(pull.review!.run_id)}>{t('list.view_result')}</Button>
            : <Button size="sm" variant="outline" className="border-app-line bg-app-soft" disabled={!!busy || (!!pull.review && ['queued', 'running'].includes(pull.review.status))} onClick={() => void review(pull.number)}>{busy === `pr-${pull.number}` ? <LoaderCircle className="animate-spin" /> : <Play />}{t('list.review_now')}</Button>}
        </div>)}</div>}
    </CardContent></Card>
    </div>
  </div>
}

type WatchRow = { id: string; name: string; private?: boolean; enabled: boolean; post_comment: boolean; gate: Settings['gate']; branch: boolean; base_branches?: string[]; default_branch?: string | null; branch_scan?: BranchScan | null; reviewed: number; updated_by?: string }

type WatchPage = { repositories: WatchRow[]; interval: number; total: number; enabled: number; partial?: boolean }
const WATCH_PAGE = 25

// Vigilancia de PRs por repositorio, paginada en el servidor: interruptor individual y acciones en bloque.
function WatchPanel({ admin, onChanged, onSelect, selected }: { admin: boolean; onChanged: () => void; onSelect: (row: { id: string; name: string }) => void; selected: string | null }) {
  const { t } = useTranslation('pulls')
  const [data, setData] = useState<WatchPage | null>(null)
  const [filter, setFilter] = useState('')
  const [onlyEnabled, setOnlyEnabled] = useState(false)
  const [page, setPage] = useState(1)
  const [nonce, setNonce] = useState(0)
  const [loading, setLoading] = useState(false)
  const [picked, setPicked] = useState<Set<string>>(new Set())
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  useEffect(() => {
    const controller = new AbortController()
    const timer = window.setTimeout(() => {
      setLoading(true)
      api.get<WatchPage>(`/api/pull-requests/watch?${toQuery({ q: filter.trim() || undefined, only: onlyEnabled ? 'enabled' : undefined, page, per_page: WATCH_PAGE })}`, { signal: controller.signal })
        .then(result => { setData(result); setError('') })
        .catch(caught => { if (!controller.signal.aborted) setError(caught instanceof Error ? caught.message : String(caught)) })
        .finally(() => { if (!controller.signal.aborted) setLoading(false) })
    }, filter ? 300 : 0)
    return () => { controller.abort(); window.clearTimeout(timer) }
  }, [filter, onlyEnabled, page, nonce])
  useEffect(() => { if (!data?.partial) return; const timer = window.setTimeout(() => setNonce(value => value + 1), 2000); return () => window.clearTimeout(timer) }, [data])
  const apply = async (body: { source_ids: string[] } | { all: true }, enabled: boolean) => {
    if (busy) return
    setBusy(true); setError('')
    try { await api.post('/api/pull-requests/settings', 'pr-settings', { ...body, enabled }); setPicked(new Set()); setNonce(value => value + 1); onChanged() }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }
  const enableAll = () => { if (data && window.confirm(t('watch.confirm_all'))) void apply({ all: true }, true) }
  if (!data) return error ? <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger">{error}</div> : <Card className="border-app-line bg-panel"><CardContent className="p-0"><SkeletonList rows={8} dense label={t('loading.watched')} /></CardContent></Card>
  const rows = data.repositories
  const allPicked = rows.length > 0 && rows.every(row => picked.has(row.id))
  const rowSummary = (row: WatchRow) => [
    ...(row.enabled ? [row.post_comment ? t('watch.comments') : t('watch.panel_only'), t(gateInline[row.gate]), ...(row.base_branches?.length ? [t('watch.targets', { branches: formatList(row.base_branches) })] : []), ...(row.branch ? [t('watch.branch_current')] : [])] : [t('watch.not_watched')]),
    ...(row.reviewed ? [t('watch.reviewed', { count: row.reviewed })] : []),
  ].join(' · ')
  return <Card className="border-app-line bg-panel"><CardHeader className="gap-3"><div className="flex flex-wrap items-start justify-between gap-3"><div><CardTitle>{t('watch.title', { total: data.enabled })}</CardTitle><CardDescription className="mt-1">{t('watch.description', { minutes: Math.round(data.interval / 60) })} {admin ? t('watch.admin_hint') : t('watch.member_hint')}</CardDescription></div>
    {admin && <Menu><MenuTrigger render={<Button size="sm" variant="outline" disabled={busy} className="border-app-line bg-app-soft" />}>{t('watch.bulk')}<ChevronDown className="size-3.5" /></MenuTrigger>
      <MenuContent><MenuItem onClick={enableAll}>{t('watch.watch_all')}</MenuItem><MenuItem disabled={data.enabled === 0} onClick={() => void apply({ all: true }, false)}>{t('watch.unwatch_all')}</MenuItem></MenuContent></Menu>}</div>
    <div className="flex flex-wrap items-center gap-2"><div className="relative"><Search className="absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-app-subtle" /><Input aria-label={t('watch.search')} value={filter} onChange={event => { setFilter(event.target.value); setPage(1) }} placeholder={t('watch.search_placeholder')} className="h-8 w-56 border-app-line bg-app-soft pl-8 text-xs" /></div>
      <label className="flex items-center gap-2 text-xs text-app-muted"><input type="checkbox" className="size-4 accent-brand" checked={onlyEnabled} onChange={event => { setOnlyEnabled(event.target.checked); setPage(1) }} />{t('watch.only_watched')}</label>
      {admin && picked.size > 0 && <><span className="text-xs text-app-muted">{t('watch.selected', { count: picked.size })}</span><Button size="sm" disabled={busy} onClick={() => void apply({ source_ids: [...picked] }, true)} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy && <LoaderCircle className="animate-spin" />}{t('watch.enable')}</Button><Button size="sm" variant="outline" className="border-app-line bg-app-soft" disabled={busy} onClick={() => void apply({ source_ids: [...picked] }, false)}>{t('watch.disable')}</Button><Button size="sm" variant="ghost" onClick={() => setPicked(new Set())}>{t('watch.clear_selection')}</Button></>}</div>
    {error && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger">{error}</div>}
    {data.partial && <p role="status" className="text-xs text-app-muted">{t('watch.partial')}</p>}
  </CardHeader><CardContent className="space-y-3 p-0 pb-4"><div className="max-h-96 overflow-y-auto border-t border-app-line">
    {admin && rows.length > 0 && <label className="flex items-center gap-3 border-b border-app-line px-5 py-2 text-xs text-app-subtle"><input type="checkbox" className="size-4 accent-brand" checked={allPicked} onChange={event => setPicked(previous => { const next = new Set(previous); for (const row of rows) { if (event.target.checked) next.add(row.id); else next.delete(row.id) } return next })} />{t('watch.select_page')}</label>}
    {rows.map(row => <div key={row.id} className={`flex items-center gap-3 border-b border-app-line px-5 py-2.5 last:border-b-0 ${selected === row.id ? 'bg-brand/5' : ''}`}>
      {admin && <input type="checkbox" aria-label={t('watch.select_one', { name: row.name })} className="size-4 accent-brand" checked={picked.has(row.id)} onChange={event => setPicked(previous => { const next = new Set(previous); if (event.target.checked) next.add(row.id); else next.delete(row.id); return next })} />}
      <button onClick={() => onSelect(row)} className="min-w-0 flex-1 text-left"><span className="block truncate text-sm font-medium hover:underline">{row.name}</span><span className="block text-xs text-app-subtle">{rowSummary(row)}</span></button>
      <label className="flex shrink-0 cursor-pointer items-center gap-2 text-xs text-app-muted"><span>{row.enabled ? t('watch.on') : t('watch.off')}</span>
        <span className="relative inline-flex"><input type="checkbox" role="switch" aria-label={t('watch.toggle', { name: row.name })} className="peer sr-only" checked={row.enabled} disabled={!admin || busy} onChange={event => void apply({ source_ids: [row.id] }, event.target.checked)} /><span className="switch-track h-5 w-9 rounded-full bg-app-soft ring-1 ring-app-faint transition peer-checked:bg-brand peer-checked:ring-brand peer-disabled:opacity-50" /><span className="absolute top-0.5 left-0.5 size-4 rounded-full bg-knob shadow transition peer-checked:translate-x-4" /></span></label>
    </div>)}
    {!rows.length && !loading && <p className="px-5 py-6 text-center text-sm text-app-subtle">{onlyEnabled ? t('watch.no_watched_match') : t('watch.no_match')}</p>}
  </div><div className="px-5"><Pager page={page} perPage={WATCH_PAGE} total={data.total} onPage={setPage} loading={loading} /></div></CardContent></Card>
}
