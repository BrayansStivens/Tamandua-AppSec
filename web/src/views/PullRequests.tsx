import { useCallback, useEffect, useState } from 'react'
import { ChevronDown, ExternalLink, GitPullRequest, LoaderCircle, Play, RefreshCw, Search } from 'lucide-react'
import { Input } from '@/components/ui/input'
import type { SessionUser } from '@/components/auth/session'
import { Pager } from '@/components/source-search'
import { Menu, MenuContent, MenuItem, MenuTrigger } from '@/components/ui/menu'
import { SkeletonCard, SkeletonList } from '@/components/loading'
import { fetchSource, type SourcePage } from '@/lib/sources'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Select, SelectContent, SelectItem, SelectTrigger } from '@/components/ui/select'
import { api, query as toQuery } from '@/lib/api'
import { readRoute, setRouteParam } from '@/lib/route'
import { formatDate } from '@/lib/types'

type Review = { run_id: string; status: string; head_sha: string; created_at: string; current: boolean; new: number; severities: Record<string, number> }
type Pull = { number: number; title: string; url: string; author: string; draft: boolean; head_sha: string; head_ref: string; base_ref: string; updated_at: string; review: Review | null }
type Settings = { enabled: boolean; post_comment: boolean; gate: 'critical' | 'high' | 'medium' | 'never'; updated_by?: string }
type Listing = { settings: Settings; pulls: Pull[]; pulls_error?: string }
type Installation = { permissions?: Record<string, string> }
const gateLabel = { critical: 'Crítica', high: 'Alta o superior', medium: 'Media o superior', never: 'Nunca bloquear' }

function reviewBadge(pull: Pull) {
  const review = pull.review
  if (!review) return <Badge variant="outline" className="border-app-line text-app-muted">Sin revisar</Badge>
  if (review.status === 'queued' || review.status === 'running') return <Badge variant="outline" className="border-info-line text-info"><LoaderCircle className="size-3 animate-spin" />Revisando</Badge>
  if (review.status === 'failed') return <Badge variant="outline" className="border-danger-line text-danger">Falló</Badge>
  if (!review.current) return <Badge variant="outline" className="border-warning-line text-warning">Hay commits nuevos</Badge>
  const blocking = (review.severities.critical ?? 0) + (review.severities.high ?? 0)
  return review.new === 0 ? <Badge variant="outline" className="border-brand/30 text-brand">Sin hallazgos nuevos</Badge>
    : <Badge variant="outline" className={blocking ? 'border-danger-line text-danger' : 'border-warning-line text-warning'}>{review.new} nuevos{blocking ? ` · ${blocking} críticos/altos` : ''}</Badge>
}

export function PullRequests({ user, onOpenRun }: { user: SessionUser; onOpenRun: (id: string) => void }) {
  // Solo el repositorio elegido: el enlace directo lo trae por id y, si no, se toma el primero de GitHub.
  const [selected, setSelected] = useState<{ id: string; name: string } | null>(null)
  const [connected, setConnected] = useState<boolean | null>(null)
  const sourceId = selected?.id ?? null
  const [listing, setListing] = useState<Listing | null>(null)
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
  const load = useCallback(async () => {
    if (!sourceId) return
    setError('')
    try { setListing(await api.get<Listing>(`/api/pull-requests?source_id=${encodeURIComponent(sourceId)}`)) }
    catch (caught) { setListing(null); setError(caught instanceof Error ? caught.message : String(caught)) }
  }, [sourceId])
  useEffect(() => { void load() }, [load])
  useEffect(() => { if (sourceId) setRouteParam('repo', sourceId) }, [sourceId])
  // Mientras haya revisiones en curso, se refresca solo.
  const running = listing?.pulls.some(pull => pull.review && ['queued', 'running'].includes(pull.review.status))
  useEffect(() => { if (!running) return; const timer = window.setInterval(() => { void load() }, 4000); return () => window.clearInterval(timer) }, [running, load])

  const save = async (change: Partial<Settings>) => {
    if (!sourceId) return
    setBusy('settings'); setError('')
    try { const settings = await api.post<Settings>('/api/pull-requests/settings', 'pr-settings', { source_id: sourceId, ...change }); setListing(previous => previous ? { ...previous, settings } : previous); setVersion(value => value + 1) }
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
    : <div className="grid gap-5 xl:grid-cols-[minmax(0,420px)_minmax(0,1fr)]"><SkeletonList rows={8} dense label="Cargando repositorios vigilados" /><div className="space-y-5"><SkeletonCard lines={2} label="Cargando repositorio" /><SkeletonList rows={4} action label="Cargando pull requests" /></div></div>
  if (!connected) return <Card className="border-app-line bg-panel"><CardContent className="flex flex-col items-center gap-2 py-14 text-center"><GitPullRequest className="size-7 text-app-subtle" /><p className="font-medium">Conecta GitHub para revisar pull requests</p><p className="max-w-md text-sm text-app-muted">La revisión usa la GitHub App instalada: elige los repositorios en Integraciones.</p></CardContent></Card>

  return <div className="grid gap-5 xl:grid-cols-[minmax(0,420px)_minmax(0,1fr)]">
    <WatchPanel key={version} admin={admin} onChanged={() => void load()} onSelect={setSelected} selected={sourceId} />
    <div className="min-w-0 space-y-5">
    <Card className="border-app-line bg-panel"><CardHeader className="gap-3">
      <div className="flex flex-wrap items-start justify-between gap-3"><div className="min-w-0"><CardTitle className="truncate">{selected?.name ?? 'Elige un repositorio'}</CardTitle><CardDescription className="mt-1 leading-6">Cada commit nuevo de un PR se escanea y se compara con la rama principal: solo cuenta lo que el PR introduce. Sus hallazgos entran en el estado del repositorio y se remedian solos cuando un commit posterior los quita o el PR se cierra sin merge.</CardDescription></div>
        {settings && <Badge variant="outline" className={settings.enabled ? 'border-brand/30 text-brand' : 'border-app-line text-app-muted'}>{settings.enabled ? 'Vigilancia activa' : 'Sin vigilancia'}</Badge>}</div>
      {settings && <div className="flex flex-wrap items-center gap-x-6 gap-y-3 rounded-xl border border-app-line bg-inset px-4 py-3 text-sm">
        <label className="flex items-center gap-2"><input type="checkbox" className="size-4 accent-brand" checked={settings.post_comment} disabled={!admin || !!busy} onChange={event => void save({ post_comment: event.target.checked })} />Comentar y marcar el commit en GitHub</label>
        <span className="flex items-center gap-2">Bloquear desde<Select value={settings.gate} disabled={!admin || !!busy} onValueChange={value => value && void save({ gate: value as Settings['gate'] })}><SelectTrigger size="sm" aria-label="Umbral de bloqueo" className="min-w-40 border-app-line bg-app-soft">{gateLabel[settings.gate]}</SelectTrigger><SelectContent className="border border-app-line bg-panel p-1 text-app-fg shadow-xl">{(Object.keys(gateLabel) as Settings['gate'][]).map(key => <SelectItem key={key} value={key}>{gateLabel[key]}</SelectItem>)}</SelectContent></Select></span>
        {!admin && <span className="text-xs text-app-subtle">Solo un administrador cambia esta configuración.</span>}
      </div>}
      {settings && !settings.enabled && <p className="text-xs leading-5 text-app-subtle">Actívala con su interruptor en la lista para que cada push se revise solo, o usa «Revisar ahora» en un PR.</p>}
      {settings?.post_comment && !canWrite && admin && <p className="text-xs leading-5 text-warning">La GitHub App instalada aún no puede comentar: falta <strong>Pull requests</strong> y <strong>Commit statuses</strong> en escritura. Las revisiones se hacen igual y se ven aquí; en cuanto la instalación acepte esos permisos, se publicarán en GitHub.</p>}
    </CardHeader></Card>
    {error && <div role="alert" className="rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{error}</div>}
    <Card className="border-app-line bg-panel"><CardContent className="p-0">
      <div className="flex items-center justify-between border-b border-app-line px-5 py-3 text-sm"><span className="font-medium">PRs abiertos{listing ? ` · ${listing.pulls.length}` : ''}</span><Button size="sm" variant="ghost" onClick={() => void load()}><RefreshCw />Actualizar</Button></div>
      {!listing ? <SkeletonList rows={4} action label="Cargando pull requests" />
        : listing.pulls_error ? <p className="px-5 py-8 text-sm leading-6 text-warning">{listing.pulls_error}</p>
        : listing.pulls.length === 0 ? <p className="px-5 py-10 text-center text-sm text-app-subtle">No hay pull requests abiertos en este repositorio.</p>
        : <div className="divide-y divide-app-line">{listing.pulls.map(pull => <div key={pull.number} className="flex flex-wrap items-center gap-3 px-5 py-3">
          <div className="min-w-0 flex-1"><a href={pull.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 text-sm font-medium hover:underline"><GitPullRequest className="size-4 text-app-subtle" />#{pull.number} {pull.title}<ExternalLink className="size-3 text-app-subtle" /></a>
            <p className="mt-0.5 text-xs text-app-subtle">{pull.author} · {pull.head_ref} → {pull.base_ref} · <span className="font-mono">{pull.head_sha?.slice(0, 7)}</span>{pull.draft ? ' · borrador' : ''}{pull.review ? ` · revisado ${formatDate(pull.review.created_at)}` : ''}</p></div>
          {reviewBadge(pull)}
          {/* Una acción según el estado: con revisión al día, verla; si no (o hay commits nuevos), revisar. */}
          {pull.review && pull.review.current && pull.review.status !== 'queued' && pull.review.status !== 'running'
            ? <Button size="sm" variant="outline" className="border-app-line bg-app-soft" onClick={() => onOpenRun(pull.review!.run_id)}>Ver resultado</Button>
            : <Button size="sm" variant="outline" className="border-app-line bg-app-soft" disabled={!!busy || (!!pull.review && ['queued', 'running'].includes(pull.review.status))} onClick={() => void review(pull.number)}>{busy === `pr-${pull.number}` ? <LoaderCircle className="animate-spin" /> : <Play />}Revisar ahora</Button>}
        </div>)}</div>}
    </CardContent></Card>
    </div>
  </div>
}

type WatchRow = { id: string; name: string; private?: boolean; enabled: boolean; post_comment: boolean; gate: Settings['gate']; reviewed: number; updated_by?: string }

type WatchPage = { repositories: WatchRow[]; interval: number; total: number; enabled: number; partial?: boolean }
const WATCH_PAGE = 25

// Vigilancia de PRs por repositorio, paginada en el servidor: interruptor individual y acciones en bloque.
function WatchPanel({ admin, onChanged, onSelect, selected }: { admin: boolean; onChanged: () => void; onSelect: (row: { id: string; name: string }) => void; selected: string | null }) {
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
  const enableAll = () => { if (data && window.confirm(`¿Vigilar todos los repositorios de la GitHub App? Cada push de cualquiera de ellos lanzará una revisión.`)) void apply({ all: true }, true) }
  if (!data) return error ? <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger">{error}</div> : <Card className="border-app-line bg-panel"><CardContent className="p-0"><SkeletonList rows={8} dense label="Cargando repositorios vigilados" /></CardContent></Card>
  const rows = data.repositories
  const allPicked = rows.length > 0 && rows.every(row => picked.has(row.id))
  return <Card className="border-app-line bg-panel"><CardHeader className="gap-3"><div className="flex flex-wrap items-start justify-between gap-3"><div><CardTitle>Repositorios vigilados · {data.enabled}</CardTitle><CardDescription className="mt-1">Los activados revisan solos cada PR nuevo o cada push, cada {Math.round(data.interval / 60)} min. {admin ? 'Actívalos uno a uno o en bloque.' : 'Solo un administrador cambia qué se vigila.'}</CardDescription></div>
    {admin && <Menu><MenuTrigger render={<Button size="sm" variant="outline" disabled={busy} className="border-app-line bg-app-soft" />}>Acciones en bloque<ChevronDown className="size-3.5" /></MenuTrigger>
      <MenuContent><MenuItem onClick={enableAll}>Vigilar todos los repositorios</MenuItem><MenuItem disabled={data.enabled === 0} onClick={() => void apply({ all: true }, false)}>Dejar de vigilar todos</MenuItem></MenuContent></Menu>}</div>
    <div className="flex flex-wrap items-center gap-2"><div className="relative"><Search className="absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-app-subtle" /><Input aria-label="Buscar repositorio" value={filter} onChange={event => { setFilter(event.target.value); setPage(1) }} placeholder="Buscar…" className="h-8 w-56 border-app-line bg-app-soft pl-8 text-xs" /></div>
      <label className="flex items-center gap-2 text-xs text-app-muted"><input type="checkbox" className="size-4 accent-brand" checked={onlyEnabled} onChange={event => { setOnlyEnabled(event.target.checked); setPage(1) }} />Solo vigilados</label>
      {admin && picked.size > 0 && <><span className="text-xs text-app-muted">{picked.size} seleccionados</span><Button size="sm" disabled={busy} onClick={() => void apply({ source_ids: [...picked] }, true)} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy && <LoaderCircle className="animate-spin" />}Activar</Button><Button size="sm" variant="outline" className="border-app-line bg-app-soft" disabled={busy} onClick={() => void apply({ source_ids: [...picked] }, false)}>Desactivar</Button><Button size="sm" variant="ghost" onClick={() => setPicked(new Set())}>Quitar selección</Button></>}</div>
    {error && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger">{error}</div>}
    {data.partial && <p role="status" className="text-xs text-app-muted">Resultados parciales: la lista de esta cuenta se está leyendo de GitHub.</p>}
  </CardHeader><CardContent className="space-y-3 p-0 pb-4"><div className="max-h-96 overflow-y-auto border-t border-app-line">
    {admin && rows.length > 0 && <label className="flex items-center gap-3 border-b border-app-line px-5 py-2 text-xs text-app-subtle"><input type="checkbox" className="size-4 accent-brand" checked={allPicked} onChange={event => setPicked(previous => { const next = new Set(previous); for (const row of rows) { if (event.target.checked) next.add(row.id); else next.delete(row.id) } return next })} />Seleccionar esta página</label>}
    {rows.map(row => <div key={row.id} className={`flex items-center gap-3 border-b border-app-line px-5 py-2.5 last:border-b-0 ${selected === row.id ? 'bg-brand/5' : ''}`}>
      {admin && <input type="checkbox" aria-label={`Seleccionar ${row.name}`} className="size-4 accent-brand" checked={picked.has(row.id)} onChange={event => setPicked(previous => { const next = new Set(previous); if (event.target.checked) next.add(row.id); else next.delete(row.id); return next })} />}
      <button onClick={() => onSelect(row)} className="min-w-0 flex-1 text-left"><span className="block truncate text-sm font-medium hover:underline">{row.name}</span><span className="block text-xs text-app-subtle">{row.enabled ? `${row.post_comment ? 'comenta en GitHub' : 'solo en el panel'} · bloquea desde ${gateLabel[row.gate].toLowerCase()}` : 'sin vigilancia'}{row.reviewed ? ` · ${row.reviewed} PR revisados` : ''}</span></button>
      <label className="flex shrink-0 cursor-pointer items-center gap-2 text-xs text-app-muted"><span>{row.enabled ? 'Activa' : 'Inactiva'}</span>
        <span className="relative inline-flex"><input type="checkbox" role="switch" aria-label={`Vigilar ${row.name}`} className="peer sr-only" checked={row.enabled} disabled={!admin || busy} onChange={event => void apply({ source_ids: [row.id] }, event.target.checked)} /><span className="switch-track h-5 w-9 rounded-full bg-app-soft ring-1 ring-app-faint transition peer-checked:bg-brand peer-checked:ring-brand peer-disabled:opacity-50" /><span className="absolute top-0.5 left-0.5 size-4 rounded-full bg-knob shadow transition peer-checked:translate-x-4" /></span></label>
    </div>)}
    {!rows.length && !loading && <p className="px-5 py-6 text-center text-sm text-app-subtle">{onlyEnabled ? 'Ningún repositorio vigilado coincide.' : 'Ningún repositorio coincide.'}</p>}
  </div><div className="px-5"><Pager page={page} perPage={WATCH_PAGE} total={data.total} onPage={setPage} loading={loading} /></div></CardContent></Card>
}
