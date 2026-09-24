import { useCallback, useEffect, useState } from 'react'
import { TriangleAlert } from 'lucide-react'
import type { SessionUser } from '@/components/auth/session'
import { RepositoryResult, type RepositoryRun } from '@/components/repository-result'
import { RunProgress, type RunningRun } from '@/components/run-progress'
import { Card, CardContent } from '@/components/ui/card'
import { Combobox, type ComboOption } from '@/components/ui/combobox'
import { assetOption, type Asset } from '@/components/asset-picker'
import { ExclusionsCard } from '@/components/exclusions'
import { Skeleton } from '@/components/loading'
import { api, query } from '@/lib/api'
import { readRoute, setRouteParam } from '@/lib/route'
import { formatDate, plural, statusLabel, type Page, type RunRow } from '@/lib/types'

type Detail = RepositoryRun & { type: string }
const CURRENT = '__current__'


// Hallazgos por repositorio: el estado actual es el último escaneo completo; se puede filtrar por ejecución.
export function Findings({ user, requestedRun, onNew }: { user: SessionUser; requestedRun: string | null; onNew: () => void }) {
  const [asset, setAsset] = useState<Asset | null>(null)
  // Resumen del activo para el selector: se refresca tras cada carga (p. ej. cuando termina un análisis) sin volver a disparar la carga.
  const [assetView, setAssetView] = useState<Asset | null>(null)
  const [run, setRun] = useState<string>(CURRENT)
  const [runLabel, setRunLabel] = useState<ComboOption | null>(null)
  const [detail, setDetail] = useState<Detail | null>(null)
  const [loading, setLoading] = useState(false)
  const [tab, setTab] = useState<'open' | 'fixed' | 'excluded' | 'all'>('open')
  useEffect(() => { if (asset) setRouteParam('repo', asset.key) }, [asset])
  useEffect(() => { setRouteParam('run', run === CURRENT ? null : run) }, [run])
  const [empty, setEmpty] = useState(false)

  const searchAssets = useCallback(async (text: string) => {
    const page = await api.get<Page<Asset>>(`/api/assets?${query({ q: text || undefined, limit: 50 })}`)
    return { options: page.items.map(assetOption), total: page.total, items: page.items }
  }, [])
  // Arranque: el repositorio de la ejecución pedida (desde el resumen o Análisis) o el de actividad más reciente.
  useEffect(() => {
    (async () => {
      if (requestedRun) {
        const target = await api.get<Detail>(`/api/runs/${encodeURIComponent(requestedRun)}`).catch(() => null)
        const source = target?.source as { id?: string; uid?: string | null; name: string } | undefined
        if (target && source) {
          // Por identidad, no por nombre: un repositorio renombrado sigue encontrándose.
          const found = (await api.get<Page<Asset>>(`/api/assets?${query({ key: source.uid || source.id, limit: 1 })}`)).items[0]
          if (found) { setAsset(found); setRun(requestedRun); setRunLabel(runOption(target)); return }
        }
      }
      const wanted = readRoute().params.get('repo')
      const first = (await api.get<Page<Asset>>(`/api/assets?${query({ key: wanted || undefined, limit: 1 })}`)).items[0]
        ?? (await api.get<Page<Asset>>('/api/assets?limit=1')).items[0]
      if (first) setAsset(first); else setEmpty(true)
    })().catch(() => setEmpty(true))
  }, [requestedRun])

  // «Estado actual» es el registro del repositorio (escaneos y PRs juntos); una ejecución concreta es su foto.
  const load = useCallback(async () => {
    if (!asset) return
    setLoading(true)
    try {
      const next = run === CURRENT
        ? await api.get<Detail>(`/api/assets/state?${query({ key: asset.key, status: tab })}`)
        : await api.get<Detail>(`/api/runs/${encodeURIComponent(run)}`)
      setDetail(next)
      if (run !== CURRENT) setRunLabel(runOption(next))
      const fresh = (await api.get<Page<Asset>>(`/api/assets?${query({ key: asset.key, limit: 1 })}`).catch(() => null))?.items[0]
      setAssetView(fresh ?? asset)
    } finally { setLoading(false) }
  }, [asset, run, tab])
  useEffect(() => { void load() }, [load])

  const searchRuns = useCallback(async (text: string) => {
    if (!asset) return { options: [], total: 0 }
    const page = await api.get<Page<RunRow>>(`/api/runs/page?${query({ asset: asset.key, type: 'repository_scan,image_scan,pr_review', q: text || undefined, limit: 50 })}`)
    const current: ComboOption = { id: CURRENT, label: 'Estado actual', hint: 'escaneos y PRs juntos, con lo remediado aparte' }
    return { options: [...(text ? [] : [current]), ...page.items.map(runOption)], total: page.total + (text ? 0 : 1) }
  }, [asset])

  // Los contadores salen del estado recién consultado: cambian en cuanto se triagea algo.
  const counts = (detail?.summary as { lifecycle?: { open: number; fixed: number; suppressed: number; excluded?: number } } | undefined)?.lifecycle ?? null
  if (empty) return <Card className="border-app-line bg-panel"><CardContent className="py-14 text-center text-sm text-app-muted">Aún no hay repositorios ni imágenes analizados. Lanza un análisis de código o de una imagen para empezar.</CardContent></Card>
  return <div className="space-y-5">
    <div className="grid gap-3 md:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
      <div className="space-y-1"><span className="text-xs text-app-muted">Activo</span><Combobox label="Activo" placeholder="Busca un repositorio o una imagen…" value={asset ? assetOption(assetView?.key === asset.key ? assetView : asset) : null}
        search={searchAssets} onSelect={option => { void searchAssets(option.label).then(result => { const next = result.items.find(item => item.key === option.id); if (next) { setAsset(next); setRun(CURRENT); setRunLabel(null) } }) }} /></div>
      <div className="space-y-1"><span className="text-xs text-app-muted">Ejecución</span><Combobox label="Ejecución" placeholder="Estado actual" value={run === CURRENT ? { id: CURRENT, label: 'Estado actual', hint: 'escaneos y PRs' } : runLabel}
        search={searchRuns} onSelect={option => { setRun(option.id); setRunLabel(option.id === CURRENT ? null : option) }} emptyText="Sin ejecuciones que coincidan" /></div>
    </div>
    {asset?.removed_at && <div role="alert" className="flex items-start gap-2 rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-800 dark:text-rose-200"><TriangleAlert className="mt-0.5 size-4 shrink-0" /><span>GitHub ya no da acceso a este repositorio (se borró o se quitó de la App) desde el {formatDate(asset.removed_at)}. Si no vuelve, sus hallazgos, triage y tickets enlazados se borran a las 24 horas.</span></div>}
    {run === CURRENT && asset && <ExclusionsCard key={asset.key} assetKey={asset.key} canEdit={user.role === 'admin'} onChanged={() => void load()} />}
    {run === CURRENT && <div className="flex flex-wrap gap-1.5">{([['open', 'Abiertos'], ['fixed', 'Remediados'], ['excluded', 'Excluidos'], ['all', 'Todos']] as const)
      .filter(([key]) => key !== 'excluded' || tab === 'excluded' || (counts?.excluded ?? 0) > 0)
      .map(([key, text]) => <button key={key} onClick={() => setTab(key)} className={`rounded-lg border px-3 py-1.5 text-sm ${tab === key ? 'border-brand/50 bg-brand/10 text-brand' : 'border-app-line bg-app-soft text-app-muted'}`}>{text}{counts ? ` · ${key === 'open' ? counts.open + counts.suppressed : key === 'fixed' ? counts.fixed : key === 'excluded' ? (counts.excluded ?? 0) : counts.open + counts.suppressed + counts.fixed + (counts.excluded ?? 0)}` : ''}</button>)}</div>}
    {loading && !detail ? <Skeleton tiles={6} rows={5} />
      : detail && (detail.status === 'queued' || detail.status === 'running' || detail.status === 'failed')
        ? <RunProgress run={detail as unknown as RunningRun} onFinished={() => void load()} />
        : detail ? <RepositoryResult key={`${run}:${tab}`} run={detail} onNew={onNew} canAccept={user.role === 'admin'} onChanged={() => void load()} initialView={run === CURRENT && tab !== 'open' ? 'all' : 'active'} exportStatus={tab} /> : null}
  </div>
}

function runOption(row: RunRow | Detail): ComboOption {
  const pull = (row as Detail).pull_request ?? (row as RunRow & { pull_request?: { number: number; title: string } }).pull_request
  const kind = row.type === 'pr_review' ? `PR${pull ? ` #${pull.number}` : ''}` : 'Escaneo completo'
  return { id: row.id, label: `${kind} · ${formatDate(row.created_at)}`, hint: `${statusLabel(row.status)} · ${plural(row.summary?.candidates ?? 0, 'hallazgo', 'hallazgos')}${pull?.title ? ` · ${pull.title}` : ''}` }
}
