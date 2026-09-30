import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { TriangleAlert } from 'lucide-react'
import type { SessionUser } from '@/features/auth/session'
import { RepositoryResult, type RepositoryRun } from '@/features/findings/repository-result'
import { RunProgress, type RunningRun } from '@/features/analyses/run-progress'
import { Card, CardContent } from '@/shared/ui/card'
import { Combobox, type ComboOption } from '@/shared/ui/combobox'
import { assetOption, type Asset } from '@/features/sources/asset-picker'
import { RepositorySettings } from '@/features/findings/repository-settings'
import { Skeleton } from '@/shared/ui/loading'
import { api, query } from '@/shared/api/http'
import { readRoute, setRouteParam } from '@/shared/lib/route'
import { formatDate, type Page, type RunRow } from '@/shared/lib/types'
import i18n from '@/shared/i18n'

type Detail = RepositoryRun & { type: string }
const CURRENT = '__current__'
const RUN_STATUS: Record<string, string> = {
  completed: 'common:run_status.completed', incomplete: 'common:run_status.incomplete', failed: 'common:run_status.failed',
  queued: 'common:run_status.queued', running: 'common:run_status.running',
}

// Hallazgos por repositorio: el estado actual es el último escaneo completo; se puede filtrar por ejecución.
export function Findings({ user, requestedRun, onNew, onOpenPolicies }: { user: SessionUser; requestedRun: string | null; onNew: () => void; onOpenPolicies: () => void }) {
  const { t } = useTranslation('findings')
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
    const page = await api.get<Page<RunRow>>(`/api/runs/page?${query({ asset: asset.key, type: 'repository_scan,image_scan,pr_review,sarif_import', q: text || undefined, limit: 50 })}`)
    const current: ComboOption = { id: CURRENT, label: t('page.current'), hint: t('page.current_hint') }
    return { options: [...(text ? [] : [current]), ...page.items.map(runOption)], total: page.total + (text ? 0 : 1) }
  }, [asset, t])

  // Los contadores salen del estado recién consultado: cambian en cuanto se triagea algo.
  const counts = (detail?.summary as { lifecycle?: { open: number; fixed: number; suppressed: number; excluded?: number } } | undefined)?.lifecycle ?? null
  if (empty) return <Card className="border-app-line bg-panel"><CardContent className="py-14 text-center text-sm text-app-muted">{t('page.empty')}</CardContent></Card>
  return <div className="space-y-5">
    <div className="grid gap-3 md:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
      <div className="space-y-1"><span className="text-xs text-app-muted">{t('page.asset')}</span><Combobox label={t('page.asset')} placeholder={t('page.asset_placeholder')} value={asset ? assetOption(assetView?.key === asset.key ? assetView : asset) : null}
        search={searchAssets} onSelect={option => { void searchAssets(option.label).then(result => { const next = result.items.find(item => item.key === option.id); if (next) { setAsset(next); setRun(CURRENT); setRunLabel(null) } }) }} /></div>
      <div className="space-y-1"><span className="text-xs text-app-muted">{t('page.run')}</span><Combobox label={t('page.run')} placeholder={t('page.current')} value={run === CURRENT ? { id: CURRENT, label: t('page.current'), hint: t('page.current_hint_short') } : runLabel}
        search={searchRuns} onSelect={option => { setRun(option.id); setRunLabel(option.id === CURRENT ? null : option) }} emptyText={t('page.no_runs')} /></div>
    </div>
    {asset?.removed_at && <div role="alert" className="flex items-start gap-2 rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger"><TriangleAlert className="mt-0.5 size-4 shrink-0" /><span>{t('page.removed', { date: formatDate(asset.removed_at) })}</span></div>}
    {/* This repository's own settings in one strip: the findings list is what matters. Global policies live in Policies. */}
    {run === CURRENT && asset && <RepositorySettings key={asset.key} assetKey={asset.key} name={asset.name} secrets={!asset.key.startsWith('image:')}
      canEdit={user.role === 'admin'} onChanged={() => void load()} onOpenPolicies={onOpenPolicies} />}
    {run === CURRENT && <div className="flex flex-wrap gap-1.5">{([['open', t('page.tabs.open')], ['fixed', t('page.tabs.fixed')], ['excluded', t('page.tabs.excluded')], ['all', t('common:state.all')]] as const)
      .filter(([key]) => key !== 'excluded' || tab === 'excluded' || (counts?.excluded ?? 0) > 0)
      .map(([key, text]) => <button key={key} type="button" aria-pressed={tab === key} onClick={() => setTab(key)} className={`rounded-lg border px-3 py-1.5 text-sm ${tab === key ? 'border-brand/50 bg-brand/10 text-brand' : 'border-app-line bg-app-soft text-app-muted'}`}>{text}{counts ? ` · ${key === 'open' ? counts.open + counts.suppressed : key === 'fixed' ? counts.fixed : key === 'excluded' ? (counts.excluded ?? 0) : counts.open + counts.suppressed + counts.fixed + (counts.excluded ?? 0)}` : ''}</button>)}</div>}
    {loading && !detail ? <Skeleton tiles={6} rows={5} />
      : detail && (detail.status === 'queued' || detail.status === 'running' || detail.status === 'failed')
        ? <RunProgress run={detail as unknown as RunningRun} onFinished={() => void load()} />
        : detail ? <RepositoryResult key={`${run}:${tab}`} run={detail} onNew={onNew} canAccept={user.role === 'admin'} onChanged={() => void load()} initialView={run === CURRENT && tab !== 'open' ? 'all' : 'active'} exportStatus={tab} /> : null}
  </div>
}

function runOption(row: RunRow | Detail): ComboOption {
  const pull = (row as Detail).pull_request ?? (row as RunRow & { pull_request?: { number: number; title: string } }).pull_request
  const kind = row.type === 'pr_review' ? (pull ? i18n.t('findings:page.kind_pr_number', { number: pull.number }) : i18n.t('findings:page.kind_pr'))
    : row.type === 'advisory_watch' ? i18n.t('findings:page.kind_advisory')
    : row.type === 'sarif_import' ? i18n.t('findings:page.kind_import', { tool: row.trigger?.tool ?? 'SARIF' }) : i18n.t('findings:page.kind_scan')
  const status = RUN_STATUS[row.status] ? i18n.t(RUN_STATUS[row.status]) : row.status
  return { id: row.id, label: `${kind} · ${formatDate(row.created_at)}`, hint: `${status} · ${i18n.t('common:count.findings', { count: row.summary?.candidates ?? 0 })}${pull?.title ? ` · ${pull.title}` : ''}` }
}
