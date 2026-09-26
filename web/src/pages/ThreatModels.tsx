import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react'
import { ArrowDownToLine, ArrowLeft, ArrowUpFromLine, BookOpen, ChevronDown, ChevronRight, Pencil, LoaderCircle, Network, Plus, Save, ShieldAlert, Sparkles, Trash2 } from 'lucide-react'
import { Trans, useTranslation } from 'react-i18next'
import type { SessionUser } from '@/features/auth/session'
import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { Input } from '@/shared/ui/input'
import { Menu, MenuContent, MenuGroup, MenuItem, MenuTrigger } from '@/shared/ui/menu'
import { Skeleton, SkeletonCard, SkeletonList, SkeletonTiles } from '@/shared/ui/loading'
import { SourceSearch } from '@/features/sources/source-search'
import type { Source } from '@/features/sources/sources'
import { api } from '@/shared/api/http'
import { readRoute, setRouteParam } from '@/shared/lib/route'
import { formatDate } from '@/shared/lib/types'
import { ThreatCanvas } from '@/features/threats/threat-canvas'
import { ThreatJsonImporter } from '@/features/threats/threat-json-importer'
import { categoryHelp, methodName, METHOD_ORDER, type Methodology } from '@/features/threats/threat-guides'
import { AttackMappings, AttackTrees, GuidePanel, ManualThreatDialog, MethodDialog, MethodPicker, PastaStages } from '@/features/threats/threat-methods'
import { assetGroups, newId, type Catalog, type Component, type CustomModule, type Flow, type Kind, type Model, type Threat, type View, type Asset, type ManualThreat } from '@/features/threats/threat-model-types'

// Catalog keys (`threats` namespace; severities from `common`).
const statusLabel = { evidenced: 'status.evidenced', open: 'status.open', mitigated: 'status.mitigated', accepted: 'status.accepted', not_applicable: 'status.not_applicable' }
const statusClass = { evidenced: 'border-warning-line bg-warning-soft text-warning', open: 'border-app-line text-app-secondary', mitigated: 'border-brand/30 text-brand', accepted: 'border-brand/30 text-brand', not_applicable: 'border-app-line text-app-subtle' }
const severityClass: Record<string, string> = { critical: 'border-transparent bg-danger-solid text-on-solid', high: 'border-attention-line bg-attention-soft text-attention', medium: 'border-warning-line bg-warning-soft text-warning', low: 'border-info-line bg-info-soft text-info' }
const severityLabel: Record<string, string> = { critical: 'common:severity.critical', high: 'common:severity.high', medium: 'common:severity.medium', low: 'common:severity.low', info: 'common:severity.info' }
const LIKELIHOOD = { low: 'threat.likelihood.low', medium: 'threat.likelihood.medium', high: 'threat.likelihood.high' } as const
const IMPACT = { low: 'threat.impact.low', medium: 'threat.impact.medium', high: 'threat.impact.high' } as const
const DECISION_HINT = { mitigated: 'decision.mitigated', accepted: 'decision.accepted', not_applicable: 'decision.not_applicable' } as const
const isMethodology = (value?: string): value is Methodology => METHOD_ORDER.includes(value as Methodology)
const select = 'h-8 rounded-lg border border-app-line bg-app-soft px-2 text-xs text-app-fg'

export function ThreatModels({ user, onOpenRun }: { user: SessionUser; onOpenRun: (id: string) => void }) {
  const { t } = useTranslation('threats')
  const [catalog, setCatalog] = useState<Catalog | null>(null)
  const [openId, setOpenId] = useState<string | null>(() => readRoute().params.get('model'))
  useEffect(() => { setRouteParam('model', openId) }, [openId])
  const [creating, setCreating] = useState(false)
  const [importing, setImporting] = useState(false)
  const [error, setError] = useState('')
  const load = useCallback(() => api.get<Catalog>('/api/threat-models').then(setCatalog).catch(caught => setError(caught instanceof Error ? caught.message : String(caught))), [])
  useEffect(() => { void load() }, [load])
  if (!catalog) return error ? <div role="alert" className="rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{error}</div> : <Skeleton rows={4} />
  if (openId) return <Editor id={openId} catalog={catalog} user={user} onBack={() => { setOpenId(null); void load() }} onOpenRun={onOpenRun} />
  return <div className="space-y-5">
    <Card className="border-app-line bg-panel"><CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3"><div><CardTitle>{t('list.title')}</CardTitle><CardDescription className="mt-1 max-w-3xl leading-6"><Trans t={t} i18nKey="list.description" components={{ strong: <strong /> }} /></CardDescription></div><div className="flex flex-wrap gap-2"><Button variant="outline" onClick={() => setImporting(true)}><ArrowUpFromLine />{t('list.import')}</Button><Button onClick={() => setCreating(true)} className="bg-primary text-primary-foreground hover:bg-primary/90"><Plus />{t('list.new')}</Button></div></CardHeader>
      {error && <div role="alert" className="mx-6 mb-4 rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-sm text-danger">{error}</div>}
      <CardContent>{catalog.models.length === 0 ? <div className="flex flex-col items-center gap-2 py-12 text-center"><Network className="size-7 text-app-subtle" /><p className="font-medium">{t('list.empty')}</p><p className="max-w-md text-sm text-app-muted">{t('list.empty_hint')}</p></div>
        : <div className="divide-y divide-app-line rounded-xl border border-app-line">{catalog.models.map(item => <button key={item.id} onClick={() => setOpenId(item.id)} className="flex w-full items-center gap-3 px-4 py-3 text-left transition hover:bg-app-soft"><Network className="size-4 text-app-subtle" /><span className="min-w-0 flex-1"><span className="block text-sm font-medium">{item.name}<span className="ml-2 rounded border border-app-line px-1.5 py-0.5 align-middle text-[11px] font-normal text-app-subtle">{isMethodology(item.methodology ?? 'stride') ? methodName((item.methodology ?? 'stride') as Methodology) : item.methodology}</span></span><span className="block truncate text-xs text-app-subtle">{[t('count.components', { count: item.components }), t('count.flows', { count: item.flows }), ...(item.updated_at ? [t('list.updated', { date: formatDate(item.updated_at), user: item.updated_by })] : [])].join(' · ')}</span></span><ChevronRight className="size-4 text-app-subtle" /></button>)}</div>}</CardContent></Card>
    <CreateDialog open={creating} assets={catalog.assets} onClose={() => setCreating(false)} onCreated={id => { setCreating(false); setOpenId(id) }} />
    {importing && <ThreatJsonImporter onClose={() => setImporting(false)} onImported={id => { setImporting(false); setOpenId(id) }} />}
  </div>
}

// Los modelos enlazan por identidad estable (`github#123`), que sobrevive a un renombrado.
const sourceKey = (source: Source) => source.uid ?? source.id

function CreateDialog({ open, assets, onClose, onCreated }: { open: boolean; assets: Asset[]; onClose: () => void; onCreated: (id: string) => void }) {
  const { t } = useTranslation('threats')
  const [name, setName] = useState('')
  const [methodology, setMethodology] = useState<Methodology>('stride')
  const [customModules, setCustomModules] = useState<CustomModule[]>(['manual', 'elements'])
  // Se guarda el nombre de cada elegido: la búsqueda cambia de página y el nombre sigue haciendo falta.
  const [chosenNames, setChosenNames] = useState<Record<string, string>>({})
  const chosen = Object.keys(chosenNames)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const scanned = new Set(assets.filter(item => item.last_run).map(item => item.id))
  const toggle = (source: Source, on: boolean) => setChosenNames(previous => { const next = { ...previous }; const key = sourceKey(source); if (on && Object.keys(next).length < 10) next[key] = source.name; else delete next[key]; return next })
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setBusy(true); setError('')
    try {
      // Sin nombre, el sistema se llama como sus repositorios: el nombre no debe bloquear la propuesta.
      const fallback = Object.values(chosenNames).map(item => item.split('/').pop()).join(' + ').slice(0, 80)
      const finalName = name.trim() || fallback || t('create.default_name')
      const body = chosen.length ? { name: finalName, suggest: chosen, methodology, custom_modules: customModules } : { model: { name: finalName, methodology, custom_modules: customModules, components: [], flows: [], boundaries: [], repositories: [] } }
      onCreated((await api.post<View>('/api/threat-models', 'save-threat-model', body)).model.id)
      setName(''); setChosenNames({})
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }
  return <Dialog open={open} onOpenChange={next => { if (!next) onClose() }}><DialogContent className="max-h-[92vh] max-w-2xl overflow-y-auto">
    <DialogHeader><DialogTitle>{t('create.title')}</DialogTitle><DialogDescription>{t('create.description')}</DialogDescription></DialogHeader>
    <form className="space-y-4" onSubmit={submit}>
      <div className="space-y-1.5"><span className="text-xs text-app-muted">{t('create.approach')}</span><MethodPicker value={methodology} onChange={setMethodology} /><p className="text-[11px] leading-4 text-app-subtle">{t('create.approach_hint')}</p></div>
      {methodology === 'custom' && <CustomModulesPicker value={customModules} onChange={setCustomModules} />}
      <div className="space-y-1.5"><label htmlFor="tm-name" className="text-xs text-app-muted">{t('create.name')}</label><Input id="tm-name" autoFocus maxLength={80} value={name} onChange={event => setName(event.target.value)} placeholder={t('create.name_placeholder')} className="border-app-line bg-app-soft" /></div>
      <details className="rounded-lg border border-app-line px-3 py-2" open={chosen.length > 0}><summary className="cursor-pointer text-xs text-app-muted">{chosen.length ? t('create.from_repos_chosen', { count: chosen.length }) : t('create.from_repos')}</summary><div className="mt-2 space-y-1.5"><p className="text-[11px] leading-4 text-app-subtle">{t('create.from_repos_hint')}</p>{open && <SourceSearch perPage={8} empty={t('create.no_repos')} render={item => <label className="flex items-center gap-2 rounded px-2 py-1 text-sm hover:bg-app-soft"><input type="checkbox" className="size-4 accent-brand" checked={sourceKey(item) in chosenNames} disabled={!(sourceKey(item) in chosenNames) && chosen.length >= 10} onChange={event => toggle(item, event.target.checked)} /><span className="min-w-0 flex-1 truncate">{item.name}</span>{scanned.has(sourceKey(item)) ? <span className="shrink-0 text-[11px] text-brand">{t('create.scanned')}</span> : <span className="shrink-0 text-[11px] text-app-subtle">{t('create.not_scanned')}</span>}</label>} />}
        <p className="text-[11px] leading-4 text-app-subtle">{t('create.not_scanned_hint')}</p></div></details>
      {error && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger">{error}</div>}
      <DialogFooter><Button type="button" variant="ghost" onClick={onClose}>{t('common:actions.cancel')}</Button><Button type="submit" disabled={busy} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy ? <LoaderCircle className="animate-spin" /> : chosen.length ? <Sparkles /> : <Plus />}{busy && chosen.length ? t('create.reading') : chosen.length ? t('create.submit_propose') : t('create.submit')}</Button></DialogFooter>
    </form>
  </DialogContent></Dialog>
}

function Editor({ id, catalog: base, user, onBack, onOpenRun }: { id: string; catalog: Catalog; user: SessionUser; onBack: () => void; onOpenRun: (id: string) => void }) {
  const { t } = useTranslation('threats')
  const [view, setView] = useState<View | null>(null)
  const [draft, setDraft] = useState<Model | null>(null)
  const [tab, setTab] = useState<string>('')
  const [picking, setPicking] = useState(false)
  // La guía se abre a demanda y se recuerda: quien ya sabe modelar no la ve si no la pide.
  const [guide, setGuide] = useState(() => { try { return localStorage.getItem('tm-guide') === 'open' } catch { return false } })
  const toggleGuide = (next: boolean) => { setGuide(next); try { localStorage.setItem('tm-guide', next ? 'open' : 'closed') } catch { /* sin almacenamiento */ } }
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [picked, setPicked] = useState<Asset[]>([])
  const load = useCallback(async () => { const data = await api.get<View>(`/api/threat-models/${id}`); setView(data); setDraft(data.model) }, [id])
  // El catálogo solo trae lo analizado y los dominios; los repositorios del modelo llegan con su detalle.
  const catalog = useMemo<Catalog>(() => {
    const assets = new Map(base.assets.map(item => [item.id, item]))
    for (const item of [...(view?.assets ?? []), ...picked]) assets.set(item.id, { ...assets.get(item.id), ...item })
    return { ...base, assets: [...assets.values()] }
  }, [base, view, picked])
  useEffect(() => { load().catch(caught => setError(caught instanceof Error ? caught.message : String(caught))) }, [load])
  const dirty = useMemo(() => !!view && !!draft && JSON.stringify(view.model) !== JSON.stringify(draft), [view, draft])
  const save = async () => {
    if (!draft) return
    setBusy(true); setError('')
    try { const data = await api.post<View>('/api/threat-models', 'save-threat-model', { id, model: payloadOf(draft) }); setView(data); setDraft(data.model) }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }
  const remove = async () => {
    if (!window.confirm(t('editor.confirm_delete'))) return
    try { await api.post('/api/threat-models/delete', 'delete-threat-model', { id }); onBack() } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) }
  }
  if (!view || !draft) return error ? <div role="alert" className="text-sm text-danger">{error}</div>
    : <div className="space-y-5"><SkeletonCard lines={2} label={t('editor.loading_model')} /><SkeletonTiles count={6} label={t('editor.loading_summary')} /><SkeletonList rows={5} label={t('editor.loading_threats')} /></div>
  const summary = view.summary
  const methodology: Methodology = draft.methodology ?? 'stride'
  const tabs = methodology === 'custom' ? customTabs(draft.custom_modules ?? ['manual', 'elements']) : TABS[methodology]
  const current = tabs.some(([key]) => key === tab) ? tab : tabs[0][0]
  // Amenazas propias: se guardan al momento junto con el resto del modelo.
  const saveModel = async (next: Model) => {
    setBusy(true); setError('')
    try { const data = await api.post<View>('/api/threat-models', 'save-threat-model', { id, model: payloadOf(next) }); setView(data); setDraft(data.model); return true }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)); return false } finally { setBusy(false) }
  }
  const downloadFile = async (file: string) => {
    if (dirty && !(await saveModel(draft))) return
    try {
      setError('')
      const name = draft.name.replace(/[^a-z0-9-]+/gi, '-').slice(0, 60) || t('editor.file_fallback')
      await api.download(`/api/threat-models/${id}/${file}`, `${name}-${file}`)
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) }
  }
  return <div className="space-y-5">
    <div className="flex flex-col gap-4 rounded-2xl border border-app-line bg-panel p-5">
      <div className="flex flex-wrap items-start justify-between gap-3"><div className="min-w-0"><button onClick={onBack} className="mb-2 inline-flex items-center gap-1 text-xs text-app-subtle hover:text-app-fg"><ArrowLeft className="size-3" />{t('editor.back')}</button><h2 className="text-xl font-semibold">{view.model.name}</h2><div className="mt-1.5 flex flex-wrap items-center gap-2"><button onClick={() => setPicking(true)} className="inline-flex items-center gap-1 rounded-lg border border-brand/30 bg-brand/[0.07] px-2 py-0.5 text-xs font-medium text-brand hover:bg-brand/10" title={t('editor.change_approach')}>{methodName(methodology)}<Pencil className="size-3" /></button><button onClick={() => toggleGuide(!guide)} aria-pressed={guide} className="inline-flex items-center gap-1 rounded-lg border border-app-line px-2 py-0.5 text-xs text-app-muted hover:text-app-fg"><BookOpen className="size-3" />{guide ? t('editor.hide_guide') : t('editor.guide')}</button></div><p className="mt-1 text-xs text-app-subtle">{[t('count.components', { count: view.model.components.length }), t('count.flows', { count: view.model.flows.length }), t('count.boundaries', { count: view.model.boundaries.length }), ...(view.model.updated_at ? [t('editor.updated', { date: formatDate(view.model.updated_at), user: view.model.updated_by })] : [])].join(' · ')}</p></div>
        {/* Una sola entrada para exportar (ley de Hick): ocho formatos en dos grupos, no ocho botones a la vez. */}
        <div className="flex flex-wrap gap-2"><Menu><MenuTrigger render={<Button size="sm" variant="outline" disabled={busy} className="border-app-line bg-app-soft" />}><ArrowDownToLine />{t('editor.export')}<ChevronDown className="size-3.5" /></MenuTrigger>
          <MenuContent>{EXPORTS.map(group => <MenuGroup key={group.label} label={t(group.label)}>{group.items.map(([label, file]) => <MenuItem key={file} onClick={() => void downloadFile(file)}>{t(label)}</MenuItem>)}</MenuGroup>)}</MenuContent></Menu>
          {user.role === 'admin' && <Button size="sm" variant="ghost" onClick={() => void remove()} aria-label={t('editor.delete')}><Trash2 /></Button>}</div></div>
      <ProjectRepositories draft={draft} setDraft={setDraft} catalog={catalog} onError={setError} onPicked={asset => setPicked(previous => [...previous, asset])} />
      {methodology === 'custom' && <CustomModulesPicker value={draft.custom_modules ?? ['manual', 'elements']} onChange={custom_modules => setDraft({ ...draft, custom_modules })} />}
      {tabs.some(([key]) => key === 'threats') && <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-6">{(['evidenced', 'open', 'mitigated', 'accepted', 'not_applicable'] as const).map(status => <div key={status} className="rounded-xl border border-app-line bg-inset px-3 py-2"><div className="text-xl font-semibold tabular-nums">{summary.by_status[status] ?? 0}</div><div className="text-xs text-app-muted">{t(statusLabel[status])}</div></div>)}<div className="rounded-xl border border-app-line bg-inset px-3 py-2"><div className="text-xl font-semibold tabular-nums">{summary.total}</div><div className="text-xs text-app-muted">{t('editor.total')}</div></div></div>}
    </div>
    {error && <div role="alert" className="rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{error}</div>}
    <div className="flex flex-wrap items-center gap-2">{tabs.map(([key, label]) => <Button key={key} size="sm" variant={current === key ? 'default' : 'outline'} className={current === key ? '' : 'border-app-line bg-app-soft'} onClick={() => setTab(key)}>{t(label)}</Button>)}
      {dirty && <span className="ml-auto flex items-center gap-2 text-xs text-warning">{t('editor.unsaved')}<Button size="sm" onClick={() => void save()} disabled={busy} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy ? <LoaderCircle className="animate-spin" /> : <Save />}{t('editor.save')}</Button></span>}</div>
    <div className={guide ? 'grid gap-5 xl:grid-cols-[minmax(0,1fr)_340px]' : ''}><div className="min-w-0 space-y-5">
      {current === 'threats' && <Threats view={view} draft={draft} methodology={methodology} busy={busy} onChanged={setView} onOpenRun={onOpenRun} onSaveModel={saveModel} />}
      {current === 'diagram' && <ThreatCanvas model={draft} setModel={setDraft} threats={view.threats} catalog={catalog} compact={guide} />}
      {current === 'elements' && <Elements draft={draft} setDraft={setDraft} catalog={catalog} />}
      {current === 'stages' && <PastaStages model={draft} setModel={setDraft} threats={view.threats} catalog={catalog} onGo={setTab} />}
      {current === 'trees' && <AttackTrees model={draft} setModel={setDraft} />}
      {current === 'attack' && <AttackMappings model={draft} setModel={setDraft} catalog={catalog} />}
    </div>{guide && <GuidePanel methodology={methodology} onClose={() => toggleGuide(false)} />}</div>
    {picking && <MethodDialog current={methodology} onClose={() => setPicking(false)} onPick={next => { setPicking(false); setDraft({ ...draft, methodology: next }); setTab('') }} />}
  </div>
}

// Repositorios del proyecto: se asocian cuando se quiera y de ellos se pueden proponer componentes.
function ProjectRepositories({ draft, setDraft, catalog, onError, onPicked }: { draft: Model; setDraft: (model: Model) => void; catalog: Catalog; onError: (text: string) => void; onPicked: (asset: Asset) => void }) {
  const { t } = useTranslation('threats')
  const [busy, setBusy] = useState('')
  const linked = draft.repositories ?? []
  const names = Object.fromEntries(catalog.assets.map(item => [item.id, item.name]))
  const associate = (source: Source) => {
    const key = sourceKey(source)
    if (linked.includes(key)) return
    onPicked({ id: key, name: source.name, kind: 'repository' })
    setDraft({ ...draft, repositories: [...linked, key] })
  }
  const inUse = new Set(draft.components.map(item => item.asset).filter(Boolean))
  const propose = async (repositories: string[]) => {
    setBusy(repositories.join(',')); onError('')
    try {
      const result = await api.post<{ model: Model; added: { components: number; flows: number } }>('/api/threat-models/propose', 'propose-components', { model: payloadOf(draft), repositories })
      setDraft({ ...draft, ...result.model })
      if (!result.added.components && !result.added.flows) onError(t('repos.nothing_new'))
    } catch (caught) { onError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy('') }
  }
  return <div className="flex flex-wrap items-center gap-2 rounded-xl border border-app-line bg-inset px-3 py-2">
    <span className="text-xs font-medium text-app-muted">{t('repos.title')}</span>
    {linked.length === 0 && <span className="text-xs text-app-subtle">{t('repos.none')}</span>}
    {linked.map(id => <span key={id} className="inline-flex items-center gap-1 rounded-lg border border-app-line bg-panel py-0.5 pr-1 pl-2 text-xs">
      {names[id] ?? id}
      <button type="button" onClick={() => void propose([id])} disabled={!!busy} aria-label={t('repos.propose_from', { name: names[id] ?? id })} title={t('repos.propose_hint')} className="grid size-6 place-items-center rounded text-brand hover:bg-brand/10">{busy === id ? <LoaderCircle className="size-3 animate-spin" /> : <Sparkles className="size-3" />}</button>
      {!inUse.has(id) && <button onClick={() => setDraft({ ...draft, repositories: linked.filter(item => item !== id) })} className="grid size-6 place-items-center rounded text-app-subtle hover:text-app-fg" aria-label={t('repos.remove', { name: names[id] ?? id })}>×</button>}
    </span>)}
    {(draft.repository_refs ?? []).map(reference => <span key={reference} className="inline-flex items-center gap-1 rounded-lg border border-warning-line bg-warning-soft py-0.5 pr-1 pl-2 text-xs text-warning" title={t('repos.ref_hint')}>{t('repos.ref', { ref: reference })} <button onClick={() => setDraft({ ...draft, repository_refs: (draft.repository_refs ?? []).filter(item => item !== reference) })} className="rounded px-1" aria-label={t('repos.remove_ref', { ref: reference })}>×</button></span>)}
    {linked.length < 50 && <details className="w-full rounded-lg border border-app-line bg-panel p-2"><summary className="cursor-pointer text-xs text-app-muted">{t('repos.link')}</summary><div className="mt-2"><SourceSearch perPage={8} render={item => <button type="button" disabled={linked.includes(sourceKey(item))} className="block w-full truncate rounded px-2 py-1 text-left text-xs hover:bg-app-soft disabled:opacity-50" onClick={() => associate(item)}>{linked.includes(sourceKey(item)) ? t('repos.already_linked', { name: item.name }) : item.name}</button>} /></div></details>}
  </div>
}

// Labels are catalog keys (`threats` namespace).
const EXPORTS: { label: string; items: [string, string][] }[] = [
  { label: 'exports.reports', items: [['exports.pdf', 'report.pdf'], ['exports.markdown', 'report.md']] },
  { label: 'exports.tools', items: [['exports.json', 'model.json'], ['exports.svg', 'diagram.svg'], ['exports.threat_dragon', 'threat-dragon.json'], ['exports.pytm', 'tm.py']] },
]

const TABS: Record<Methodology, [string, string][]> = {
  stride: [['threats', 'tabs.threats'], ['diagram', 'tabs.diagram'], ['elements', 'tabs.elements']],
  linddun: [['threats', 'tabs.privacy_threats'], ['diagram', 'tabs.diagram'], ['elements', 'tabs.elements']],
  pasta: [['stages', 'tabs.stages'], ['diagram', 'tabs.diagram'], ['threats', 'tabs.threats'], ['trees', 'tabs.trees'], ['elements', 'tabs.elements']],
  attack_trees: [['trees', 'tabs.trees'], ['diagram', 'tabs.diagram'], ['threats', 'tabs.threats']],
  attack: [['attack', 'tabs.attack'], ['diagram', 'tabs.diagram'], ['threats', 'tabs.threats']],
  custom: [['diagram', 'tabs.diagram']],
}

const CUSTOM_OPTIONS: { key: CustomModule; title: string; description: string }[] = [
  { key: 'stride', title: 'modules.stride.title', description: 'modules.stride.description' },
  { key: 'linddun', title: 'modules.linddun.title', description: 'modules.linddun.description' },
  { key: 'manual', title: 'modules.manual.title', description: 'modules.manual.description' },
  { key: 'pasta', title: 'modules.pasta.title', description: 'modules.pasta.description' },
  { key: 'trees', title: 'modules.trees.title', description: 'modules.trees.description' },
  { key: 'attack', title: 'modules.attack.title', description: 'modules.attack.description' },
  { key: 'elements', title: 'modules.elements.title', description: 'modules.elements.description' },
]

function customTabs(modules: CustomModule[]): [string, string][] {
  const tabs: [string, string][] = [['diagram', 'tabs.diagram']]
  if (modules.some(item => ['stride', 'linddun', 'manual'].includes(item))) tabs.push(['threats', 'tabs.threats'])
  if (modules.includes('pasta')) tabs.push(['stages', 'tabs.pasta_stages'])
  if (modules.includes('trees')) tabs.push(['trees', 'tabs.trees'])
  if (modules.includes('attack')) tabs.push(['attack', 'tabs.attack'])
  if (modules.includes('elements')) tabs.push(['elements', 'tabs.elements'])
  return tabs
}

function CustomModulesPicker({ value, onChange }: { value: CustomModule[]; onChange: (next: CustomModule[]) => void }) {
  const { t } = useTranslation('threats')
  return <div className="space-y-2 rounded-xl border border-app-line bg-inset p-3"><div><p className="text-sm font-semibold">{t('modules.title')}</p><p className="text-xs text-app-muted">{t('modules.hint')}</p></div>
    <div className="grid gap-2 sm:grid-cols-2">{CUSTOM_OPTIONS.map(option => <label key={option.key} className="flex cursor-pointer items-start gap-2 rounded-lg border border-app-line bg-panel p-2.5 text-xs"><input type="checkbox" className="mt-0.5 size-4 shrink-0 accent-brand" checked={value.includes(option.key)} onChange={event => onChange(event.target.checked ? [...value, option.key] : value.filter(item => item !== option.key))} /><span><strong className="block text-app-fg">{t(option.title)}</strong><span className="text-app-muted">{t(option.description)}</span></span></label>)}</div>
  </div>
}

function payloadOf(model: Model) {
  return { name: model.name, description: model.description, methodology: model.methodology ?? 'stride', custom_modules: model.custom_modules ?? ['manual', 'elements'], repositories: model.repositories ?? [], repository_refs: model.repository_refs ?? [], components: model.components, flows: model.flows,
           boundaries: model.boundaries, manual_threats: model.manual_threats ?? [], attack_trees: model.attack_trees ?? [],
           attack_mappings: model.attack_mappings ?? [], pasta: Object.fromEntries(Object.entries(model.pasta ?? {}).filter(([, text]) => text.trim())) }
}

function Threats({ view, draft, methodology, busy, onChanged, onOpenRun, onSaveModel }: { view: View; draft: Model; methodology: Methodology; busy: boolean; onChanged: (view: View) => void; onOpenRun: (id: string) => void; onSaveModel: (model: Model) => Promise<boolean> }) {
  const { t } = useTranslation('threats')
  const [editing, setEditing] = useState<ManualThreat | 'new' | null>(null)
  const categoryKey = (row: Threat) => methodology === 'custom' ? `${row.framework ?? 'manual'}:${row.stride}` : row.stride
  const codes = [...new Set(view.threats.map(categoryKey).filter(Boolean))]
  const categoryRow = (code: string) => view.threats.find(row => categoryKey(row) === code)
  const saveManual = async (threat: ManualThreat) => {
    const list = draft.manual_threats ?? []
    const next = list.some(item => item.id === threat.id) ? list.map(item => item.id === threat.id ? threat : item) : [...list, threat]
    if (await onSaveModel({ ...draft, manual_threats: next })) setEditing(null)
  }
  const removeManual = async (manualId: string) => {
    if (!window.confirm(t('threat.confirm_remove'))) return
    await onSaveModel({ ...draft, manual_threats: (draft.manual_threats ?? []).filter(item => item.id !== manualId) })
  }
  const [stride, setStride] = useState('all')
  const [status, setStatus] = useState('pending')
  const [deciding, setDeciding] = useState<{ threat: Threat; status: 'mitigated' | 'accepted' | 'not_applicable' } | null>(null)
  const [open, setOpen] = useState<string | null>(null)
  const rows = view.threats.filter(row => (stride === 'all' || categoryKey(row) === stride) && (status === 'all' || (status === 'pending' ? row.status === 'evidenced' || row.status === 'open' : row.status === status)))
  const reopen = async (threat: Threat) => onChanged(await api.post<View>('/api/threat-models/decide', 'threat-decision', { id: view.model.id, threat: threat.id, status: 'open' }))
  return <Card className="border-app-line bg-panel"><CardContent className="space-y-4 p-5">
    <div className="flex flex-wrap gap-2">
      {['all', ...codes].map(letter => { const category = categoryRow(letter); return <button key={letter} onClick={() => setStride(letter)} title={category && category.framework !== 'manual' ? categoryHelp((category.framework ?? methodology) as Methodology, category.stride) : undefined} className={`rounded-lg border px-2.5 py-1 text-xs ${stride === letter ? 'border-brand/50 bg-brand/10 text-brand' : 'border-app-line bg-app-soft text-app-muted'}`}>{letter === 'all' ? t('filter.all') : `${methodology === 'custom' ? `${category?.framework?.toUpperCase() ?? t('filter.manual')} · ` : category?.stride && category.stride.length <= 2 ? `${category.stride} · ` : ''}${category?.category ?? letter} (${view.threats.filter(row => categoryKey(row) === letter).length})`}</button> })}
      <Button size="sm" variant="outline" className="border-app-line bg-app-soft" onClick={() => setEditing('new')}><Plus />{t('filter.add_threat')}</Button>
      <select aria-label={t('filter.status')} value={status} onChange={event => setStatus(event.target.value)} className={`${select} ml-auto`}><option value="pending">{t('filter.pending')}</option><option value="all">{t('filter.all_statuses')}</option>{Object.entries(statusLabel).map(([key, label]) => <option key={key} value={key}>{t(label)}</option>)}</select>
    </div>
    {rows.length === 0 ? <p className="py-8 text-center text-sm text-app-subtle">{view.threats.length ? t('filter.no_match') : t('filter.empty')}</p>
      : <div className="divide-y divide-app-line overflow-hidden rounded-xl border border-app-line">{rows.map(row => { const expanded = open === row.id
        return <div key={row.id}>
          <button type="button" aria-expanded={expanded} onClick={() => setOpen(expanded ? null : row.id)} className="grid w-full gap-2 px-4 py-3 text-left transition hover:bg-app-soft md:grid-cols-[110px_90px_minmax(0,1fr)_120px] md:items-center">
            <Badge variant="outline" className={`w-fit ${statusClass[row.status]}`}>{t(statusLabel[row.status])}{row.evidence_count ? ` · ${row.evidence_count}` : ''}</Badge>
            <Badge variant="outline" className={`w-fit ${severityClass[row.severity]}`}>{severityLabel[row.severity] ? t(severityLabel[row.severity]) : row.severity}</Badge>
            <span className="flex min-w-0 items-start gap-2"><ChevronRight className={`mt-1 size-3.5 shrink-0 text-app-subtle transition ${expanded ? 'rotate-90' : ''}`} /><span className="min-w-0"><span className="block truncate text-sm font-medium">{row.title}</span><span className="block truncate text-xs text-app-subtle">{row.element_name}</span></span></span>
            <span className="text-xs text-app-muted">{row.stride} · {row.category}</span>
          </button>
          {expanded && <div className="space-y-3 border-t border-app-line bg-inset px-4 py-4 text-sm">
            <p className="text-app-secondary">{row.why}</p>
            <div><span className="text-xs font-medium text-app-muted">{t('threat.mitigations')}</span><ul className="mt-1 list-disc space-y-0.5 pl-5 text-app-secondary">{row.mitigations.map(item => <li key={item}>{item}</li>)}</ul></div>
            <p className="font-mono text-xs text-app-subtle">{row.rule} · {row.cwe.map(item => `CWE-${item}`).join(', ')}</p>
            {row.evidence.length > 0 && <div className="rounded-lg border border-warning-line bg-warning-soft p-3"><span className="text-xs font-medium text-warning"><ShieldAlert className="mr-1 inline size-3.5" />{t('threat.evidence', { count: row.evidence_count })}</span><span className="mt-0.5 block text-[11px] text-app-subtle">{row.evidence_scope?.some(scope => !scope.path) ? t('threat.evidence_repo') : t('threat.evidence_paths', { paths: row.evidence_scope?.map(scope => scope.path).join(', ') })}</span><ul className="mt-2 space-y-1 text-xs">{row.evidence.slice(0, 8).map(item => <li key={item.fingerprint} className="flex flex-wrap items-center gap-2"><Badge variant="outline" className={`text-[11px] ${severityClass[item.severity] ?? ''}`}>{severityLabel[item.severity] ? t(severityLabel[item.severity]) : item.severity}</Badge><span className="text-app-secondary">{item.title}</span><span className="font-mono text-app-subtle">{item.location}</span><button onClick={() => onOpenRun(item.run_id)} className="text-brand hover:underline">{t('threat.view_findings')}</button></li>)}</ul></div>}
            {row.framework === 'manual' && (row.likelihood || row.impact || row.owner) && <p className="text-xs text-app-muted">{t('threat.rating', { likelihood: row.likelihood ? t(LIKELIHOOD[row.likelihood]) : '—', impact: row.impact ? t(IMPACT[row.impact]) : '—', owner: row.owner || '—' })}</p>}
            {row.framework === 'manual' && <div className="flex gap-1.5"><Button size="xs" variant="outline" className="border-app-line bg-app-soft" onClick={() => setEditing((draft.manual_threats ?? []).find(item => item.id === row.manual_id) ?? null)}><Pencil />{t('common:actions.edit')}</Button><Button size="xs" variant="ghost" onClick={() => void removeManual(row.manual_id ?? '')}><Trash2 />{t('common:actions.remove')}</Button></div>}
            {row.decision && <p className="text-xs text-app-muted"><strong>{t(statusLabel[row.status])}</strong> {t('threat.decided', { by: row.decision.by, date: formatDate(row.decision.at), reason: row.decision.reason })}</p>}
            <div className="flex flex-wrap gap-1.5">{row.decision ? <Button size="xs" variant="outline" className="border-app-line bg-app-soft" onClick={() => void reopen(row)}>{t('threat.reopen')}</Button>
              : (['mitigated', 'accepted', 'not_applicable'] as const).map(next => <Button key={next} size="xs" variant="outline" className="border-app-line bg-app-soft" onClick={() => setDeciding({ threat: row, status: next })}>{t(statusLabel[next])}</Button>)}</div>
          </div>}
        </div> })}</div>}
    {editing && <ManualThreatDialog model={draft} initial={editing === 'new' ? undefined : editing} methodology={methodology} busy={busy} onClose={() => setEditing(null)} onSave={threat => void saveManual(threat)} />}
    {deciding && <DecisionDialog modelId={view.model.id} threat={deciding.threat} status={deciding.status} onClose={() => setDeciding(null)} onDone={next => { setDeciding(null); onChanged(next) }} />}
  </CardContent></Card>
}

function DecisionDialog({ modelId, threat, status, onClose, onDone }: { modelId: string; threat: Threat; status: 'mitigated' | 'accepted' | 'not_applicable'; onClose: () => void; onDone: (view: View) => void }) {
  const { t } = useTranslation('threats')
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setBusy(true); setError('')
    try { onDone(await api.post<View>('/api/threat-models/decide', 'threat-decision', { id: modelId, threat: threat.id, status, reason })) }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }
  return <Dialog open onOpenChange={next => { if (!next) onClose() }}><DialogContent className="max-w-lg">
    <DialogHeader><DialogTitle>{t(statusLabel[status])} · {threat.title}</DialogTitle><DialogDescription>{threat.element_name}. {t(DECISION_HINT[status])}{threat.evidence_count ? ` ${t('decision.evidence', { count: threat.evidence_count })}` : ''}</DialogDescription></DialogHeader>
    <form className="space-y-4" onSubmit={submit}><textarea aria-label={t('decision.reason')} required minLength={10} maxLength={500} rows={3} value={reason} onChange={event => setReason(event.target.value)} className="w-full rounded-lg border border-app-line bg-app-soft px-3 py-2 text-sm" />
      {error && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger">{error}</div>}
      <DialogFooter><Button type="button" variant="ghost" onClick={onClose}>{t('common:actions.cancel')}</Button><Button type="submit" disabled={busy || reason.trim().length < 10} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy && <LoaderCircle className="animate-spin" />}{t('common:actions.save')}</Button></DialogFooter></form>
  </DialogContent></Dialog>
}

function Chips({ value, options, onChange }: { value: string[]; options: Record<string, string>; onChange: (next: string[]) => void }) {
  return <div className="flex flex-wrap gap-1">{Object.entries(options).map(([key, label]) => <button key={key} type="button" aria-pressed={value.includes(key)} onClick={() => onChange(value.includes(key) ? value.filter(item => item !== key) : [...value, key])} className={`min-h-6 rounded border px-2 py-0.5 text-[11px] ${value.includes(key) ? 'border-brand/50 bg-brand/10 text-brand' : 'border-app-line text-app-subtle'}`}>{label}</button>)}</div>
}

function Elements({ draft, setDraft, catalog }: { draft: Model; setDraft: (model: Model) => void; catalog: Catalog }) {
  const { t } = useTranslation('threats')
  const ids = draft.components.map(item => item.id)
  const boundaryOf = (component: string) => draft.boundaries.find(item => item.components.includes(component))?.id ?? ''
  const updateComponent = (id: string, change: Partial<Component>) => setDraft({ ...draft, components: draft.components.map(item => item.id === id ? { ...item, ...change } : item) })
  const moveTo = (component: string, boundary: string) => setDraft({ ...draft, boundaries: draft.boundaries.map(item => ({ ...item, components: item.id === boundary ? [...item.components.filter(id => id !== component), component] : item.components.filter(id => id !== component) })) })
  const addComponent = () => { const id = newId('componente', ids); setDraft({ ...draft, components: [...draft.components, { id, name: t('canvas.new_component'), kind: 'service', data: [], internet_facing: false, authenticates: false, encrypted_at_rest: false }] }) }
  const removeComponent = (id: string) => setDraft({ ...draft, components: draft.components.filter(item => item.id !== id), flows: draft.flows.filter(flow => flow.source !== id && flow.target !== id), boundaries: draft.boundaries.map(item => ({ ...item, components: item.components.filter(member => member !== id) })) })
  const updateFlow = (id: string, change: Partial<Flow>) => setDraft({ ...draft, flows: draft.flows.map(item => item.id === id ? { ...item, ...change } : item) })
  const addFlow = () => { if (draft.components.length < 2) return; setDraft({ ...draft, flows: [...draft.flows, { id: newId('flujo', draft.flows.map(item => item.id)), source: ids[0], target: ids[1], protocol: 'https', data: [], authenticated: true, encrypted: true }] }) }
  const cell = 'px-2 py-2 align-top'
  return <div className="space-y-5">
    <Card className="border-app-line bg-panel"><CardHeader className="flex flex-row items-center justify-between"><CardTitle className="text-base">{t('elements.boundaries')}</CardTitle><Button size="sm" variant="outline" className="border-app-line bg-app-soft" onClick={() => setDraft({ ...draft, boundaries: [...draft.boundaries, { id: newId('frontera', draft.boundaries.map(item => item.id)), name: t('canvas.new_boundary'), components: [] }] })}><Plus />{t('canvas.boundary')}</Button></CardHeader>
      <CardContent className="flex flex-wrap gap-2">{draft.boundaries.map(item => <div key={item.id} className="flex items-center gap-1 rounded-lg border border-app-line bg-inset px-2 py-1"><Input aria-label={t('elements.boundary_name')} value={item.name} maxLength={80} onChange={event => setDraft({ ...draft, boundaries: draft.boundaries.map(entry => entry.id === item.id ? { ...entry, name: event.target.value } : entry) })} className="h-7 w-40 border-0 bg-transparent px-1 text-sm" /><span className="text-xs text-app-subtle">{item.components.length}</span><Button size="xs" variant="ghost" aria-label={t('inspector.remove_boundary')} onClick={() => setDraft({ ...draft, boundaries: draft.boundaries.filter(entry => entry.id !== item.id) })}><Trash2 /></Button></div>)}{!draft.boundaries.length && <p className="text-sm text-app-subtle">{t('elements.no_boundaries')}</p>}</CardContent></Card>
    <Card className="border-app-line bg-panel"><CardHeader className="flex flex-row items-center justify-between"><CardTitle className="text-base">{t('elements.components')}</CardTitle><Button size="sm" variant="outline" className="border-app-line bg-app-soft" onClick={addComponent}><Plus />{t('canvas.component')}</Button></CardHeader>
      <CardContent className="overflow-x-auto"><table className="w-full min-w-[980px] text-sm"><thead><tr className="text-left text-xs text-app-subtle"><th scope="col" className={cell}>{t('elements.name_technology')}</th><th scope="col" className={cell}>{t('inspector.kind')}</th><th scope="col" className={cell}>{t('canvas.boundary')}</th><th scope="col" className={cell}>{t('elements.asset')}</th><th scope="col" className={cell}>{t('inspector.data')}</th><th scope="col" className={cell}>{t('elements.properties')}</th><th scope="col"><span className="sr-only">{t('elements.actions')}</span></th></tr></thead>
        <tbody className="divide-y divide-app-line">{draft.components.map(item => <tr key={item.id}>
          <td className={cell}><Input aria-label={t('inspector.name')} value={item.name} maxLength={80} onChange={event => updateComponent(item.id, { name: event.target.value })} className="h-8 border-app-line bg-app-soft" /><Input aria-label={t('inspector.technology')} value={item.technology ?? ''} maxLength={80} placeholder={t('inspector.technology')} onChange={event => updateComponent(item.id, { technology: event.target.value })} className="mt-1 h-7 border-app-line bg-app-soft text-xs" />{item.origin === 'suggested' && <span className="mt-1 block max-w-64 text-[11px] leading-4 text-brand" title={item.description}>{item.description || t('elements.suggested')}</span>}</td>
          <td className={cell}><select aria-label={t('inspector.kind')} value={item.kind} onChange={event => updateComponent(item.id, { kind: event.target.value as Kind, custom_kind: event.target.value === 'custom' ? item.custom_kind || t('canvas.custom_kind_default') : '', custom_base: event.target.value === 'custom' ? item.custom_base || 'service' : undefined })} className={select}>{Object.entries(catalog.kinds).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select>{item.kind === 'custom' && <><Input aria-label={t('inspector.custom_kind')} value={item.custom_kind ?? ''} maxLength={80} onChange={event => updateComponent(item.id, { custom_kind: event.target.value })} className="mt-1 h-7 border-app-line bg-app-soft text-xs" /><select aria-label={t('inspector.custom_base')} value={item.custom_base || 'service'} onChange={event => updateComponent(item.id, { custom_base: event.target.value as Exclude<Kind, 'custom'> })} className={`${select} mt-1`}>{Object.entries(catalog.kinds).filter(([key]) => key !== 'custom').map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select></>}</td>
          <td className={cell}><select aria-label={t('canvas.boundary')} value={boundaryOf(item.id)} onChange={event => moveTo(item.id, event.target.value)} className={select}><option value="">{t('elements.no_boundary')}</option>{draft.boundaries.map(entry => <option key={entry.id} value={entry.id}>{entry.name}</option>)}</select></td>
          <td className={cell}><select aria-label={t('elements.linked_asset')} value={item.asset ?? ''} onChange={event => updateComponent(item.id, { asset: event.target.value || null, asset_ref: event.target.value ? '' : item.asset_ref })} className={`${select} max-w-48`}><option value="">{t('inspector.not_linked')}</option>{assetGroups(catalog, draft).map(group => <optgroup key={group.label} label={group.label}>{group.items.map(asset => <option key={asset.id} value={asset.id}>{asset.name}</option>)}</optgroup>)}</select>{item.asset_ref && !item.asset && <span className="mt-1 block text-[11px] text-warning">{t('elements.pending_ref', { ref: item.asset_ref })}</span>}</td>
          <td className={cell}><Chips value={item.data} options={catalog.classifications} onChange={data => updateComponent(item.id, { data })} /></td>
          <td className={`${cell} space-y-1 text-xs`}>{([['internet_facing', 'canvas.internet_facing'], ['authenticates', 'inspector.authenticates'], ['encrypted_at_rest', 'canvas.encrypted_at_rest']] as const).map(([key, label]) => <label key={key} className="flex items-center gap-1.5 whitespace-nowrap"><input type="checkbox" className="size-3.5 accent-brand" checked={item[key]} onChange={event => updateComponent(item.id, { [key]: event.target.checked })} />{t(label)}</label>)}</td>
          <td className={cell}><Button size="xs" variant="ghost" aria-label={t('repos.remove', { name: item.name })} onClick={() => removeComponent(item.id)}><Trash2 /></Button></td>
        </tr>)}</tbody></table></CardContent></Card>
    <Card className="border-app-line bg-panel"><CardHeader className="flex flex-row items-center justify-between"><CardTitle className="text-base">{t('elements.flows')}</CardTitle><Button size="sm" variant="outline" className="border-app-line bg-app-soft" disabled={draft.components.length < 2} onClick={addFlow}><Plus />{t('elements.flow')}</Button></CardHeader>
      <CardContent className="overflow-x-auto"><table className="w-full min-w-[900px] text-sm"><thead><tr className="text-left text-xs text-app-subtle"><th scope="col" className={cell}>{t('elements.source_target')}</th><th scope="col" className={cell}>{t('elements.name_protocol')}</th><th scope="col" className={cell}>{t('inspector.data')}</th><th scope="col" className={cell}>{t('elements.properties')}</th><th scope="col"><span className="sr-only">{t('elements.actions')}</span></th></tr></thead>
        <tbody className="divide-y divide-app-line">{draft.flows.map(flow => <tr key={flow.id}>
          <td className={cell}><div className="flex items-center gap-1"><select aria-label={t('elements.source')} value={flow.source} onChange={event => updateFlow(flow.id, { source: event.target.value })} className={select}>{draft.components.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select>→<select aria-label={t('elements.target')} value={flow.target} onChange={event => updateFlow(flow.id, { target: event.target.value })} className={select}>{draft.components.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select></div></td>
          <td className={cell}><Input aria-label={t('elements.flow_name')} value={flow.name ?? ''} maxLength={80} placeholder={t('inspector.flow_name')} onChange={event => updateFlow(flow.id, { name: event.target.value })} className="h-8 border-app-line bg-app-soft" /><select aria-label={t('inspector.protocol')} value={flow.protocol} onChange={event => updateFlow(flow.id, { protocol: event.target.value })} className={`${select} mt-1`}>{catalog.protocols.map(item => <option key={item} value={item}>{item.toUpperCase()}</option>)}</select></td>
          <td className={cell}><Chips value={flow.data} options={catalog.classifications} onChange={data => updateFlow(flow.id, { data })} /></td>
          <td className={`${cell} space-y-1 text-xs`}><label className="flex items-center gap-1.5"><input type="checkbox" className="size-3.5 accent-brand" checked={flow.authenticated} onChange={event => updateFlow(flow.id, { authenticated: event.target.checked })} />{t('inspector.authenticated')}</label><label className="flex items-center gap-1.5"><input type="checkbox" className="size-3.5 accent-brand" checked={flow.encrypted} onChange={event => updateFlow(flow.id, { encrypted: event.target.checked })} />{t('elements.encrypted')}</label></td>
          <td className={cell}><Button size="xs" variant="ghost" aria-label={t('elements.remove_flow')} onClick={() => setDraft({ ...draft, flows: draft.flows.filter(item => item.id !== flow.id) })}><Trash2 /></Button></td>
        </tr>)}</tbody></table>{!draft.flows.length && <p className="py-4 text-sm text-app-subtle">{t('elements.no_flows')}</p>}</CardContent></Card>
  </div>
}
