import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react'
import { ArrowDownToLine, ArrowLeft, ArrowUpFromLine, BookOpen, ChevronRight, Pencil, LoaderCircle, Network, Plus, Save, ShieldAlert, Sparkles, Trash2 } from 'lucide-react'
import type { SessionUser } from '@/components/auth/session'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/loading'
import { api } from '@/lib/api'
import { readRoute, setRouteParam } from '@/lib/route'
import { formatDate } from '@/lib/types'
import { ThreatCanvas } from '@/components/threat-canvas'
import { ThreatJsonImporter } from '@/components/threat-json-importer'
import { categoryHelp, GUIDES, type Methodology } from '@/components/threat-guides'
import { AttackMappings, AttackTrees, GuidePanel, ManualThreatDialog, MethodDialog, MethodPicker, PastaStages } from '@/components/threat-methods'
import { assetGroups, newId, type Catalog, type Component, type CustomModule, type Flow, type Kind, type Model, type Threat, type View, type Asset, type ManualThreat } from '@/components/threat-model-types'

const statusLabel = { evidenced: 'Con indicios', open: 'Abierta', mitigated: 'Mitigada', accepted: 'Aceptada', not_applicable: 'No aplica' }
const statusClass = { evidenced: 'border-amber-500/50 bg-amber-500/15 text-amber-900 dark:text-amber-200', open: 'border-app-line text-app-secondary', mitigated: 'border-brand/30 text-brand', accepted: 'border-violet-500/30 text-violet-800 dark:text-violet-300', not_applicable: 'border-app-line text-app-subtle' }
const severityClass: Record<string, string> = { critical: 'border-transparent bg-rose-600 text-white', high: 'border-orange-500/30 bg-orange-500/15 text-orange-800 dark:text-orange-300', medium: 'border-amber-500/30 bg-amber-400/15 text-amber-800 dark:text-amber-300', low: 'border-sky-500/30 bg-sky-400/15 text-sky-800 dark:text-sky-300' }
const severityLabel: Record<string, string> = { critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja' }
const select = 'h-8 rounded-lg border border-app-line bg-app-soft px-2 text-xs text-app-fg'

export function ThreatModels({ user, onOpenRun }: { user: SessionUser; onOpenRun: (id: string) => void }) {
  const [catalog, setCatalog] = useState<Catalog | null>(null)
  const [openId, setOpenId] = useState<string | null>(() => readRoute().params.get('model'))
  useEffect(() => { setRouteParam('model', openId) }, [openId])
  const [creating, setCreating] = useState(false)
  const [importing, setImporting] = useState(false)
  const [error, setError] = useState('')
  const load = useCallback(() => api.get<Catalog>('/api/threat-models').then(setCatalog).catch(caught => setError(caught instanceof Error ? caught.message : String(caught))), [])
  useEffect(() => { void load() }, [load])
  if (!catalog) return error ? <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-700 dark:text-rose-200">{error}</div> : <Skeleton rows={4} />
  if (openId) return <Editor id={openId} catalog={catalog} user={user} onBack={() => { setOpenId(null); void load() }} onOpenRun={onOpenRun} />
  return <div className="space-y-5">
    <Card className="border-app-line bg-panel"><CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3"><div><CardTitle>Modelos de amenazas</CardTitle><CardDescription className="mt-1 max-w-3xl leading-6">Dibuja el sistema —componentes, flujos de datos y fronteras de confianza— y analízalo con el enfoque que prefieras. Si el código de un componente tiene hallazgos abiertos relacionados, la amenaza aparece <strong>con indicios</strong>: una señal para revisar, no una confirmación.</CardDescription></div><div className="flex flex-wrap gap-2"><Button variant="outline" onClick={() => setImporting(true)}><ArrowUpFromLine />Importar JSON</Button><Button onClick={() => setCreating(true)} className="bg-primary text-primary-foreground hover:bg-primary/90"><Plus />Nuevo modelo</Button></div></CardHeader>
      {error && <div role="alert" className="mx-6 mb-4 rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-700 dark:text-rose-200">{error}</div>}
      <CardContent>{catalog.models.length === 0 ? <div className="flex flex-col items-center gap-2 py-12 text-center"><Network className="size-7 text-app-subtle" /><p className="font-medium">Aún no hay modelos</p><p className="max-w-md text-sm text-app-muted">Crea un proyecto para un sistema o una funcionalidad. Puedes dibujarlo a mano o proponer componentes desde uno o varios repositorios, ahora o más adelante.</p></div>
        : <div className="divide-y divide-app-line rounded-xl border border-app-line">{catalog.models.map(item => <button key={item.id} onClick={() => setOpenId(item.id)} className="flex w-full items-center gap-3 px-4 py-3 text-left transition hover:bg-app-soft"><Network className="size-4 text-app-subtle" /><span className="min-w-0 flex-1"><span className="block text-sm font-medium">{item.name}<span className="ml-2 rounded border border-app-line px-1.5 py-0.5 align-middle text-[10px] font-normal text-app-subtle">{GUIDES[(item.methodology ?? 'stride') as Methodology]?.name ?? item.methodology}</span></span><span className="block truncate text-xs text-app-subtle">{item.components} componentes · {item.flows} flujos{item.updated_at ? ` · actualizado ${formatDate(item.updated_at)} por ${item.updated_by}` : ''}</span></span><ChevronRight className="size-4 text-app-subtle" /></button>)}</div>}</CardContent></Card>
    <CreateDialog open={creating} assets={catalog.assets} onClose={() => setCreating(false)} onCreated={id => { setCreating(false); setOpenId(id) }} />
    {importing && <ThreatJsonImporter onClose={() => setImporting(false)} onImported={id => { setImporting(false); setOpenId(id) }} />}
  </div>
}

function CreateDialog({ open, assets, onClose, onCreated }: { open: boolean; assets: Asset[]; onClose: () => void; onCreated: (id: string) => void }) {
  const [name, setName] = useState('')
  const [methodology, setMethodology] = useState<Methodology>('stride')
  const [customModules, setCustomModules] = useState<CustomModule[]>(['manual', 'elements'])
  const [chosen, setChosen] = useState<string[]>([])
  const [filter, setFilter] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const repositories = assets.filter(item => item.kind === 'repository' && item.name.toLowerCase().includes(filter.trim().toLowerCase()))
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setBusy(true); setError('')
    try {
      // Sin nombre, el sistema se llama como sus repositorios: el nombre no debe bloquear la propuesta.
      const fallback = assets.filter(item => chosen.includes(item.id)).map(item => item.name.split('/').pop()).join(' + ').slice(0, 80)
      const finalName = name.trim() || fallback || 'Nuevo proyecto'
      const body = chosen.length ? { name: finalName, suggest: chosen, methodology, custom_modules: customModules } : { model: { name: finalName, methodology, custom_modules: customModules, components: [], flows: [], boundaries: [], repositories: [] } }
      onCreated((await api.post<View>('/api/threat-models', 'save-threat-model', body)).model.id)
      setName(''); setChosen([])
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }
  return <Dialog open={open} onOpenChange={next => { if (!next) onClose() }}><DialogContent className="max-h-[92vh] max-w-2xl overflow-y-auto">
    <DialogHeader><DialogTitle>Nuevo proyecto de modelado</DialogTitle><DialogDescription>Un proyecto modela un sistema o una funcionalidad. No necesita repositorios para empezar: puedes asociarlos después, uno o varios (microservicios, microfrontends), y proponer componentes desde ellos.</DialogDescription></DialogHeader>
    <form className="space-y-4" onSubmit={submit}>
      <div className="space-y-1.5"><span className="text-xs text-app-muted">Enfoque</span><MethodPicker value={methodology} onChange={setMethodology} /><p className="text-[11px] leading-4 text-app-subtle">Se puede cambiar después sin perder el diagrama.</p></div>
      {methodology === 'custom' && <CustomModulesPicker value={customModules} onChange={setCustomModules} />}
      <div className="space-y-1.5"><label htmlFor="tm-name" className="text-xs text-app-muted">Nombre del proyecto</label><Input id="tm-name" autoFocus maxLength={80} value={name} onChange={event => setName(event.target.value)} placeholder="p. ej. Pagos, Portal de clientes, Login" className="border-app-line bg-app-soft" /></div>
      <details className="rounded-lg border border-app-line px-3 py-2" open={chosen.length > 0}><summary className="cursor-pointer text-xs text-app-muted">Partir de repositorios (opcional){chosen.length ? ` · ${chosen.length} elegidos` : ''}</summary><div className="mt-2 space-y-1.5"><p className="text-[11px] leading-4 text-app-subtle">Se leen sus manifiestos (package.json, pyproject, go.mod, Cargo.toml, compose) y se propone cada componente citando de qué dependencia sale.</p><div className="flex items-center justify-end gap-2"><Input aria-label="Buscar repositorio" value={filter} onChange={event => setFilter(event.target.value)} placeholder="Buscar…" className="h-7 w-40 border-app-line bg-app-soft text-xs" /></div>
        {repositories.length ? <div className="max-h-64 space-y-0.5 overflow-y-auto rounded-lg border border-app-line p-2">{repositories.map(item => <label key={item.id} className="flex items-center gap-2 rounded px-2 py-1 text-sm hover:bg-app-soft"><input type="checkbox" className="size-4 accent-brand" checked={chosen.includes(item.id)} onChange={event => setChosen(previous => event.target.checked ? [...previous, item.id] : previous.filter(id => id !== item.id))} /><span className="min-w-0 flex-1 truncate">{item.name}</span>{item.last_run ? <span className="shrink-0 text-[10px] text-brand">escaneado</span> : <span className="shrink-0 text-[10px] text-app-subtle">sin escanear</span>}</label>)}</div> : <p className="text-xs text-app-subtle">{filter ? 'Ningún repositorio coincide.' : 'Conecta GitHub en Integraciones para elegir repositorios.'}</p>}
        <p className="text-[11px] leading-4 text-app-subtle">Los repositorios sin escanear se modelan igual, pero sus amenazas no tendrán indicios hasta que los analices.</p></div></details>
      {error && <div role="alert" className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-700 dark:text-rose-200">{error}</div>}
      <DialogFooter><Button type="button" variant="ghost" onClick={onClose}>Cancelar</Button><Button type="submit" disabled={busy} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy ? <LoaderCircle className="animate-spin" /> : chosen.length ? <Sparkles /> : <Plus />}{busy && chosen.length ? 'Leyendo manifiestos…' : chosen.length ? 'Crear y proponer componentes' : 'Crear proyecto'}</Button></DialogFooter>
    </form>
  </DialogContent></Dialog>
}

function Editor({ id, catalog, user, onBack, onOpenRun }: { id: string; catalog: Catalog; user: SessionUser; onBack: () => void; onOpenRun: (id: string) => void }) {
  const [view, setView] = useState<View | null>(null)
  const [draft, setDraft] = useState<Model | null>(null)
  const [tab, setTab] = useState<string>('')
  const [picking, setPicking] = useState(false)
  // La guía se abre a demanda y se recuerda: quien ya sabe modelar no la ve si no la pide.
  const [guide, setGuide] = useState(() => { try { return localStorage.getItem('tm-guide') === 'open' } catch { return false } })
  const toggleGuide = (next: boolean) => { setGuide(next); try { localStorage.setItem('tm-guide', next ? 'open' : 'closed') } catch { /* sin almacenamiento */ } }
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const load = useCallback(async () => { const data = await api.get<View>(`/api/threat-models/${id}`); setView(data); setDraft(data.model) }, [id])
  useEffect(() => { load().catch(caught => setError(caught instanceof Error ? caught.message : String(caught))) }, [load])
  const dirty = useMemo(() => !!view && !!draft && JSON.stringify(view.model) !== JSON.stringify(draft), [view, draft])
  const save = async () => {
    if (!draft) return
    setBusy(true); setError('')
    try { const data = await api.post<View>('/api/threat-models', 'save-threat-model', { id, model: payloadOf(draft) }); setView(data); setDraft(data.model) }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }
  const remove = async () => {
    if (!window.confirm('¿Borrar este modelo de amenazas? No se puede deshacer.')) return
    try { await api.post('/api/threat-models/delete', 'delete-threat-model', { id }); onBack() } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) }
  }
  if (!view || !draft) return error ? <div role="alert" className="text-sm text-rose-700">{error}</div> : <LoaderCircle className="size-5 animate-spin text-app-muted" />
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
  const downloadDiagram = async () => {
    if (dirty && !(await saveModel(draft))) return
    const link = document.createElement('a')
    link.href = `/api/threat-models/${id}/diagram.svg`
    link.download = `${draft.name.replace(/[^a-z0-9-]+/gi, '-').slice(0, 60) || 'modelo'}-diagrama.svg`
    document.body.append(link)
    link.click()
    link.remove()
  }
  const downloadJson = async () => {
    if (dirty && !(await saveModel(draft))) return
    const link = document.createElement('a')
    link.href = `/api/threat-models/${id}/model.json`
    link.download = `${draft.name.replace(/[^a-z0-9-]+/gi, '-').slice(0, 60) || 'modelo'}.json`
    document.body.append(link)
    link.click()
    link.remove()
  }
  return <div className="space-y-5">
    <div className="flex flex-col gap-4 rounded-2xl border border-app-line bg-panel p-5">
      <div className="flex flex-wrap items-start justify-between gap-3"><div className="min-w-0"><button onClick={onBack} className="mb-2 inline-flex items-center gap-1 text-xs text-app-subtle hover:text-app-fg"><ArrowLeft className="size-3" />Modelos</button><h2 className="text-xl font-semibold">{view.model.name}</h2><div className="mt-1.5 flex flex-wrap items-center gap-2"><button onClick={() => setPicking(true)} className="inline-flex items-center gap-1 rounded-lg border border-brand/30 bg-brand/[0.07] px-2 py-0.5 text-xs font-medium text-brand hover:bg-brand/10" title="Cambiar el enfoque">{GUIDES[methodology].name}<Pencil className="size-3" /></button><button onClick={() => toggleGuide(!guide)} aria-pressed={guide} className="inline-flex items-center gap-1 rounded-lg border border-app-line px-2 py-0.5 text-xs text-app-muted hover:text-app-fg"><BookOpen className="size-3" />{guide ? 'Ocultar guía' : 'Guía'}</button></div><p className="mt-1 text-xs text-app-subtle">{view.model.components.length} componentes · {view.model.flows.length} flujos · {view.model.boundaries.length} fronteras{view.model.updated_at ? ` · ${formatDate(view.model.updated_at)} por ${view.model.updated_by}` : ''}</p></div>
        <div className="flex flex-wrap gap-2"><Button size="sm" variant="outline" disabled={busy} className="border-app-line bg-app-soft" onClick={() => void downloadJson()}><ArrowDownToLine />Modelo JSON</Button><Button size="sm" variant="outline" disabled={busy} className="border-app-line bg-app-soft" onClick={() => void downloadDiagram()}><ArrowDownToLine />Diagrama SVG</Button>{[['Threat Dragon', 'threat-dragon.json'], ['pytm', 'tm.py'], ['Informe', 'report.md']].map(([label, file]) => <a key={file} href={`/api/threat-models/${id}/${file}`} download={`${view.model.name}-${file}`}><Button size="sm" variant="outline" className="border-app-line bg-app-soft"><ArrowDownToLine />{label}</Button></a>)}{user.role === 'admin' && <Button size="sm" variant="ghost" onClick={() => void remove()} aria-label="Borrar modelo"><Trash2 /></Button>}</div></div>
      <ProjectRepositories draft={draft} setDraft={setDraft} catalog={catalog} onError={setError} />
      {methodology === 'custom' && <CustomModulesPicker value={draft.custom_modules ?? ['manual', 'elements']} onChange={custom_modules => setDraft({ ...draft, custom_modules })} />}
      {tabs.some(([key]) => key === 'threats') && <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-6">{(['evidenced', 'open', 'mitigated', 'accepted', 'not_applicable'] as const).map(status => <div key={status} className="rounded-xl border border-app-line bg-inset px-3 py-2"><div className="text-xl font-semibold tabular-nums">{summary.by_status[status] ?? 0}</div><div className="text-xs text-app-muted">{statusLabel[status]}</div></div>)}<div className="rounded-xl border border-app-line bg-inset px-3 py-2"><div className="text-xl font-semibold tabular-nums">{summary.total}</div><div className="text-xs text-app-muted">Total</div></div></div>}
    </div>
    {error && <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-700 dark:text-rose-200">{error}</div>}
    <div className="flex flex-wrap items-center gap-2">{tabs.map(([key, label]) => <Button key={key} size="sm" variant={current === key ? 'default' : 'outline'} className={current === key ? '' : 'border-app-line bg-app-soft'} onClick={() => setTab(key)}>{label}</Button>)}
      {dirty && <span className="ml-auto flex items-center gap-2 text-xs text-amber-700 dark:text-amber-300">Cambios sin guardar<Button size="sm" onClick={() => void save()} disabled={busy} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy ? <LoaderCircle className="animate-spin" /> : <Save />}Guardar y recalcular</Button></span>}</div>
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
function ProjectRepositories({ draft, setDraft, catalog, onError }: { draft: Model; setDraft: (model: Model) => void; catalog: Catalog; onError: (text: string) => void }) {
  const [busy, setBusy] = useState('')
  const linked = draft.repositories ?? []
  const names = Object.fromEntries(catalog.assets.map(item => [item.id, item.name]))
  const available = catalog.assets.filter(item => item.kind === 'repository' && !linked.includes(item.id))
  const inUse = new Set(draft.components.map(item => item.asset).filter(Boolean))
  const propose = async (repositories: string[]) => {
    setBusy(repositories.join(',')); onError('')
    try {
      const result = await api.post<{ model: Model; added: { components: number; flows: number } }>('/api/threat-models/propose', 'propose-components', { model: payloadOf(draft), repositories })
      setDraft({ ...draft, ...result.model })
      if (!result.added.components && !result.added.flows) onError('No hay componentes nuevos que proponer desde ese repositorio: lo detectado ya está en el diagrama.')
    } catch (caught) { onError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy('') }
  }
  return <div className="flex flex-wrap items-center gap-2 rounded-xl border border-app-line bg-inset px-3 py-2">
    <span className="text-xs font-medium text-app-muted">Repositorios del proyecto</span>
    {linked.length === 0 && <span className="text-xs text-app-subtle">ninguno todavía · el modelo no los necesita, pero con ellos se proponen componentes y aparecen indicios</span>}
    {linked.map(id => <span key={id} className="inline-flex items-center gap-1 rounded-lg border border-app-line bg-panel py-0.5 pr-1 pl-2 text-xs">
      {names[id] ?? id}
      <button onClick={() => void propose([id])} disabled={!!busy} className="rounded px-1 text-brand hover:bg-brand/10" title="Proponer componentes desde este repositorio">{busy === id ? <LoaderCircle className="size-3 animate-spin" /> : <Sparkles className="size-3" />}</button>
      {!inUse.has(id) && <button onClick={() => setDraft({ ...draft, repositories: linked.filter(item => item !== id) })} className="rounded px-1 text-app-subtle hover:text-app-fg" aria-label={`Quitar ${names[id] ?? id}`}>×</button>}
    </span>)}
    {(draft.repository_refs ?? []).map(reference => <span key={reference} className="inline-flex items-center gap-1 rounded-lg border border-amber-500/30 bg-amber-500/10 py-0.5 pr-1 pl-2 text-xs text-amber-800 dark:text-amber-200" title="Referencia del archivo importado; no está conectada">{reference} · sin vincular <button onClick={() => setDraft({ ...draft, repository_refs: (draft.repository_refs ?? []).filter(item => item !== reference) })} className="rounded px-1" aria-label={`Quitar referencia ${reference}`}>×</button></span>)}
    {available.length > 0 && <select aria-label="Asociar un repositorio" value="" onChange={event => { if (event.target.value) setDraft({ ...draft, repositories: [...linked, event.target.value] }) }} className={select}>
      <option value="">+ Asociar repositorio…</option>{available.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select>}
  </div>
}

const TABS: Record<Methodology, [string, string][]> = {
  stride: [['threats', 'Amenazas'], ['diagram', 'Diagrama'], ['elements', 'Tabla']],
  linddun: [['threats', 'Amenazas de privacidad'], ['diagram', 'Diagrama'], ['elements', 'Tabla']],
  pasta: [['stages', 'Etapas'], ['diagram', 'Diagrama'], ['threats', 'Amenazas'], ['trees', 'Árboles de ataque'], ['elements', 'Tabla']],
  attack_trees: [['trees', 'Árboles de ataque'], ['diagram', 'Diagrama'], ['threats', 'Amenazas']],
  attack: [['attack', 'Técnicas ATT&CK'], ['diagram', 'Diagrama'], ['threats', 'Amenazas']],
  custom: [['diagram', 'Diagrama']],
}

const CUSTOM_OPTIONS: { key: CustomModule; title: string; description: string }[] = [
  { key: 'stride', title: 'STRIDE', description: 'Reglas automáticas de seguridad sobre el diagrama' },
  { key: 'linddun', title: 'LINDDUN', description: 'Reglas de privacidad para datos personales' },
  { key: 'manual', title: 'Amenazas propias', description: 'Escenarios, valoración y mitigaciones escritas por el equipo' },
  { key: 'pasta', title: 'Etapas PASTA', description: 'Objetivos, alcance, descomposición y riesgo' },
  { key: 'trees', title: 'Árboles de ataque', description: 'Rutas posibles para alcanzar un objetivo' },
  { key: 'attack', title: 'MITRE ATT&CK', description: 'Mapeo de técnicas relevantes' },
  { key: 'elements', title: 'Tabla de elementos', description: 'Edición tabular de componentes, flujos y fronteras' },
]

function customTabs(modules: CustomModule[]): [string, string][] {
  const tabs: [string, string][] = [['diagram', 'Diagrama']]
  if (modules.some(item => ['stride', 'linddun', 'manual'].includes(item))) tabs.push(['threats', 'Amenazas'])
  if (modules.includes('pasta')) tabs.push(['stages', 'Etapas PASTA'])
  if (modules.includes('trees')) tabs.push(['trees', 'Árboles de ataque'])
  if (modules.includes('attack')) tabs.push(['attack', 'Técnicas ATT&CK'])
  if (modules.includes('elements')) tabs.push(['elements', 'Tabla'])
  return tabs
}

function CustomModulesPicker({ value, onChange }: { value: CustomModule[]; onChange: (next: CustomModule[]) => void }) {
  return <div className="space-y-2 rounded-xl border border-app-line bg-inset p-3"><div><p className="text-sm font-semibold">Herramientas del modelo</p><p className="text-xs text-app-muted">El diagrama siempre está disponible. Elige libremente los análisis y vistas que quieres usar; puedes cambiarlos después.</p></div>
    <div className="grid gap-2 sm:grid-cols-2">{CUSTOM_OPTIONS.map(option => <label key={option.key} className="flex cursor-pointer items-start gap-2 rounded-lg border border-app-line bg-panel p-2.5 text-xs"><input type="checkbox" className="mt-0.5 size-4 shrink-0 accent-brand" checked={value.includes(option.key)} onChange={event => onChange(event.target.checked ? [...value, option.key] : value.filter(item => item !== option.key))} /><span><strong className="block text-app-fg">{option.title}</strong><span className="text-app-muted">{option.description}</span></span></label>)}</div>
  </div>
}

function payloadOf(model: Model) {
  return { name: model.name, description: model.description, methodology: model.methodology ?? 'stride', custom_modules: model.custom_modules ?? ['manual', 'elements'], repositories: model.repositories ?? [], repository_refs: model.repository_refs ?? [], components: model.components, flows: model.flows,
           boundaries: model.boundaries, manual_threats: model.manual_threats ?? [], attack_trees: model.attack_trees ?? [],
           attack_mappings: model.attack_mappings ?? [], pasta: Object.fromEntries(Object.entries(model.pasta ?? {}).filter(([, text]) => text.trim())) }
}

function Threats({ view, draft, methodology, busy, onChanged, onOpenRun, onSaveModel }: { view: View; draft: Model; methodology: Methodology; busy: boolean; onChanged: (view: View) => void; onOpenRun: (id: string) => void; onSaveModel: (model: Model) => Promise<boolean> }) {
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
    if (!window.confirm('¿Quitar esta amenaza?')) return
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
      {['all', ...codes].map(letter => { const category = categoryRow(letter); return <button key={letter} onClick={() => setStride(letter)} title={category && category.framework !== 'manual' ? categoryHelp((category.framework ?? methodology) as Methodology, category.stride) : undefined} className={`rounded-lg border px-2.5 py-1 text-xs ${stride === letter ? 'border-brand/50 bg-brand/10 text-brand' : 'border-app-line bg-app-soft text-app-muted'}`}>{letter === 'all' ? 'Todas' : `${methodology === 'custom' ? `${category?.framework?.toUpperCase() ?? 'PROPIA'} · ` : category?.stride && category.stride.length <= 2 ? `${category.stride} · ` : ''}${category?.category ?? letter} (${view.threats.filter(row => categoryKey(row) === letter).length})`}</button> })}
      <Button size="sm" variant="outline" className="border-app-line bg-app-soft" onClick={() => setEditing('new')}><Plus />Amenaza</Button>
      <select aria-label="Estado" value={status} onChange={event => setStatus(event.target.value)} className={`${select} ml-auto`}><option value="pending">Pendientes</option><option value="all">Todos los estados</option>{Object.entries(statusLabel).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select>
    </div>
    {rows.length === 0 ? <p className="py-8 text-center text-sm text-app-subtle">{view.threats.length ? 'Nada con estos filtros.' : 'Añade componentes y flujos para que aparezcan amenazas.'}</p>
      : <div className="divide-y divide-app-line overflow-hidden rounded-xl border border-app-line">{rows.map(row => { const expanded = open === row.id
        return <div key={row.id}>
          <button onClick={() => setOpen(expanded ? null : row.id)} className="grid w-full gap-2 px-4 py-3 text-left transition hover:bg-app-soft md:grid-cols-[110px_90px_minmax(0,1fr)_120px] md:items-center">
            <Badge variant="outline" className={`w-fit ${statusClass[row.status]}`}>{statusLabel[row.status]}{row.evidence_count ? ` · ${row.evidence_count}` : ''}</Badge>
            <Badge variant="outline" className={`w-fit ${severityClass[row.severity]}`}>{severityLabel[row.severity]}</Badge>
            <span className="flex min-w-0 items-start gap-2"><ChevronRight className={`mt-1 size-3.5 shrink-0 text-app-subtle transition ${expanded ? 'rotate-90' : ''}`} /><span className="min-w-0"><span className="block truncate text-sm font-medium">{row.title}</span><span className="block truncate text-xs text-app-subtle">{row.element_name}</span></span></span>
            <span className="text-xs text-app-muted">{row.stride} · {row.category}</span>
          </button>
          {expanded && <div className="space-y-3 border-t border-app-line bg-inset px-4 py-4 text-sm">
            <p className="text-app-secondary">{row.why}</p>
            <div><span className="text-xs font-medium text-app-muted">Mitigaciones</span><ul className="mt-1 list-disc space-y-0.5 pl-5 text-app-secondary">{row.mitigations.map(item => <li key={item}>{item}</li>)}</ul></div>
            <p className="font-mono text-xs text-app-subtle">{row.rule} · {row.cwe.map(item => `CWE-${item}`).join(', ')}</p>
            {row.evidence.length > 0 && <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3"><span className="text-xs font-medium text-amber-900 dark:text-amber-200"><ShieldAlert className="mr-1 inline size-3.5" />Indicios en los análisis ({row.evidence_count})</span><span className="mt-0.5 block text-[11px] text-app-subtle">Hallazgos abiertos relacionados con esta amenaza{row.evidence_scope?.some(scope => !scope.path) ? ' en el repositorio entero: indica la carpeta del componente en el diagrama para afinar' : ` en ${row.evidence_scope?.map(scope => scope.path).join(', ')}`}. Son una señal para revisar, no una confirmación.</span><ul className="mt-2 space-y-1 text-xs">{row.evidence.slice(0, 8).map(item => <li key={item.fingerprint} className="flex flex-wrap items-center gap-2"><Badge variant="outline" className={`text-[10px] ${severityClass[item.severity] ?? ''}`}>{severityLabel[item.severity] ?? item.severity}</Badge><span className="text-app-secondary">{item.title}</span><span className="font-mono text-app-subtle">{item.location}</span><button onClick={() => onOpenRun(item.run_id)} className="text-brand hover:underline">Ver hallazgos</button></li>)}</ul></div>}
            {row.framework === 'manual' && (row.likelihood || row.impact || row.owner) && <p className="text-xs text-app-muted">Posibilidad: {row.likelihood ? ({ low: 'baja', medium: 'media', high: 'alta' } as const)[row.likelihood] : '—'} · impacto: {row.impact ? ({ low: 'bajo', medium: 'medio', high: 'alto' } as const)[row.impact] : '—'} · responsable: {row.owner || '—'}</p>}
            {row.framework === 'manual' && <div className="flex gap-1.5"><Button size="xs" variant="outline" className="border-app-line bg-app-soft" onClick={() => setEditing((draft.manual_threats ?? []).find(item => item.id === row.manual_id) ?? null)}><Pencil />Editar</Button><Button size="xs" variant="ghost" onClick={() => void removeManual(row.manual_id ?? '')}><Trash2 />Quitar</Button></div>}
            {row.decision && <p className="text-xs text-app-muted"><strong>{statusLabel[row.status]}</strong> por {row.decision.by} el {formatDate(row.decision.at)}: {row.decision.reason}</p>}
            <div className="flex flex-wrap gap-1.5">{row.decision ? <Button size="xs" variant="outline" className="border-app-line bg-app-soft" onClick={() => void reopen(row)}>Reabrir</Button>
              : (['mitigated', 'accepted', 'not_applicable'] as const).map(next => <Button key={next} size="xs" variant="outline" className="border-app-line bg-app-soft" onClick={() => setDeciding({ threat: row, status: next })}>{statusLabel[next]}</Button>)}</div>
          </div>}
        </div> })}</div>}
    {editing && <ManualThreatDialog model={draft} initial={editing === 'new' ? undefined : editing} methodology={methodology} busy={busy} onClose={() => setEditing(null)} onSave={threat => void saveManual(threat)} />}
    {deciding && <DecisionDialog modelId={view.model.id} threat={deciding.threat} status={deciding.status} onClose={() => setDeciding(null)} onDone={next => { setDeciding(null); onChanged(next) }} />}
  </CardContent></Card>
}

function DecisionDialog({ modelId, threat, status, onClose, onDone }: { modelId: string; threat: Threat; status: 'mitigated' | 'accepted' | 'not_applicable'; onClose: () => void; onDone: (view: View) => void }) {
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
    <DialogHeader><DialogTitle>{statusLabel[status]} · {threat.title}</DialogTitle><DialogDescription>{threat.element_name}. {status === 'mitigated' ? 'Di qué control la mitiga (y dónde se puede comprobar).' : status === 'accepted' ? 'Di por qué se asume el riesgo y hasta cuándo.' : 'Di por qué no aplica a este sistema.'}{threat.evidence_count ? ` Ojo: hay ${threat.evidence_count} hallazgos abiertos que la evidencian.` : ''}</DialogDescription></DialogHeader>
    <form className="space-y-4" onSubmit={submit}><textarea aria-label="Motivo" required minLength={10} maxLength={500} rows={3} value={reason} onChange={event => setReason(event.target.value)} className="w-full rounded-lg border border-app-line bg-app-soft px-3 py-2 text-sm" />
      {error && <div role="alert" className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-700 dark:text-rose-200">{error}</div>}
      <DialogFooter><Button type="button" variant="ghost" onClick={onClose}>Cancelar</Button><Button type="submit" disabled={busy || reason.trim().length < 10} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy && <LoaderCircle className="animate-spin" />}Guardar</Button></DialogFooter></form>
  </DialogContent></Dialog>
}

function Chips({ value, options, onChange }: { value: string[]; options: Record<string, string>; onChange: (next: string[]) => void }) {
  return <div className="flex flex-wrap gap-1">{Object.entries(options).map(([key, label]) => <button key={key} type="button" onClick={() => onChange(value.includes(key) ? value.filter(item => item !== key) : [...value, key])} className={`rounded border px-1.5 py-0.5 text-[10px] ${value.includes(key) ? 'border-brand/50 bg-brand/10 text-brand' : 'border-app-line text-app-subtle'}`}>{label}</button>)}</div>
}

function Elements({ draft, setDraft, catalog }: { draft: Model; setDraft: (model: Model) => void; catalog: Catalog }) {
  const ids = draft.components.map(item => item.id)
  const boundaryOf = (component: string) => draft.boundaries.find(item => item.components.includes(component))?.id ?? ''
  const updateComponent = (id: string, change: Partial<Component>) => setDraft({ ...draft, components: draft.components.map(item => item.id === id ? { ...item, ...change } : item) })
  const moveTo = (component: string, boundary: string) => setDraft({ ...draft, boundaries: draft.boundaries.map(item => ({ ...item, components: item.id === boundary ? [...item.components.filter(id => id !== component), component] : item.components.filter(id => id !== component) })) })
  const addComponent = () => { const id = newId('componente', ids); setDraft({ ...draft, components: [...draft.components, { id, name: 'Nuevo componente', kind: 'service', data: [], internet_facing: false, authenticates: false, encrypted_at_rest: false }] }) }
  const removeComponent = (id: string) => setDraft({ ...draft, components: draft.components.filter(item => item.id !== id), flows: draft.flows.filter(flow => flow.source !== id && flow.target !== id), boundaries: draft.boundaries.map(item => ({ ...item, components: item.components.filter(member => member !== id) })) })
  const updateFlow = (id: string, change: Partial<Flow>) => setDraft({ ...draft, flows: draft.flows.map(item => item.id === id ? { ...item, ...change } : item) })
  const addFlow = () => { if (draft.components.length < 2) return; setDraft({ ...draft, flows: [...draft.flows, { id: newId('flujo', draft.flows.map(item => item.id)), source: ids[0], target: ids[1], protocol: 'https', data: [], authenticated: true, encrypted: true }] }) }
  const cell = 'px-2 py-2 align-top'
  return <div className="space-y-5">
    <Card className="border-app-line bg-panel"><CardHeader className="flex flex-row items-center justify-between"><CardTitle className="text-base">Fronteras de confianza</CardTitle><Button size="sm" variant="outline" className="border-app-line bg-app-soft" onClick={() => setDraft({ ...draft, boundaries: [...draft.boundaries, { id: newId('frontera', draft.boundaries.map(item => item.id)), name: 'Nueva frontera', components: [] }] })}><Plus />Frontera</Button></CardHeader>
      <CardContent className="flex flex-wrap gap-2">{draft.boundaries.map(item => <div key={item.id} className="flex items-center gap-1 rounded-lg border border-app-line bg-inset px-2 py-1"><Input aria-label="Nombre de la frontera" value={item.name} maxLength={80} onChange={event => setDraft({ ...draft, boundaries: draft.boundaries.map(entry => entry.id === item.id ? { ...entry, name: event.target.value } : entry) })} className="h-7 w-40 border-0 bg-transparent px-1 text-sm" /><span className="text-xs text-app-subtle">{item.components.length}</span><Button size="xs" variant="ghost" aria-label="Quitar frontera" onClick={() => setDraft({ ...draft, boundaries: draft.boundaries.filter(entry => entry.id !== item.id) })}><Trash2 /></Button></div>)}{!draft.boundaries.length && <p className="text-sm text-app-subtle">Sin fronteras: los flujos no cruzan ninguna y se pierden amenazas de tránsito.</p>}</CardContent></Card>
    <Card className="border-app-line bg-panel"><CardHeader className="flex flex-row items-center justify-between"><CardTitle className="text-base">Componentes</CardTitle><Button size="sm" variant="outline" className="border-app-line bg-app-soft" onClick={addComponent}><Plus />Componente</Button></CardHeader>
      <CardContent className="overflow-x-auto"><table className="w-full min-w-[980px] text-sm"><thead><tr className="text-left text-xs text-app-subtle"><th className={cell}>Nombre y tecnología</th><th className={cell}>Tipo</th><th className={cell}>Frontera</th><th className={cell}>Repositorio o dominio</th><th className={cell}>Datos</th><th className={cell}>Propiedades</th><th /></tr></thead>
        <tbody className="divide-y divide-app-line">{draft.components.map(item => <tr key={item.id}>
          <td className={cell}><Input aria-label="Nombre" value={item.name} maxLength={80} onChange={event => updateComponent(item.id, { name: event.target.value })} className="h-8 border-app-line bg-app-soft" /><Input aria-label="Tecnología" value={item.technology ?? ''} maxLength={80} placeholder="Tecnología" onChange={event => updateComponent(item.id, { technology: event.target.value })} className="mt-1 h-7 border-app-line bg-app-soft text-xs" />{item.origin === 'suggested' && <span className="mt-1 block max-w-64 text-[10px] leading-4 text-brand" title={item.description}>{item.description || 'propuesto desde el repositorio'}</span>}</td>
          <td className={cell}><select aria-label="Tipo" value={item.kind} onChange={event => updateComponent(item.id, { kind: event.target.value as Kind, custom_kind: event.target.value === 'custom' ? item.custom_kind || 'Tipo propio' : '', custom_base: event.target.value === 'custom' ? item.custom_base || 'service' : undefined })} className={select}>{Object.entries(catalog.kinds).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select>{item.kind === 'custom' && <><Input aria-label="Nombre del tipo propio" value={item.custom_kind ?? ''} maxLength={80} onChange={event => updateComponent(item.id, { custom_kind: event.target.value })} className="mt-1 h-7 border-app-line bg-app-soft text-xs" /><select aria-label="Rol base para el análisis" value={item.custom_base || 'service'} onChange={event => updateComponent(item.id, { custom_base: event.target.value as Exclude<Kind, 'custom'> })} className={`${select} mt-1`}>{Object.entries(catalog.kinds).filter(([key]) => key !== 'custom').map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select></>}</td>
          <td className={cell}><select aria-label="Frontera" value={boundaryOf(item.id)} onChange={event => moveTo(item.id, event.target.value)} className={select}><option value="">Ninguna</option>{draft.boundaries.map(entry => <option key={entry.id} value={entry.id}>{entry.name}</option>)}</select></td>
          <td className={cell}><select aria-label="Activo enlazado" value={item.asset ?? ''} onChange={event => updateComponent(item.id, { asset: event.target.value || null, asset_ref: event.target.value ? '' : item.asset_ref })} className={`${select} max-w-48`}><option value="">Sin enlazar</option>{assetGroups(catalog, draft).map(group => <optgroup key={group.label} label={group.label}>{group.items.map(asset => <option key={asset.id} value={asset.id}>{asset.name}</option>)}</optgroup>)}</select>{item.asset_ref && !item.asset && <span className="mt-1 block text-[11px] text-amber-700 dark:text-amber-300">{item.asset_ref} · pendiente de vincular</span>}</td>
          <td className={cell}><Chips value={item.data} options={catalog.classifications} onChange={data => updateComponent(item.id, { data })} /></td>
          <td className={`${cell} space-y-1 text-xs`}>{([['internet_facing', 'Expuesto a Internet'], ['authenticates', 'Autentica'], ['encrypted_at_rest', 'Cifrado en reposo']] as const).map(([key, label]) => <label key={key} className="flex items-center gap-1.5 whitespace-nowrap"><input type="checkbox" className="size-3.5 accent-brand" checked={item[key]} onChange={event => updateComponent(item.id, { [key]: event.target.checked })} />{label}</label>)}</td>
          <td className={cell}><Button size="xs" variant="ghost" aria-label={`Quitar ${item.name}`} onClick={() => removeComponent(item.id)}><Trash2 /></Button></td>
        </tr>)}</tbody></table></CardContent></Card>
    <Card className="border-app-line bg-panel"><CardHeader className="flex flex-row items-center justify-between"><CardTitle className="text-base">Flujos de datos</CardTitle><Button size="sm" variant="outline" className="border-app-line bg-app-soft" disabled={draft.components.length < 2} onClick={addFlow}><Plus />Flujo</Button></CardHeader>
      <CardContent className="overflow-x-auto"><table className="w-full min-w-[900px] text-sm"><thead><tr className="text-left text-xs text-app-subtle"><th className={cell}>Origen → destino</th><th className={cell}>Nombre y protocolo</th><th className={cell}>Datos</th><th className={cell}>Propiedades</th><th /></tr></thead>
        <tbody className="divide-y divide-app-line">{draft.flows.map(flow => <tr key={flow.id}>
          <td className={cell}><div className="flex items-center gap-1"><select aria-label="Origen" value={flow.source} onChange={event => updateFlow(flow.id, { source: event.target.value })} className={select}>{draft.components.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select>→<select aria-label="Destino" value={flow.target} onChange={event => updateFlow(flow.id, { target: event.target.value })} className={select}>{draft.components.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select></div></td>
          <td className={cell}><Input aria-label="Nombre del flujo" value={flow.name ?? ''} maxLength={80} placeholder="Qué viaja" onChange={event => updateFlow(flow.id, { name: event.target.value })} className="h-8 border-app-line bg-app-soft" /><select aria-label="Protocolo" value={flow.protocol} onChange={event => updateFlow(flow.id, { protocol: event.target.value })} className={`${select} mt-1`}>{catalog.protocols.map(item => <option key={item} value={item}>{item.toUpperCase()}</option>)}</select></td>
          <td className={cell}><Chips value={flow.data} options={catalog.classifications} onChange={data => updateFlow(flow.id, { data })} /></td>
          <td className={`${cell} space-y-1 text-xs`}><label className="flex items-center gap-1.5"><input type="checkbox" className="size-3.5 accent-brand" checked={flow.authenticated} onChange={event => updateFlow(flow.id, { authenticated: event.target.checked })} />Autenticado</label><label className="flex items-center gap-1.5"><input type="checkbox" className="size-3.5 accent-brand" checked={flow.encrypted} onChange={event => updateFlow(flow.id, { encrypted: event.target.checked })} />Cifrado</label></td>
          <td className={cell}><Button size="xs" variant="ghost" aria-label="Quitar flujo" onClick={() => setDraft({ ...draft, flows: draft.flows.filter(item => item.id !== flow.id) })}><Trash2 /></Button></td>
        </tr>)}</tbody></table>{!draft.flows.length && <p className="py-4 text-sm text-app-subtle">Sin flujos. Los datos que se mueven entre componentes son donde aparecen la mayoría de amenazas.</p>}</CardContent></Card>
  </div>
}
