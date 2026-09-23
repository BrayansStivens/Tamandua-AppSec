import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react'
import { ArrowDownToLine, ArrowLeft, ChevronRight, LoaderCircle, Network, Plus, Save, ShieldAlert, Sparkles, Trash2 } from 'lucide-react'
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

type Kind = 'actor' | 'web_app' | 'api' | 'service' | 'function' | 'database' | 'cache' | 'queue' | 'storage' | 'external' | 'identity'
type Component = { id: string; name: string; kind: Kind; description?: string; technology?: string; asset?: string | null; data: string[]; internet_facing: boolean; authenticates: boolean; encrypted_at_rest: boolean; origin?: string }
type Flow = { id: string; source: string; target: string; name?: string; protocol: string; data: string[]; authenticated: boolean; encrypted: boolean }
type Boundary = { id: string; name: string; components: string[] }
type Model = { id: string; name: string; description?: string; components: Component[]; flows: Flow[]; boundaries: Boundary[]; updated_at?: string; updated_by?: string }
type Evidence = { asset: string; run_id: string; fingerprint: string; title: string; severity: string; location: string }
type Threat = { id: string; rule: string; stride: string; category: string; title: string; why: string; mitigations: string[]; cwe: number[]; element: string; element_name: string; severity: string; status: 'evidenced' | 'open' | 'mitigated' | 'accepted' | 'not_applicable'; decision?: { status: string; reason: string; by: string; at: string } | null; evidence: Evidence[]; evidence_count: number }
type Summary = { total: number; by_status: Record<string, number>; by_stride: Record<string, number>; by_severity: Record<string, number> }
type View = { model: Model; threats: Threat[]; summary: Summary }
type Asset = { id: string; name: string; kind: 'repository' | 'domain'; last_run?: string | null; scanned_at?: string }
type Catalog = { models: { id: string; name: string; description?: string; updated_at?: string; updated_by?: string; components: number; flows: number }[]; assets: Asset[]; kinds: Record<Kind, string>; protocols: string[]; classifications: Record<string, string> }

const STRIDE: Record<string, string> = { S: 'Suplantación', T: 'Manipulación', R: 'Repudio', I: 'Divulgación', D: 'Denegación', E: 'Elevación' }
const statusLabel = { evidenced: 'Evidenciada', open: 'Abierta', mitigated: 'Mitigada', accepted: 'Aceptada', not_applicable: 'No aplica' }
const statusClass = { evidenced: 'border-transparent bg-rose-600 text-white', open: 'border-amber-500/40 text-amber-800 dark:text-amber-300', mitigated: 'border-brand/30 text-brand', accepted: 'border-violet-500/30 text-violet-800 dark:text-violet-300', not_applicable: 'border-app-line text-app-subtle' }
const severityClass: Record<string, string> = { critical: 'border-transparent bg-rose-600 text-white', high: 'border-orange-500/30 bg-orange-500/15 text-orange-800 dark:text-orange-300', medium: 'border-amber-500/30 bg-amber-400/15 text-amber-800 dark:text-amber-300', low: 'border-sky-500/30 bg-sky-400/15 text-sky-800 dark:text-sky-300' }
const severityLabel: Record<string, string> = { critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja' }
const STORES: Kind[] = ['database', 'cache', 'queue', 'storage']
const PROCESSES: Kind[] = ['web_app', 'api', 'service', 'function']
const newId = (name: string, used: string[]) => { const base = name.normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 30) || 'c'; let id = base, n = 2; while (used.includes(id)) id = `${base}-${n++}`; return id }
const select = 'h-8 rounded-lg border border-app-line bg-app-soft px-2 text-xs text-app-fg'

export function ThreatModels({ user, onOpenRun }: { user: SessionUser; onOpenRun: (id: string) => void }) {
  const [catalog, setCatalog] = useState<Catalog | null>(null)
  const [openId, setOpenId] = useState<string | null>(() => readRoute().params.get('model'))
  useEffect(() => { setRouteParam('model', openId) }, [openId])
  const [creating, setCreating] = useState(false)
  const [error, setError] = useState('')
  const load = useCallback(() => api.get<Catalog>('/api/threat-models').then(setCatalog).catch(caught => setError(caught instanceof Error ? caught.message : String(caught))), [])
  useEffect(() => { void load() }, [load])
  if (!catalog) return error ? <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-700 dark:text-rose-200">{error}</div> : <Skeleton rows={4} />
  if (openId) return <Editor id={openId} catalog={catalog} user={user} onBack={() => { setOpenId(null); void load() }} onOpenRun={onOpenRun} />
  return <div className="space-y-5">
    <Card className="border-app-line bg-panel"><CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3"><div><CardTitle>Modelos de amenazas</CardTitle><CardDescription className="mt-1 max-w-3xl leading-6">Describe el sistema —componentes, flujos de datos y fronteras de confianza— y se aplican reglas STRIDE sobre cada elemento. Si un repositorio enlazado tiene hallazgos abiertos que confirman una amenaza, aparece como <strong>evidenciada</strong> con enlace a ellos.</CardDescription></div><Button onClick={() => setCreating(true)} className="bg-primary text-primary-foreground hover:bg-primary/90"><Plus />Nuevo modelo</Button></CardHeader>
      <CardContent>{catalog.models.length === 0 ? <div className="flex flex-col items-center gap-2 py-12 text-center"><Network className="size-7 text-app-subtle" /><p className="font-medium">Aún no hay modelos</p><p className="max-w-md text-sm text-app-muted">Empieza con una propuesta hecha a partir de lo que ya escaneaste: se detectan frameworks, bases de datos y servicios externos, y tú la corriges.</p></div>
        : <div className="divide-y divide-app-line rounded-xl border border-app-line">{catalog.models.map(item => <button key={item.id} onClick={() => setOpenId(item.id)} className="flex w-full items-center gap-3 px-4 py-3 text-left transition hover:bg-app-soft"><Network className="size-4 text-app-subtle" /><span className="min-w-0 flex-1"><span className="block text-sm font-medium">{item.name}</span><span className="block truncate text-xs text-app-subtle">{item.components} componentes · {item.flows} flujos{item.updated_at ? ` · actualizado ${formatDate(item.updated_at)} por ${item.updated_by}` : ''}</span></span><ChevronRight className="size-4 text-app-subtle" /></button>)}</div>}</CardContent></Card>
    <CreateDialog open={creating} assets={catalog.assets} onClose={() => setCreating(false)} onCreated={id => { setCreating(false); setOpenId(id) }} />
  </div>
}

function CreateDialog({ open, assets, onClose, onCreated }: { open: boolean; assets: Asset[]; onClose: () => void; onCreated: (id: string) => void }) {
  const [name, setName] = useState('')
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
      const finalName = name.trim() || fallback || 'Nuevo sistema'
      const body = chosen.length ? { name: finalName, suggest: chosen } : { model: { name: finalName, components: [], flows: [], boundaries: [] } }
      onCreated((await api.post<View>('/api/threat-models', 'save-threat-model', body)).model.id)
      setName(''); setChosen([])
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }
  return <Dialog open={open} onOpenChange={next => { if (!next) onClose() }}><DialogContent className="max-w-lg">
    <DialogHeader><DialogTitle>Nuevo modelo de amenazas</DialogTitle><DialogDescription>Elige los repositorios que forman el sistema. Se leen en el momento sus manifiestos (package.json, pyproject, go.mod, Cargo.toml, compose) y se propone cada componente citando de qué dependencia sale. O déjalo vacío para empezar en blanco.</DialogDescription></DialogHeader>
    <form className="space-y-4" onSubmit={submit}>
      <div className="space-y-1.5"><label htmlFor="tm-name" className="text-xs text-app-muted">Nombre del sistema (opcional)</label><Input id="tm-name" autoFocus maxLength={80} value={name} onChange={event => setName(event.target.value)} placeholder="Si lo dejas vacío, se usan los nombres de los repositorios" className="border-app-line bg-app-soft" /></div>
      <div className="space-y-1.5"><div className="flex items-center justify-between gap-2"><span className="text-xs text-app-muted">Repositorios{chosen.length ? ` · ${chosen.length} elegidos` : ''}</span><Input aria-label="Buscar repositorio" value={filter} onChange={event => setFilter(event.target.value)} placeholder="Buscar…" className="h-7 w-40 border-app-line bg-app-soft text-xs" /></div>
        {repositories.length ? <div className="max-h-64 space-y-0.5 overflow-y-auto rounded-lg border border-app-line p-2">{repositories.map(item => <label key={item.id} className="flex items-center gap-2 rounded px-2 py-1 text-sm hover:bg-app-soft"><input type="checkbox" className="size-4 accent-brand" checked={chosen.includes(item.id)} onChange={event => setChosen(previous => event.target.checked ? [...previous, item.id] : previous.filter(id => id !== item.id))} /><span className="min-w-0 flex-1 truncate">{item.name}</span>{item.last_run ? <span className="shrink-0 text-[10px] text-brand">escaneado</span> : <span className="shrink-0 text-[10px] text-app-subtle">sin escanear</span>}</label>)}</div> : <p className="text-xs text-app-subtle">{filter ? 'Ningún repositorio coincide.' : 'Conecta GitHub en Integraciones para elegir repositorios.'}</p>}
        <p className="text-[11px] leading-4 text-app-subtle">Los repositorios sin escanear se modelan igual, pero sus amenazas no tendrán evidencia hasta que los escanees.</p></div>
      {error && <div role="alert" className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-700 dark:text-rose-200">{error}</div>}
      <DialogFooter><Button type="button" variant="ghost" onClick={onClose}>Cancelar</Button><Button type="submit" disabled={busy} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy ? <LoaderCircle className="animate-spin" /> : chosen.length ? <Sparkles /> : <Plus />}{busy && chosen.length ? 'Leyendo manifiestos…' : chosen.length ? 'Proponer modelo' : 'Crear en blanco'}</Button></DialogFooter>
    </form>
  </DialogContent></Dialog>
}

function Editor({ id, catalog, user, onBack, onOpenRun }: { id: string; catalog: Catalog; user: SessionUser; onBack: () => void; onOpenRun: (id: string) => void }) {
  const [view, setView] = useState<View | null>(null)
  const [draft, setDraft] = useState<Model | null>(null)
  const [tab, setTab] = useState<'threats' | 'diagram' | 'elements'>('threats')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const load = useCallback(async () => { const data = await api.get<View>(`/api/threat-models/${id}`); setView(data); setDraft(data.model) }, [id])
  useEffect(() => { load().catch(caught => setError(caught instanceof Error ? caught.message : String(caught))) }, [load])
  const dirty = useMemo(() => !!view && !!draft && JSON.stringify(view.model) !== JSON.stringify(draft), [view, draft])
  const save = async () => {
    if (!draft) return
    setBusy(true); setError('')
    try { const data = await api.post<View>('/api/threat-models', 'save-threat-model', { id, model: { name: draft.name, description: draft.description, components: draft.components, flows: draft.flows, boundaries: draft.boundaries } }); setView(data); setDraft(data.model) }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }
  const remove = async () => {
    if (!window.confirm('¿Borrar este modelo de amenazas? No se puede deshacer.')) return
    try { await api.post('/api/threat-models/delete', 'delete-threat-model', { id }); onBack() } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) }
  }
  if (!view || !draft) return error ? <div role="alert" className="text-sm text-rose-700">{error}</div> : <LoaderCircle className="size-5 animate-spin text-app-muted" />
  const summary = view.summary
  return <div className="space-y-5">
    <div className="flex flex-col gap-4 rounded-2xl border border-app-line bg-panel p-5">
      <div className="flex flex-wrap items-start justify-between gap-3"><div className="min-w-0"><button onClick={onBack} className="mb-2 inline-flex items-center gap-1 text-xs text-app-subtle hover:text-app-fg"><ArrowLeft className="size-3" />Modelos</button><h2 className="text-xl font-semibold">{view.model.name}</h2><p className="mt-1 text-xs text-app-subtle">{view.model.components.length} componentes · {view.model.flows.length} flujos · {view.model.boundaries.length} fronteras{view.model.updated_at ? ` · ${formatDate(view.model.updated_at)} por ${view.model.updated_by}` : ''}</p></div>
        <div className="flex flex-wrap gap-2">{[['Threat Dragon', 'threat-dragon.json'], ['pytm', 'tm.py'], ['Informe', 'report.md']].map(([label, file]) => <a key={file} href={`/api/threat-models/${id}/${file}`} download={`${view.model.name}-${file}`}><Button size="sm" variant="outline" className="border-app-line bg-app-soft"><ArrowDownToLine />{label}</Button></a>)}{user.role === 'admin' && <Button size="sm" variant="ghost" onClick={() => void remove()} aria-label="Borrar modelo"><Trash2 /></Button>}</div></div>
      <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-6">{(['evidenced', 'open', 'mitigated', 'accepted', 'not_applicable'] as const).map(status => <div key={status} className="rounded-xl border border-app-line bg-inset px-3 py-2"><div className="text-xl font-semibold tabular-nums">{summary.by_status[status] ?? 0}</div><div className="text-xs text-app-muted">{statusLabel[status]}</div></div>)}<div className="rounded-xl border border-app-line bg-inset px-3 py-2"><div className="text-xl font-semibold tabular-nums">{summary.total}</div><div className="text-xs text-app-muted">Total STRIDE</div></div></div>
    </div>
    {error && <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-700 dark:text-rose-200">{error}</div>}
    <div className="flex flex-wrap items-center gap-2">{([['threats', 'Amenazas'], ['diagram', 'Diagrama'], ['elements', 'Componentes y flujos']] as const).map(([key, label]) => <Button key={key} size="sm" variant={tab === key ? 'default' : 'outline'} className={tab === key ? '' : 'border-app-line bg-app-soft'} onClick={() => setTab(key)}>{label}</Button>)}
      {dirty && <span className="ml-auto flex items-center gap-2 text-xs text-amber-700 dark:text-amber-300">Cambios sin guardar<Button size="sm" onClick={() => void save()} disabled={busy} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy ? <LoaderCircle className="animate-spin" /> : <Save />}Guardar y recalcular</Button></span>}</div>
    {tab === 'threats' && <Threats view={view} onChanged={setView} onOpenRun={onOpenRun} />}
    {tab === 'diagram' && <Diagram model={draft} threats={view.threats} kinds={catalog.kinds} />}
    {tab === 'elements' && <Elements draft={draft} setDraft={setDraft} catalog={catalog} />}
  </div>
}

function Threats({ view, onChanged, onOpenRun }: { view: View; onChanged: (view: View) => void; onOpenRun: (id: string) => void }) {
  const [stride, setStride] = useState('all')
  const [status, setStatus] = useState('pending')
  const [deciding, setDeciding] = useState<{ threat: Threat; status: 'mitigated' | 'accepted' | 'not_applicable' } | null>(null)
  const [open, setOpen] = useState<string | null>(null)
  const rows = view.threats.filter(row => (stride === 'all' || row.stride === stride) && (status === 'all' || (status === 'pending' ? row.status === 'evidenced' || row.status === 'open' : row.status === status)))
  const reopen = async (threat: Threat) => onChanged(await api.post<View>('/api/threat-models/decide', 'threat-decision', { id: view.model.id, threat: threat.id, status: 'open' }))
  return <Card className="border-app-line bg-panel"><CardContent className="space-y-4 p-5">
    <div className="flex flex-wrap gap-2">
      {['all', ...Object.keys(STRIDE)].map(letter => <button key={letter} onClick={() => setStride(letter)} className={`rounded-lg border px-2.5 py-1 text-xs ${stride === letter ? 'border-brand/50 bg-brand/10 text-brand' : 'border-app-line bg-app-soft text-app-muted'}`}>{letter === 'all' ? 'Todo STRIDE' : `${letter} · ${STRIDE[letter]} (${view.summary.by_stride[letter] ?? 0})`}</button>)}
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
            {row.evidence.length > 0 && <div className="rounded-lg border border-rose-500/30 bg-rose-500/5 p-3"><span className="text-xs font-medium text-rose-800 dark:text-rose-200"><ShieldAlert className="mr-1 inline size-3.5" />Evidencia en los escaneos ({row.evidence_count})</span><ul className="mt-2 space-y-1 text-xs">{row.evidence.slice(0, 8).map(item => <li key={item.fingerprint} className="flex flex-wrap items-center gap-2"><Badge variant="outline" className={`text-[10px] ${severityClass[item.severity] ?? ''}`}>{severityLabel[item.severity] ?? item.severity}</Badge><span className="text-app-secondary">{item.title}</span><span className="font-mono text-app-subtle">{item.location}</span><button onClick={() => onOpenRun(item.run_id)} className="text-brand hover:underline">Ver hallazgos</button></li>)}</ul></div>}
            {row.decision && <p className="text-xs text-app-muted"><strong>{statusLabel[row.status]}</strong> por {row.decision.by} el {formatDate(row.decision.at)}: {row.decision.reason}</p>}
            <div className="flex flex-wrap gap-1.5">{row.decision ? <Button size="xs" variant="outline" className="border-app-line bg-app-soft" onClick={() => void reopen(row)}>Reabrir</Button>
              : (['mitigated', 'accepted', 'not_applicable'] as const).map(next => <Button key={next} size="xs" variant="outline" className="border-app-line bg-app-soft" onClick={() => setDeciding({ threat: row, status: next })}>{statusLabel[next]}</Button>)}</div>
          </div>}
        </div> })}</div>}
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

// Diagrama de flujo de datos: una columna por frontera de confianza, en el orden declarado.
function Diagram({ model, threats, kinds }: { model: Model; threats: Threat[]; kinds: Record<Kind, string> }) {
  const columns = [...model.boundaries.map(item => ({ boundary: item, members: item.components })),
    ...(() => { const placed = new Set(model.boundaries.flatMap(item => item.components)); const loose = model.components.filter(item => !placed.has(item.id)).map(item => item.id); return loose.length ? [{ boundary: null as Boundary | null, members: loose }] : [] })()]
  const W = 170, H = 64, GAP_X = 250, GAP_Y = 104, TOP = 50
  const position: Record<string, { x: number; y: number }> = {}
  columns.forEach((column, index) => column.members.forEach((member, row) => { position[member] = { x: 40 + index * GAP_X, y: TOP + row * GAP_Y } }))
  const width = Math.max(1, columns.length) * GAP_X + 40
  const height = TOP + Math.max(1, ...columns.map(column => column.members.length)) * GAP_Y + 20
  const hot = new Set(threats.filter(row => row.status === 'evidenced').map(row => row.element))
  const byId = Object.fromEntries(model.components.map(item => [item.id, item]))
  if (!model.components.length) return <Card className="border-app-line bg-panel"><CardContent className="py-12 text-center text-sm text-app-subtle">Añade componentes en «Componentes y flujos» para ver el diagrama.</CardContent></Card>
  return <Card className="border-app-line bg-panel"><CardContent className="space-y-3 p-5">
    <div className="overflow-x-auto"><svg role="img" aria-label={`Diagrama de flujo de datos de ${model.name}`} viewBox={`0 0 ${width} ${height}`} className="min-w-[640px] text-app-fg" style={{ width: '100%', maxHeight: 640 }}>
      <defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" className="fill-current text-app-subtle" /></marker></defs>
      {columns.map((column, index) => column.boundary && <g key={column.boundary.id}><rect x={20 + index * GAP_X} y={12} width={GAP_X - 40} height={height - 24} rx={14} className="fill-none stroke-current text-rose-500/60" strokeDasharray="6 5" strokeWidth={1.5} /><text x={32 + index * GAP_X} y={32} className="fill-current text-rose-700 dark:text-rose-300" fontSize={12} fontWeight={600}>{column.boundary.name}</text></g>)}
      {model.flows.map(flow => { const a = position[flow.source], b = position[flow.target]; if (!a || !b) return null
        const x1 = a.x + W / 2, y1 = a.y + H / 2, x2 = b.x + W / 2, y2 = b.y + H / 2
        const dx = x2 - x1, dy = y2 - y1, length = Math.hypot(dx, dy) || 1
        const trim = (dx === 0 ? H / 2 : Math.min(W / 2 / Math.abs(dx / length), H / 2 / Math.abs(dy / length || 1e-6))) + 4
        const sx = x1 + dx / length * trim, sy = y1 + dy / length * trim, ex = x2 - dx / length * trim, ey = y2 - dy / length * trim
        const flagged = hot.has(flow.id)
        return <g key={flow.id}><line x1={sx} y1={sy} x2={ex} y2={ey} markerEnd="url(#arrow)" className={`stroke-current ${flagged ? 'text-rose-500' : 'text-app-subtle'}`} strokeWidth={flagged ? 2 : 1.4} strokeDasharray={flow.encrypted ? undefined : '4 3'} /><text x={(sx + ex) / 2} y={(sy + ey) / 2 - 6} textAnchor="middle" fontSize={10} className="fill-current text-app-muted">{flow.name || flow.protocol.toUpperCase()}</text></g> })}
      {model.components.map(item => { const p = position[item.id]; if (!p) return null
        const flagged = hot.has(item.id), stroke = `stroke-current ${flagged ? 'text-rose-500' : 'text-app-muted'}`
        const shape = STORES.includes(item.kind) ? <><line x1={p.x} y1={p.y} x2={p.x + W} y2={p.y} className={stroke} strokeWidth={flagged ? 2.4 : 1.6} /><line x1={p.x} y1={p.y + H} x2={p.x + W} y2={p.y + H} className={stroke} strokeWidth={flagged ? 2.4 : 1.6} /></>
          : <><rect x={p.x} y={p.y} width={W} height={H} rx={PROCESSES.includes(item.kind) ? H / 2 : 4} className="fill-current text-app-soft" /><rect x={p.x} y={p.y} width={W} height={H} rx={PROCESSES.includes(item.kind) ? H / 2 : 4} className={`fill-none ${stroke}`} strokeWidth={flagged ? 2.4 : 1.4} /></>
        return <g key={item.id}>{shape}<text x={p.x + W / 2} y={p.y + H / 2 - 3} textAnchor="middle" fontSize={12} fontWeight={600} className="fill-current">{item.name.length > 22 ? `${item.name.slice(0, 21)}…` : item.name}</text><text x={p.x + W / 2} y={p.y + H / 2 + 13} textAnchor="middle" fontSize={10} className="fill-current text-app-subtle">{item.technology || kinds[byId[item.id]?.kind] || ''}</text></g> })}
    </svg></div>
    <p className="text-xs text-app-subtle">Rectángulo: actor o tercero · píldora: proceso · dos líneas: almacén · línea discontinua: flujo sin cifrar · en rojo: elementos con amenazas evidenciadas por hallazgos abiertos.</p>
  </CardContent></Card>
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
          <td className={cell}><select aria-label="Tipo" value={item.kind} onChange={event => updateComponent(item.id, { kind: event.target.value as Kind })} className={select}>{Object.entries(catalog.kinds).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select></td>
          <td className={cell}><select aria-label="Frontera" value={boundaryOf(item.id)} onChange={event => moveTo(item.id, event.target.value)} className={select}><option value="">Ninguna</option>{draft.boundaries.map(entry => <option key={entry.id} value={entry.id}>{entry.name}</option>)}</select></td>
          <td className={cell}><select aria-label="Activo enlazado" value={item.asset ?? ''} onChange={event => updateComponent(item.id, { asset: event.target.value || null })} className={`${select} max-w-48`}><option value="">Sin enlazar</option>{catalog.assets.map(asset => <option key={asset.id} value={asset.id}>{asset.name}</option>)}</select></td>
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
