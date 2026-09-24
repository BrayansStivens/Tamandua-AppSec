import { useState, type FormEvent, type ReactNode } from 'react'
import { BookOpen, ChevronRight, ExternalLink, GitBranch, LoaderCircle, Plus, Target, Trash2, X } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { attackUrl, GUIDES, METHOD_ORDER, type Methodology } from '@/components/threat-guides'
import { elementsOf, newId, type AttackMapping, type AttackTree, type Catalog, type Level, type ManualThreat, type Model, type Threat, type TreeNode } from '@/components/threat-model-types'

// Apartados propios de cada enfoque de modelado y su guía de consulta.

const select = 'h-8 rounded-lg border border-app-line bg-app-soft px-2 text-xs text-app-fg'
const area = 'w-full rounded-lg border border-app-line bg-app-soft px-3 py-2 text-sm leading-6 text-app-fg'
const LEVELS: Record<Level, string> = { low: 'Baja', medium: 'Media', high: 'Alta' }
const SEVERITIES = { critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja' } as const


// ------------------------------------------------------------------ elegir enfoque

export function MethodPicker({ value, onChange }: { value: Methodology; onChange: (next: Methodology) => void }) {
  return <div role="radiogroup" aria-label="Enfoque de modelado" className="grid gap-2 sm:grid-cols-2">
    {METHOD_ORDER.map(key => <button key={key} type="button" role="radio" aria-checked={value === key} onClick={() => onChange(key)}
      className={`rounded-xl border p-3 text-left transition ${value === key ? 'border-brand/60 bg-brand/[0.07]' : 'border-app-line bg-app-soft hover:border-app-faint'}`}>
      <span className="flex items-center justify-between gap-2"><span className="text-sm font-semibold">{GUIDES[key].name}</span>{key === 'stride' && <Badge variant="outline" className="border-app-line text-[11px] text-app-subtle">Recomendado para empezar</Badge>}</span>
      <span className="mt-1 block text-xs leading-5 text-app-muted">{GUIDES[key].purpose}</span>
    </button>)}
  </div>
}

export function MethodDialog({ current, onClose, onPick }: { current: Methodology; onClose: () => void; onPick: (next: Methodology) => void }) {
  const [value, setValue] = useState<Methodology>(current)
  return <Dialog open onOpenChange={next => { if (!next) onClose() }}><DialogContent className="max-w-2xl">
    <DialogHeader><DialogTitle>Enfoque del modelo</DialogTitle><DialogDescription>El diagrama, las amenazas propias y las decisiones se conservan al cambiar de enfoque; solo cambia cómo se analiza.</DialogDescription></DialogHeader>
    <MethodPicker value={value} onChange={setValue} />
    <DialogFooter><Button variant="ghost" onClick={onClose}>Cancelar</Button><Button onClick={() => onPick(value)} className="bg-primary text-primary-foreground hover:bg-primary/90">Usar {GUIDES[value].name}</Button></DialogFooter>
  </DialogContent></Dialog>
}

// ------------------------------------------------------------------ guía de consulta

export function GuidePanel({ methodology, onClose }: { methodology: Methodology; onClose: () => void }) {
  const guide = GUIDES[methodology]
  return <aside aria-label={`Guía de ${guide.name}`} className="space-y-4 rounded-2xl border border-app-line bg-panel p-4 text-sm xl:sticky xl:top-20 xl:max-h-[calc(100vh-6rem)] xl:overflow-y-auto">
    <div className="flex items-start justify-between gap-2"><p className="flex items-center gap-2 font-semibold"><BookOpen className="size-4 text-brand" />Guía de {guide.name}</p>
      <Button size="icon-sm" variant="ghost" aria-label="Cerrar la guía" onClick={onClose}><X /></Button></div>
    <p className="text-app-secondary">{guide.purpose}</p>
    <p className="text-xs leading-5 text-app-muted"><strong className="font-medium text-app-secondary">Cuándo: </strong>{guide.when}</p>
    {guide.categories && <div className="space-y-2">{guide.categories.map(item => <div key={item.code} className="rounded-lg border border-app-line bg-inset px-3 py-2">
      <p className="text-xs font-semibold"><span className="mr-1.5 inline-block min-w-6 rounded bg-brand/10 px-1 text-center font-mono text-brand">{item.code}</span>{item.name}{item.original && <span className="font-normal text-app-subtle"> · {item.original}</span>}</p>
      <p className="mt-1 text-xs leading-5 text-app-muted">{item.question}{item.property && <span className="text-app-subtle"> Protege: {item.property.toLowerCase()}.</span>}</p>
    </div>)}</div>}
    <details open={!guide.categories}><summary className="cursor-pointer text-xs font-medium text-app-secondary">Cómo se hace</summary>
      <ol className="mt-2 list-decimal space-y-1.5 pl-4 text-xs leading-5 text-app-muted">{guide.steps.map(step => <li key={step}>{step}</li>)}</ol></details>
    {guide.tips.map(tip => <p key={tip} className="rounded-lg bg-app-soft px-3 py-2 text-xs leading-5 text-app-muted">{tip}</p>)}
    {guide.source && <a href={guide.source.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-xs text-brand hover:underline">{guide.source.label}<ExternalLink className="size-3" /></a>}
  </aside>
}


// ------------------------------------------------------------------ amenazas propias

export function ManualThreatDialog({ model, initial, methodology, onClose, onSave, busy }: {
  model: Model; initial?: ManualThreat; methodology: Methodology; onClose: () => void; onSave: (threat: ManualThreat) => void; busy: boolean
}) {
  const [draft, setDraft] = useState<ManualThreat>(() => initial ?? { id: newId('amenaza', (model.manual_threats ?? []).map(item => item.id)), title: '', severity: 'medium' })
  const set = (change: Partial<ManualThreat>) => setDraft(previous => ({ ...previous, ...change }))
  const categories = GUIDES[methodology === 'pasta' ? 'stride' : methodology].categories ?? []
  const submit = (event: FormEvent) => { event.preventDefault(); onSave(draft) }
  return <Dialog open onOpenChange={next => { if (!next) onClose() }}><DialogContent className="max-w-xl">
    <DialogHeader><DialogTitle>{initial ? 'Editar amenaza' : 'Añadir amenaza'}</DialogTitle><DialogDescription>Describe el escenario: quién hace qué, sobre qué activo y con qué consecuencia. Se guarda con el modelo.</DialogDescription></DialogHeader>
    <form className="space-y-3" onSubmit={submit}>
      <Field label="Título"><Input required maxLength={160} value={draft.title} onChange={event => set({ title: event.target.value })} placeholder="p. ej. Robo de la sesión en una red Wi-Fi pública" className="border-app-line bg-app-soft" /></Field>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Categoría"><Input list="threat-categories" maxLength={40} value={draft.category ?? ''} onChange={event => set({ category: event.target.value })} placeholder={categories.length ? `p. ej. ${categories[0].code}` : 'la que uses en tu equipo'} className="border-app-line bg-app-soft" />
          <datalist id="threat-categories">{categories.map(item => <option key={item.code} value={item.code}>{item.name}</option>)}</datalist></Field>
        <Field label="Elemento"><select value={draft.element ?? ''} onChange={event => set({ element: event.target.value })} className={`${select} w-full`}><option value="">Todo el sistema</option>{elementsOf(model).map(item => <option key={item.id} value={item.id}>{item.label}</option>)}</select></Field>
      </div>
      <Field label="Escenario"><textarea rows={3} maxLength={1500} value={draft.scenario ?? ''} onChange={event => set({ scenario: event.target.value })} className={area} placeholder="Un atacante en la misma red captura la cookie de sesión porque…" /></Field>
      <div className="grid gap-3 sm:grid-cols-4">
        <Field label="Severidad"><select value={draft.severity} onChange={event => set({ severity: event.target.value as ManualThreat['severity'] })} className={`${select} w-full`}>{Object.entries(SEVERITIES).map(([key, text]) => <option key={key} value={key}>{text}</option>)}</select></Field>
        <Field label="Posibilidad"><LevelSelect value={draft.likelihood ?? null} onChange={likelihood => set({ likelihood })} /></Field>
        <Field label="Impacto"><LevelSelect value={draft.impact ?? null} onChange={impact => set({ impact })} /></Field>
        <Field label="Responsable"><Input maxLength={80} value={draft.owner ?? ''} onChange={event => set({ owner: event.target.value })} className="h-8 border-app-line bg-app-soft" /></Field>
      </div>
      <Field label="Mitigación"><textarea rows={2} maxLength={1500} value={draft.mitigation ?? ''} onChange={event => set({ mitigation: event.target.value })} className={area} /></Field>
      <DialogFooter><Button type="button" variant="ghost" onClick={onClose}>Cancelar</Button><Button type="submit" disabled={busy || !draft.title.trim()} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy && <LoaderCircle className="animate-spin" />}Guardar</Button></DialogFooter>
    </form>
  </DialogContent></Dialog>
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return <label className="block space-y-1"><span className="text-[11px] font-medium text-app-muted">{label}</span>{children}</label>
}

function LevelSelect({ value, onChange }: { value: Level | null; onChange: (next: Level | null) => void }) {
  return <select value={value ?? ''} onChange={event => onChange((event.target.value || null) as Level | null)} className={`${select} w-full`}><option value="">—</option>{Object.entries(LEVELS).map(([key, text]) => <option key={key} value={key}>{text}</option>)}</select>
}

// ------------------------------------------------------------------ PASTA

const STAGE_HINTS: Record<string, string> = {
  objectives: '¿Qué debe lograr el sistema para el negocio? ¿Qué no puede pasar nunca (fraude, fuga, caída)? ¿Qué exige la ley o los clientes?',
  scope: 'Tecnologías, infraestructura, dependencias y proveedores. Qué queda fuera de este análisis.',
  decomposition: 'Actores, componentes, flujos y fronteras: se dibujan en «Diagrama». Anota aquí los casos de uso clave.',
  threats: 'Quién atacaría y por qué. Las amenazas STRIDE del diagrama salen solas en «Amenazas»; añade las que conozcas del sector.',
  vulnerabilities: 'Debilidades conocidas relacionadas con esas amenazas: los hallazgos abiertos de los análisis aparecen abajo; añade auditorías o pentests.',
  attacks: 'Cómo se encadenarían amenazas y debilidades para lograr un objetivo. Usa los árboles de ataque.',
  risk: 'Probabilidad e impacto en el negocio de cada escenario, contramedidas y riesgo residual aceptado.',
}

export function PastaStages({ model, setModel, threats, catalog, onGo }: { model: Model; setModel: (model: Model) => void; threats: Threat[]; catalog: Catalog; onGo: (tab: string) => void }) {
  const notes = model.pasta ?? {}
  const [open, setOpen] = useState<string>(catalog.methods.pasta_stages.find(stage => !notes[stage.key])?.key ?? 'objectives')
  const withEvidence = threats.filter(row => row.status === 'evidenced')
  const findings = withEvidence.reduce((total, row) => total + row.evidence_count, 0)
  const pending = threats.filter(row => row.status === 'evidenced' || row.status === 'open')
  const auto: Record<string, ReactNode> = {
    decomposition: <Auto>{model.components.length} componentes, {model.flows.length} flujos y {model.boundaries.length} fronteras. <Go onClick={() => onGo('diagram')}>Abrir el diagrama</Go></Auto>,
    threats: <Auto>{threats.length} amenazas ({threats.filter(row => row.framework === 'manual').length} escritas por el equipo). <Go onClick={() => onGo('threats')}>Ver amenazas</Go></Auto>,
    vulnerabilities: <Auto>{withEvidence.length ? <>{withEvidence.length} amenazas con indicios en {findings} hallazgos abiertos de los análisis: {withEvidence.slice(0, 4).map(row => row.title).join(' · ')}{withEvidence.length > 4 ? '…' : ''}.</> : 'Ningún hallazgo abierto de los análisis se relaciona aún con estas amenazas.'} <Go onClick={() => onGo('threats')}>Ver indicios</Go></Auto>,
    attacks: <Auto>{(model.attack_trees ?? []).length} árboles de ataque. <Go onClick={() => onGo('trees')}>Abrir árboles</Go></Auto>,
    risk: <Auto>{pending.length} amenazas pendientes: {(['critical', 'high', 'medium', 'low'] as const).map(level => `${pending.filter(row => row.severity === level).length} ${SEVERITIES[level].toLowerCase()}s`).join(' · ')}.</Auto>,
  }
  return <div className="space-y-2">{catalog.methods.pasta_stages.map(stage => { const expanded = open === stage.key
    return <div key={stage.key} className="rounded-xl border border-app-line bg-panel">
      <button type="button" aria-expanded={expanded} onClick={() => setOpen(expanded ? '' : stage.key)} className="flex w-full items-center gap-2 px-4 py-3 text-left"><ChevronRight className={`size-4 text-app-subtle transition ${expanded ? 'rotate-90' : ''}`} /><span className="flex-1 text-sm font-medium">{stage.title}</span>{notes[stage.key] && <Badge variant="outline" className="border-brand/30 text-[11px] text-brand">con notas</Badge>}</button>
      {expanded && <div className="space-y-3 border-t border-app-line px-4 py-4">
        <p className="text-xs leading-5 text-app-subtle">{STAGE_HINTS[stage.key]}</p>
        {auto[stage.key]}
        <textarea aria-label={stage.title} rows={4} maxLength={4000} value={notes[stage.key] ?? ''} onChange={event => setModel({ ...model, pasta: { ...notes, [stage.key]: event.target.value } })} className={area} placeholder="Notas de esta etapa" />
      </div>}
    </div> })}</div>
}

function Auto({ children }: { children: ReactNode }) {
  return <p className="rounded-lg border border-app-line bg-inset px-3 py-2 text-xs leading-5 text-app-muted">{children}</p>
}
function Go({ onClick, children }: { onClick: () => void; children: ReactNode }) {
  return <button type="button" onClick={onClick} className="text-brand hover:underline">{children}</button>
}

// ------------------------------------------------------------------ árboles de ataque

const GOALS = ['Acceder a la cuenta de otro usuario', 'Obtener datos personales de la base de datos', 'Ejecutar código en el servidor',
  'Dejar el servicio sin disponibilidad', 'Hacer un pago o pedido en nombre de otro']

export function AttackTrees({ model, setModel }: { model: Model; setModel: (model: Model) => void }) {
  const trees = model.attack_trees ?? []
  const setTrees = (next: AttackTree[]) => setModel({ ...model, attack_trees: next })
  const add = (goal: string) => setTrees([...trees, { id: newId(goal || 'arbol', trees.map(item => item.id)), goal: goal || 'Nuevo objetivo', nodes: [] }])
  return <div className="space-y-4">
    <div className="flex flex-wrap items-center gap-2">
      <Button size="sm" onClick={() => add('')} className="bg-primary text-primary-foreground hover:bg-primary/90"><Plus />Árbol</Button>
      <select aria-label="Objetivos frecuentes" value="" onChange={event => { if (event.target.value) add(event.target.value) }} className={select}><option value="">Empezar desde un objetivo frecuente…</option>{GOALS.map(goal => <option key={goal}>{goal}</option>)}</select>
    </div>
    {trees.length === 0 && <p className="rounded-xl border border-dashed border-app-line px-4 py-10 text-center text-sm text-app-subtle">Aún no hay árboles. Empieza por el objetivo del atacante que más te preocupe.</p>}
    {trees.map(tree => <TreeEditor key={tree.id} tree={tree} model={model} onChange={next => setTrees(trees.map(item => item.id === tree.id ? next : item))} onRemove={() => setTrees(trees.filter(item => item.id !== tree.id))} />)}
  </div>
}

// Una rama Y queda cortada si se mitiga uno de sus pasos; una O, solo si se mitigan todos.
function blocked(node: TreeNode, children: Record<string, TreeNode[]>): boolean {
  const kids = children[node.id] ?? []
  if (node.mitigated) return true
  if (!kids.length) return false
  return node.gate === 'and' ? kids.some(kid => blocked(kid, children)) : kids.every(kid => blocked(kid, children))
}

function TreeEditor({ tree, model, onChange, onRemove }: { tree: AttackTree; model: Model; onChange: (tree: AttackTree) => void; onRemove: () => void }) {
  const children: Record<string, TreeNode[]> = {}
  for (const node of tree.nodes) (children[node.parent ?? 'root'] ??= []).push(node)
  const roots = children.root ?? []
  const rootGate = roots.length > 1 ? 'o' : ''
  const open = roots.filter(node => !blocked(node, children)).length
  const addNode = (parent: string | null) => onChange({ ...tree, nodes: [...tree.nodes, { id: newId('paso', tree.nodes.map(item => item.id)), parent, text: 'Nuevo paso', gate: 'or', mitigated: false }] })
  const update = (id: string, change: Partial<TreeNode>) => onChange({ ...tree, nodes: tree.nodes.map(item => item.id === id ? { ...item, ...change } : item) })
  const remove = (id: string) => { const gone = new Set([id]); let grew = true
    while (grew) { grew = false; for (const node of tree.nodes) if (node.parent && gone.has(node.parent) && !gone.has(node.id)) { gone.add(node.id); grew = true } }
    onChange({ ...tree, nodes: tree.nodes.filter(item => !gone.has(item.id)) }) }
  const elements = elementsOf(model)
  const render = (node: TreeNode, depth: number): ReactNode => {
    const kids = children[node.id] ?? []
    const cut = blocked(node, children)
    return <div key={node.id} style={{ marginLeft: depth ? 20 : 0 }} className="space-y-1.5">
      <div className={`flex flex-wrap items-center gap-2 rounded-lg border px-2 py-1.5 ${cut ? 'border-app-line bg-app-soft opacity-70' : 'border-app-line bg-panel'}`}>
        <GitBranch className="size-3.5 shrink-0 text-app-subtle" />
        <Input aria-label="Paso" value={node.text} maxLength={200} onChange={event => update(node.id, { text: event.target.value })} className={`h-7 min-w-48 flex-1 border-app-line bg-app-soft text-sm ${cut ? 'line-through' : ''}`} />
        {kids.length > 0 && <select aria-label="Cómo se combinan sus pasos" value={node.gate} onChange={event => update(node.id, { gate: event.target.value as 'and' | 'or' })} className={select} title="O: basta con uno de sus pasos · Y: hacen falta todos"><option value="or">O · basta uno</option><option value="and">Y · todos</option></select>}
        <select aria-label="Dificultad" value={node.difficulty ?? ''} onChange={event => update(node.id, { difficulty: (event.target.value || null) as Level | null })} className={select}><option value="">Dificultad</option>{Object.entries(LEVELS).map(([key, text]) => <option key={key} value={key}>{text}</option>)}</select>
        <select aria-label="Elemento" value={node.element ?? ''} onChange={event => update(node.id, { element: event.target.value })} className={`${select} max-w-40`}><option value="">Sin elemento</option>{elements.map(item => <option key={item.id} value={item.id}>{item.label}</option>)}</select>
        <label className="flex items-center gap-1 text-xs text-app-muted"><input type="checkbox" className="size-3.5 accent-brand" checked={node.mitigated} onChange={event => update(node.id, { mitigated: event.target.checked })} />Mitigado</label>
        <Button size="xs" variant="ghost" onClick={() => addNode(node.id)} aria-label="Añadir un paso debajo"><Plus />Paso</Button>
        <Button size="xs" variant="ghost" onClick={() => remove(node.id)} aria-label="Quitar este paso y los de debajo"><Trash2 /></Button>
      </div>
      {kids.map(kid => render(kid, depth + 1))}
    </div>
  }
  return <div className="space-y-3 rounded-2xl border border-app-line bg-panel p-4">
    <div className="flex flex-wrap items-center gap-2"><Target className="size-4 text-brand" /><Input aria-label="Objetivo del atacante" value={tree.goal} maxLength={200} onChange={event => onChange({ ...tree, goal: event.target.value })} className="h-8 min-w-64 flex-1 border-app-line bg-app-soft font-medium" />
      <span className="text-xs text-app-subtle">{roots.length ? `${open} de ${roots.length} rutas abiertas${rootGate ? ' (basta una)' : ''}` : 'sin rutas'}</span>
      <Button size="xs" variant="ghost" onClick={onRemove} aria-label="Quitar el árbol"><Trash2 /></Button></div>
    <div className="space-y-1.5">{roots.map(node => render(node, 0))}</div>
    <Button size="sm" variant="outline" className="border-app-line bg-app-soft" onClick={() => addNode(null)}><Plus />Ruta</Button>
  </div>
}

// ------------------------------------------------------------------ MITRE ATT&CK

const MAPPING_STATUS = { relevant: 'Relevante', mitigated: 'Mitigada', not_applicable: 'No aplica' } as const

export function AttackMappings({ model, setModel, catalog }: { model: Model; setModel: (model: Model) => void; catalog: Catalog }) {
  const { techniques, tactics, suggestions } = catalog.methods
  const rows = model.attack_mappings ?? []
  const setRows = (next: AttackMapping[]) => setModel({ ...model, attack_mappings: next })
  const [technique, setTechnique] = useState('')
  const [element, setElement] = useState('')
  const elements = elementsOf(model)
  const label = Object.fromEntries(elements.map(item => [item.id, item.label]))
  const has = (id: string, target: string) => rows.some(row => row.technique === id && (row.element ?? '') === target)
  const add = (id: string, target: string) => { if (id && !has(id, target)) setRows([...rows, { technique: id, element: target, status: 'relevant' }]) }
  // Sugerencias por tipo de componente, que no se añaden solas.
  const proposals = model.components.flatMap(component => {
    const keys = [component.kind, ...(component.internet_facing && ['web_app', 'api', 'service', 'function'].includes(component.kind) ? ['internet_process'] : []),
                  ...(['web_app', 'api', 'service', 'function'].includes(component.kind) ? ['process'] : [])]
    return [...new Set(keys.flatMap(key => suggestions[key] ?? []))].filter(id => !has(id, component.id)).map(id => ({ id, component }))
  }).slice(0, 24)
  const byTactic = Object.entries(tactics).map(([key, name]) => ({ key, name, items: Object.entries(techniques).filter(([, item]) => item.tactics[0] === key) })).filter(group => group.items.length)
  return <div className="space-y-4">
    <div className="flex flex-wrap items-end gap-2 rounded-2xl border border-app-line bg-panel p-4">
      <label className="min-w-64 flex-1 space-y-1"><span className="text-[11px] font-medium text-app-muted">Técnica</span>
        <select value={technique} onChange={event => setTechnique(event.target.value)} className={`${select} w-full`}><option value="">Elige una técnica…</option>
          {byTactic.map(group => <optgroup key={group.key} label={`${group.name} (${group.key})`}>{group.items.map(([id, item]) => <option key={id} value={id}>{id} · {item.name_es}</option>)}</optgroup>)}</select></label>
      <label className="min-w-48 space-y-1"><span className="text-[11px] font-medium text-app-muted">Elemento</span>
        <select value={element} onChange={event => setElement(event.target.value)} className={`${select} w-full`}><option value="">Todo el sistema</option>{elements.map(item => <option key={item.id} value={item.id}>{item.label}</option>)}</select></label>
      <Button size="sm" disabled={!technique} onClick={() => { add(technique, element); setTechnique('') }} className="bg-primary text-primary-foreground hover:bg-primary/90"><Plus />Mapear</Button>
    </div>
    {proposals.length > 0 && <details className="rounded-2xl border border-app-line bg-panel p-4"><summary className="cursor-pointer text-sm font-medium">Sugerencias para revisar ({proposals.length})</summary>
      <p className="mt-1 text-xs text-app-subtle">Técnicas habituales contra este tipo de componentes. No se añaden solas: añade las que apliquen.</p>
      <div className="mt-3 flex flex-wrap gap-1.5">{proposals.map(({ id, component }) => <button key={`${id}:${component.id}`} onClick={() => add(id, component.id)} className="inline-flex items-center gap-1 rounded-lg border border-app-line bg-app-soft px-2 py-1 text-xs text-app-muted hover:border-brand/40 hover:text-brand"><Plus className="size-3" /><span className="font-mono">{id}</span> {techniques[id]?.name_es} → {component.name}</button>)}</div>
    </details>}
    {rows.length === 0 ? <p className="rounded-xl border border-dashed border-app-line px-4 py-10 text-center text-sm text-app-subtle">Sin técnicas mapeadas. Empieza por las sugerencias o por la táctica «Acceso inicial».</p>
      : <div className="divide-y divide-app-line overflow-hidden rounded-2xl border border-app-line bg-panel">{rows.map((row, index) => { const item = techniques[row.technique]
        return <div key={`${row.technique}:${row.element}`} className="grid gap-2 px-4 py-3 md:grid-cols-[minmax(0,1.2fr)_minmax(0,0.8fr)_130px_minmax(0,1fr)_36px] md:items-start">
          <div className="min-w-0"><a href={attackUrl(row.technique)} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-sm font-medium hover:text-brand"><span className="font-mono text-xs text-app-subtle">{row.technique}</span>{item?.name_es}<ExternalLink className="size-3 text-app-subtle" /></a>
            <p className="text-[11px] text-app-subtle">{item?.name} · {item?.tactics.map(key => tactics[key]).join(', ')}</p></div>
          <p className="text-xs text-app-muted">{row.element ? label[row.element] ?? '—' : 'Todo el sistema'}</p>
          <select aria-label="Estado" value={row.status} onChange={event => setRows(rows.map((entry, position) => position === index ? { ...entry, status: event.target.value as AttackMapping['status'] } : entry))} className={select}>{Object.entries(MAPPING_STATUS).map(([key, text]) => <option key={key} value={key}>{text}</option>)}</select>
          <Input aria-label="Control o nota" value={row.note ?? ''} maxLength={600} placeholder="Qué la previene o la detecta" onChange={event => setRows(rows.map((entry, position) => position === index ? { ...entry, note: event.target.value } : entry))} className="h-8 border-app-line bg-app-soft text-xs" />
          <Button size="icon-sm" variant="ghost" aria-label="Quitar" onClick={() => setRows(rows.filter((_, position) => position !== index))}><Trash2 /></Button>
        </div> })}</div>}
    <p className="text-[11px] text-app-subtle">MITRE ATT&CK® es una marca de The MITRE Corporation. Aquí hay una selección de técnicas; el catálogo completo está en attack.mitre.org.</p>
  </div>
}
