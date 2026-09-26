import { useState, type FormEvent, type ReactNode } from 'react'
import { BookOpen, ChevronRight, ExternalLink, GitBranch, LoaderCircle, Plus, Target, Trash2, X } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { Input } from '@/shared/ui/input'
import { currentLocale } from '@/shared/i18n'
import { attackUrl, guideOf, methodName, METHOD_ORDER, type Methodology } from '@/features/threats/threat-guides'
import { elementsOf, newId, type AttackMapping, type AttackTree, type Catalog, type Level, type ManualThreat, type Model, type Threat, type TreeNode } from '@/features/threats/threat-model-types'

// Apartados propios de cada enfoque de modelado y su guía de consulta.

const select = 'h-8 rounded-lg border border-app-line bg-app-soft px-2 text-xs text-app-fg'
const area = 'w-full rounded-lg border border-app-line bg-app-soft px-3 py-2 text-sm leading-6 text-app-fg'
// Catalog keys: levels in `threats`, severities in `common`.
const LEVELS: Record<Level, string> = { low: 'level.low', medium: 'level.medium', high: 'level.high' }
const SEVERITIES = { critical: 'common:severity.critical', high: 'common:severity.high', medium: 'common:severity.medium', low: 'common:severity.low' } as const
const SEVERITY_COUNT = { critical: 'pasta.severity_count.critical', high: 'pasta.severity_count.high', medium: 'pasta.severity_count.medium', low: 'pasta.severity_count.low' } as const

// The server sends the English ATT&CK name plus a Spanish one.
const techniqueName = (item?: { name: string; name_es?: string }) => item ? (currentLocale() === 'es' && item.name_es ? item.name_es : item.name) : undefined


// ------------------------------------------------------------------ elegir enfoque

export function MethodPicker({ value, onChange }: { value: Methodology; onChange: (next: Methodology) => void }) {
  const { t } = useTranslation('threats')
  return <div role="radiogroup" aria-label={t('methods.picker_label')} className="grid gap-2 sm:grid-cols-2">
    {METHOD_ORDER.map(key => <button key={key} type="button" role="radio" aria-checked={value === key} onClick={() => onChange(key)}
      className={`rounded-xl border p-3 text-left transition ${value === key ? 'border-brand/60 bg-brand/[0.07]' : 'border-app-line bg-app-soft hover:border-app-faint'}`}>
      <span className="flex items-center justify-between gap-2"><span className="text-sm font-semibold">{methodName(key)}</span>{key === 'stride' && <Badge variant="outline" className="border-app-line text-[11px] text-app-subtle">{t('methods.recommended')}</Badge>}</span>
      <span className="mt-1 block text-xs leading-5 text-app-muted">{guideOf(key).purpose}</span>
    </button>)}
  </div>
}

export function MethodDialog({ current, onClose, onPick }: { current: Methodology; onClose: () => void; onPick: (next: Methodology) => void }) {
  const { t } = useTranslation('threats')
  const [value, setValue] = useState<Methodology>(current)
  return <Dialog open onOpenChange={next => { if (!next) onClose() }}><DialogContent className="max-w-2xl">
    <DialogHeader><DialogTitle>{t('methods.dialog_title')}</DialogTitle><DialogDescription>{t('methods.dialog_description')}</DialogDescription></DialogHeader>
    <MethodPicker value={value} onChange={setValue} />
    <DialogFooter><Button variant="ghost" onClick={onClose}>{t('common:actions.cancel')}</Button><Button onClick={() => onPick(value)} className="bg-primary text-primary-foreground hover:bg-primary/90">{t('methods.use', { name: methodName(value) })}</Button></DialogFooter>
  </DialogContent></Dialog>
}

// ------------------------------------------------------------------ guía de consulta

export function GuidePanel({ methodology, onClose }: { methodology: Methodology; onClose: () => void }) {
  const { t } = useTranslation('threats')
  const guide = guideOf(methodology)
  return <aside aria-label={t('guide.title', { name: guide.name })} className="space-y-4 rounded-2xl border border-app-line bg-panel p-4 text-sm xl:sticky xl:top-20 xl:max-h-[calc(100vh-6rem)] xl:overflow-y-auto">
    <div className="flex items-start justify-between gap-2"><p className="flex items-center gap-2 font-semibold"><BookOpen className="size-4 text-brand" />{t('guide.title', { name: guide.name })}</p>
      <Button size="icon-sm" variant="ghost" aria-label={t('guide.close')} onClick={onClose}><X /></Button></div>
    <p className="text-app-secondary">{guide.purpose}</p>
    <p className="text-xs leading-5 text-app-muted"><strong className="font-medium text-app-secondary">{t('guide.when')} </strong>{guide.when}</p>
    {guide.categories && <div className="space-y-2">{guide.categories.map(item => <div key={item.code} className="rounded-lg border border-app-line bg-inset px-3 py-2">
      <p className="text-xs font-semibold"><span className="mr-1.5 inline-block min-w-6 rounded bg-brand/10 px-1 text-center font-mono text-brand">{item.code}</span>{item.name}{item.original && item.original !== item.name && <span className="font-normal text-app-subtle"> · {item.original}</span>}</p>
      <p className="mt-1 text-xs leading-5 text-app-muted">{item.question}{item.property && <span className="text-app-subtle"> {t('guide.property', { property: item.property.toLowerCase() })}</span>}</p>
    </div>)}</div>}
    <details open={!guide.categories}><summary className="cursor-pointer text-xs font-medium text-app-secondary">{t('guide.how')}</summary>
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
  const { t } = useTranslation('threats')
  const set = (change: Partial<ManualThreat>) => setDraft(previous => ({ ...previous, ...change }))
  const categories = guideOf(methodology === 'pasta' ? 'stride' : methodology).categories ?? []
  const submit = (event: FormEvent) => { event.preventDefault(); onSave(draft) }
  return <Dialog open onOpenChange={next => { if (!next) onClose() }}><DialogContent className="max-w-xl">
    <DialogHeader><DialogTitle>{initial ? t('manual.edit_title') : t('manual.add_title')}</DialogTitle><DialogDescription>{t('manual.description')}</DialogDescription></DialogHeader>
    <form className="space-y-3" onSubmit={submit}>
      <Field label={t('manual.title')}><Input required maxLength={160} value={draft.title} onChange={event => set({ title: event.target.value })} placeholder={t('manual.title_placeholder')} className="border-app-line bg-app-soft" /></Field>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label={t('manual.category')}><Input list="threat-categories" maxLength={40} value={draft.category ?? ''} onChange={event => set({ category: event.target.value })} placeholder={categories.length ? t('manual.category_example', { code: categories[0].code }) : t('manual.category_placeholder')} className="border-app-line bg-app-soft" />
          <datalist id="threat-categories">{categories.map(item => <option key={item.code} value={item.code}>{item.name}</option>)}</datalist></Field>
        <Field label={t('manual.element')}><select value={draft.element ?? ''} onChange={event => set({ element: event.target.value })} className={`${select} w-full`}><option value="">{t('manual.whole_system')}</option>{elementsOf(model).map(item => <option key={item.id} value={item.id}>{item.label}</option>)}</select></Field>
      </div>
      <Field label={t('manual.scenario')}><textarea rows={3} maxLength={1500} value={draft.scenario ?? ''} onChange={event => set({ scenario: event.target.value })} className={area} placeholder={t('manual.scenario_placeholder')} /></Field>
      <div className="grid gap-3 sm:grid-cols-4">
        <Field label={t('manual.severity')}><select value={draft.severity} onChange={event => set({ severity: event.target.value as ManualThreat['severity'] })} className={`${select} w-full`}>{Object.entries(SEVERITIES).map(([key, text]) => <option key={key} value={key}>{t(text)}</option>)}</select></Field>
        <Field label={t('manual.likelihood')}><LevelSelect value={draft.likelihood ?? null} onChange={likelihood => set({ likelihood })} /></Field>
        <Field label={t('manual.impact')}><LevelSelect value={draft.impact ?? null} onChange={impact => set({ impact })} /></Field>
        <Field label={t('manual.owner')}><Input maxLength={80} value={draft.owner ?? ''} onChange={event => set({ owner: event.target.value })} className="h-8 border-app-line bg-app-soft" /></Field>
      </div>
      <Field label={t('manual.mitigation')}><textarea rows={2} maxLength={1500} value={draft.mitigation ?? ''} onChange={event => set({ mitigation: event.target.value })} className={area} /></Field>
      <DialogFooter><Button type="button" variant="ghost" onClick={onClose}>{t('common:actions.cancel')}</Button><Button type="submit" disabled={busy || !draft.title.trim()} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy && <LoaderCircle className="animate-spin" />}{t('common:actions.save')}</Button></DialogFooter>
    </form>
  </DialogContent></Dialog>
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return <label className="block space-y-1"><span className="text-[11px] font-medium text-app-muted">{label}</span>{children}</label>
}

function LevelSelect({ value, onChange }: { value: Level | null; onChange: (next: Level | null) => void }) {
  const { t } = useTranslation('threats')
  return <select value={value ?? ''} onChange={event => onChange((event.target.value || null) as Level | null)} className={`${select} w-full`}><option value="">—</option>{Object.entries(LEVELS).map(([key, text]) => <option key={key} value={key}>{t(text)}</option>)}</select>
}

// ------------------------------------------------------------------ PASTA

const STAGE_HINTS: Record<string, string> = {
  objectives: 'pasta.hints.objectives', scope: 'pasta.hints.scope', decomposition: 'pasta.hints.decomposition', threats: 'pasta.hints.threats',
  vulnerabilities: 'pasta.hints.vulnerabilities', attacks: 'pasta.hints.attacks', risk: 'pasta.hints.risk',
}

export function PastaStages({ model, setModel, threats, catalog, onGo }: { model: Model; setModel: (model: Model) => void; threats: Threat[]; catalog: Catalog; onGo: (tab: string) => void }) {
  const { t } = useTranslation('threats')
  const notes = model.pasta ?? {}
  const [open, setOpen] = useState<string>(catalog.methods.pasta_stages.find(stage => !notes[stage.key])?.key ?? 'objectives')
  const withEvidence = threats.filter(row => row.status === 'evidenced')
  const findings = withEvidence.reduce((total, row) => total + row.evidence_count, 0)
  const pending = threats.filter(row => row.status === 'evidenced' || row.status === 'open')
  const auto: Record<string, ReactNode> = {
    decomposition: <Auto>{t('pasta.auto.decomposition', { components: t('count.components', { count: model.components.length }), flows: t('count.flows', { count: model.flows.length }), boundaries: t('count.boundaries', { count: model.boundaries.length }) })} <Go onClick={() => onGo('diagram')}>{t('pasta.auto.open_diagram')}</Go></Auto>,
    threats: <Auto>{t('pasta.auto.threats', { threats: t('count.threats', { count: threats.length }), count: threats.filter(row => row.framework === 'manual').length })} <Go onClick={() => onGo('threats')}>{t('pasta.auto.view_threats')}</Go></Auto>,
    vulnerabilities: <Auto>{withEvidence.length ? t('pasta.auto.evidence', { threats: t('count.threats', { count: withEvidence.length }), findings: t('count.open_findings', { count: findings }), titles: `${withEvidence.slice(0, 4).map(row => row.title).join(' · ')}${withEvidence.length > 4 ? '…' : ''}` }) : t('pasta.auto.no_evidence')} <Go onClick={() => onGo('threats')}>{t('pasta.auto.view_evidence')}</Go></Auto>,
    attacks: <Auto>{t('pasta.auto.trees', { count: (model.attack_trees ?? []).length })} <Go onClick={() => onGo('trees')}>{t('pasta.auto.open_trees')}</Go></Auto>,
    risk: <Auto>{t('pasta.auto.risk', { count: pending.length, breakdown: (['critical', 'high', 'medium', 'low'] as const).map(level => t(SEVERITY_COUNT[level], { count: pending.filter(row => row.severity === level).length })).join(' · ') })}</Auto>,
  }
  return <div className="space-y-2">{catalog.methods.pasta_stages.map(stage => { const expanded = open === stage.key
    return <div key={stage.key} className="rounded-xl border border-app-line bg-panel">
      <button type="button" aria-expanded={expanded} onClick={() => setOpen(expanded ? '' : stage.key)} className="flex w-full items-center gap-2 px-4 py-3 text-left"><ChevronRight className={`size-4 text-app-subtle transition ${expanded ? 'rotate-90' : ''}`} /><span className="flex-1 text-sm font-medium">{stage.title}</span>{notes[stage.key] && <Badge variant="outline" className="border-brand/30 text-[11px] text-brand">{t('pasta.has_notes')}</Badge>}</button>
      {expanded && <div className="space-y-3 border-t border-app-line px-4 py-4">
        {STAGE_HINTS[stage.key] && <p className="text-xs leading-5 text-app-subtle">{t(STAGE_HINTS[stage.key])}</p>}
        {auto[stage.key]}
        <textarea aria-label={stage.title} rows={4} maxLength={4000} value={notes[stage.key] ?? ''} onChange={event => setModel({ ...model, pasta: { ...notes, [stage.key]: event.target.value } })} className={area} placeholder={t('pasta.notes_placeholder')} />
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

export function AttackTrees({ model, setModel }: { model: Model; setModel: (model: Model) => void }) {
  const { t } = useTranslation('threats')
  const goals: unknown = t('trees.goals', { returnObjects: true })
  const trees = model.attack_trees ?? []
  const setTrees = (next: AttackTree[]) => setModel({ ...model, attack_trees: next })
  const add = (goal: string) => setTrees([...trees, { id: newId(goal || 'arbol', trees.map(item => item.id)), goal: goal || t('trees.new_goal'), nodes: [] }])
  return <div className="space-y-4">
    <div className="flex flex-wrap items-center gap-2">
      <Button size="sm" onClick={() => add('')} className="bg-primary text-primary-foreground hover:bg-primary/90"><Plus />{t('trees.tree')}</Button>
      <select aria-label={t('trees.common_goals')} value="" onChange={event => { if (event.target.value) add(event.target.value) }} className={select}><option value="">{t('trees.start_from_goal')}</option>{(Array.isArray(goals) ? goals.map(String) : []).map(goal => <option key={goal}>{goal}</option>)}</select>
    </div>
    {trees.length === 0 && <p className="rounded-xl border border-dashed border-app-line px-4 py-10 text-center text-sm text-app-subtle">{t('trees.empty')}</p>}
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
  const { t } = useTranslation('threats')
  const children: Record<string, TreeNode[]> = {}
  for (const node of tree.nodes) (children[node.parent ?? 'root'] ??= []).push(node)
  const roots = children.root ?? []
  const open = roots.filter(node => !blocked(node, children)).length
  const addNode = (parent: string | null) => onChange({ ...tree, nodes: [...tree.nodes, { id: newId('paso', tree.nodes.map(item => item.id)), parent, text: t('trees.new_step'), gate: 'or', mitigated: false }] })
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
        <Input aria-label={t('trees.step')} value={node.text} maxLength={200} onChange={event => update(node.id, { text: event.target.value })} className={`h-7 min-w-48 flex-1 border-app-line bg-app-soft text-sm ${cut ? 'line-through' : ''}`} />
        {kids.length > 0 && <select aria-label={t('trees.gate')} value={node.gate} onChange={event => update(node.id, { gate: event.target.value as 'and' | 'or' })} className={select} title={t('trees.gate_hint')}><option value="or">{t('trees.gate_or')}</option><option value="and">{t('trees.gate_and')}</option></select>}
        <select aria-label={t('trees.difficulty')} value={node.difficulty ?? ''} onChange={event => update(node.id, { difficulty: (event.target.value || null) as Level | null })} className={select}><option value="">{t('trees.difficulty')}</option>{Object.entries(LEVELS).map(([key, text]) => <option key={key} value={key}>{t(text)}</option>)}</select>
        <select aria-label={t('manual.element')} value={node.element ?? ''} onChange={event => update(node.id, { element: event.target.value })} className={`${select} max-w-40`}><option value="">{t('trees.no_element')}</option>{elements.map(item => <option key={item.id} value={item.id}>{item.label}</option>)}</select>
        <label className="flex items-center gap-1 text-xs text-app-muted"><input type="checkbox" className="size-3.5 accent-brand" checked={node.mitigated} onChange={event => update(node.id, { mitigated: event.target.checked })} />{t('trees.mitigated')}</label>
        <Button size="xs" variant="ghost" onClick={() => addNode(node.id)} aria-label={t('trees.add_step')}><Plus />{t('trees.step')}</Button>
        <Button size="xs" variant="ghost" onClick={() => remove(node.id)} aria-label={t('trees.remove_step')}><Trash2 /></Button>
      </div>
      {kids.map(kid => render(kid, depth + 1))}
    </div>
  }
  return <div className="space-y-3 rounded-2xl border border-app-line bg-panel p-4">
    <div className="flex flex-wrap items-center gap-2"><Target className="size-4 text-brand" /><Input aria-label={t('trees.goal')} value={tree.goal} maxLength={200} onChange={event => onChange({ ...tree, goal: event.target.value })} className="h-8 min-w-64 flex-1 border-app-line bg-app-soft font-medium" />
      <span className="text-xs text-app-subtle">{roots.length ? t('trees.paths', { open, count: roots.length }) : t('trees.no_paths')}</span>
      <Button size="xs" variant="ghost" onClick={onRemove} aria-label={t('trees.remove_tree')}><Trash2 /></Button></div>
    <div className="space-y-1.5">{roots.map(node => render(node, 0))}</div>
    <Button size="sm" variant="outline" className="border-app-line bg-app-soft" onClick={() => addNode(null)}><Plus />{t('trees.path')}</Button>
  </div>
}

// ------------------------------------------------------------------ MITRE ATT&CK

const MAPPING_STATUS = { relevant: 'attack.status.relevant', mitigated: 'attack.status.mitigated', not_applicable: 'attack.status.not_applicable' } as const

export function AttackMappings({ model, setModel, catalog }: { model: Model; setModel: (model: Model) => void; catalog: Catalog }) {
  const { t } = useTranslation('threats')
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
      <label className="min-w-64 flex-1 space-y-1"><span className="text-[11px] font-medium text-app-muted">{t('attack.technique')}</span>
        <select value={technique} onChange={event => setTechnique(event.target.value)} className={`${select} w-full`}><option value="">{t('attack.choose_technique')}</option>
          {byTactic.map(group => <optgroup key={group.key} label={`${group.name} (${group.key})`}>{group.items.map(([id, item]) => <option key={id} value={id}>{id} · {techniqueName(item)}</option>)}</optgroup>)}</select></label>
      <label className="min-w-48 space-y-1"><span className="text-[11px] font-medium text-app-muted">{t('manual.element')}</span>
        <select value={element} onChange={event => setElement(event.target.value)} className={`${select} w-full`}><option value="">{t('manual.whole_system')}</option>{elements.map(item => <option key={item.id} value={item.id}>{item.label}</option>)}</select></label>
      <Button size="sm" disabled={!technique} onClick={() => { add(technique, element); setTechnique('') }} className="bg-primary text-primary-foreground hover:bg-primary/90"><Plus />{t('attack.map')}</Button>
    </div>
    {proposals.length > 0 && <details className="rounded-2xl border border-app-line bg-panel p-4"><summary className="cursor-pointer text-sm font-medium">{t('attack.suggestions', { count: proposals.length })}</summary>
      <p className="mt-1 text-xs text-app-subtle">{t('attack.suggestions_hint')}</p>
      <div className="mt-3 flex flex-wrap gap-1.5">{proposals.map(({ id, component }) => <button key={`${id}:${component.id}`} onClick={() => add(id, component.id)} className="inline-flex items-center gap-1 rounded-lg border border-app-line bg-app-soft px-2 py-1 text-xs text-app-muted hover:border-brand/40 hover:text-brand"><Plus className="size-3" /><span className="font-mono">{id}</span> {techniqueName(techniques[id])} → {component.name}</button>)}</div>
    </details>}
    {rows.length === 0 ? <p className="rounded-xl border border-dashed border-app-line px-4 py-10 text-center text-sm text-app-subtle">{t('attack.empty')}</p>
      : <div className="divide-y divide-app-line overflow-hidden rounded-2xl border border-app-line bg-panel">{rows.map((row, index) => { const item = techniques[row.technique]
        return <div key={`${row.technique}:${row.element}`} className="grid gap-2 px-4 py-3 md:grid-cols-[minmax(0,1.2fr)_minmax(0,0.8fr)_130px_minmax(0,1fr)_36px] md:items-start">
          <div className="min-w-0"><a href={attackUrl(row.technique)} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-sm font-medium hover:text-brand"><span className="font-mono text-xs text-app-subtle">{row.technique}</span>{techniqueName(item)}<ExternalLink className="size-3 text-app-subtle" /></a>
            <p className="text-[11px] text-app-subtle">{[techniqueName(item) !== item?.name ? item?.name : '', item?.tactics.map(key => tactics[key]).join(', ')].filter(Boolean).join(' · ')}</p></div>
          <p className="text-xs text-app-muted">{row.element ? label[row.element] ?? '—' : t('manual.whole_system')}</p>
          <select aria-label={t('attack.status_label')} value={row.status} onChange={event => setRows(rows.map((entry, position) => position === index ? { ...entry, status: event.target.value as AttackMapping['status'] } : entry))} className={select}>{Object.entries(MAPPING_STATUS).map(([key, text]) => <option key={key} value={key}>{t(text)}</option>)}</select>
          <Input aria-label={t('attack.note')} value={row.note ?? ''} maxLength={600} placeholder={t('attack.note_placeholder')} onChange={event => setRows(rows.map((entry, position) => position === index ? { ...entry, note: event.target.value } : entry))} className="h-8 border-app-line bg-app-soft text-xs" />
          <Button size="icon-sm" variant="ghost" aria-label={t('common:actions.remove')} onClick={() => setRows(rows.filter((_, position) => position !== index))}><Trash2 /></Button>
        </div> })}</div>}
    <p className="text-[11px] text-app-subtle">{t('attack.trademark')}</p>
  </div>
}
